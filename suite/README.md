# RedactWall Regression Suite (`suite/`)

A standalone, black-box regression suite the team runs against the evolving web
app. It is **separate from the unit suite in `test/`**: it boots the real
Express app over HTTP (or a real browser for the UI tier) and asserts observable
behavior only — route contracts, auth boundaries, PII hygiene, audit tamper
evidence, detector quality floors, and end-to-end console journeys.

Everything uses **synthetic data only** (`123-45-6789`, `4111111111111111`,
`jane.doe@example.com`, `524-71-xxxx`). No raw prompt text, PII, or secrets are
logged or thrown beyond those synthetic markers.

## Layout

```
suite/
  runner.js                 # node runner for the non-UI tiers
  support/                  # shared bootstrap, login/ingest helpers, e2e app boot
  contract/  *.suite.js     # API contract: status codes, auth boundaries, response shape
  security/  *.suite.js     # authz/IDOR, brute force, CSRF, PII-leak, audit tamper, headers
  detector/  *.suite.js     # alwaysBlock regression + held-out eval floors
  flows/     *.suite.spec.js# Playwright console journeys (own playwright.config.js)
  playwright.config.js      # flows config, reusing the scripts/playwright-server pattern
```

## Running

```bash
npm run suite:smoke      # fast subset: files tagged "// @tier smoke"
npm run suite            # full non-UI run (contract + security + detector)
npm run suite:contract   # one tier
npm run suite:security
npm run suite:detector
npm run suite:ui         # Playwright flows tier (port-safe wrapper)
```

Under the hood:

- `node suite/runner.js [--full|--smoke|--tier <name>]` discovers every
  `suite/**/*.suite.js` under the `contract`/`security`/`detector` tiers and runs
  each file in its **own `node --test` child process** (modeled on
  `scripts/run-node-tests.js`) so one file's env / app instance never leaks into
  another.
- **Smoke selection** is by marker: a file is in the smoke set when its **first
  line contains `// @tier smoke`**. Current smoke files: `contract/health`,
  `contract/sensor-routes`, `security/pii-leak`, `detector/always-block`.
- The **UI tier** runs through `scripts/run-playwright.js` (the same port-locking
  wrapper the product uses) with `--config=suite/playwright.config.js`, which
  boots `suite/support/playwright-server.js` — a variant of
  `scripts/playwright-server.js` that also sets `AUDITOR_USER` /
  `AUDITOR_PASSWORD` so the role journeys work.

## Shared bootstrap (`support/app.js`)

Each `*.suite.js` calls `bootEnv()` at the **top of the file, before requiring
the app**, so server modules read the temp SQLite path, temp policy, and suite
credentials at load time (the same discipline as `test/support/listen.js`).
Helpers: `withServer(app, fn)` (ephemeral loopback port), `login(port, role)`
(returns `{cookie, csrfToken}`), `gate(port, payload)` (ingest client for
`/api/v1/gate`), and `seedHeldPrompt(port, opts)`.

## Test cases implemented

Contract tier
1. `contract/admin-routes.suite.js` — every admin GET route from the README route
   table returns 401 unauthenticated and its documented top-level shape when
   authenticated; unsafe routes 401 without a session; unknown ids 404; sealed
   fields never serialize.
2. `contract/sensor-routes.suite.js` — every `/api/v1/*` route 401s without
   `x-api-key`; gate happy path returns `allow` + a prompt-free signed receipt;
   held prompts return `block` with no receipt; `/api/v1/policy` shape; policy
   round-trip `PUT /api/policy` → `GET /api/policy` → `GET /api/v1/policy` stays
   consistent and the sensor payload excludes admin-only retention fields.
3. `contract/health.suite.js` — `/healthz`, `/readyz`, `/api/login-options`
   shapes (public, credential-free).
   Also `contract/scim-routes.suite.js` — SCIM `/scim/v2` bearer boundary + user
   lifecycle + list envelopes.

Security tier
4. `security/authz-csrf.suite.js` — IDOR: approver cannot decide a
   security_admin-routed item or one assigned to another approver (403 / bulk
   skip "not yours to decide"); auditor is 403 on every CSRF write.
5. `security/login-bruteforce.suite.js` — repeated bad passwords lock the
   user+IP key and return **429** (discovered from `server/auth.js`:
   `LOGIN_MAX_ATTEMPTS`, then 429 even for the correct password); lockout is
   per-key.
6. CSRF — same file as (4): a valid session without / with a wrong
   `x-csrf-token` is rejected on unsafe admin routes.
7. `security/pii-leak.suite.js` — synthetic SSN `123-45-6789` + card
   `4111111111111111` through the gate never appear raw in `/api/queries`,
   `/api/audit`, `/api/export/evidence`, `/api/stats` (and more), **nor in
   server stdout/stderr** — captured in-process by wrapping the write streams
   before the app loads.
8. `security/audit-tamper.suite.js` — write evidence, then mutate a query row
   and an audit row directly via a second `better-sqlite3` connection to the
   temp DB, and assert `/api/audit` integrity reports `evidence` then `chain`
   broken (the audit table's append-only guard triggers are dropped first, as a
   disk-level attacker would).
9. `security/security-headers.suite.js` — CSP (`script-src 'self'`,
   `frame-ancestors 'none'`), `X-Content-Type-Options`, `X-Frame-Options`,
   `Referrer-Policy`, `Permissions-Policy`, no `X-Powered-By`, and
   HttpOnly + SameSite=Strict cookie — asserted black-box over HTTP.

Detector tier
10. `detector/always-block.suite.js` — every alwaysBlock type (US_SSN,
    CREDIT_CARD, BANK_ACCOUNT, ROUTING_NUMBER, IBAN, US_PASSPORT, SECRET_KEY,
    PRIVATE_KEY) is withheld (`pending`) via `POST /api/v1/gate` even under
    `warn` enforcement, while non-hard-stop content is only warned.
11. `detector/eval-floors.suite.js` — imports `scripts/eval-detect.js` and
    re-asserts the published precision/recall/FP floors on the held-out corpus.

UI flows tier (Playwright)
12. `flows/auditor-journey.suite.spec.js` — auditor login → read-only console
    (no approve/deny/save controls) → evidence export works and is PII-free →
    direct API write from that session returns 403.
13. `flows/sse-live-update.suite.spec.js` — console open, ingest a blocking
    prompt, the queue/pending badge updates over EventSource `/api/stream`
    **without a page reload** (navigation counter asserted unchanged).
14. `flows/bulk-queue.suite.spec.js` — seed 3 held items, select all in the
    queue UI, bulk-deny, assert all three transition to `denied`.
15. `flows/session-expiry.suite.spec.js` — clear cookies mid-session; the next
    action lands back on `/login.html` with no page error.

Focused unit tests added to the normal `test/` suite for the four
previously-untested server modules: `test/audit-integrity.test.js`,
`test/url-policy.test.js`, `test/sensor-metadata.test.js`,
`test/ai-app-catalog-module.test.js`.

## Adding a test

1. Pick a tier directory (`contract`, `security`, `detector`). Name the file
   `something.suite.js`.
2. First lines:
   ```js
   // @tier smoke            // optional — include only if it should run in smoke
   'use strict';
   const test = require('node:test');
   const assert = require('node:assert');
   const support = require('../support/app');
   support.bootEnv();        // BEFORE requiring the app; pass { policy, env } to customize
   const app = support.requireApp();
   ```
3. Use `support.withServer(app, async (port) => { ... })`, `support.login`,
   `support.gate`, and `support.seedHeldPrompt`. Keep data synthetic.
4. For a browser journey, add a `*.suite.spec.js` under `flows/` and run with
   `npm run suite:ui`.

## Environment notes

- Playwright browsers live under `PLAYWRIGHT_BROWSERS_PATH` (`/opt/pw-browsers`).
  The bundled full-chromium build revision can differ from the one
  `@playwright/test` resolves by default, so `suite/playwright.config.js` pins
  `launchOptions.executablePath` to the `chromium-*/chrome-linux*/chrome` binary
  it finds there. Do **not** run `playwright install`.

## Known findings

- **Audit append-only is DB-enforced, not just app-enforced (positive).** The
  `audit` table carries SQLite `BEFORE UPDATE`/`BEFORE DELETE` triggers
  (`server/storage/migrations.js`) that abort tampering with
  `"audit log is append-only"`. The tamper test must drop those triggers on its
  raw connection before it can even simulate a disk-level attacker — a good
  defense-in-depth result, not a bug.
- No product bugs were found by this suite. All tiers pass against
  `server/app.js` as-is. Product code was not modified.
