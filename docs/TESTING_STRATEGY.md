# Testing Strategy

How PromptWall is tested, which gate runs when, and the rules that keep the
suites meaningful. Modeled on Google's test-size discipline and GitLab's
smoke/regression tiers and flaky-test quarantine policy, scaled to a small
team.

## The test estate

| Layer | Where | Runner | When it runs |
|-------|-------|--------|--------------|
| Unit + integration (small/medium) | `test/*.test.js` (~140 files) | `npm test` (`scripts/run-node-tests.js`, sequential per-file `node --test`) | Every commit (pre-commit hook) and CI |
| Browser E2E (large) | `e2e/*.spec.js` | `npm run test:browser` (Playwright, chromium) | Every commit via `review:ci` and CI |
| Detector quality gate | `test/fixtures/semantic-eval.json` | `npm run eval` (`scripts/eval-detect.js --ci` in CI) | Every detector change; CI |
| Engine parity | `detection-engine/detect.js` vs browser copy | `npm run sync-check` | Every commit; CI |
| **Standalone regression suite (black box)** | `suite/` | `npm run suite:smoke` / `npm run suite` | Smoke on every PR-sized change; full before every release |
| Postgres battery | `test/storage-postgres.test.js` | `npm test` with `SENTINEL_TEST_PG_URL` | CI (Postgres 16 service) |

The `suite/` directory is deliberately **separate from `test/`**: it drives
the running web app over HTTP and a real browser only, so it survives internal
refactors and is the durable regression net as the app evolves. See
`suite/README.md` for tiers and how to add cases.

## Test sizes (Google-style, enforced by convention)

- **Small** — single process, no network, no disk beyond temp files, no
  sleeps. Most detector, policy, validation, and crypto tests. This is where
  the bulk of tests belong (~80%).
- **Medium** — single machine, may bind an ephemeral port and use a temp
  SQLite file (`test/support/listen.js` pattern). API and workflow tests.
- **Large** — real browser or multi-process (Playwright, gateway smokes,
  `suite/flows`). Keep these few and high-value; they are release gates, not
  the regression net.

## Gates

- **Pre-commit** (`npm run review:agent` via `.githooks`): the full local
  review gate must pass before a commit lands.
- **CI on every push/PR** (`.github/workflows/ci.yml`): dependency audit,
  generated-doc drift, engine sync, AI-domain coverage, full `npm test` with
  Postgres, Playwright E2E, audit-chain verification, detector eval with
  floors, semantic-model determinism, config-mutation guard, Docker build.
- **Release gate**: everything above plus `npm run suite` (full standalone
  regression suite) on the release commit — see `docs/RELEASE_PROCESS.md`.

## Non-negotiable quality floors

- Detector eval (`npm run eval`): semantic precision >= 0.90, recall >= 0.70,
  structured recall >= 0.95, and **zero false positives on benign prompts**.
  Never tune against the held-out fixture; it is the test, not training data.
- `alwaysBlock` types (US_SSN, CREDIT_CARD, BANK_ACCOUNT, ROUTING_NUMBER,
  IBAN, US_PASSPORT, SECRET_KEY, PRIVATE_KEY) must always block or tokenize —
  `suite/detector/` asserts this end-to-end through the API.
- No raw PII or prompt bodies in any test output, fixture, or assertion
  message. Synthetic values only (`123-45-6789`, `4111111111111111`,
  `jane.doe@example.com`).
- Never weaken an assertion to make a test pass.

## Flaky test policy (quarantine with a deadline)

A test that fails intermittently on the main branch gets quarantined the same
day: mark it `.skip` with a dated `// QUARANTINED(YYYY-MM-DD): <reason>`
comment and open a tracking issue. Quarantined tests must be fixed, demoted
to a smaller size, or deleted within two weeks. **More than two quarantined
tests blocks the next release.** Retry-until-green is not a fix; the Windows
retry knobs in `scripts/run-node-tests.js` exist for platform flakiness, not
test flakiness.

## Coverage

Global line-coverage percentages are not a gate. What matters:

- `detection-engine/` and the audit/crypto modules (`server/db.js`,
  `server/crypto.js`, `server/audit-integrity.js`, `server/receipts.js`)
  should stay near-fully covered — these are the modules an examiner's trust
  rests on. Check occasionally with
  `node --test --experimental-test-coverage test/<area>*.test.js`.
- Every new server module ships with a focused test file; every bug fix
  ships with a regression test that failed before the fix.

## Adding tests: where does my test go?

- Testing a function or module contract → `test/<module>.test.js` (small).
- Testing an HTTP behavior of the app → `test/` with `support/listen.js`
  (medium).
- Testing what an operator or attacker can do to a **running** instance
  (auth boundaries, IDOR, UI journeys, PII-leak sweeps, contract shapes) →
  `suite/` (see `suite/README.md`).
- Testing browser sensor behavior on AI pages → `e2e/browser-extension.spec.js`.
