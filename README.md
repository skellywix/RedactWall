# PromptWall

**Stop sensitive data from reaching AI tools — before it leaves the device.**

PromptWall inspects what people type, paste, or upload into ChatGPT, Claude,
Copilot, and Gemini, and **warns, asks for justification, or blocks** based on your
policy. Detection runs locally (instant, nothing leaves the device just to be
scanned), and every event flows to one simple dashboard with a full audit trail.
The same policy can also block entire AI destinations before prompt or file
content is analyzed.

Built to be **simple to deploy** for regulated teams (credit unions / NCUA, GLBA,
HIPAA, PCI-DSS): install the browser extension, pick one of three policy modes, done.

> Inspired by enterprise DLP platforms (e.g. Strac) but deliberately stripped down:
> one extension, three policy toggles, one dashboard — not 30 SaaS connectors.

See `docs/COMPETITIVE_ALIGNMENT.md` for the current competitor-backed product
alignment notes and `PLANS/promptwall-product-alignment.md` for the broader
rename and product-readiness contract.

---

## The product, in one picture

```
  WHERE DATA LEAKS                     ONE CONTROL PLANE
  ┌─────────────────────────┐
  │ 🌐 Browser extension     │──┐      ┌───────────────────────────┐
  │   type / paste / upload  │  │      │  PromptWall server    │
  ├─────────────────────────┤  │      │                           │
  │ 💻 Endpoint agent        │  ├────► │  • policy (warn/justify/  │
  │   files to desktop AI    │  │      │    block)                 │
  ├─────────────────────────┤  │      │  • approval queue         │
  │ 🔌 MCP guard             │──┘      │  • audit log (hash-chain) │
  │   redact before model    │        │  • dashboard              │
  └─────────────────────────┘        └───────────────────────────┘
        every sensor shares the SAME local detection engine
```

Three sensors, one brain. Each sensor runs the shared hybrid detector locally and
reports verdicts to the server for policy, queueing, and audit.

## Four enforcement modes (you pick one)

| Mode | What the user sees | Use when |
|------|--------------------|----------|
| **Warn** | A nudge: "this has PII — send anyway?" | Light touch, awareness |
| **Require justification** | Must type a business reason to proceed (logged) | Balance security + productivity |
| **Redact & send** | Sensitive values become tokens, the prompt sends safely, and the AI's reply is restored locally | Keep people productive with **zero raw PII leaving the device** |
| **Block** | Hard stop; can request Security Admin approval | High-risk / strict compliance |

Hard-stop items (SSN, cards, bank/routing, secrets, private keys) always block —
or, in **Redact** mode, are tokenized — regardless of the chosen mode. One-click
**regulation templates** (NCUA/GLBA, PCI-DSS, HIPAA, Baseline, Redact-first) set
sensible modes, thresholds, and hard-stops for you.

## Destination controls

The Policy tab maintains two destination lists:

- `governedDestinations`: AI hosts that should be covered and counted in the
  Coverage tab.
- `blockedDestinations`: AI hosts or desktop app labels that are forbidden.
  Browser sends, browser file uploads, endpoint file flows, gateway prompts,
  uploaded files, and response scans short-circuit as `destination_blocked`
  before prompt or file content is analyzed or retained.
- `blockedFileUploadDestinations`: AI hosts or desktop app labels where normal
  chat is allowed but file uploads are forbidden. Browser/API uploads and
  endpoint file flows short-circuit as `file_upload_blocked` before uploaded
  bytes, extracted text, or sensitive filenames are retained.

Entries accept exact hosts, URLs, subdomains, and wildcards such as
`*.example-ai.com`. Desktop labels normalize spaces to hyphens, so a native
handoff destination like `Desktop AI` can be blocked with `desktop-ai`.

## Hybrid detection (local, fast, semantic, pluggable)

Detection is a **plugin registry** (inspired by Strac's auditor): each detector is a
self-describing unit you can enable or disable per policy. Two layers, both on-device:

1. **Structured PII and tripwires (23 detectors)** — SSN, credit cards (Luhn), routing numbers
   (ABA), IBAN (mod-97), US passport, TIN/EIN, driver's license, license plate, VIN,
   email, phone, IP, DOB, US address, API keys, private keys, passwords, and planted
   canary tokens for leak drills.
2. **Semantic categories** — source code, legal/contracts, credentials, and
   confidential business context (e.g. "we're considering leaving our vendor, do not
   share"). This is what keyword lists miss.

`classifySemantic()` in `detection-engine/detect.js` runs a **compact on-device classifier** —
a per-category hashing-trick logistic regression with **subword (char n-gram) features**
(trained by `npm run train-semantic`), now covering **all four categories** (source code,
legal/contracts, credentials, confidential business). It **augments** precise keyword rules
(max-combine), so literal markers fire and paraphrases like "thinking about switching away
from our vendor, keep this internal" get caught too.

Quality is **measured, not asserted**: `npm run eval` scores the engine on a *held-out,
hand-labeled* corpus (`test/fixtures/semantic-eval.json`) it never trained on, and the
floors are enforced in CI (`test/eval.test.js`). Current held-out result: **semantic
precision 100% / recall 94%, structured PII 100% / 100%, and zero false positives on
benign business prompts** — the number that decides whether an admin keeps the control on.
Thresholds are calibrated on benign prompts the model never saw, so "zero false positives"
means something. Add a structured detector by pushing one object to the `DETECTORS`
registry; disable any detector via the policy `disabledDetectors` list.

## File scanning (PDF / Word / Excel / PowerPoint)

People paste *and upload* sensitive files into AI tools. A **processor layer**
(`server/processors.js`) extracts text from PDFs, `.docx`, `.xlsx`, and `.pptx` (plus all
text formats) so uploads get the same detection as typed prompts. The endpoint
agent uses it locally for every watched file and reports only sanitized evidence
to the control plane. In redact mode, structured-only endpoint findings also
produce a local `.promptwall-redacted/*.txt` companion file with typed
placeholders and no token vault; semantic or mixed findings stay held for
review. A signed native handoff prototype also lets a future desktop collector
write content-free upload-intent events for absolute local files, so the agent
can scan files headed to desktop AI apps without relying only on a watched
folder. Browser/API sensors can also call `POST /api/v1/scan-file`
with a base64 file. Add a new file type by pushing a processor with
`{ supports(name), extract(buffer) }`. Supported files fail closed if extraction
times out or the parser cannot inspect the file, and the audit log records the
blocked unscanned file without storing the file bytes.

---


## Quick start

```bash
npm run setup
npm start
# dashboard: http://localhost:4000   (credentials in .env)
```

`npm run setup` installs dependencies, writes a local `.env` with stable secrets,
initializes the SQLite store, and runs deployment preflight. The generated admin
password and ingest key live in `.env`; production setup also writes
`ADMIN_TOTP_SECRET` for authenticator enrollment.

For browser E2E test setup, install Chromium too:

```bash
npm run setup -- --with-browser
```

For a production-style install:

```bash
npm run setup:prod
npm run mfa:uri
npm start
```

For Docker:

```bash
npm run setup:prod -- --skip-install
npm run mfa:uri
docker compose up -d --build
```

`npm run mfa:uri` prints a standard authenticator-app enrollment URI for
`ADMIN_TOTP_SECRET`. Treat that URI as a secret and enroll it before pilot users
can reach the console.

See `docs/DEPLOYMENT.md` for native Node, Docker Compose, health checks, and
preflight, auditor access, and sanitized examiner-export details.

For paid AWS SaaS deployments, use `docs/AWS_SAAS_DEPLOYMENT.md`. The supported
commercial path for the current codebase is a customer-silo AWS stack with one
tenant id, a paid seat limit, managed sensor identity, and local EBS-backed
SQLite evidence storage.

For technician-led customer installs, use `docs/TECHNICIAN_DEPLOYMENT_GUIDE.md`
as the production readiness runbook and handoff checklist.

### Try the browser extension (flagship)

1. Chrome → Extensions → enable Developer mode → **Load unpacked** → select the
   `sensors/browser-extension/` folder.
2. Configure the extension with the demo ingest key from your `.env` or shell:

   ```javascript
   chrome.storage.local.set({ ingestKey: "<demo-ingest-key>", serverUrl: "http://localhost:4000", enabled: true });
   ```

3. Open ChatGPT or Claude and type a prompt containing a fake SSN (e.g.
   `123-45-6789`) or paste a code block. You'll get an inline banner; the event
   appears on the dashboard.
4. Change the mode in the dashboard **Policy** tab (warn / justify / block) — the
   extension picks it up automatically.

Package a pilot handoff artifact with:

```bash
npm run package:extension
npm run package:endpoint-agent
npm run package:mcp-guard
```

The extension zip lands in `dist/browser-extension/`, the endpoint agent zip lands in
`dist/endpoint-agent/`, and the MCP guard zip lands in `dist/mcp-guard/`. Each
artifact gets a SHA-256 manifest and refuses packaged development keys or prompt
bodies. Configure real pilot keys through Chrome managed storage or local sensor
environment config, not inside packages.

### Try the other sensors

```bash
npm run simulate                      # pushes sample prompts (API/proxy path)
npm run fire-drill -- http://localhost:4000  # sends a synthetic canary control
node sensors/mcp-guard/guard.js               # demo: redact a SharePoint doc before the model sees it
node sensors/endpoint-agent/agent.js <dir>    # watch a folder, or process signed native file-flow handoffs
node sensors/endpoint-agent/write-handoff.js --file <path> --destination "Desktop AI"  # write a signed native upload intent
```

For a Windows pilot, install the endpoint sensor as a logon task:

```powershell
.\scripts\install-endpoint-agent.ps1 -SentinelUrl "https://promptwall.example.com" -IngestKey "<pilot-ingest-key>"
```

The native handoff writer is a safe collector shim for pilots and future OS/app hooks. It signs a bounded upload-intent JSON file with the local endpoint config secret, references only an absolute local file path, and never reads file bytes or accepts the handoff secret as a command-line argument.

### Test the product

```bash
npm test              # Node unit/integration coverage
npm run test:browser  # Playwright: login, approval, policy save, evidence export
npm run sync-check    # shared detection engine parity
npm run backup -- backups  # SQLite audit-store backup + verification manifest
```

## Development and Git workflow

The repository uses one Git source of truth: this app repo folder. In the current
checkout that folder is still `promptsentinel/` under the `promptsentinel-app/`
workspace wrapper, so run `cd promptsentinel` before source edits, `npm`
commands, commits, or pushes. The product name is PromptWall; after Codex,
editors, terminals, and Git status watchers are closed, finish the local folder
rename from the wrapper with:

```powershell
Rename-Item -LiteralPath .\promptsentinel -NewName promptwall
```

After that, run source edits, `npm` commands, commits, and pushes from
`promptwall/`.

This repo is configured with a review-first workflow:

- Run `npm run hooks:install` once (or after cloning to future team members).
- `npm run review:ci` runs the full local gate:
  - `git diff --check`
  - `npm test`
  - `npm run sync-check`
  - `npm run eval`
- The `pre-commit` hook runs `npm run review:agent` and blocks commits if checks fail.
- The `post-commit` hook runs the same review gate and pushes only when checks pass.
- If push fails (network/credentials), the commit stays local and you can retry with `git push`.
- For Codex-driven changes, a separate checker/review agent should review substantive diffs before handoff. The hook gate is still the deterministic local test gate.

For any review notes you want to preserve, add them to `ITERATIONS.md` and `STATUS.md` with the date and commands you ran.

## Project layout

```
server/app.js                         Control plane: gate API, policy, approval queue, SSE, audit
server/public/index.html              Dashboard (queue, activity, audit, policy)
server/policy.js                      Enforcement policy + scanner config
server/processors.js                  File-processor registry
server/db.js                          SQLite store + hash-chained audit log
detection-engine/detect.js            Hybrid detection engine used by every sensor and the server
sensors/browser-extension/            Browser extension (MV3) flagship sensor
  lib/detect.js                       Synced copy of detection-engine/detect.js
sensors/endpoint-agent/agent.js       Desktop file sensor reference
sensors/mcp-guard/guard.js            MCP tool-response redactor reference
scripts/                              Setup, packaging, simulation, training, sync checks
```

For stack decisions and migration rationale, see `STACK_REVIEW.md`.

## Where each layer stands

| Layer | Status |
|-------|--------|
| Control plane (policy, queue, audit, dashboard) | Working — SQLite (WAL/transactions), tamper-evident audit covering the evidence |
| Hybrid detection engine | Working — 22 structured detectors + **4-category on-device semantic model** (measured P100/R94 on a held-out set) |
| Reversible redaction | Working — tokenize/detokenize, sealed vault, `/api/v1/rehydrate` |
| Browser extension | Working — warn/justify/**redact**/block, real-button send, MDM identity, Man-in-the-Prompt guard |
| Shadow-AI discovery | Working — flags use of ungoverned AI tools |
| Destination controls | Working — governed destination coverage, full destination blocking, and file-upload-only blocking across browser, endpoint, gate, file, and response paths |
| Output scanning | Working — `/api/v1/scan-response` flags PII/secrets in AI replies |
| MCP guard / Endpoint agent | Working references - inline/MCP redaction; local endpoint folder watch plus signed native file-flow handoff prototype; redacted companion files for structured-only findings |
| Auth & ops | Working: login lockout, password-confirmed raw reveal and release approval, release-token scoped polling, stable secret, `/healthz` · `/readyz` · `/api/metrics`, sensor version posture, sanitized examiner export with coverage and lineage, Docker, CI |

## Shipped since the skeleton (see `ITERATIONS.md`)

- **On-device semantic model** behind `classifySemantic()` (no heavy runtime; `npm run train-semantic`).
- **SQLite** store (WAL + transactions) with audit integrity that covers the evidence, not just the event header.
- **Backup/verify/restore** tooling for the SQLite evidence store with prompt-free manifests.
- **Reversible redaction / Redact-&-Send**, sealed token vault, local response re-hydration.
- **MDM identity**, reliable per-site send, **Man-in-the-Prompt** guard, **shadow-AI** discovery.
- **Coverage posture** showing governed destinations, active sensors, shadow-AI sightings, and sensor versions.
- **Sanitized examiner export** with audit integrity, policy diffs, coverage posture, and lineage by user, destination, sensor, channel, category, and decision.
- **Login lockout**, stable session secret, regulation **templates**, **/healthz · /readyz · /api/metrics**, Docker + CI.

## Still ahead (to ship commercially)

- SSO, polished MFA enrollment UX, and multiple admin roles; deeper multi-tenant isolation per institution.
- Signed Chrome Web Store listing and force-install rollout; local extension zip plus integrity manifest are packaged.
- Email/Slack escalation rules on top of the sanitized SIEM webhook.
- Ship the signed native endpoint collector that feeds the tested handoff contract from clipboard and AI-app upload flows.
- Upgrade the on-device classifier to a quantized ONNX/WASM NER when recall demands it.

## Configuration

Copy `.env.example` to `.env` (or export):

| Var | Purpose |
|-----|---------|
| `PORT` | Dashboard/API port (default 4000) |
| `NODE_ENV` | Set to `production` to enforce deployment preflight blockers |
| `HTTPS` / `COOKIE_SECURE` | Mark admin session cookies secure when the dashboard is served over TLS |
| `SENTINEL_DB_PATH` | SQLite store path (default `data/sentinel.db`). Use **local disk**, never a cloud-synced folder or network share. Production preflight blocks unsafe paths. |
| `SENTINEL_SAAS_MODE` | Set to `true` for a paid customer stack. Requires tenant context, managed user identity, tenant id, and seat limit. |
| `SENTINEL_TENANT_ID` | Lowercase customer tenant slug accepted from sensors, for example `cu-acme`. |
| `SENTINEL_SEAT_LIMIT` | Purchased seat count. New managed users beyond this count are blocked and recorded as `SEAT_LIMIT_BLOCKED`. |
| `SENTINEL_REQUIRE_TENANT_CONTEXT` | Requires sensors to send the matching `orgId`. Enabled automatically by SaaS mode. |
| `SENTINEL_REQUIRE_USER_IDENTITY` | Requires sensors to send managed user identity instead of `unknown` or `unattributed@unmanaged`. Enabled automatically by SaaS mode. |
| `SENTINEL_POLICY_PATH` | Optional policy file path for isolated tests or pilots (default `config/policy.json`) |
| `ADMIN_USER` / `ADMIN_PASSWORD` | Console credentials; production preflight requires a non-default password of at least 16 characters |
| `ADMIN_TOTP_SECRET` | Base32 authenticator secret for Security Admin MFA; production preflight requires it and admin login requires a current 6-digit code when set |
| `AUDITOR_USER` / `AUDITOR_PASSWORD` | Optional read-only console credentials for examiner or client-demo access; set both together, keep `AUDITOR_USER` distinct from `ADMIN_USER`, and use at least 16 characters for `AUDITOR_PASSWORD` |
| `SENTINEL_SECRET` | Session cookie signing secret; production preflight requires at least 32 characters from environment |
| `SENTINEL_DATA_KEY` | Encrypts retained raw prompts at rest; production preflight requires at least 32 characters for this key or the `SENTINEL_SECRET` fallback |
| `INGEST_API_KEY` | Key sensors present to the gate API; production preflight requires a non-default key of at least 32 characters |
| `ENDPOINT_AGENT_HANDOFF_DIR` | Optional local spool for signed native endpoint upload-intent events |
| `ENDPOINT_AGENT_HANDOFF_SECRET` | Optional 32-plus-character local HMAC secret required before native endpoint handoff events are accepted |
| `INGEST_AUTH_MAX_FAILURES` | Optional invalid ingest-key throttle threshold (default 20, bounded 3 to 1000) |
| `INGEST_AUTH_WINDOW_MS` | Optional invalid ingest-key throttle window (default 60000 ms, bounded 1000 to 3600000) |
| `INGEST_AUTH_LOCK_MS` | Optional invalid ingest-key throttle lock time (default 60000 ms, bounded 1000 to 3600000) |
| `FILE_EXTRACT_TIMEOUT_MS` | Optional per-file extraction timeout (default 5000 ms, bounded 100 to 60000) |
| `FILE_EXTRACT_MAX_CHARS` | Optional extracted-text cap before detection (default 1000000 chars, bounded 1000 to 5000000) |
| `SIEM_WEBHOOK_URL` | Optional sanitized webhook for high-risk security events, sensor version gaps, and failed admin step-up checks |
| `SIEM_WEBHOOK_TOKEN` | Optional bearer token for the SIEM webhook |
| `SIEM_ALERT_MIN_RISK` / `SIEM_ALERT_MIN_SEVERITY` | Alert thresholds for allowed-but-risky events; blocked and response-flagged events alert automatically |

PromptWall also accepts product-prefixed aliases for new deployments while
preserving the older `SENTINEL_*` and endpoint keys for existing installs. Use
one family per setting; a non-empty legacy key wins when both are set.

| Existing key | PromptWall alias |
|--------------|------------------|
| `SENTINEL_ENV_PATH` | `PROMPTWALL_ENV_PATH` |
| `SENTINEL_URL` | `PROMPTWALL_URL` |
| `SENTINEL_DB_PATH` | `PROMPTWALL_DB_PATH` |
| `SENTINEL_POLICY_PATH` | `PROMPTWALL_POLICY_PATH` |
| `SENTINEL_SAAS_MODE` | `PROMPTWALL_SAAS_MODE` |
| `SENTINEL_TENANT_ID` | `PROMPTWALL_TENANT_ID` |
| `SENTINEL_SEAT_LIMIT` | `PROMPTWALL_SEAT_LIMIT` |
| `SENTINEL_REQUIRE_TENANT_CONTEXT` | `PROMPTWALL_REQUIRE_TENANT_CONTEXT` |
| `SENTINEL_REQUIRE_USER_IDENTITY` | `PROMPTWALL_REQUIRE_USER_IDENTITY` |
| `SENTINEL_SECRET` | `PROMPTWALL_SECRET` |
| `SENTINEL_DATA_KEY` | `PROMPTWALL_DATA_KEY` |
| `SENTINEL_REQUEST_TIMEOUT_MS` | `PROMPTWALL_REQUEST_TIMEOUT_MS` |
| `INGEST_API_KEY` | `PROMPTWALL_INGEST_API_KEY` |
| `ENDPOINT_AGENT_WATCH_DIR` | `PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR` |
| `ENDPOINT_AGENT_HANDOFF_DIR` | `PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR` |
| `ENDPOINT_AGENT_HANDOFF_SECRET` | `PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET` |

Production preflight requires Security Admin MFA through `ADMIN_TOTP_SECRET`,
custom secrets with minimum lengths, 16 characters for `ADMIN_PASSWORD` and
optional `AUDITOR_PASSWORD`, and 32 characters for `INGEST_API_KEY`,
`SENTINEL_SECRET`, and `SENTINEL_DATA_KEY` when raw approval retention is
enabled. If auditor login is configured, both `AUDITOR_USER` and
`AUDITOR_PASSWORD` must be present and `AUDITOR_USER` must be distinct from
`ADMIN_USER`. Development/demo mode reports weak or missing custom values as
warnings.

`/readyz` reports whether the database and deployment preflight are usable. Logged-in admins can inspect detailed checks at `/api/preflight`.

## Compliance note

Detection happens locally on each sensor. For most events only redacted +
masked data is stored. The one exception is an item **held for admin approval**:
its raw prompt is retained so the admin can review it. That raw value is
**encrypted at rest (AES-256-GCM)** and decrypted only on an explicit,
password-confirmed, audit-logged reveal. Institutions that forbid any
server-side raw retention can set
`storeRawForApproval: false` in policy, in which case reveal shows the redacted
prompt only. Set `SENTINEL_DATA_KEY` (stable across restarts) to enable the
encryption; with no key configured, raw prompts are not stored at all. Finalized
approval records purge retained raw prompt data and token vaults after
`rawRetentionDays` (default 30) while keeping redacted metadata and the
hash-chained audit trail.

Approving a held prompt also requires password confirmation. A stale or stolen
admin browser session alone is not enough to release a blocked prompt.
Sensors polling `/api/v1/status/:id` for a held prompt must also present the
per-query release token returned by the original gate response in the
`x-release-token` header. The server stores only the token hash, so one sensor
key plus a guessed or leaked query id is not enough to read release state for
another held item.

Even so, a product that inspects employee input requires proper authorization
and clear employee notice. See `AI_Chat_DLP_Implementation_Plan.docx` for the
legal prerequisites and (optional) network-layer deployment for unmanaged devices.
