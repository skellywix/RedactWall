# PromptSentinel Deployment

PromptSentinel has two supported deployment paths:

1. Native Node.js for demos, pilots, and single-host installs.
2. Docker Compose for repeatable container installs.
3. AWS customer-silo SaaS stacks for paid customer deployments.

Use synthetic data for setup checks. Do not seed real member, patient, cardholder, employee, or customer data into a demo.

For AWS paid-customer deployment, see `docs/AWS_SAAS_DEPLOYMENT.md`. The first
commercial AWS path is one isolated stack per customer with app-level tenant and
seat enforcement.

## Native Setup

Requirements:

- Node.js 22 or newer.
- npm, included with Node.js.
- A local disk path for SQLite.

From the project folder:

```bash
npm run setup
npm start
```

`npm run setup` does four things:

1. Installs dependencies from `package-lock.json`.
2. Creates `.env` with stable admin, MFA, ingest, session, and data-encryption secrets.
3. Initializes `data/sentinel.db`.
4. Runs the same deployment preflight used by `/readyz`.

For production-safe defaults:

```bash
npm run setup:prod
npm run mfa:uri
npm start
```

Production mode expects TLS at the dashboard edge. If TLS is terminated by a reverse proxy, keep `COOKIE_SECURE=true` and serve the dashboard only over HTTPS.
`npm run mfa:uri` prints a standard authenticator-app enrollment URI for
`ADMIN_TOTP_SECRET`. Treat that URI as a secret and enroll it before pilot users
can reach the console.

To inspect an existing install without changing files:

```bash
npm run setup:check
```

## Docker Compose

Generate config first:

```bash
npm run setup:prod -- --skip-install
npm run mfa:uri
```

Then start the container:

```bash
docker compose up -d --build
```

The Compose file mounts a named volume at `/data`, overrides
`SENTINEL_DB_PATH` to `/data/sentinel.db`, and checks `/readyz` for container
health, so the container keeps runtime state outside the image and reports
unhealthy if database or production preflight readiness is blocked.

For a local HTTP-only container smoke test, set these in `.env` before starting Compose:

```text
NODE_ENV=development
HTTPS=false
COOKIE_SECURE=false
```

For a pilot or production deployment behind TLS:

```text
NODE_ENV=production
HTTPS=true
COOKIE_SECURE=true
```

## Health Checks

```bash
curl http://localhost:4000/healthz
curl http://localhost:4000/readyz
```

`/healthz` confirms the process is alive. `/readyz` confirms the database opens and production preflight is not blocked.

Logged-in admins can inspect detailed configuration checks at:

```text
http://localhost:4000/api/preflight
```

## Sensor Version Posture

The dashboard Coverage tab summarizes governed destinations, active sensors, and
the latest reported version for each sensor. Browser extension, endpoint agent,
and MCP guard events include bounded operational metadata only:

```json
{ "name": "browser_extension", "version": "0.3.0", "platform": "chrome_mv3" }
```

Mixed versions show as an attention item so a pilot admin can spot partial
rollouts after a managed extension or agent update. The coverage API does not
include prompt bodies, raw retained prompts, token vaults, or decision notes.

## Browser Extension Package

Build the Chrome extension artifact before a managed pilot handoff:

```bash
npm run package:extension
```

The command writes a zip and adjacent SHA-256 manifest under `dist/extension/`.
It verifies Manifest V3 wiring, managed-storage schema coverage, synced engine
copies, and absence of a packaged development ingest key. Configure `serverUrl`,
`ingestKey`, and identity through Chrome managed storage or local demo storage.

## Endpoint Agent Package

Build the endpoint file-sensor artifact before a Windows pilot handoff:

```bash
npm run package:endpoint-agent
```

The command writes a zip and adjacent SHA-256 manifest under
`dist/endpoint-agent/`. It includes the endpoint runtime, shared detection
engine, policy evaluator, env loader, file-type processor registry, and scheduled-task
install/run/uninstall scripts. It refuses synthetic prompt bodies and packaged
development ingest keys. Set the real `SENTINEL_URL`, `INGEST_API_KEY`, and
watch directory during install; the agent inspects supported files locally and
does not contact the control plane without an explicit ingest key.

## MCP Guard Package

Build the MCP guard artifact before an agent pilot handoff:

```bash
npm run package:mcp-guard
```

The command writes a zip and adjacent SHA-256 manifest under `dist/mcp-guard/`.
It includes the guard runtime, shared detection engine, env loader, and version
metadata. It excludes the local direct-run demo and refuses synthetic prompt
bodies or development ingest keys. Set `SENTINEL_URL` and `INGEST_API_KEY` in
the host MCP runtime environment; do not bake them into the package. The guard
does not contact the control plane without an explicit ingest key.

## Endpoint Agent On Windows

For a pilot workstation, install the endpoint file sensor as a per-user scheduled task. The task starts at logon, restarts on failure, and reads its ingest key from a local config file instead of exposing it in the task command line.

Run PowerShell from the project folder:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -SentinelUrl "https://promptsentinel.example.com" `
  -IngestKey "<pilot-ingest-key>" `
  -WatchDir "$env:USERPROFILE\PromptSentinelWatch"
```

This creates:

```text
Task:   PromptSentinelEndpointAgent
Config: %LOCALAPPDATA%\PromptSentinel\endpoint-agent.env
Log:    %LOCALAPPDATA%\PromptSentinel\logs\endpoint-agent.log
```

The config file carries `SENTINEL_URL`, `INGEST_API_KEY`, and `ENDPOINT_AGENT_WATCH_DIR`. Keep it restricted to the installing user, Administrators, and SYSTEM. For an all-user managed install, pass an explicit `-ConfigDir "$env:ProgramData\PromptSentinel"` from an elevated PowerShell session.

The agent inspects supported watched files locally. Under redact policy, structured-only findings write a safe companion text file under `.promptsentinel-redacted` and report `redacted_available` evidence to the control plane; semantic or mixed findings remain held for Security Admin review.

Check status:

```powershell
Get-ScheduledTask -TaskName PromptSentinelEndpointAgent
Get-Content "$env:LOCALAPPDATA\PromptSentinel\logs\endpoint-agent.log" -Tail 40
```

Uninstall:

```powershell
.\scripts\uninstall-endpoint-agent.ps1
```

Remove local endpoint config too:

```powershell
.\scripts\uninstall-endpoint-agent.ps1 -RemoveConfig
```

## Required Secrets

Set these through `.env`, container environment, or a deployment secret manager:

| Variable | Purpose |
| --- | --- |
| `ADMIN_PASSWORD` | Security Admin console password. Production preflight requires non-default, at least 16 characters. |
| `ADMIN_TOTP_SECRET` | Base32 authenticator secret for Security Admin MFA. Production preflight requires it, and admin login requires a current 6-digit code when it is set. |
| `AUDITOR_USER` / `AUDITOR_PASSWORD` | Optional read-only console account for examiner or client-demo access. Set both together, keep `AUDITOR_USER` distinct from `ADMIN_USER`, and use at least 16 characters for `AUDITOR_PASSWORD`. |
| `SENTINEL_SECRET` | Stable session-signing secret shared by all instances. Production preflight requires at least 32 characters from environment. |
| `SENTINEL_DATA_KEY` | Stable AES-256-GCM data key source for retained approval prompts. Production preflight requires this key, or the `SENTINEL_SECRET` fallback, to be at least 32 characters. |
| `INGEST_API_KEY` | Sensor and proxy key for `/api/v1/*` ingest endpoints. Production preflight requires non-default, at least 32 characters. |
| `SENTINEL_DB_PATH` | SQLite path on local persistent disk. |
| `SENTINEL_SAAS_MODE` | Set to `true` for a paid customer stack. Production preflight then requires tenant id and seat limit. |
| `SENTINEL_TENANT_ID` | Lowercase customer tenant slug accepted from sensors, for example `cu-acme`. |
| `SENTINEL_SEAT_LIMIT` | Purchased seat count. New managed users beyond this count are blocked and recorded as `SEAT_LIMIT_BLOCKED`. |
| `SENTINEL_REQUIRE_TENANT_CONTEXT` | Requires sensors to send the matching `orgId`. Enabled automatically by SaaS mode. |
| `SENTINEL_REQUIRE_USER_IDENTITY` | Requires sensors to send managed user identity instead of `unknown` or `unattributed@unmanaged`. Enabled automatically by SaaS mode. |

Never bind `SENTINEL_DB_PATH` to a cloud-synced folder or network share. SQLite locking must be backed by local disk semantics, and production preflight blocks missing, cloud-synced, or UNC/network SQLite paths before startup readiness passes.

`npm run setup:prod` generates values that meet these floors. When values come from a deployment secret manager, keep the same minimum lengths or `/readyz` will report production readiness as blocked.

Production preflight also blocks missing Security Admin MFA and short custom
secrets. Use a base32 `ADMIN_TOTP_SECRET` at least 16 characters long, at least
16 characters for `ADMIN_PASSWORD` and `AUDITOR_PASSWORD` when auditor login is
configured, and at least 32 random characters for `INGEST_API_KEY`,
`SENTINEL_SECRET`, and `SENTINEL_DATA_KEY` when retained raw approval data is
enabled. `npm run setup:prod` generates a TOTP secret; enroll it in the
operator's authenticator app before serving the console to pilot users:

```bash
npm run mfa:uri
```

The command prints a standard `otpauth://` enrollment URI. Treat it like a
password because it contains the MFA seed. For a non-default env file or
white-label issuer, use:

```bash
npm run mfa:uri -- --env pilot.env --issuer "PromptSentinel Pilot"
```

Auditor sessions can read sanitized dashboard evidence, audit status, policy,
and examiner exports. They cannot reveal retained raw prompts, approve or deny
held prompts, run retention purges, apply policy templates, or edit policy.

## SIEM Alerts

Set `SIEM_WEBHOOK_URL` to send sanitized security events to a SOC or SIEM webhook. Payloads omit prompt bodies, raw retained prompts, token vaults, and raw finding values.

Blocked prompt/file events, response leakage, hidden-instruction blocks, and failed or locked admin step-up confirmations for raw reveal and approval release are alertable. Webhook delivery is best-effort and never blocks the user-facing request.

Sensor version posture gaps are also alertable. If browser extension, endpoint
agent, or MCP guard events show mixed versions or missing version metadata,
PromptSentinel sends a forced `SENSOR_VERSION_GAP` alert with bounded source,
version, and platform metadata only.

## Retention Operations

PromptSentinel retains raw approval prompts and token vaults only for records that need review or rehydration. Set `rawRetentionDays` in policy to define how long finalized `approved`, `denied`, and `redacted` records keep those sealed fields. The default is 30 days.

Revealing a retained raw prompt or approving a held prompt release requires an active Security Admin session, a CSRF token, and password confirmation. Successful reveals, failed reveal confirmations, approved releases, and failed approval confirmations are written to the audit log.

Sensors or proxy bridges that poll `/api/v1/status/:id` for a held prompt must
send the `x-release-token` header returned by the original gate response.
PromptSentinel stores only the token hash, rejects query-string release tokens,
and the reference Squid/ICAP bridge forwards the header automatically through
`awaitRelease`.

The server runs a retention purge on startup and then hourly. Security Admins can also run it from the Policy tab or with:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "https://promptsentinel.example.com/api/retention/purge" `
  -WebSession $adminSession `
  -Headers @{ "x-csrf-token" = $csrfToken }
```

Purge events keep the redacted metadata and hash-chained audit trail intact, and evidence exports show purge timestamps and the non-sensitive field names removed.

## Backup And Restore

Back up the SQLite evidence store to local encrypted storage or a managed backup target:

```bash
npm run backup -- backups
```

The command writes a `.db` backup plus a `.manifest.json` file with the backup hash, size, counts, and audit-chain verification result. The manifest intentionally omits prompt bodies; treat the `.db` file itself as sensitive runtime state.

Verify a backup before you rely on it:

```bash
npm run backup:verify -- backups/sentinel-YYYY-MM-DDTHH-MM-SS-sssZ.db
```

For an offline restore, stop the PromptSentinel process, restore to a new local-disk path, verify it, and then point `SENTINEL_DB_PATH` at the restored file:

```bash
npm run backup:restore -- backups/sentinel-YYYY-MM-DDTHH-MM-SS-sssZ.db data/restored-sentinel.db
npm run backup:verify -- data/restored-sentinel.db
```

Use `--force` only when intentionally replacing an existing restore target.

## Validation Gate

Before handing a deployment to a pilot user, run:

```bash
npm test
npm run sync-check
npm run setup:check
node -e "const v=require('./src/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

For dashboard changes:

```bash
npm run test:browser
```

For detector changes:

```bash
npm run eval
npm run simulate -- http://localhost:4000
```
