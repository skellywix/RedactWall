# PromptWall Deployment

PromptWall has three supported deployment paths:

1. Native Node.js for demos, pilots, and single-host installs.
2. Docker Compose for repeatable container installs.
3. AWS customer-silo SaaS stacks for paid customer deployments.

Use synthetic data for setup checks. Do not seed real member, patient, cardholder, employee, or customer data into a demo.

For AWS paid-customer deployment, see `docs/AWS_SAAS_DEPLOYMENT.md`. The first
commercial AWS path is one isolated stack per customer with app-level tenant and
seat enforcement.

For install technicians taking a customer to production readiness, use
`docs/TECHNICIAN_DEPLOYMENT_GUIDE.md` as the step-by-step runbook and handoff
checklist.

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

## SCIM Provisioning

Set `SCIM_BEARER_TOKEN` to enable customer identity provisioning at
`/scim/v2/*`; leave it empty to disable the surface. The endpoint accepts
`application/scim+json`, uses bearer auth, stores provisioned users and groups in
the local evidence database, and maps known PromptWall group display names onto
the local `security_admin`, `approver`, `auditor`, and `operator` roles.

This is lifecycle provisioning, not browser-session login. Keep local Security
Admin credentials as the break-glass console path until SSO/OIDC login lands.
See `docs/SCIM_PROVISIONING.md` for endpoint details and IdP setup notes.

## Sensor Version And Install Health

The dashboard Coverage tab summarizes governed destinations, active sensors, and
the latest reported version for each sensor. Browser extension, endpoint agent,
and MCP guard events include bounded operational metadata only:

```json
{ "name": "browser_extension", "version": "0.3.0", "platform": "chrome_mv3" }
```

Mixed versions show as an attention item so a pilot admin can spot partial
rollouts after a managed extension or agent update. Browser extension, endpoint,
and MCP guard install validation can also report bounded check results through
`POST /api/v1/heartbeat`; failed checks show as sensor install-health attention
in Coverage and in the sanitized examiner export. The Coverage tab also includes
a Fleet Install Health table that rolls the latest required-sensor state up by
user, org, source, version, platform, and failed check ID. The coverage API does
not include prompt bodies, raw retained prompts, token vaults, ingest keys,
handoff secrets, tool output, or decision notes.

## Browser Extension Package

Build and check the Chrome extension artifact before a managed pilot handoff:

```bash
npm run release:extension:check -- dist/browser-extension
```

The command writes a zip, adjacent SHA-256 manifest, and release-readiness JSON
under `dist/browser-extension/`. It verifies Manifest V3 wiring,
managed-storage schema coverage, synced engine copies, browser install-health
heartbeat support, Chrome force-install policy examples, the private or unlisted
release checklist, and absence of a packaged development ingest key. Configure
`serverUrl`, `ingestKey`, and identity through Chrome managed storage or local
demo storage.

The extension posts sanitized install-health heartbeats on install, browser
startup, and a periodic `installHeartbeat` alarm when server config is present.
The heartbeat verifies Manifest V3 metadata, background worker wiring, content
script coverage, protection status, server URL, ingest-key presence, managed
configuration, managed identity, tenant id, and policy cache availability. It
posts only check IDs, boolean status, and short details; it does not post ingest
keys, prompts, file content, or browser page content.

## Endpoint Agent Package

Build the endpoint file-sensor artifact before a Windows pilot handoff:

```bash
npm run package:endpoint-agent
```

The command writes a zip and adjacent SHA-256 manifest under
`dist/endpoint-agent/`. It includes the endpoint runtime, shared detection
engine, policy evaluator, env loader, file-type processor registry, signed
native handoff prototype, metadata-only handoff writer, Windows protected-upload
desktop collector, and scheduled-task plus shell-action install/run/uninstall
scripts, plus the endpoint install validation checker. It refuses synthetic
prompt bodies and packaged development ingest keys. Set the real `SENTINEL_URL`,
`INGEST_API_KEY`, and watch directory during install; the agent inspects
supported files locally and does not contact the control plane without an
explicit ingest key.

## MCP Guard Package

Build the MCP guard artifact before an agent pilot handoff:

```bash
npm run package:mcp-guard
```

The command writes a zip and adjacent SHA-256 manifest under `dist/mcp-guard/`.
It includes the guard runtime, shared detection engine, env loader, version
metadata, and MCP guard install validation checker. It excludes the local
direct-run demo and refuses synthetic prompt bodies or development ingest keys.
Set `SENTINEL_URL` and `INGEST_API_KEY` in the host MCP runtime environment; do
not bake them into the package. The guard does not contact the control plane
without an explicit ingest key.

Validate the unpacked MCP guard runtime and optionally emit sanitized health
evidence:

```powershell
npm run mcp:check -- `
  --env ".env" `
  --emit-heartbeat `
  --user "tech@example.test" `
  --org-id "cu-acme"
```

The checker verifies the MCP env file or runtime environment, server URL,
ingest-key presence, Node version, guard runtime, shared detection engine, env
loader, and package manifest. It posts only check IDs, boolean status, and short
details; it does not print or post ingest keys, prompt text, tool output, or
document content.

## Endpoint Agent On Windows

For a pilot workstation, install the endpoint file sensor as a per-user scheduled task. The task starts at logon, restarts on failure, and reads its ingest key from a local config file instead of exposing it in the task command line.

Run PowerShell from the project folder:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -SentinelUrl "https://promptwall.example.com" `
  -IngestKey "<pilot-ingest-key>" `
  -WatchDir "$env:USERPROFILE\PromptWallWatch"
```

This creates:

```text
Task:   PromptWallEndpointAgent
Config: %LOCALAPPDATA%\PromptWall\endpoint-agent.env
Log:    %LOCALAPPDATA%\PromptWall\logs\endpoint-agent.log
```

The config file carries `SENTINEL_URL`, `INGEST_API_KEY`, and `ENDPOINT_AGENT_WATCH_DIR`. Keep it restricted to the installing user, Administrators, and SYSTEM. For an all-user managed install, pass an explicit `-ConfigDir "$env:ProgramData\PromptWall"` from an elevated PowerShell session.

Validate the local install and optionally emit sanitized health evidence:

```powershell
npm run endpoint:check -- `
  --env "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env" `
  --emit-heartbeat `
  --user "tech@example.test" `
  --org-id "cu-acme"
```

Add `--require-desktop-collector` when native handoff is in scope. The checker
prints and posts only check IDs, boolean status, and short details. It does not
print or post the ingest key, handoff secret, prompt text, extracted text, or
file bytes.

The agent inspects supported watched files locally. Under redact policy, structured-only findings write a safe companion text file under `.promptwall-redacted` and report `redacted_available` evidence to the control plane; semantic or mixed findings remain held for Security Admin review.

For desktop file flows, enable the native handoff directory with an explicit
local secret. The endpoint agent keeps scanning locally; the handoff event is
only a signed upload intent with destination metadata and an absolute local file
path.

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -SentinelUrl "https://promptwall.example.com" `
  -IngestKey "<pilot-ingest-key>" `
  -HandoffSecret "<32-plus-character-local-handoff-secret>"
```

When enabled, the config also carries `ENDPOINT_AGENT_HANDOFF_DIR` and
`ENDPOINT_AGENT_HANDOFF_SECRET`. Each handoff event must be signed with that
secret, must name an absolute local file path and destination app, and must not
contain file bytes, prompt text, `contentBase64`, or raw document content. The
endpoint agent then scans the referenced file through the same local processor
and reports only sanitized findings, placeholders, and destination metadata.
The handoff directory is ACL-restricted to the installing user, Administrators,
and SYSTEM. This is the tested contract for native collectors; it does not
install kernel drivers or universal app hooks.

### Protected Upload Collector

The packaged desktop collector installs a per-user Windows Explorer shell action
for a production pilot. A user right-clicks one or more selected files and chooses
`PromptWall Protected Upload`; the collector writes a signed metadata-only
handoff event for each selected file, waits for the endpoint agent to consume it, and logs only
sanitized collector status. The endpoint agent then scans the referenced file
locally and reports sanitized evidence through the normal control-plane path.

Install it as part of the endpoint agent setup:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -SentinelUrl "https://promptwall.example.com" `
  -IngestKey "<pilot-ingest-key>" `
  -HandoffSecret "<32-plus-character-local-handoff-secret>" `
  -InstallDesktopCollector
```

Or install only the shell action after endpoint setup:

```powershell
.\scripts\install-desktop-collector.ps1 `
  -ConfigDir "$env:LOCALAPPDATA\PromptWall"
```

The collector uses the Policy tab's `Default desktop upload destination` value
first, then `ENDPOINT_AGENT_DESKTOP_DESTINATION` from local endpoint config as an
offline fallback, then `Desktop AI`. Use `-DesktopCollectorDestination` or
`-Destination` only when you intentionally need a local fallback or app-specific
override.

The shell action command does not include the ingest key or handoff secret. It
loads `%LOCALAPPDATA%\PromptWall\endpoint-agent.env` through
`SENTINEL_ENV_PATH`, invokes
`sensors\endpoint-agent\collectors\protected-upload.js`, and passes only the
selected local file paths to the collector process. The Explorer verb is marked
with `MultiSelectModel=Player` so it remains available for multi-file
selections. The collector verifies each path is a local file, writes signed
events through the packaged writer, and never reads file bytes.

For automation or app-specific integrations, call the collector directly:

```powershell
$env:SENTINEL_ENV_PATH = "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env"
node .\sensors\endpoint-agent\collectors\protected-upload.js `
  --file "$env:USERPROFILE\Downloads\loan-file.pdf" `
  --destination "Desktop AI" `
  --user "analyst@example.com" `
  --wait `
  --json
```

An app integration or pilot script can still use the lower-level writer to
produce one signed upload-intent event without putting the handoff secret on the
command line:

```powershell
$env:SENTINEL_ENV_PATH = "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env"
node .\sensors\endpoint-agent\write-handoff.js `
  --file "$env:USERPROFILE\Downloads\loan-file.pdf" `
  --destination "Desktop AI" `
  --user "analyst@example.com"
```

The writer loads `ENDPOINT_AGENT_HANDOFF_SECRET` and
`ENDPOINT_AGENT_HANDOFF_DIR`, or their `PROMPTWALL_*` aliases, from the endpoint
config, verifies the referenced path is a local file, writes the event
atomically, and never reads the file body.

Check status:

```powershell
Get-ScheduledTask -TaskName PromptWallEndpointAgent
Get-Content "$env:LOCALAPPDATA\PromptWall\logs\endpoint-agent.log" -Tail 40
Get-Content "$env:LOCALAPPDATA\PromptWall\logs\desktop-collector.log" -Tail 40
```

Uninstall:

```powershell
.\scripts\uninstall-endpoint-agent.ps1 -RemoveDesktopCollector
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
| `APPROVER_USER` / `APPROVER_PASSWORD` | Optional reviewer console account that can approve or deny items assigned to the approver role. Set both together, keep `APPROVER_USER` distinct from admin and auditor users, and use at least 16 characters for `APPROVER_PASSWORD`. |
| `AUDITOR_USER` / `AUDITOR_PASSWORD` | Optional read-only console account for examiner or client-demo access. Set both together, keep `AUDITOR_USER` distinct from `ADMIN_USER`, and use at least 16 characters for `AUDITOR_PASSWORD`. |
| `SENTINEL_SECRET` | Stable session-signing secret shared by all instances. Production preflight requires at least 32 characters from environment. |
| `SENTINEL_DATA_KEY` | Stable AES-256-GCM data key source for retained approval prompts. Production preflight requires this key, or the `SENTINEL_SECRET` fallback, to be at least 32 characters. |
| `INGEST_API_KEY` | Sensor and proxy key for `/api/v1/*` ingest endpoints. Production preflight requires non-default, at least 32 characters. |
| `SCIM_BEARER_TOKEN` | Optional bearer token for `/scim/v2/*` provisioning. Leave empty to disable SCIM. Production preflight requires at least 32 characters when set. |
| `SENTINEL_DB_PATH` | SQLite path on local persistent disk. |
| `SENTINEL_SAAS_MODE` | Set to `true` for a paid customer stack. Production preflight then requires tenant id and seat limit. |
| `SENTINEL_TENANT_ID` | Lowercase customer tenant slug accepted from sensors, for example `cu-acme`. |
| `SENTINEL_SEAT_LIMIT` | Purchased seat count. New managed users beyond this count are blocked and recorded as `SEAT_LIMIT_BLOCKED`. |
| `SENTINEL_REQUIRE_TENANT_CONTEXT` | Requires sensors to send the matching `orgId`. Enabled automatically by SaaS mode. |
| `SENTINEL_REQUIRE_USER_IDENTITY` | Requires sensors to send managed user identity instead of `unknown` or `unattributed@unmanaged`. Enabled automatically by SaaS mode. |
| `ENDPOINT_AGENT_HANDOFF_DIR` | Optional local spool for signed native endpoint upload-intent events. |
| `ENDPOINT_AGENT_HANDOFF_SECRET` | Optional 32-plus-character local HMAC secret required before the endpoint agent accepts native handoff events. |

PromptWall accepts product-prefixed aliases for new deployments while keeping
the existing `SENTINEL_*`, `INGEST_API_KEY`, and endpoint-agent names valid for
upgrades. Use one family per setting; a non-empty legacy key wins when both are
set.

| Existing key | PromptWall alias |
| --- | --- |
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
| `SCIM_BEARER_TOKEN` | `PROMPTWALL_SCIM_BEARER_TOKEN` |
| `ENDPOINT_AGENT_WATCH_DIR` | `PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR` |
| `ENDPOINT_AGENT_HANDOFF_DIR` | `PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR` |
| `ENDPOINT_AGENT_HANDOFF_SECRET` | `PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET` |

Never bind `SENTINEL_DB_PATH` to a cloud-synced folder or network share. SQLite locking must be backed by local disk semantics, and production preflight blocks missing, cloud-synced, or UNC/network SQLite paths before startup readiness passes.

`npm run setup:prod` generates values that meet these floors. When values come from a deployment secret manager, keep the same minimum lengths or `/readyz` will report production readiness as blocked.

Production preflight also blocks missing Security Admin MFA and short custom
secrets. Use a base32 `ADMIN_TOTP_SECRET` at least 16 characters long, at least
16 characters for `ADMIN_PASSWORD`, `APPROVER_PASSWORD` when approver login is
configured, and `AUDITOR_PASSWORD` when auditor login is configured; use at
least 32 random characters for `INGEST_API_KEY`,
`SCIM_BEARER_TOKEN` when SCIM is enabled, `SENTINEL_SECRET`, and
`SENTINEL_DATA_KEY` when retained raw approval data is enabled.
`npm run setup:prod` generates a TOTP secret; enroll it in the operator's
authenticator app before serving the console to pilot users:

```bash
npm run mfa:uri
```

The command prints a standard `otpauth://` enrollment URI. Treat it like a
password because it contains the MFA seed. For a non-default env file or
white-label issuer, use:

```bash
npm run mfa:uri -- --env pilot.env --issuer "PromptWall Pilot"
```

Auditor sessions can read sanitized dashboard evidence, audit status, policy,
and examiner exports. They cannot reveal retained raw prompts, approve or deny
held prompts, run retention purges, apply policy templates, or edit policy.

The examiner export at `/api/export/evidence` includes:

- Audit-chain verification and hash-chained audit entries with detail hashes,
  not free-form audit detail text.
- Current policy plus parsed policy diffs for governed destinations, blocked
  destinations, file-upload blocks, retention, detector, and scanner changes.
- Coverage posture, governed and shadow destinations, active sensors, sensor
  versions, version gaps, and fleet install-health state by user, org, and
  required sensor.
- Approval workflow metadata for held or blocked records: assigned role,
  assigned group, routing reason, SLA due time, escalation state, and
  notification status.
- Prompt/file lineage summaries by user, destination, sensor, channel,
  category, and decision, plus per-event sanitized findings and prompt hashes.

It does not include raw prompt bodies, retained sealed prompts, token vaults,
release tokens, decision notes, or uploaded file bytes.

## SIEM Alerts

Set `SIEM_WEBHOOK_URL` to send sanitized security events to a SOC or SIEM webhook. Payloads omit prompt bodies, raw retained prompts, token vaults, and raw finding values. Alert payloads include bounded workflow metadata so a SOC can see the assigned group and SLA without receiving sensitive content.

Blocked prompt/file events, response leakage, hidden-instruction blocks, and failed or locked admin step-up confirmations for raw reveal and approval release are alertable. Webhook delivery is best-effort and never blocks the user-facing request.

Sensor version posture gaps are also alertable. If browser extension, endpoint
agent, or MCP guard events show mixed versions or missing version metadata,
PromptWall sends a forced `SENSOR_VERSION_GAP` alert with bounded source,
version, and platform metadata only.

## Approval Workflow Notifications

Configure customer-specific approval ownership in the Policy tab with
`approvalRoutingRules`. Rules match only metadata: detector ids, semantic
categories, source, channel, destination, severity, and risk score. They set
`assignedGroup`, `assignedRole`, and `slaMinutes` before notification delivery.
Keep rule ids, group ids, and reason codes generic enough for examiner evidence;
do not encode member names, account numbers, file names, or case details in the
policy.

Set one or more approval notification channels when a customer wants routed
approvals to notify a queue, chat channel, SOAR workflow, or ticketing bridge:

| Setting | Purpose |
| --- | --- |
| `PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_URL` or `APPROVAL_NOTIFY_WEBHOOK_URL` | Generic sanitized JSON webhook. |
| `PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_TOKEN` or `APPROVAL_NOTIFY_WEBHOOK_TOKEN` | Optional bearer token for the generic webhook. |
| `PROMPTWALL_APPROVAL_SLACK_WEBHOOK_URL` or `APPROVAL_SLACK_WEBHOOK_URL` | Slack incoming webhook. |
| `PROMPTWALL_APPROVAL_TEAMS_WEBHOOK_URL` or `APPROVAL_TEAMS_WEBHOOK_URL` | Microsoft Teams webhook. |

Approval notifications are separate from SIEM alerts. They include query id,
owner group, owner role, SLA, source, channel, destination, severity, detector
labels, and routing reason. They omit prompt bodies, redacted prompt previews,
token vaults, release tokens, decision notes, raw finding values, and uploaded
file bytes.

Delivery is best-effort. PromptWall records `notificationStatus`,
`notificationLastAttemptAt`, `notificationAttemptCount`, and bounded channel
names on the query, then writes an audit event such as
`APPROVAL_NOTIFICATION_SENT` or `APPROVAL_NOTIFICATION_FAILED`. Webhook URLs and
tokens are secrets; do not commit them to policy files, `.env.example`, docs
with real values, or support tickets.

The server also runs an SLA escalation pass at startup and every five minutes.
Overdue routed items receive `escalatedAt`, `escalationReason=sla_due`, an
`APPROVAL_ESCALATED` audit entry, and an escalation notification when a channel
is configured.

## Destination Policy Controls

Security Admins can edit `governedDestinations` and `blockedDestinations` from
the Policy tab. Governed destinations drive coverage posture and shadow-AI
classification. Blocked destinations are hard app-level stops: browser sends,
browser file uploads, endpoint file flows, `/api/v1/gate`,
`/api/v1/scan-file`, and `/api/v1/scan-response` return
`destination_blocked` before prompt or file content is analyzed or retained.

`blockUnapprovedAiDestinations` is enabled by default. Known AI hosts that are
not governed, allowed, blocked, or file-upload-blocked are treated as unapproved
and stop as `destination_blocked`. Security Admins can review a shadow-AI
destination from the Coverage tab and must enter a short reason before moving it
to govern, allow, or block policy state.

Security Admins can also edit `blockedFileUploadDestinations` when a customer
wants chat allowed but document upload forbidden for a destination. Browser
uploads, endpoint file flows, and `/api/v1/scan-file` return
`file_upload_blocked` before uploaded bytes, extracted text, or sensitive
filenames are retained.

Use host names or URLs for web tools, for example `chatgpt.com` or
`https://chat.deepseek.com`. Use wildcards such as `*.example-ai.com` for
subdomains. Desktop app labels normalize spaces to hyphens, so a native handoff
destination of `Desktop AI` matches `desktop-ai`.

## Retention Operations

PromptWall retains raw approval prompts and token vaults only for records that need review or rehydration. Set `rawRetentionDays` in policy to define how long finalized `approved`, `denied`, and `redacted` records keep those sealed fields. The default is 30 days.

Revealing a retained raw prompt requires an active Security Admin session, a CSRF token, and password confirmation. Approving a held prompt release requires an active Security Admin session or an optional approver session assigned to that item, plus CSRF and password confirmation. Successful reveals, failed reveal confirmations, approved releases, and failed approval confirmations are written to the audit log.

Sensors or proxy bridges that poll `/api/v1/status/:id` for a held prompt must
send the `x-release-token` header returned by the original gate response.
PromptWall stores only the token hash, rejects query-string release tokens,
and the reference Squid/ICAP bridge forwards the header automatically through
`awaitRelease`.

The server runs a retention purge on startup and then hourly. Security Admins can also run it from the Policy tab or with:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "https://promptwall.example.com/api/retention/purge" `
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

For an offline restore, stop the PromptWall process, restore to a new local-disk path, verify it, and then point `SENTINEL_DB_PATH` at the restored file:

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
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
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
