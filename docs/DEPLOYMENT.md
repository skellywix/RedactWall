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

## SCIM Provisioning And OIDC Login

Set `SCIM_BEARER_TOKEN` to enable customer identity provisioning at
`/scim/v2/*`; leave it empty to disable the surface. The endpoint accepts
`application/scim+json`, uses bearer auth, stores provisioned users and groups in
the local evidence database, and maps known PromptWall group display names onto
the local `security_admin`, `approver`, `auditor`, and `operator` roles.

Set `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and
`OIDC_REDIRECT_URI` to enable the console SSO button. OIDC login validates the
authorization-code callback, state, nonce, RS256 ID-token signature, issuer,
audience, expiry, and active SCIM user before issuing the normal PromptWall
session cookie. Keep local Security Admin credentials as the break-glass console
path. See `docs/SCIM_PROVISIONING.md` for endpoint details and IdP setup notes.

## Scoped Policy And Exceptions

Use `docs/POLICY_SCOPES.md` when a customer needs stricter controls for a user,
SCIM group, source, channel, destination, detector, or semantic category. The
control plane applies these scopes on gate and file-scan events and records
matched scope ids in evidence. Time-bound exceptions can allow matching
non-hard-stop events until `expiresAt`; hard-stop entities still block.
Exception rules can also carry `ownerGroup`, `reviewerRole`, and `reviewAfter`
metadata so temporary allow rules have an accountable review owner before they
expire. Evidence exports summarize review-due, expiring-soon, expired, and
active exception state without including matched users or prompt bodies.

Configure common scoped rules and time-bound exceptions from the Policy tab's
guided builders, then review the generated JSON in the scoped-policy editors
before saving. Use the advanced editors or admin policy API for uncommon
matchers. The dashboard keeps the JSON shape explicit so install-day technicians
can paste customer-specific scoped rules without weakening the global baseline.

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

After the private or unlisted Chrome Web Store item exists, rerun the same gate
with the real id:

```bash
npm run release:extension:check -- dist/browser-extension <chrome-web-store-id>
```

That adds a prompt-free
`promptwall-extension-v<version>.extension-settings.json` artifact for Chrome
Enterprise force-install policy. It contains the extension id, `force_installed`,
and the Chrome Web Store update URL only; managed storage with `serverUrl`,
`orgId`, user identity, and the ingest key stays in the customer's policy system
or vault.

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
prompt bodies and packaged development ingest keys. Set the real
`PROMPTWALL_URL`, `INGEST_API_KEY`, and watch directory during install; the
legacy `SENTINEL_URL` key remains accepted for existing configs. The agent
inspects supported files locally and does not contact the control plane without
an explicit ingest key.

## MCP Guard Package

Build the MCP guard artifact before an agent pilot handoff:

```bash
npm run package:mcp-guard
```

The command writes a zip and adjacent SHA-256 manifest under `dist/mcp-guard/`.
It includes the guard runtime, connector SDK, Microsoft 365 Graph file-content
connector, shared detection engine, env loader, version metadata, and MCP guard
install validation checker. It excludes the local direct-run demo and refuses
synthetic prompt bodies or development ingest keys. Set `PROMPTWALL_URL` and
`INGEST_API_KEY` in the host MCP runtime environment; the legacy `SENTINEL_URL`
key remains accepted for existing configs. Do not bake secrets into the package.
The guard does not contact the control plane without an explicit ingest key.

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
ingest-key presence, Node version, guard runtime, connector SDK, Microsoft 365
connector, shared detection engine, env loader, and package manifest. It posts
only check IDs, boolean status, and short details; it does not print or post
ingest keys, prompt text, tool output, or document content.

Future MCP content connectors must wrap every tool handler with
`sanitizeToolResult()` or `wrapConnectorTool()` from `sensors/mcp-guard/sdk.js`
before returning data to the model. See `docs/MCP_CONNECTOR_SDK.md`.

For the shipped Microsoft 365 connector, provide a Graph access token through
the host MCP runtime environment and use least-privileged file scopes for the
pilot. The connector supports text-readable driveItem content and rejects
unsupported binary content by default. See `docs/MCP_MICROSOFT365_CONNECTOR.md`.
When Microsoft 365 environment values are present, `npm run mcp:check` also
adds sanitized connector health checks for token presence, tenant ID, and scope
count without printing or posting the token.

## Endpoint Agent On Windows

For a pilot workstation, install the endpoint file sensor as a per-user scheduled task. The task starts at logon, restarts on failure, and reads its ingest key from a local config file instead of exposing it in the task command line.

Run PowerShell from the project folder:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -PromptWallUrl "https://promptwall.example.com" `
  -IngestKey "<pilot-ingest-key>" `
  -WatchDir "$env:USERPROFILE\PromptWallWatch"
```

This creates:

```text
Task:   PromptWallEndpointAgent
Config: %LOCALAPPDATA%\PromptWall\endpoint-agent.env
Log:    %LOCALAPPDATA%\PromptWall\logs\endpoint-agent.log
```

The config file carries `PROMPTWALL_URL`, `INGEST_API_KEY`, and `ENDPOINT_AGENT_WATCH_DIR`. Keep it restricted to the installing user, Administrators, and SYSTEM. The installer still accepts the legacy `-SentinelUrl` parameter and existing `SENTINEL_URL` config files remain valid. For an all-user managed install, pass an explicit `-ConfigDir "$env:ProgramData\PromptWall"` from an elevated PowerShell session.

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

The agent inspects supported watched files locally. Under redact policy, structured-only findings write a safe companion text file under `.promptwall-redacted` and report `redacted_available` evidence to the control plane; semantic or mixed findings remain held for Security Admin review. Image files (`.png`, `.jpg`, `.jpeg`, `.tif`, `.tiff`, `.bmp`, `.webp`) are supported as a fail-closed modality and return `ocr_required` until an endpoint-local OCR processor is configured.

For desktop file flows, enable the native handoff directory with an explicit
local secret. The endpoint agent keeps scanning locally; the handoff event is
only a signed upload intent with destination metadata and an absolute local file
path.

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -PromptWallUrl "https://promptwall.example.com" `
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

### Customer Detector Packs

Put customer-specific sensitive types in `config/custom-detectors.json`, or set
`PROMPTWALL_CUSTOM_DETECTORS_PATH` / `SENTINEL_CUSTOM_DETECTORS_PATH` to an
alternate JSON file for a customer silo. Detector packs are data-only. Each
enabled detector supplies an uppercase `id`, bounded `pattern`, optional
`context`, `severity`, `score`, `group`, and validator knobs such as
`minDigits`, `maxDigits`, `requireDigit`, `requireLetter`, `plausibleId`, or
`checksum: "luhn"`.

The shared engine rejects unsafe regex shapes, unbounded repetition, backrefs,
built-in detector ID overrides, and duplicate custom IDs. The control plane
normalizes the pack and sends it to browser, endpoint, and MCP sensors through
`/api/v1/policy`; `/api/v1/detectors` and examiner evidence packs include the
same custom IDs so Security Admins can use them in `alwaysBlock`, scoped policy,
exceptions, and approval routing.

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
  -PromptWallUrl "https://promptwall.example.com" `
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
`PROMPTWALL_ENV_PATH`, invokes
`sensors\endpoint-agent\collectors\protected-upload.js`, and passes only the
selected local file paths to the collector process. The Explorer verb is marked
with `MultiSelectModel=Player` so it remains available for multi-file
selections. The legacy `SENTINEL_ENV_PATH` alias remains accepted for existing
scripts. The collector verifies each path is a local file, writes signed events
through the packaged writer, and never reads file bytes.

For automation or app-specific integrations, call the collector directly:

```powershell
$env:PROMPTWALL_ENV_PATH = "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env"
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
$env:PROMPTWALL_ENV_PATH = "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env"
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
| `OIDC_ISSUER` | Optional OIDC issuer URL for console SSO. When any OIDC value is set, production preflight requires issuer, client id, client secret, redirect URI, and SCIM provisioning. |
| `OIDC_CLIENT_ID` | OIDC web application client id. |
| `OIDC_CLIENT_SECRET` | OIDC web application client secret. Production preflight requires at least 32 characters when OIDC is configured. |
| `OIDC_REDIRECT_URI` | OIDC callback URL, usually `https://promptwall.customer.example/auth/oidc/callback`. |
| `OIDC_AUTHORIZATION_ENDPOINT` / `OIDC_TOKEN_ENDPOINT` / `OIDC_JWKS_URI` | Optional explicit endpoints. Leave all three empty for issuer discovery, or set all three together. |
| `SENTINEL_DB_PATH` | SQLite path on local persistent disk. |
| `SENTINEL_SAAS_MODE` | Set to `true` for a paid customer stack. Production preflight then requires tenant id and seat limit. |
| `SENTINEL_TENANT_ID` | Lowercase customer tenant slug accepted from sensors, for example `cu-acme`. |
| `SENTINEL_SEAT_LIMIT` | Purchased seat count. New managed users beyond this count are blocked and recorded as `SEAT_LIMIT_BLOCKED`. |
| `SENTINEL_REQUIRE_TENANT_CONTEXT` | Requires sensors to send the matching `orgId`. Enabled automatically by SaaS mode. |
| `SENTINEL_REQUIRE_USER_IDENTITY` | Requires sensors to send managed user identity instead of `unknown` or `unattributed@unmanaged`. Enabled automatically by SaaS mode. |
| `SENTINEL_POLICY_PATH` | Optional policy file path for isolated tests, pilots, or customer-silo policy storage. |
| `SENTINEL_CUSTOM_DETECTORS_PATH` / `PROMPTWALL_CUSTOM_DETECTORS_PATH` | Optional customer detector-pack path. Defaults to `config/custom-detectors.json`. |
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
| `SENTINEL_CUSTOM_DETECTORS_PATH` | `PROMPTWALL_CUSTOM_DETECTORS_PATH` |
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
| `OIDC_ISSUER` | `PROMPTWALL_OIDC_ISSUER` |
| `OIDC_CLIENT_ID` | `PROMPTWALL_OIDC_CLIENT_ID` |
| `OIDC_CLIENT_SECRET` | `PROMPTWALL_OIDC_CLIENT_SECRET` |
| `OIDC_REDIRECT_URI` | `PROMPTWALL_OIDC_REDIRECT_URI` |
| `OIDC_AUTHORIZATION_ENDPOINT` | `PROMPTWALL_OIDC_AUTHORIZATION_ENDPOINT` |
| `OIDC_TOKEN_ENDPOINT` | `PROMPTWALL_OIDC_TOKEN_ENDPOINT` |
| `OIDC_JWKS_URI` | `PROMPTWALL_OIDC_JWKS_URI` |
| `OIDC_SCOPE` | `PROMPTWALL_OIDC_SCOPE` |
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
`SCIM_BEARER_TOKEN` when SCIM is enabled, `OIDC_CLIENT_SECRET` when OIDC is
enabled, `SENTINEL_SECRET`, and `SENTINEL_DATA_KEY` when retained raw approval
data is enabled.
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
- Report metadata, control mappings, and optional backup verification plus
  restore-drill status when generated with the evidence-pack CLI.

It does not include raw prompt bodies, retained sealed prompts, token vaults,
release tokens, decision notes, or uploaded file bytes.

The dashboard Lineage tab uses the same prompt-free aggregation through
`/api/lineage`. It shows lineage by user, destination, sensor, channel,
category, and decision so Security Admins and auditors can answer coverage and
examiner questions without downloading the full evidence pack.

Generate a dated examiner pack from the local evidence store:

```bash
npm run evidence:pack -- evidence-packs
```

Attach backup verification and a restore-drill check when those artifacts exist:

```bash
npm run evidence:pack:zip -- evidence-packs \
  backups/sentinel-YYYY-MM-DDTHH-MM-SS-sssZ.db \
  data/restored-sentinel.db
```

For scheduled customer-silo reporting, copy
`config/evidence-schedule.example.json` to
`config/evidence-schedule.json`, set the output folder and cadence, and invoke
it from the platform scheduler:

```bash
npm run evidence:pack:scheduled -- config/evidence-schedule.json
```

On Windows pilot or customer-silo hosts, install the local scheduled task:

```powershell
npm run evidence:pack:install-task
```

The task runs `scripts/run-evidence-pack.ps1`, writes run status to
`%LOCALAPPDATA%\PromptWall\logs\evidence-pack.log`, and passes only the repo
path, schedule config path, and log path as task arguments. It does not place
environment secrets, prompt bodies, release tokens, or upload contents in the
scheduled task definition.

On Linux customer-silo hosts, especially the Docker shape used by the AWS
runbook, keep the schedule config in the mounted data folder and install the
systemd timer:

```bash
sudo cp config/evidence-schedule.example.json /var/lib/promptwall/evidence-schedule.json
sudo editor /var/lib/promptwall/evidence-schedule.json
sudo npm run evidence:pack:install-systemd -- \
  --mode docker \
  --container promptwall \
  --config /data/evidence-schedule.json \
  --on-calendar quarterly
```

Set the schedule config `outDir` to `/data/evidence-packs` for Docker hosts.
The systemd unit writes status to `/var/log/promptwall/evidence-pack.log`, uses
`Persistent=true` for missed runs, and stores only scheduler metadata in
`/etc/promptwall/evidence-pack.env`.

## SIEM Alerts

Set `SIEM_WEBHOOK_URL` to send sanitized security events to a SOC or SIEM webhook. Payloads omit prompt bodies, raw retained prompts, token vaults, and raw finding values. Alert payloads include bounded workflow metadata so a SOC can see the assigned group and SLA without receiving sensitive content.

Blocked prompt/file events, response leakage, hidden-instruction blocks, and failed or locked admin step-up confirmations for raw reveal and approval release are alertable. Webhook delivery is best-effort and never blocks the user-facing request.

Sensor version posture gaps are also alertable. If browser extension, endpoint
agent, or MCP guard events show mixed versions or missing version metadata,
PromptWall sends a forced `SENSOR_VERSION_GAP` alert with bounded source,
version, and platform metadata only.

## Approval Workflow Notifications

Configure customer-specific approval ownership in the Policy tab with
`approvalRoutingRules`. Rules match only metadata: SCIM user names, SCIM groups,
org ids, detector ids, semantic categories, source, channel, destination,
severity, and risk score. They set `assignedGroup`, `assignedRole`, and
`slaMinutes` before notification delivery. Keep rule ids, group ids, and reason
codes generic enough for examiner evidence; do not encode member names, account
numbers, file names, or case details in the policy.

Set one or more approval notification channels when a customer wants routed
approvals to notify a queue, chat channel, SOAR workflow, or ticketing bridge:

| Setting | Purpose |
| --- | --- |
| `PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_URL` or `APPROVAL_NOTIFY_WEBHOOK_URL` | Generic sanitized JSON webhook. |
| `PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_TOKEN` or `APPROVAL_NOTIFY_WEBHOOK_TOKEN` | Optional bearer token for the generic webhook. |
| `PROMPTWALL_APPROVAL_SLACK_WEBHOOK_URL` or `APPROVAL_SLACK_WEBHOOK_URL` | Slack incoming webhook. |
| `PROMPTWALL_APPROVAL_TEAMS_WEBHOOK_URL` or `APPROVAL_TEAMS_WEBHOOK_URL` | Microsoft Teams webhook. |
| `PROMPTWALL_APPROVAL_SMTP_HOST` or `APPROVAL_SMTP_HOST` | SMTP relay host for plain-text sanitized approval email. |
| `PROMPTWALL_APPROVAL_SMTP_PORT` or `APPROVAL_SMTP_PORT` | SMTP relay port; defaults to `587`, or `465` when implicit TLS is enabled. |
| `PROMPTWALL_APPROVAL_SMTP_FROM` or `APPROVAL_SMTP_FROM` | Sender address for approval notifications. |
| `PROMPTWALL_APPROVAL_SMTP_TO` or `APPROVAL_SMTP_TO` | Comma- or semicolon-separated reviewer distribution-list addresses. |
| `PROMPTWALL_APPROVAL_SMTP_USERNAME` or `APPROVAL_SMTP_USERNAME` | Optional SMTP username. |
| `PROMPTWALL_APPROVAL_SMTP_PASSWORD` or `APPROVAL_SMTP_PASSWORD` | Optional SMTP password. |
| `PROMPTWALL_APPROVAL_SMTP_SECURE` or `APPROVAL_SMTP_SECURE` | Set `true` for implicit TLS, usually port `465`. |
| `PROMPTWALL_APPROVAL_SMTP_ALLOW_INSECURE` or `APPROVAL_SMTP_ALLOW_INSECURE` | Set `true` only for a trusted local relay without TLS. |

Approval notifications are separate from SIEM alerts. They include query id,
owner group, owner role, SLA, source, channel, destination, severity, detector
labels, and routing reason. They omit prompt bodies, redacted prompt previews,
token vaults, release tokens, decision notes, raw finding values, and uploaded
file bytes. SMTP email uses the same sanitized routing fields as the webhook
payload and strips mail-header newlines before delivery.

Delivery is best-effort. PromptWall records `notificationStatus`,
`notificationLastAttemptAt`, `notificationAttemptCount`, and bounded channel
names on the query, then writes an audit event such as
`APPROVAL_NOTIFICATION_SENT` or `APPROVAL_NOTIFICATION_FAILED`. Webhook URLs,
SMTP credentials, and reviewer distribution lists are operational secrets; do
not commit them to policy files, `.env.example`, docs with real values, or
support tickets. SMTP requires TLS by default. Use the insecure relay opt-in
only for a trusted local mail relay inside the customer network.

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

Security Admins can edit `blockedBrowserActions` for destination-scoped browser
action blocks. The first enforced action is `paste`: when a configured
destination matches, the browser prevents the paste before clipboard text lands
in the composer and reports only sanitized `action_blocked` evidence.

Security Admins can set `responseScanMode` from the Policy tab to choose how
AI replies are handled when `/api/v1/scan-response` detects sensitive content.
`flag` records sanitized evidence and alerts, `redact` returns a safe response
preview without creating a reviewer queue item, and `block` suppresses display
as `response_blocked` with sanitized workflow routing.

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

After backup verification and any restore drill, generate an examiner pack that
records both statuses without embedding the `.db` content:

```bash
npm run evidence:pack -- evidence-packs \
  backups/sentinel-YYYY-MM-DDTHH-MM-SS-sssZ.db \
  data/restored-sentinel.db
```

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
