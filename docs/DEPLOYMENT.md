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
`SENTINEL_DB_PATH` to `/data/sentinel.db`, `SENTINEL_POLICY_PATH` to
`/data/policy.json`, and `SENTINEL_CUSTOM_DETECTORS_PATH` to
`/data/custom-detectors.json`. It checks `/readyz` for container health, so the
container keeps runtime state outside the image and reports unhealthy if
database or production preflight readiness is blocked. The container runs with a
read-only root filesystem, a writable `/tmp` tmpfs, no extra Linux
capabilities, and `no-new-privileges`; keep all mutable customer state under
`/data`.

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

For paid customer Docker installs, keep these paths on the mounted local-disk
volume:

```text
SENTINEL_DB_PATH=/data/sentinel.db
SENTINEL_POLICY_PATH=/data/policy.json
SENTINEL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json
```

## Health Checks

```bash
curl http://localhost:4000/healthz
curl http://localhost:4000/readyz
```

`/healthz` confirms the process is alive. `/readyz` confirms the database opens and production preflight is not blocked.

Logged-in Security Admins can inspect detailed configuration checks and
scrape-friendly operational counters at:

```text
http://localhost:4000/api/preflight
http://localhost:4000/api/metrics
```

`/api/metrics` returns uptime, aggregate event counts, audit-chain status, audit
entry count, and a timestamp. It does not include prompt bodies or raw finding
values.

## In-App Updates From GitHub

Security Admins can open **Updates** in the dashboard to configure and run a
source-clone update from GitHub. The updater uses the existing Git remote, so a
production source install should have `origin` pointed at the approved
PromptWall GitHub repo and should track the production branch, normally `main`.

The update button is deliberately conservative:

1. Verifies the configured remote is GitHub.
2. Blocks if the checked-out branch does not match the configured update branch.
3. Blocks if the source tree has local edits or untracked source files.
4. Verifies the SQLite audit chain.
5. Creates a database backup under the active data root, for example
   `/data/backups/updates` or `data/backups/updates`.
6. Fetches the configured branch and fast-forwards only.
7. Runs the configured dependency step, usually `npm ci --omit=dev`.
8. Marks restart required, or schedules the configured restart command when the
   host explicitly enables backend restart execution.

The updater never runs `git reset`, `git clean`, or volume-delete commands.
Runtime state should still live outside source, using:

```text
SENTINEL_DB_PATH=/data/sentinel.db
SENTINEL_POLICY_PATH=/data/policy.json
SENTINEL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json
```

For Docker image deployments, rebuild and roll the image through your normal
host or CloudFormation process instead of using the source-clone updater inside
a read-only container. A host checkout can schedule a restart command after an
update is applied, but backend execution of that command is disabled unless
the host sets:

```text
PROMPTWALL_UPDATE_RESTART_ENABLED=true
```

For stricter production hosts, set `PROMPTWALL_UPDATE_RESTART_COMMAND` in the
service environment and leave the dashboard restart command blank. Otherwise the
dashboard command is treated as an operator hint and the update will finish with
`restart required`.

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
path. See `docs/SCIM_PROVISIONING.md` for endpoint details and
`docs/IDENTITY_IDP_SETUP.md` for Microsoft Entra and Okta setup recipes. Logged
in operators can also open the dashboard Identity tab, or print the same
secret-free handoff from the CLI:

```bash
npm run identity:setup -- --provider entra --base-url https://promptwall.customer.example --tenant-id <tenant-id-or-domain>
npm run identity:setup -- --provider okta --base-url https://promptwall.customer.example --tenant-id <customer.okta.com>
```

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

Managed browser packages report `chrome_mv3`, `edge_mv3`, or `firefox_mv3`
depending on the installed target.

Mixed versions show as an attention item so a pilot admin can spot partial
rollouts after a managed extension or agent update. Browser extension, endpoint,
and MCP guard install validation can also report bounded check results through
`POST /api/v1/heartbeat`; failed checks show as sensor install-health attention
in Coverage and in the sanitized examiner export. The Coverage tab also includes
a Fleet Install Health table that rolls the latest required-sensor state up by
user, org, source, version, platform, and failed check ID. Endpoint agent
heartbeats with AI tool inventory checks also render an Endpoint AI Tools panel
and evidence rows by sanitized tool id, user, org, platform, approval state, and
last-seen time. The coverage API does not include prompt bodies, raw retained
prompts, token vaults, ingest keys, handoff secrets, tool output, process
arguments, local executable paths, or decision notes.

## Browser Extension Package

Build and check browser extension artifacts before a managed pilot handoff:

```bash
npm run release:extension:check -- dist/browser-extension
```

The command writes Chrome, Edge, and Firefox zips, adjacent SHA-256 manifests,
and a shared release-readiness JSON under `dist/browser-extension/`. It verifies
Manifest V3 wiring, managed-storage schema coverage, synced engine copies, the
WebExtension API bridge, browser install-health heartbeat support,
force-install policy examples, the browser release checklist, and absence of a
packaged development ingest key. Configure `serverUrl`, `ingestKey`, and
identity through managed browser storage or local demo storage.

After browser store items or signed Firefox install URLs exist, rerun the same
gate with the final values:

```bash
npm run release:extension:check -- dist/browser-extension --chrome-extension-id <chrome-web-store-id> --edge-extension-id <edge-addons-id> --firefox-install-url https://downloads.customer.example/promptwall-firefox.xpi
```

That adds prompt-free `promptwall-<browser>-extension-v<version>.extension-settings.json`
artifacts for browser force-install policy. They contain extension IDs, install
or update URLs, and `force_installed` mode only; managed storage with
`serverUrl`, `orgId`, user identity, and the ingest key stays in the customer's
policy system or vault.

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
desktop collector, one-shot clipboard guard, optional endpoint-local OCR bridge,
and scheduled-task plus
shell-action install/run/uninstall scripts, plus the endpoint install validation
checker. It refuses synthetic
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
connector, Google Drive connector, Slack connector, Microsoft Teams connector,
Atlassian Jira/Confluence connector, database read-only connector, shared
detection engine, env loader, version metadata, and MCP guard install
validation checker. It excludes
the local direct-run demo and refuses synthetic prompt bodies or development
ingest keys. Set `PROMPTWALL_URL` and `INGEST_API_KEY` in the host MCP runtime
environment; the legacy `SENTINEL_URL` key remains accepted for existing
configs. Do not bake secrets into the package. The guard does not contact the
control plane without an explicit ingest key.

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
connector, Google Drive connector, Slack connector, Microsoft Teams connector,
Atlassian Jira/Confluence connector, database read-only connector, shared
detection engine, env loader, and package manifest. It posts only check IDs,
boolean status, and short details; it does not print or post ingest keys,
prompt text, tool output, DSNs, SQL text, document IDs, or document content.

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

For the shipped Google Drive connector, provide a Google Drive access token
through the host MCP runtime environment and prefer
`https://www.googleapis.com/auth/drive.readonly` for delegated pilots. The
connector uses Drive media downloads for blob files and text-oriented exports
for Google Workspace documents, then redacts before returning MCP output. See
`docs/MCP_GOOGLE_DRIVE_CONNECTOR.md`. When Google Drive environment values are
present, `npm run mcp:check` adds sanitized token, optional tenant, and scope
count health checks without printing or posting the token.

For the shipped Slack connector, provide a Slack bot token through the host MCP
runtime environment as `SLACK_BOT_TOKEN` or `SLACK_CONNECTOR_TOKEN`. Prefer the
narrowest approved scopes for the pilot: `channels:history` for public channel
history, `groups:history` for private channels, and `files:read` for private
file reads. The connector defaults conversation fetches to 15 messages, rejects
non-Slack private file URLs, rejects unsupported binary file content, and redacts
before returning MCP output. See `docs/MCP_SLACK_CONNECTOR.md`. When Slack
environment values are present, `npm run mcp:check` adds sanitized token,
optional team or enterprise ID, and scope count health checks without printing
or posting the token.

For the shipped Microsoft Teams connector, provide a Graph access token through
the host MCP runtime environment as `TEAMS_GRAPH_ACCESS_TOKEN`,
`M365_GRAPH_ACCESS_TOKEN`, or `MICROSOFT_GRAPH_ACCESS_TOKEN`. Prefer
resource-specific read scopes for the pilot, such as
`ChannelMessage.Read.Group` and `ChatMessage.Read.Chat`, and use broader Graph
read scopes only after customer approval. The connector reads channel or chat
messages, converts HTML message bodies to plain text, caps Graph page size at
50, and redacts before returning MCP output. See
`docs/MCP_TEAMS_CONNECTOR.md`. When Teams environment values are present,
`npm run mcp:check` adds sanitized token, optional tenant, and scope count
health checks without printing or posting the token.

For the shipped Atlassian connector, provide an Atlassian Cloud site URL and
access token through the host MCP runtime environment as `ATLASSIAN_SITE_URL`
plus `ATLASSIAN_ACCESS_TOKEN` or `ATLASSIAN_API_TOKEN`. Set
`ATLASSIAN_EMAIL` when using API-token Basic auth. Prefer
`read:jira-work` and `read:page:confluence` for pilots. The connector reads
bounded Jira issue fields and Confluence page bodies, converts them to plain
text, and redacts before returning MCP output. See
`docs/MCP_ATLASSIAN_CONNECTOR.md`. When Atlassian environment values are
present, `npm run mcp:check` adds sanitized token, tenant, and scope count
health checks without printing or posting the token, issue key, or page id.

For the shipped database read-only connector, provide a SQLite DSN through the
host MCP runtime environment as `MCP_DATABASE_DSN` or `DATABASE_READONLY_DSN`.
Set `MCP_DATABASE_LABEL` for bounded health evidence and
`MCP_DATABASE_SCOPES` when a pilot wants a custom scope label. The connector
opens SQLite with read-only options, accepts only single-statement `SELECT` or
`WITH` queries, wraps results in an outer `LIMIT`, and redacts rows before
returning MCP output. See `docs/MCP_DATABASE_READONLY_CONNECTOR.md`. When
database environment values are present, `npm run mcp:check` adds sanitized DSN
presence, label, and scope count checks without printing or posting the DSN,
absolute file path, SQL text, row values, or schema output.

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
file bytes, executable paths, or process arguments. The endpoint checker also
adds a sanitized local AI tool inventory to the heartbeat. Detected tools are
reported as stable check ids such as `ai_tool_cursor` or
`ai_tool_claude_desktop`.

Optional sanctioned endpoint AI tools:

```powershell
Add-Content "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env" "ENDPOINT_AGENT_APPROVED_AI_TOOLS=cursor,claude_desktop"
```

When `ENDPOINT_AGENT_APPROVED_AI_TOOLS` is set, detected endpoint AI tools not
on that list report endpoint AI-tool inventory attention. Install-health stays
reserved for runtime and configuration failures. This makes endpoint/developer tool
visibility show up in Coverage without sending local paths, process args, document
names, prompt text, or file content.
The endpoint checker still prints unapproved tool checks as attention, but it
does not fail install readiness when runtime and configuration checks pass.

Optional named endpoint file-flow profiles:

```powershell
Add-Content "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env" @'
ENDPOINT_AGENT_FILE_FLOW_PROFILES=[{"id":"lending","dir":"C:\\PromptWall\\Flows\\Lending","destination":"Copilot Desktop"},{"id":"call_center","dir":"C:\\PromptWall\\Flows\\CallCenter","destination":"ChatGPT Desktop"}]
'@
```

Profiles let a pilot watch multiple local app, drop, or staging folders and map
each one to the AI destination that should appear in policy and evidence. The
endpoint agent scans files locally through the same processor path as the main
watch folder and native handoff spool. Install-health heartbeats report only
profile ids, counts, and `configured directory` or `missing directory` status;
they do not print or post watched paths, file names, file bytes, extracted text,
or prompts. The Coverage tab summarizes the profile count as `Endpoint
file-flow profiles` so operators can see which workstation flows are ready.

The agent inspects supported watched files locally. Under redact policy, structured-only findings write a safe companion text file under `.promptwall-redacted` and report `redacted_available` evidence to the control plane; semantic or mixed findings remain held for Security Admin review. The managed browser extension also inspects text-readable file selections and drops locally before upload. It sends only synthetic file labels, masked detector evidence, categories, risk metadata, and client outcomes to `/api/v1/gate`; it does not send file bytes, raw filenames, `contentBase64`, or extracted text to the control plane. Unsupported, oversized, unreadable, or OCR-needed browser uploads fail closed as `file_blocked_unscanned` or `ocr_required`. Direct API uploads through `/api/v1/scan-file` still return `ocr_required` for images until an endpoint-local OCR path is in scope. Endpoint agents can optionally run a workstation-local OCR command and then send only sanitized detector evidence to the control plane.

Optional endpoint-local OCR:

```powershell
Add-Content "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env" @'
ENDPOINT_AGENT_OCR_COMMAND=C:\Program Files\Tesseract-OCR\tesseract.exe
ENDPOINT_AGENT_OCR_ARGS_JSON=["{file}","stdout"]
ENDPOINT_AGENT_OCR_TIMEOUT_MS=15000
ENDPOINT_AGENT_OCR_MAX_CHARS=1000000
'@
```

The OCR command runs through `execFile` without a shell. If the command is not
configured, image files stay blocked as `ocr_required`. If it is configured and
returns text, the endpoint agent runs the same local detector/redactor path used
for text, PDF, Office, and native handoff files. Image bytes and raw OCR text do
not go to `/api/v1/scan-file` or `/api/v1/gate`.

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
  -InstallDesktopCollector `
  -InstallClipboardGuard `
  -ClipboardGuardClearOnBlock
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

### Browser File-Intent Native Messaging Host

The managed browser extension blocks uploads it cannot inspect locally (too
large, OCR required, or not text-readable) and tells the user the file needs
endpoint inspection. With the file-intent host installed, the extension also
hands the endpoint agent that file's NAME and SIZE - never bytes - over Chrome
native messaging. The host resolves the intent against the user's staging
folders (`Downloads`, `Desktop`, `Documents` by default, or
`ENDPOINT_AGENT_INTENT_SEARCH_DIRS` from endpoint config), and on exactly one
name+size match writes the same signed metadata-only handoff event the desktop
collectors use. The endpoint agent then scans the real file locally, including
the OCR path, and reports only sanitized evidence.

Install it per user after endpoint agent setup, bound to the deployed
extension id:

```powershell
.\scripts\install-file-intent-host.ps1 `
  -ExtensionId "<32-character-extension-id>" `
  -ConfigDir "$env:LOCALAPPDATA\PromptWall" `
  -Browser both
```

The installer writes a secret-free launcher (`file-intent-host.cmd`), the
`com.promptwall.file_intent` host manifest bound to that one extension origin,
and per-user `NativeMessagingHosts` registry keys for Chrome and/or Edge. The
ingest key and handoff secret stay in `endpoint-agent.env`; the launcher only
points `PROMPTWALL_ENV_PATH` at it. Host replies to the browser carry only
sanitized statuses (`handoff_written`, `not_found`, `ambiguous`) - never local
paths. Ambiguous matches (the same name+size in two roots) write nothing.
Remove the registration with `.\scripts\uninstall-file-intent-host.ps1`.

### Clipboard Guard

The packaged endpoint runtime also includes a one-shot clipboard guard for
Windows pilots. It reads the current clipboard locally, runs the same shared
detection engine, and sends only masked findings, detector counts, risk, and
severity to the control plane. Clean or empty clipboard values are not reported.

Run in report-only mode:

```powershell
$env:PROMPTWALL_ENV_PATH = "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env"
npm run desktop:clipboard -- --destination "Desktop AI" --user "analyst@example.com" --json
```

Run in block mode:

```powershell
$env:PROMPTWALL_ENV_PATH = "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env"
npm run desktop:clipboard -- --clear-on-block --destination "Desktop AI" --user "analyst@example.com" --json
```

Report-only mode records sanitized `paste_flagged` evidence when sensitive
content is present. `--clear-on-block` clears the local clipboard first, then
records sanitized `action_blocked` evidence. The guard never writes clipboard
text to disk and never sends `contentBase64`, raw clipboard text, or raw document
content to the control plane. If Windows refuses the clear operation, the guard
records sanitized `paste_flagged` evidence and exits nonzero.

Install the clipboard guard as a Start Menu shortcut for pilot users:

```powershell
.\scripts\install-clipboard-guard.ps1 `
  -ConfigDir "$env:LOCALAPPDATA\PromptWall" `
  -ShortcutName "PromptWall Clipboard Guard" `
  -Destination "Desktop AI" `
  -ClearOnBlock
```

The shortcut runs `scripts\run-clipboard-guard.ps1` with the local endpoint
config path and writes only the guard's sanitized JSON result to
`%LOCALAPPDATA%\PromptWall\logs\clipboard-guard.log`. The shortcut arguments do
not contain the ingest key, native handoff secret, clipboard text, or prompt
content. Use `-DesktopShortcut` if the pilot wants a desktop shortcut as well;
use `-HotKey "CTRL+ALT+P"` only when the customer explicitly wants a keyboard
shortcut.

Run the packaged launcher directly:

```powershell
.\scripts\run-clipboard-guard.ps1 `
  -RepoRoot (Get-Location).Path `
  -ConfigPath "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env" `
  -Destination "Desktop AI" `
  -ClearOnBlock
```

### Git Push Guard

The endpoint package includes a local git pre-push guard for source-code and
secret exfiltration checks. It inspects outbound diffs before `git push`
transfers objects, blocks sensitive or unbounded pushes locally, and reports
only masked detector evidence through `/api/v1/gate` as `action_blocked` with
`channel: "git_push"`. It never sends raw source, patch text, repository paths,
remote repository names, or remote URL paths to the control plane.

Run a manual staged-diff check:

```powershell
$env:PROMPTWALL_ENV_PATH = "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env"
npm run desktop:git-push -- --staged --remote-url "https://github.com/customer/repo.git" --user "engineer@example.com" --json
```

Install it into one pilot repository:

```powershell
npm run desktop:git-push:install -- `
  -RepoPath "C:\Work\lending-app" `
  -ConfigPath "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env" `
  -AllowedHost github.com
```

The installer writes a managed `.git/hooks/pre-push` hook that loads only
`PROMPTWALL_ENV_PATH` and invokes the collector with Git's remote name, remote
URL, and pre-push ref updates. Existing branches are scanned as
`remote_sha..local_sha`; new branches are scanned against Git's empty tree so
first pushes do not bypass inspection. Use `-AllowedHost` or
`PROMPTWALL_GIT_ALLOWED_HOSTS` for sanctioned corporate Git hosts: source-code
only pushes to those hosts are allowed, but detected secrets, regulated member
data, contracts, health data, or confidential business context still block. The
hook does not contain the ingest key, native handoff secret, prompt text, source
code, or repository remote path.

Uninstall from that repository:

```powershell
.\scripts\uninstall-git-push-guard.ps1 -RepoPath "C:\Work\lending-app"
```

Check status:

```powershell
Get-ScheduledTask -TaskName PromptWallEndpointAgent
Get-Content "$env:LOCALAPPDATA\PromptWall\logs\endpoint-agent.log" -Tail 40
Get-Content "$env:LOCALAPPDATA\PromptWall\logs\desktop-collector.log" -Tail 40
Get-Content "$env:LOCALAPPDATA\PromptWall\logs\clipboard-guard.log" -Tail 40
```

Uninstall:

```powershell
.\scripts\uninstall-endpoint-agent.ps1 -RemoveDesktopCollector -RemoveClipboardGuard
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
| `OIDC_SCOPE` | OIDC scopes requested by console SSO, defaulting to `openid email profile`. |
| `OIDC_AUTHORIZATION_ENDPOINT` / `OIDC_TOKEN_ENDPOINT` / `OIDC_JWKS_URI` | Optional explicit endpoints. Leave all three empty for issuer discovery, or set all three together. |
| `SENTINEL_DB_PATH` | SQLite path on local persistent disk. |
| `SENTINEL_SAAS_MODE` | Set to `true` for a paid customer stack. Production preflight then requires tenant id and seat limit. |
| `SENTINEL_TENANT_ID` | Lowercase customer tenant slug accepted from sensors, for example `cu-acme`. |
| `SENTINEL_SEAT_LIMIT` | Purchased seat count. New managed users beyond this count are blocked and recorded as `SEAT_LIMIT_BLOCKED`. |
| `SENTINEL_REQUIRE_TENANT_CONTEXT` | Requires sensors to send the matching `orgId`. Enabled automatically by SaaS mode. |
| `SENTINEL_REQUIRE_USER_IDENTITY` | Requires sensors to send managed user identity instead of `unknown` or `unattributed@unmanaged`. Enabled automatically by SaaS mode. |
| `SENTINEL_POLICY_PATH` | Optional policy file path for isolated tests, pilots, or customer-silo policy storage. Docker customer silos default to `/data/policy.json`. |
| `SENTINEL_CUSTOM_DETECTORS_PATH` / `PROMPTWALL_CUSTOM_DETECTORS_PATH` | Optional customer detector-pack path. Docker customer silos default to `/data/custom-detectors.json`; native Node defaults to `config/custom-detectors.json`. |
| `ENDPOINT_AGENT_HANDOFF_DIR` | Optional local spool for signed native endpoint upload-intent events. |
| `ENDPOINT_AGENT_HANDOFF_SECRET` | Optional 32-plus-character local HMAC secret required before the endpoint agent accepts native handoff events. |
| `ENDPOINT_AGENT_OCR_COMMAND` / `PROMPTWALL_ENDPOINT_AGENT_OCR_COMMAND` | Optional endpoint-local OCR command for image files. Disabled by default. |
| `ENDPOINT_AGENT_OCR_ARGS_JSON` / `PROMPTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON` | Optional JSON string array of OCR command args. Include `{file}` where the image path belongs; otherwise the file path is appended. |
| `ENDPOINT_AGENT_OCR_TIMEOUT_MS` / `PROMPTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS` | Optional OCR command timeout, defaulting to 15000 ms. |
| `ENDPOINT_AGENT_OCR_MAX_CHARS` / `PROMPTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS` | Optional OCR output cap before detection, defaulting to 1000000 chars. |
| `ENDPOINT_AGENT_APPROVED_AI_TOOLS` / `PROMPTWALL_ENDPOINT_AGENT_APPROVED_AI_TOOLS` | Optional comma-separated sanctioned endpoint AI tool ids. Detected local AI tools outside this list report endpoint AI-tool inventory attention using sanitized ids only. |
| `ENDPOINT_AGENT_FILE_FLOW_PROFILES` / `PROMPTWALL_ENDPOINT_AGENT_FILE_FLOW_PROFILES` | Optional JSON array of named endpoint file-flow watcher profiles. Heartbeats report profile ids/status only. |

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
| `ENDPOINT_AGENT_OCR_COMMAND` | `PROMPTWALL_ENDPOINT_AGENT_OCR_COMMAND` |
| `ENDPOINT_AGENT_OCR_ARGS_JSON` | `PROMPTWALL_ENDPOINT_AGENT_OCR_ARGS_JSON` |
| `ENDPOINT_AGENT_OCR_TIMEOUT_MS` | `PROMPTWALL_ENDPOINT_AGENT_OCR_TIMEOUT_MS` |
| `ENDPOINT_AGENT_OCR_MAX_CHARS` | `PROMPTWALL_ENDPOINT_AGENT_OCR_MAX_CHARS` |
| `ENDPOINT_AGENT_APPROVED_AI_TOOLS` | `PROMPTWALL_ENDPOINT_AGENT_APPROVED_AI_TOOLS` |
| `ENDPOINT_AGENT_FILE_FLOW_PROFILES` | `PROMPTWALL_ENDPOINT_AGENT_FILE_FLOW_PROFILES` |

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
  versions, version gaps, endpoint AI tool posture by sanitized id, and fleet
  install-health state by user, org, and required sensor.
- Approval workflow metadata for held or blocked records: assigned role,
  assigned group, routing reason, SLA due time, escalation state, and
  notification status.
- Prompt/file lineage summaries by user, destination, sensor, channel,
  category, and decision, plus per-event sanitized findings and prompt hashes.
- Report metadata, control mappings, and optional backup verification plus
  restore-drill status when generated with the evidence-pack CLI.

`queryLimit` bounds only the exported per-event query rows. Coverage posture and
lineage summaries are computed from the full local evidence history so a small
pack does not silently undercount older users, destinations, sensors, or
decisions.

It does not include raw prompt bodies, retained sealed prompts, token vaults,
release tokens, decision notes, process arguments, local executable paths, or
uploaded file bytes.

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

For vendor-risk or procurement review, export the Security Trust Package. It is
not a live examiner evidence pack; it is a sanitized control and dependency
artifact with validation commands, security questionnaire answers, documentation
pointers, and a CycloneDX-style SBOM inventory:

```powershell
npm run security:package:zip -- C:\PromptWall\security-packages
```

Security Admins can also download it from **Audit Log > Security Trust Package**
or through `GET /api/security/package?format=zip`. The trust package excludes
prompt bodies, secrets, token vaults, raw audit details, raw URLs, local file
paths, and package-lock filesystem paths.

## SIEM Alerts

Set `SIEM_WEBHOOK_URL` to send sanitized security events to a SOC or SIEM webhook. The URL must be `https://` and must not include URL username or password credentials. Payloads omit prompt bodies, raw retained prompts, token vaults, and raw finding values. Alert payloads include bounded workflow metadata so a SOC can see the assigned group and SLA without receiving sensitive content.

Blocked prompt/file events, response leakage, hidden-instruction blocks, and failed or locked admin step-up confirmations for raw reveal and approval release are alertable. Webhook delivery is best-effort and never blocks the user-facing request.

Sensor version posture gaps are also alertable. If browser extension, endpoint
agent, or MCP guard events show mixed versions or missing version metadata,
PromptWall sends a forced `SENSOR_VERSION_GAP` alert with bounded source,
version, and platform metadata only.

Set `SIEM_POSTURE_FEED_ENABLED=true` to emit automatic sanitized
`POSTURE_FEED` snapshots when control posture changes. The feed reuses
`SIEM_WEBHOOK_URL`, deduplicates unchanged snapshots, rate-limits attempts with
`SIEM_POSTURE_MIN_INTERVAL_MS`, and omits prompt bodies, raw findings, token
vaults, freeform gap text, and audit details. Use `POST /api/posture/notify`
from an authenticated admin session for a manual one-shot `POSTURE_SNAPSHOT`.

Security Admins can also generate an offline SOC integration package from the
command center or with `GET /api/integrations/siem/package?profile=all`. Use
`profile=splunk`, `profile=sentinel`, `profile=chronicle`, or
`profile=servicenow` to narrow the package. Add `format=zip` to receive a
marketplace-style ZIP with `README.md`, `manifest.json`, the privacy contract,
profile-specific mappings, saved searches/detections, dashboard/workbook
panels, sample payloads, incident templates, and setup checklists. Add
`download=1` or `format=json` when an automation needs the raw JSON package.
The package does not call the SIEM, read webhook tokens, or include secrets.
It is aligned to Splunk HEC event metadata, Microsoft Sentinel DCR/custom table
ingestion, Google Security Operations UDM mapping, and the ServiceNow Table
API. Treat it as install content for the customer's SOC owner to import into
their tool.

The command center also supports posture segment lenses. `GET /api/posture`
returns a sanitized `segments` matrix for organization ids, SCIM identity
groups, workflow review queues, and sensor surfaces. Passing
`segment=<segment-id>` filters posture objectives, inventory, graph, trends,
and controls to that segment. Segment labels come only from deployment metadata;
prompt bodies, raw findings, file paths, and audit details are excluded.

| Setting | Purpose |
| --- | --- |
| `SIEM_WEBHOOK_URL` | HTTPS-only SOC/SIEM webhook for sanitized security and posture events. |
| `SIEM_WEBHOOK_TOKEN` | Optional bearer token sent to the webhook. |
| `SIEM_ALERT_MIN_RISK` | Minimum risk score for non-blocking security-event alerts. |
| `SIEM_ALERT_MIN_SEVERITY` | Minimum detector severity for non-blocking security-event alerts. |
| `SIEM_POSTURE_FEED_ENABLED` | Enables automatic posture snapshot subscription delivery when `true`. |
| `SIEM_POSTURE_MIN_INTERVAL_MS` | Minimum interval between changed posture-feed attempts. Defaults to five minutes. |

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
| `PROMPTWALL_APPROVAL_TICKET_WEBHOOK_URL` or `APPROVAL_TICKET_WEBHOOK_URL` | Sanitized ticket bridge webhook for Jira, Linear, ServiceNow, SOAR, or internal ticketing middleware. |
| `PROMPTWALL_APPROVAL_TICKET_WEBHOOK_TOKEN` or `APPROVAL_TICKET_WEBHOOK_TOKEN` | Optional bearer token for the ticket bridge. |
| `PROMPTWALL_APPROVAL_TICKET_SYSTEM` or `APPROVAL_TICKET_SYSTEM` | Optional system label such as `jira`, `linear`, `servicenow`, or `generic`. |
| `PROMPTWALL_APPROVAL_TICKET_PROJECT` or `APPROVAL_TICKET_PROJECT` | Optional project or queue key passed to the ticket bridge. |
| `PROMPTWALL_APPROVAL_TICKET_ISSUE_TYPE` or `APPROVAL_TICKET_ISSUE_TYPE` | Optional issue type; defaults to `Security Review`. |
| `PROMPTWALL_APPROVAL_JIRA_BASE_URL` or `APPROVAL_JIRA_BASE_URL` | Optional Jira Cloud base URL for direct sanitized issue creation. |
| `PROMPTWALL_APPROVAL_JIRA_EMAIL` or `APPROVAL_JIRA_EMAIL` | Jira account email used with an API token. |
| `PROMPTWALL_APPROVAL_JIRA_API_TOKEN` or `APPROVAL_JIRA_API_TOKEN` | Jira API token; keep in deployment secrets. |
| `PROMPTWALL_APPROVAL_JIRA_PROJECT_KEY` or `APPROVAL_JIRA_PROJECT_KEY` | Jira project key for approval workflow issues. |
| `PROMPTWALL_APPROVAL_JIRA_ISSUE_TYPE` or `APPROVAL_JIRA_ISSUE_TYPE` | Jira issue type, defaulting to `Task`. |
| `PROMPTWALL_APPROVAL_LINEAR_API_KEY` or `APPROVAL_LINEAR_API_KEY` | Optional Linear API key for direct sanitized issue creation. |
| `PROMPTWALL_APPROVAL_LINEAR_TEAM_ID` or `APPROVAL_LINEAR_TEAM_ID` | Linear team id for approval workflow issues. |
| `PROMPTWALL_APPROVAL_LINEAR_STATE_ID` or `APPROVAL_LINEAR_STATE_ID` | Optional Linear state id. |
| `PROMPTWALL_APPROVAL_LINEAR_PROJECT_ID` or `APPROVAL_LINEAR_PROJECT_ID` | Optional Linear project id. |
| `PROMPTWALL_APPROVAL_LINEAR_LABEL_IDS` or `APPROVAL_LINEAR_LABEL_IDS` | Optional comma-separated Linear label ids. |
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
file bytes. Ticket bridge payloads add a deterministic `dedupeKey`, ticket
system/project metadata, priority, and the same sanitized routing fields so a
customer bridge can create Jira, Linear, ServiceNow, or SOAR tickets without
receiving prompt bodies. Native Jira and Linear adapters create issues directly
from the same sanitized summary and description when customers do not want to
operate middleware. SMTP email uses the same sanitized routing fields as the
webhook payload and strips mail-header newlines before delivery.

Delivery is best-effort. PromptWall records `notificationStatus`,
`notificationLastAttemptAt`, `notificationAttemptCount`, and bounded channel
names on the query, then writes an audit event such as
`APPROVAL_NOTIFICATION_SENT` or `APPROVAL_NOTIFICATION_FAILED`. Webhook URLs,
ticket bridge tokens, Jira API tokens, Linear API keys, SMTP credentials, and
reviewer distribution lists are operational secrets; do not commit them to
policy files, `.env.example`, docs with real values, or support tickets.
Webhook-style URLs and native Jira/Linear API URLs must be `https://` and must
not include URL username or password credentials. SMTP
requires TLS by default. Use the insecure relay opt-in only for a trusted local
mail relay inside the customer network.

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

Proxy, firewall, SSE, and browser-isolation products can import sanitized AI
asset sightings with `POST /api/v1/discovery`. The endpoint uses the same
`x-api-key` sensor boundary as other `/api/v1/*` routes and accepts only
host-style destinations such as `perplexity.ai` or `*.example-ai.com`, plus
bounded observation counts and timestamps. Do not send prompt text, full URLs,
URL paths, file paths, request payloads, or log samples. The server rejects raw
URL paths and unknown fields, stores `[AI discovery import] <host>` as the
evidence label, and rolls the observation count into Coverage, Posture, and the
AI Control Graph.

Use the local importer when a customer hands you CSV or JSON exports from
Zscaler, Netskope, Microsoft Purview, a firewall, or a secure web gateway. It
normalizes common destination/user/count/timestamp columns, strips URL paths
locally, aggregates repeated observations, and posts only sanitized host-level
sightings:

```powershell
$env:INGEST_API_KEY = '<sensor-ingest-key>'
npm run discovery:import -- --input .\proxy-ai-export.csv --vendor zscaler --dry-run
npm run discovery:import -- --input .\proxy-ai-export.csv --vendor zscaler --sentinel-url http://localhost:4000
```

Prefer `--dry-run` first. Dry-run output lists only host names and counts, never
raw URLs, prompt text, file paths, or request payloads.

## AI LLM Gateway

Use the enforced AI LLM Gateway for private apps and internal agents that can
point at a local OpenAI-compatible, Anthropic Messages, or Gemini
`generateContent` endpoint. The gateway requires a client token, keeps provider
API keys on the gateway host, gates prompts through PromptWall before upstream
traffic, scans model responses before release, and fails closed when required
inspection is unavailable.

For a single local worker:

```powershell
$env:PROMPTWALL_GATEWAY_TOKEN = '<client-token>'
$env:PROMPTWALL_GATEWAY_UPSTREAM_API_KEY = '<provider-key>'
node scripts/ai-llm-gateway.js --sentinel http://127.0.0.1:4000 --upstream https://api.openai.com --port 4182
```

For direct Amazon Bedrock Runtime, configure SigV4 signing on the gateway host
and keep AWS credentials out of caller requests:

```powershell
$env:PROMPTWALL_GATEWAY_TOKEN = '<client-token>'
$env:AWS_ACCESS_KEY_ID = '<bedrock-runtime-access-key>'
$env:AWS_SECRET_ACCESS_KEY = '<bedrock-runtime-secret-key>'
$env:AWS_SESSION_TOKEN = '<optional-session-token>'
node scripts/ai-llm-gateway.js --sentinel http://127.0.0.1:4000 --upstream https://bedrock-runtime.us-east-1.amazonaws.com --upstream-auth-scheme aws-sigv4 --aws-region us-east-1 --allowed-models 'anthropic.claude-*,amazon.nova-*'
```

Supported Bedrock paths are `/model/{modelId}/converse`,
`/model/{modelId}/converse-stream`, `/model/{modelId}/invoke`, and
`/model/{modelId}/invoke-with-response-stream`. PromptWall inspects text
content blocks and blocks Bedrock image/document/video/tool blocks by default
because those bytes are not locally inspected by this gateway.

For multiple gateway workers or hosts, start the shared limiter service first:

```powershell
$env:PROMPTWALL_RATE_LIMITER_TOKEN = '<shared-limiter-token>'
$env:PROMPTWALL_RATE_LIMITER_DB = 'C:\PromptWall\data\gateway-shared-rate-limiter.db'
npm run gateway:rate-limiter -- --host 127.0.0.1 --port 4183
```

Then point each gateway at it:

```powershell
$env:PROMPTWALL_GATEWAY_RATE_LIMIT_STORE = 'http'
$env:PROMPTWALL_GATEWAY_RATE_LIMIT_URL = 'http://127.0.0.1:4183/check'
$env:PROMPTWALL_GATEWAY_RATE_LIMIT_TOKEN = '<shared-limiter-token>'
node scripts/ai-llm-gateway.js --sentinel http://127.0.0.1:4000 --upstream https://api.openai.com --port 4182
```

For a pilot HA gateway layer, run the dedicated compose stack:

```powershell
$env:PROMPTWALL_GATEWAY_TOKEN = '<client-token>'
$env:PROMPTWALL_RATE_LIMITER_TOKEN = '<shared-limiter-token>'
$env:INGEST_API_KEY = '<sensor-ingest-key>'
$env:PROMPTWALL_GATEWAY_UPSTREAM_API_KEY = '<provider-key>'
docker compose -f docker-compose.gateway-ha.yml up -d --build
Invoke-RestMethod http://127.0.0.1:4182/readyz
npm run gateway:ha:smoke
```

`docker-compose.gateway-ha.yml` publishes only the gateway load balancer,
keeps the limiter private, persists hashed limiter counters in
`gateway-limiter-data`, disables load-balancer access logs, and uses the same
read-only/no-new-privileges container posture as the main PromptWall compose
path.

When a pilot needs active-active limiter replicas, use a managed Redis or Valkey
backend and scale the private limiter service:

```powershell
$env:PROMPTWALL_RATE_LIMITER_STORE = 'redis'
$env:PROMPTWALL_RATE_LIMITER_REDIS_URL = 'rediss://:<password>@redis.internal.example:6380/0'
docker compose -f docker-compose.gateway-ha.yml up -d --build --scale ai-gateway-limiter=2
Invoke-RestMethod http://127.0.0.1:4182/readyz
```

The Redis backend stores only prefixed SHA-256 limiter keys with TTLs. Do not
put raw gateway client tokens, user ids, prompts, destinations, or model output
in the Redis key prefix.

The shared limiter receives only SHA-256 gateway-client limiter keys, requested
limits, windows, and timestamps. It does not receive raw client tokens, prompts,
users, destinations, or model output. Check `/healthz` and `/readyz` on both the
gateway and limiter before routing traffic. See `docs/AI_LLM_GATEWAY.md` for
provider-specific headers, model allowlists, and streaming behavior.

Security Admins can also edit `blockedFileUploadDestinations` when a customer
wants chat allowed but document upload forbidden for a destination. Browser
uploads report `file_upload_blocked` through `/api/v1/gate` before local file
bytes are read. Endpoint file flows and `/api/v1/scan-file` also return
`file_upload_blocked` before uploaded bytes, extracted text, or sensitive
filenames are retained.

Security Admins can edit `blockedBrowserActions` for destination-scoped browser
action blocks. Supported actions are `paste`, `drop`, `copy`, and `download`:
when a configured destination matches, the browser prevents clipboard paste
before text lands in the composer, prevents drag-and-drop file uploads before
the file is read, prevents copying AI response content from the page, or cancels
downloads attributed to that AI destination. These paths report only sanitized
`action_blocked` evidence. Download blocks record host-only attribution and do
not report raw filenames, file bytes, MIME types, or download URLs. The
extension only tells the user that a local browser block was recorded after
`/api/v1/gate` returns the expected evidence id and status. If the control plane
is unreachable, the browser action still stays blocked and the toast says
evidence was not recorded yet.

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

Sensors or proxy bridges that poll `/api/v1/status/:id` for a held prompt, or
call `/api/v1/rehydrate` for a tokenized response, must send the
`x-release-token` header returned by the original gate or file-scan response.
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

## Postgres Control Plane (Scale-Out)

The default store is SQLite on local disk - right for a single-node
customer-silo stack. For a shared or highly available control plane, the same
synchronous storage interface runs on Postgres:

```
SENTINEL_DB_DRIVER=postgres
SENTINEL_DATABASE_URL=postgresql://promptwall_app@db.internal:5432/promptwall
```

For the full operator runbook — application-role setup, migration workflow,
statement-timeout/retry tuning, Postgres-mode `npm run backup` /
`npm run backup:drill`, monitoring, and sizing — see `docs/MANAGED_POSTGRES.md`.

What you get on the Postgres driver:

- **Schema migrations apply automatically on startup** (both drivers share one
  ordered migration history; `schema_migrations` records what ran).
- **Append-only audit is enforced in the database** - `UPDATE`/`DELETE` on the
  audit table raise, and the hash chain still verifies end to end.
- **Row-level tenant isolation**: the `queries` table carries an indexed
  `orgId` column with `FORCE ROW LEVEL SECURITY`; setting the
  `promptwall.org_id` session context confines reads and writes to one tenant.
  Run the application as a NON-superuser role (superusers bypass RLS).
- **Multiple control-plane replicas** can share one Postgres; set the same
  `SENTINEL_SECRET` on every instance so sessions and receipts stay valid
  across replicas, and put the replicas behind your load balancer.

Backups on Postgres work through the same tooling as SQLite: `npm run backup`
drives `pg_dump` (custom format) when the store runs on the Postgres driver,
and `npm run backup:drill` verifies a restore into a scratch database — see
`docs/MANAGED_POSTGRES.md`. Managed-provider snapshots/PITR remain a good
complement. After restoring any Postgres backup, `node -e
"console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"`
must report `ok: true` before the restored plane serves traffic.

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

### Scheduled Backups

Install a recurring backup with retention pruning. On Windows, register a
scheduled task (defaults: daily at 2:00 AM, `backups/` under the repo,
30-day retention):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-backup-task.ps1 `
  -Cadence Daily -At '2:00 AM' -BackupDir 'D:\promptwall-backups' -RetentionDays 30
```

Remove it with the same script and `-Uninstall`.

On Linux, install a systemd service + timer pair (`promptwall-backup.timer`).
`npm` mode runs `npm run backup` from a repo checkout; `docker` mode runs the
backup inside the customer-silo container against the `/data` mount:

```bash
sudo bash scripts/install-backup-systemd.sh --mode npm \
  --project-dir /opt/promptwall --backup-dir /var/backups/promptwall \
  --retention-days 30 --on-calendar daily
```

Remove it with `sudo bash scripts/install-backup-systemd.sh --uninstall`. Both
installers prune backups older than the retention window only after a
successful backup, so a failing backup never deletes the last good copies.
Point the backup directory at local disk that your existing encrypted backup
tooling then ships off-host; the `.db` files are sensitive runtime state.

### Disaster-Recovery Drill

Run the one-command restore drill on a schedule (quarterly at minimum, and
after any storage or host change):

```bash
npm run backup:drill
```

The drill creates a fresh backup, verifies the manifest hash, restores the
backup to a scratch path, re-opens the restored database read-only, and
checks that the restored audit hash-chain verifies and that the restored row
counts match the manifest. It prints a prompt-free JSON report (hashes,
counts, and PASS/FAIL checks only) and exits non-zero on any mismatch — wire
it into monitoring so a failed drill pages someone. Use
`-- --backup-dir <dir>` to run the drill against a specific backup location
and `-- --keep` to retain the drill backup and restored copy for inspection;
without `--keep` the drill removes everything it created.

A passing drill proves the backup path works end to end: the live store's
audit chain is intact, the backup is byte-identical to what the manifest
recorded, and a restore of that backup yields a database whose evidence and
tamper-evident chain still verify.

### What Backups Do Not Cover

The backup and drill cover only the SQLite evidence store. A full
disaster-recovery kit must also capture, through your configuration
management or secret manager:

- `.env` secrets — above all `SENTINEL_DATA_KEY` / `SENTINEL_SECRET`
  (without them, sealed raw prompts in a restored store cannot be revealed),
  plus `ADMIN_PASSWORD`, `INGEST_API_KEY`, and any SCIM/OIDC credentials.
- The policy file (`config/policy.json` or the `SENTINEL_POLICY_PATH`
  target) and custom detectors (`SENTINEL_CUSTOM_DETECTORS_PATH`).
- Other `config/` artifacts such as `evidence-schedule.json`.

Store those artifacts alongside the `.db` backups and include them when you
rehearse the restore.

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
