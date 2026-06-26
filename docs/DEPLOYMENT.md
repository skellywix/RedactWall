# PromptSentinel Deployment

PromptSentinel has two supported deployment paths:

1. Native Node.js for demos, pilots, and single-host installs.
2. Docker Compose for repeatable container installs.

Use synthetic data for setup checks. Do not seed real member, patient, cardholder, employee, or customer data into a demo.

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
2. Creates `.env` with stable admin, ingest, session, and data-encryption secrets.
3. Initializes `data/sentinel.db`.
4. Runs the same deployment preflight used by `/readyz`.

For production-safe defaults:

```bash
npm run setup:prod
npm start
```

Production mode expects TLS at the dashboard edge. If TLS is terminated by a reverse proxy, keep `COOKIE_SECURE=true` and serve the dashboard only over HTTPS.

To inspect an existing install without changing files:

```bash
npm run setup:check
```

## Docker Compose

Generate config first:

```bash
npm run setup:prod -- --skip-install
```

Then start the container:

```bash
docker compose up -d --build
```

The Compose file mounts a named volume at `/data` and overrides `SENTINEL_DB_PATH` to `/data/sentinel.db`, so the container keeps runtime state outside the image.

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
| `ADMIN_PASSWORD` | Security Admin console password. |
| `SENTINEL_SECRET` | Stable session-signing secret shared by all instances. |
| `SENTINEL_DATA_KEY` | Stable AES-256-GCM data key source for retained approval prompts. |
| `INGEST_API_KEY` | Sensor and proxy key for `/api/v1/*` ingest endpoints. |
| `SENTINEL_DB_PATH` | SQLite path on local persistent disk. |

Never bind `SENTINEL_DB_PATH` to a cloud-synced folder. SQLite locking must be backed by local disk semantics.

## Retention Operations

PromptSentinel retains raw approval prompts and token vaults only for records that need review or rehydration. Set `rawRetentionDays` in policy to define how long finalized `approved`, `denied`, and `redacted` records keep those sealed fields. The default is 30 days.

The server runs a retention purge on startup and then hourly. Security Admins can also run it from the Policy tab or with:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "https://promptsentinel.example.com/api/retention/purge" `
  -WebSession $adminSession `
  -Headers @{ "x-csrf-token" = $csrfToken }
```

Purge events keep the redacted metadata and hash-chained audit trail intact, and evidence exports show purge timestamps and the non-sensitive field names removed.

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
