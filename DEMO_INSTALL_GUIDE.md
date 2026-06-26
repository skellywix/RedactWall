# PromptSentinel Demo Install Guide

This guide is for running a clean client demo of PromptSentinel on a laptop or demo workstation. It covers the control plane, browser extension, file scanning path, endpoint agent, policy modes, reset steps, and the exact demo flow to show a regulated buyer.

Use synthetic data only. Do not paste real member, patient, cardholder, customer, employee, source code, or contract data into a demo.

## What The Demo Shows

PromptSentinel is a local safety layer for AI tools. The demo should prove five things:

1. Sensitive data is detected before it leaves the browser or device.
2. The same detection engine is shared by the browser extension, endpoint agent, MCP guard, and server.
3. Policy can warn, require justification, redact, or block.
4. Blocked prompts enter an admin approval queue.
5. The audit log is tamper-evident and suitable for examiner conversations.

For a client meeting, the strongest story is:

1. Start in block mode.
2. Paste a fake SSN into ChatGPT or Claude.
3. Show that PromptSentinel blocks the send before the prompt leaves the page.
4. Open the admin dashboard and show the blocked event.
5. Switch to redact mode.
6. Paste a fake credit card or fake member account prompt.
7. Show that the extension replaces sensitive values with tokens before sending.
8. Show file upload scanning by dropping a synthetic `.txt`, `.docx`, or `.pdf` file with fake sensitive data.
9. End on the audit view and policy templates.

## Demo Machine Requirements

Recommended:

- Windows 11, macOS, or Linux.
- Node.js 22 or newer.
- npm, included with normal Node.js installs.
- Google Chrome or Chromium.
- Git, if installing from a repository clone.
- Optional: Docker Desktop for container demos.

Why these requirements matter:

- The app uses `node --test`, built-in `fetch`, and native `better-sqlite3`.
- The browser sensor is a Chrome Manifest V3 extension.
- The local database is SQLite and should live on local disk, not a cloud-synced folder.
- Docker is optional. Native Node is faster for demos because extension and policy changes are easy to inspect.

## Folder Layout

Run commands from the project folder:

```powershell
cd C:\Users\Eric\Desktop\Coding_Projects\promptsentinel-app\promptsentinel
```

Important folders:

```text
server.js                 Control plane and API
public/                   Admin dashboard
extension/                Chrome extension
endpoint-agent/           Local file sensor demo
mcp-guard/                MCP tool-output redaction demo
shared/detect.js          Shared detection engine
config/policy.json        Demo policy
data/                     Runtime database and secrets, created automatically
```

`data/` is runtime state. It is ignored by Git and safe to delete when resetting a demo.

## Pre-Demo Cleanup

Before a client demo, start from a clean local runtime state:

```powershell
$serverPid = (Get-NetTCPConnection -LocalPort 4000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }
Remove-Item -LiteralPath .\data -Recurse -Force -ErrorAction SilentlyContinue
```

Then confirm the working tree has no unrelated runtime files:

```powershell
git status --short
git ls-files --others --ignored --exclude-standard | Select-Object -First 40
```

It is normal for `node_modules/` to appear as ignored if dependencies are installed. It is not source code and should not be committed.

## Run Setup

Run the project setup command:

```powershell
npm run setup
```

This installs dependencies from `package-lock.json`, writes `.env` with stable demo secrets, initializes the SQLite store, and runs deployment preflight.

If you also need browser E2E test dependencies on the demo machine:

```powershell
npm run setup -- --with-browser
```

For production-style setup, use:

```powershell
npm run setup:prod
```

## Configure Demo Secrets

`npm run setup` already writes non-default demo secrets into `.env`. If you want temporary shell-only values for a one-off demo, use the commands below.

In PowerShell:

```powershell
$env:PORT = "4000"
$env:ADMIN_USER = "admin"
$env:ADMIN_PASSWORD = "DemoOnly!2026"
$env:SENTINEL_SECRET = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
$env:SENTINEL_DATA_KEY = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
$env:INGEST_API_KEY = "demo-ingest-key"
```

For macOS or Linux:

```bash
export PORT=4000
export ADMIN_USER=admin
export ADMIN_PASSWORD='DemoOnly!2026'
export SENTINEL_SECRET="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
export SENTINEL_DATA_KEY="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
export INGEST_API_KEY=demo-ingest-key
```

Notes:

- Keep `SENTINEL_SECRET` stable for the length of the demo so admin sessions remain valid.
- Keep `SENTINEL_DATA_KEY` stable for the length of the demo so sealed approval records can be revealed.
- For a one-off localhost demo, in-memory shell variables are fine.
- For a longer pilot, copy `.env.example` to `.env` and store stable values there.

## Run The Control Plane

Start the server:

```powershell
npm start
```

Expected output:

```text
PromptSentinel running on http://localhost:4000
Raw-prompt retention: encrypted at rest (AES-256-GCM), held items only; finalized records purge after 30 day(s).
Ingest key: configured
```

Open:

```text
http://localhost:4000
```

Log in with:

```text
Username: admin
Password: DemoOnly!2026
```

Health checks:

```powershell
Invoke-RestMethod http://localhost:4000/healthz
Invoke-RestMethod http://localhost:4000/readyz
```

For a pilot or production dry run, set `NODE_ENV=production` only after replacing the default admin password, ingest key, session secret, data key, and secure-cookie settings. PromptSentinel will refuse production startup when those preflight checks fail.

## Load The Chrome Extension

For a local demo:

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Turn on Developer mode.
4. Click Load unpacked.
5. Select the `extension/` folder from this repository.
6. Pin the PromptSentinel extension.
7. Open the extension popup and confirm it says the browser is protected.

The extension defaults to:

```text
Server URL: http://localhost:4000
Ingest key: dev-ingest-key
```

If you changed `INGEST_API_KEY` to `demo-ingest-key`, set the extension's local storage value before demoing the browser flow:

1. On `chrome://extensions`, open PromptSentinel details.
2. Click service worker Inspect views.
3. In the console, run:

```javascript
chrome.storage.local.set({ ingestKey: "demo-ingest-key", serverUrl: "http://localhost:4000", enabled: true });
```

Refresh ChatGPT, Claude, Gemini, Copilot, or Perplexity after changing extension storage.

For a real pilot, use Chrome managed storage or extension policy to set `serverUrl`, `ingestKey`, `user`, `email`, and `orgId` centrally. Do not ask users to type ingest keys by hand.

Managed deployment examples live in:

```text
docs/MANAGED_EXTENSION_DEPLOYMENT.md
docs/examples/chrome-managed-storage.policy.json
docs/examples/chrome-extension-settings.example.json
```

## Configure Demo Policy

The default policy is block mode:

```json
{
  "enforcementMode": "block",
  "blockRiskScore": 20,
  "storeRawForApproval": true
}
```

Use the dashboard Policy tab for the demo. The browser extension refreshes policy automatically and caches the current setting.

Recommended sequence:

1. Start with `block`.
2. Show `warn`.
3. Show `justify`.
4. End with `redact` because it is the most client-friendly path for productivity.

Policy modes:

| Mode | What The Client Sees | Best Demo Prompt |
| --- | --- | --- |
| `block` | Prompt is stopped and can be sent to admin approval | Fake SSN or credit card |
| `warn` | User can choose to continue | Fake phone or email |
| `justify` | User must enter a business reason | Fake member address |
| `redact` | Values are tokenized before send | Fake card or SSN |

Hard-stop entities, such as SSNs, cards, bank accounts, routing numbers, passports, secrets, and private keys, remain strict. In redact mode they are tokenized instead of sent raw.

## Demo Script: Browser Extension

Open ChatGPT or Claude in Chrome. Use only synthetic examples.

### Demo 1: Benign Prompt Allows

Paste:

```text
Summarize this public blog post into three bullet points.
```

Expected:

- No block banner.
- Dashboard records an allowed low-risk event if reporting is enabled.

### Demo 2: Fake SSN Blocks

Paste:

```text
Draft a denial letter for member John Carter, SSN 524-71-9043, who applied for an auto loan.
```

Expected:

- PromptSentinel blocks before send.
- The page shows a PromptSentinel banner.
- The dashboard shows a pending item.
- Findings show `US_SSN` and possibly `PERSON_NAME`.
- The raw prompt is only retained for held approval items, only when encrypted retention is enabled, and purged from finalized records after `rawRetentionDays`.

Client talk track:

```text
This is the moment the leak normally happens. PromptSentinel stops it before the user sends it to the AI tool.
```

### Demo 3: Request Approval

In the block banner:

1. Click Request approval.
2. Open the dashboard.
3. Find the pending event.
4. Show masked findings and redacted prompt.
5. Approve or deny the event.

Expected:

- Approval and denial actions are audit logged.
- The event remains part of the hash-chained audit history.

### Demo 4: Justification Mode

Switch policy to `justify`.

Paste:

```text
Member Sarah Jones at 482 Oakwood Drive, phone 415-555-0182, needs a payoff letter.
```

Expected:

- User must type a business reason.
- The reason is recorded.
- The dashboard shows the event as justified.

Client talk track:

```text
This mode is useful when the institution wants accountability without blocking every workflow.
```

### Demo 5: Redact And Send

Switch policy to `redact`.

Paste:

```text
Help me summarize this dispute: card 4111 1111 1111 1111 was charged twice on 09/27.
```

Expected:

- The extension replaces the card number with a token before send.
- The AI tool receives the tokenized prompt.
- The local page can rehydrate tokenized responses for the user.
- The server receives metadata and tokenized text, not raw card data.

Client talk track:

```text
This is the productivity mode. The employee still gets help, but the model does not receive the sensitive value.
```

### Demo 6: Category-Only Confidential Business Content

Still in redact mode, paste:

```text
Between us, we are switching away from our core processor next quarter. Keep this internal and do not forward.
```

Expected:

- PromptSentinel blocks or holds the prompt.
- It does not send category-only confidential content raw because there is no structured value to tokenize.

Client talk track:

```text
Keyword filters miss this kind of business context. PromptSentinel treats it as sensitive even without an SSN or card number.
```

### Demo 7: Canary Token Tripwire

Paste:

```text
This fake member record contains PS-CANARY-DEMO2026ABCDEF and should never leave the institution.
```

Expected:

- PromptSentinel detects `CANARY_TOKEN`.
- The event is treated as critical.
- Alerts and evidence exports show the canary finding as masked metadata only.

Client talk track:

```text
This is a planted tripwire. A credit union can put canaries in fake records, test documents, or internal demo data. If one shows up in an AI prompt, the control proves it caught a path that should not exist.
```

After showing the manual paste, run the automated control fire drill:

```powershell
npm run fire-drill -- http://localhost:4000
```

Expected:

```text
FIRE_DRILL_OK ...
```

## Demo Script: File Upload Scanning

Create a synthetic file:

```powershell
New-Item -ItemType Directory -Force .\demo-files | Out-Null
Set-Content -LiteralPath .\demo-files\loan-summary.txt -Value "Loan file for member Jane Carter. SSN 524-71-9043. Card 4111 1111 1111 1111."
```

In ChatGPT or Claude:

1. Drag `demo-files\loan-summary.txt` into the chat composer.
2. PromptSentinel intercepts the upload attempt.
3. The file is scanned by `/api/v1/scan-file`.
4. The upload is blocked if sensitive content is found.
5. The dashboard records the event.

Expected:

- Sensitive file content is not silently uploaded.
- Supported files include text files, PDFs, Word, Excel, and PowerPoint formats.
- Unsupported files are blocked or recorded without uploading their bytes from the endpoint agent path.

For a PDF or Office demo, create a file with the same synthetic text and upload it through the browser. Keep it small and obvious.

## Demo Script: API And Proxy Path

With the server running, execute:

```powershell
npm run simulate -- http://localhost:4000
```

Expected output includes both `ALLOW` and `BLOCK` decisions:

```text
ALLOW  [risk   0] jdoe -> chatgpt.com
BLOCK  [risk  34] msmith -> claude.ai
BLOCK  [risk  30] kpatel -> gemini.google.com
```

Then open the dashboard and show:

- Allowed events.
- Pending blocked events.
- Findings and categories.
- Audit entries.
- Policy stats.

## Demo Script: Endpoint Agent

The endpoint agent watches a folder and scans files headed toward desktop AI apps.

Create a watched folder:

```powershell
New-Item -ItemType Directory -Force .\demo-watch | Out-Null
```

Start the agent in a second terminal:

```powershell
$env:SENTINEL_URL = "http://localhost:4000"
$env:INGEST_API_KEY = "demo-ingest-key"
node endpoint-agent\agent.js .\demo-watch
```

For a longer Windows pilot, install it as a logon task instead of leaving a terminal open:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -SentinelUrl "http://localhost:4000" `
  -IngestKey "demo-ingest-key" `
  -WatchDir "$env:USERPROFILE\PromptSentinelWatch"
```

Uninstall with:

```powershell
.\scripts\uninstall-endpoint-agent.ps1
```

Drop a synthetic file into the watched folder. The scheduled-task example above watches:

```text
%USERPROFILE%\PromptSentinelWatch
```

For the cleanest demo, create that folder and copy a synthetic file into it:

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\PromptSentinelWatch" | Out-Null
Copy-Item .\demo-files\loan-summary.txt "$env:USERPROFILE\PromptSentinelWatch\loan-summary.txt"
```

Expected:

- The agent scans the file.
- Sensitive supported files are sent to `/api/v1/scan-file`.
- Unsupported files are blocked locally and recorded without uploading their bytes.
- The dashboard records the result.

## Demo Script: MCP Guard

The MCP guard demonstrates the agent workflow problem: a tool retrieves sensitive data before the model sees it.

Run:

```powershell
node mcp-guard\guard.js
```

Expected:

- Structured PII is redacted.
- Category-only confidential content is whole-chunk redacted.
- The model-facing text is safe.

Client talk track:

```text
Browser controls are not enough. AI agents can pull data from tools. The MCP guard applies the same detection engine before tool output reaches the model.
```

## Admin Dashboard Tour

Show these areas in order:

1. Activity or queue view.
2. A blocked prompt with masked findings.
3. Approve and deny controls.
4. Policy mode selector.
5. Regulation templates.
6. Audit log.
7. Metrics or risk view.
8. Evidence export endpoint for examiner packets.

Key points:

- Most prompt text does not need to leave the device.
- Server records should use redacted prompts and masked findings.
- Held approval items can retain encrypted raw text if the institution allows it.
- Raw reveal is explicit and audit logged.
- Audit integrity can be checked with one command.
- Evidence exports contain policy, detector inventory, stats, audit integrity, query metadata, masked findings, and audit hashes, but not prompt bodies or audit detail text.

Export a demo evidence pack by logging into the dashboard first, then visiting:

```text
http://localhost:4000/api/export/evidence
```

## Verify The Demo Before Clients Arrive

Run:

```powershell
npm test
npm run sync-check
node -e "console.log(JSON.stringify(require('./src/db').verifyAuditChain()))"
```

Expected:

```text
tests pass
engine copies identical
{"ok":true,...}
```

If `npm run simulate` is part of the demo, run it once after the server starts:

```powershell
npm run simulate -- http://localhost:4000
```

Then reset the demo data if you want the dashboard clean:

```powershell
$serverPid = (Get-NetTCPConnection -LocalPort 4000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }
Remove-Item -LiteralPath .\data -Recurse -Force -ErrorAction SilentlyContinue
npm start
```

## Optional Docker Demo

Build:

```powershell
docker build -t promptsentinel-demo .
```

Run:

```powershell
docker run --rm --name promptsentinel-demo -p 4000:4000 `
  -e ADMIN_USER=admin `
  -e ADMIN_PASSWORD=DemoOnly!2026 `
  -e SENTINEL_SECRET=demo-session-secret-change-me `
  -e SENTINEL_DATA_KEY=demo-data-key-change-me `
  -e INGEST_API_KEY=demo-ingest-key `
  -v promptsentinel-demo-data:/data `
  promptsentinel-demo
```

Open:

```text
http://localhost:4000
```

Docker is useful when you want a self-contained server. Native Node is better when demoing code changes, local SQLite files, and extension behavior.

## Reset Or Tear Down

Stop server:

```powershell
$serverPid = (Get-NetTCPConnection -LocalPort 4000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }
```

Delete runtime state:

```powershell
Remove-Item -LiteralPath .\data -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\demo-files -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\demo-watch -Recurse -Force -ErrorAction SilentlyContinue
```

Reset the Chrome extension:

1. Go to `chrome://extensions`.
2. Remove PromptSentinel.
3. Load unpacked again if needed.

Remove Docker state:

```powershell
docker rm -f promptsentinel-demo 2>$null
docker volume rm promptsentinel-demo-data 2>$null
```

## Troubleshooting

### Dashboard Does Not Open

Check server health:

```powershell
Invoke-RestMethod http://localhost:4000/healthz
```

If the port is occupied:

```powershell
netstat -ano | findstr :4000
```

Either stop the conflicting process or choose another port:

```powershell
$env:PORT = "4100"
npm start
```

If you use a non-default port, update extension storage:

```javascript
chrome.storage.local.set({ serverUrl: "http://localhost:4100" });
```

### Extension Does Not Block

Check:

- Chrome Developer mode is on.
- The loaded folder is exactly `extension/`.
- The extension popup says protecting this browser.
- The AI site tab was refreshed after loading the extension.
- The site is in `extension/manifest.json` host permissions.
- The server URL and ingest key match the server.

### Dashboard Shows 401 For Sensor Events

The ingest key does not match.

Server:

```powershell
$env:INGEST_API_KEY = "demo-ingest-key"
npm start
```

Extension service worker console:

```javascript
chrome.storage.local.set({ ingestKey: "demo-ingest-key" });
```

### Native SQLite Install Fails

`better-sqlite3` is a native package. Use Node.js 22 or newer and run:

```powershell
npm run setup
```

If the local machine cannot build native packages, use Docker for the server demo.

### Audit Chain Fails

Run:

```powershell
node -e "console.log(JSON.stringify(require('./src/db').verifyAuditChain(), null, 2))"
```

For a demo machine, the simplest fix is to reset runtime data:

```powershell
$serverPid = (Get-NetTCPConnection -LocalPort 4000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }
Remove-Item -LiteralPath .\data -Recurse -Force -ErrorAction SilentlyContinue
npm start
```

Do not do this on a real pilot without exporting or preserving evidence first.

## Client Demo Checklist

Before the meeting:

- Setup completed with `npm run setup`.
- Server starts on `http://localhost:4000`.
- Admin password is not the default.
- `.env` contains `SENTINEL_SECRET`, `SENTINEL_DATA_KEY`, and `INGEST_API_KEY`.
- Chrome extension is loaded and pinned.
- Extension storage points to the right server and ingest key.
- Policy starts in `block`.
- Synthetic demo files are ready.
- No real customer data is on the demo machine.
- `npm test` passes.
- `npm run sync-check` passes.
- Audit chain verifies.

During the meeting:

- Say what PromptSentinel stops before showing the UI.
- Use synthetic examples only.
- Show a benign prompt first.
- Show a block.
- Show approval queue and audit.
- Show justification.
- Show redact mode last.
- Show file scanning.
- Tie the demo back to examiner evidence.

After the meeting:

- Stop the server.
- Delete demo runtime data if the machine is shared.
- Remove the unpacked extension if it was installed on a client-owned machine.

## Production Pilot Notes

This demo is not a full production rollout. For a client pilot, plan these before deployment:

- HTTPS and a stable server hostname.
- Non-default admin credentials.
- SSO or MFA for admins.
- Stable `SENTINEL_SECRET`, `SENTINEL_DATA_KEY`, and `INGEST_API_KEY`.
- Local-disk database storage or a managed database migration.
- Managed Chrome extension deployment.
- Employee notice and authorization.
- Log retention policy.
- Raw approval-data retention window in `rawRetentionDays`.
- Incident response workflow for blocked prompts.
- SIEM or email alerting for critical events.
- Backup and restore procedure for audit evidence.

The compliance story is strongest when the demo maps product behavior to controls:

- Access control for admin console and approval actions.
- Audit and accountability through tamper-evident event logs.
- Data minimization through local detection and redacted records.
- Encryption at rest for retained raw approval items.
- Policy enforcement before prompts reach external AI tools.

## Works Cited

Docker. "Docker Build Overview." *Docker Docs*, Docker, https://docs.docker.com/build/. Accessed 26 June 2026.

Federal Trade Commission. "FTC Safeguards Rule: What Your Business Needs to Know." *Federal Trade Commission*, https://www.ftc.gov/business-guidance/resources/ftc-safeguards-rule-what-your-business-needs-know. Accessed 26 June 2026.

Google. "Hello World Extension." *Chrome for Developers*, https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world. Accessed 26 June 2026.

National Credit Union Administration. "Cybersecurity Resources." *NCUA*, https://ncua.gov/regulation-supervision/cybersecurity-resources. Accessed 26 June 2026.

National Institute of Standards and Technology. "Security and Privacy Controls for Information Systems and Organizations." *NIST Special Publication 800-53, Revision 5*, National Institute of Standards and Technology, https://csrc.nist.gov/pubs/sp/800/53/r5/final. Accessed 26 June 2026.

Node.js. "Download Node.js." *Node.js*, OpenJS Foundation, https://nodejs.org/en/download. Accessed 26 June 2026.

PCI Security Standards Council. "PCI DSS." *PCI Security Standards Council*, https://www.pcisecuritystandards.org/standards/pci-dss/. Accessed 26 June 2026.
