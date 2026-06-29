# PromptWall Demo Technician Setup Guide

This guide is for the person preparing and operating a PromptWall demo machine.
It covers local setup, browser extension configuration, synthetic fixtures,
verification, reset, and troubleshooting.

Use synthetic data only. Do not use real member, patient, cardholder, customer,
employee, source code, contract, credential, or private business data.

The presenter-facing guide is `docs/SALES_DEMO_GUIDE.md`.

<!-- DEMO_GUIDE_CURRENT_STATE_START -->
## Current App Snapshot

This section is generated from the app by `npm run docs:demo-guide`. Do not hand-edit between the markers. Run `npm run docs:demo-guide:check` before a client demo and in the review gate so the demo guides move with the product.

| Source | Current value |
| --- | --- |
| App package | `promptwall@0.3.0` |
| Active repo folder | `promptwall` |
| Server entrypoint | `server/app.js` |
| Browser extension | `PromptWall - AI Data Guard` version `0.3.0` |
| Default enforcement mode | `block` |
| Block thresholds | severity `2`, risk score `20` |
| Raw approval retention | enabled for `30` day(s) |
| Governed destinations | `chatgpt.com`, `openai.com`, `claude.ai`, `anthropic.com`, `gemini.google.com`, `copilot.microsoft.com`, `perplexity.ai`, `poe.com`, `chat.deepseek.com`, `deepseek.com`, `chat.qwen.ai`, `qwen.ai`, `tongyi.aliyun.com`, `kimi.com`, `kimi.moonshot.cn`, `doubao.com`, `yuanbao.tencent.com`, `yiyan.baidu.com`, `ernie.baidu.com`, `chatglm.cn`, `z.ai` |
| Browser content hosts | `*.baichuan-ai.com`, `*.bigmodel.cn`, `*.blackbox.ai`, `*.bolt.new`, `*.character.ai`, `*.chatbot.theb.ai`, `*.chatglm.cn`, `*.chatsonic.com`, `*.cohere.com`, `*.copy.ai`, `*.cursor.com`, `*.deepseek.com`, `*.doubao.com`, `*.elevenlabs.io`, `*.flowith.io`, `*.genspark.ai`, `*.grammarly.com`, `*.grok.com`, `*.groq.com`, `*.hailuoai.com`, `*.huggingface.co`, `*.hunyuan.tencent.com`, `*.ideogram.ai`, `*.jasper.ai`, `*.kimi.com`, `*.krea.ai`, `*.lovable.dev`, `*.manus.im`, `*.metaso.cn`, `*.midjourney.com`, `*.minimax.io`, `*.mistral.ai`, `*.monica.im`, `*.moonshot.cn`, `*.notion.so`, `*.phind.com`, `*.pi.ai`, `*.quillbot.com`, `*.qwen.ai`, `*.replicate.com`, `*.replit.com`, `*.runwayml.com`, `*.suno.com`, `*.udio.com`, `*.v0.dev`, `*.wenxiaobai.com`, `*.windsurf.com`, `*.writesonic.com`, `*.x.ai`, `*.you.com`, `*.z.ai`, `ai.360.com`, `aistudio.google.com`, `baichuan-ai.com`, `bard.google.com`, `bigmodel.cn`, `bing.com`, `blackbox.ai`, `bolt.new`, `character.ai`, `chat.openai.com`, `chatbot.theb.ai`, `chatglm.cn`, `chatgpt.com`, `chatsonic.com`, `claude.ai`, `cohere.com`, `copilot.microsoft.com`, `copy.ai`, `cursor.com`, `deepseek.com`, `doubao.com`, `elevenlabs.io`, `ernie.baidu.com`, `flowith.io`, `gemini.google.com`, `genspark.ai`, `grammarly.com`, `grok.com`, `groq.com`, `hailuoai.com`, `huggingface.co`, `hunyuan.tencent.com`, `ideogram.ai`, `jasper.ai`, `kimi.com`, `krea.ai`, `lovable.dev`, `manus.im`, `meta.ai`, `metaso.cn`, `midjourney.com`, `minimax.io`, `mistral.ai`, `monica.im`, `moonshot.cn`, `notebooklm.google.com`, `notion.so`, `perplexity.ai`, `phind.com`, `pi.ai`, `poe.com`, `qianwen.aliyun.com`, `quillbot.com`, `qwen.ai`, `replicate.com`, `replit.com`, `runwayml.com`, `spark.xfyun.cn`, `suno.com`, `tiangong.kunlun.com`, `tongyi.aliyun.com`, `udio.com`, `v0.dev`, `wenxiaobai.com`, `windsurf.com`, `writesonic.com`, `www.bing.com`, `www.perplexity.ai`, `www.poe.com`, `x.ai`, `xinghuo.xfyun.cn`, `yiyan.baidu.com`, `you.com`, `yuanbao.tencent.com`, `z.ai` |
| Browser local control-plane permissions | `127.0.0.1`, `localhost`, `localhost:4000` |
| Hard-stop entities | `US_SSN`, `CREDIT_CARD`, `BANK_ACCOUNT`, `ROUTING_NUMBER`, `IBAN`, `US_PASSPORT`, `US_TIN_EIN`, `US_ITIN`, `US_NPI`, `US_DRIVERS_LICENSE`, `MEMBER_ID`, `LOAN_NUMBER`, `MEDICAL_RECORD_NUMBER`, `HEALTH_INSURANCE_ID`, `DOB`, `SECRET_KEY`, `PRIVATE_KEY`, `CANARY_TOKEN` |
| Detector inventory | 33 detectors: `BANK_ACCOUNT`, `CANARY_TOKEN`, `CONFIDENTIAL_BUSINESS`, `CREDENTIALS`, `CREDIT_CARD`, `DOB`, `EMAIL_ADDRESS`, `HEALTH_INSURANCE_ID`, `HEALTH_RECORD`, `IBAN`, `IPV6_ADDRESS`, `IP_ADDRESS`, `LEGAL_CONTRACT`, `LOAN_NUMBER`, `MEDICAL_RECORD_NUMBER`, `MEMBER_ID`, `PASSWORD`, `PERSON_NAME`, `PHONE_NUMBER`, `PRIVATE_KEY`, `ROUTING_NUMBER`, `SECRET_KEY`, `SOURCE_CODE`, `SWIFT_BIC`, `US_ADDRESS`, `US_DRIVERS_LICENSE`, `US_ITIN`, `US_LICENSE_PLATE`, `US_NPI`, `US_PASSPORT`, `US_SSN`, `US_TIN_EIN`, `VIN` |
| Semantic categories | `CONFIDENTIAL_BUSINESS`, `CREDENTIALS`, `LEGAL_CONTRACT`, `SOURCE_CODE` |
| Policy templates | `baseline (Baseline (recommended start))`, `hipaa (HIPAA (PHI))`, `ncua_glba (NCUA / GLBA (credit unions, banks))`, `pci_dss (PCI-DSS (cardholder data))`, `redact_first (Redact-first (productivity))` |

### Supported File Demo Types

- Text and config: `.conf`, `.csv`, `.eml`, `.env`, `.htm`, `.html`, `.ini`, `.java`, `.js`, `.json`, `.log`, `.md`, `.py`, `.rtf`, `.sql`, `.ts`, `.tsv`, `.txt`, `.xml`, `.yaml`, `.yml`
- Office: `.docx`, `.pptx`, `.xlsx`
- PDF: `.pdf`
- Image OCR required: `.bmp`, `.jpeg`, `.jpg`, `.png`, `.tif`, `.tiff`, `.webp`

### Demo And Verification Commands

| Command | Current script |
| --- | --- |
| `npm run setup` | `node scripts/setup.js` |
| `npm run setup:prod` | `node scripts/setup.js --production` |
| `npm run setup:check` | `node scripts/setup.js --check --skip-install` |
| `npm run start` | `node server/app.js` |
| `npm run simulate` | `node scripts/simulate.js` |
| `npm run fire-drill` | `node scripts/fire-drill.js` |
| `npm run test` | `node scripts/run-node-tests.js` |
| `npm run test:browser` | `node scripts/run-playwright.js` |
| `npm run test:admin-console` | `node scripts/run-playwright.js admin-console.spec.js` |
| `npm run test:browser-extension` | `node scripts/run-playwright.js browser-extension.spec.js --project=chromium` |
| `npm run sync-check` | `node scripts/sync-check.js` |
| `npm run eval` | `node scripts/eval-detect.js` |
| `npm run backup` | `node scripts/backup-store.js create` |
| `npm run backup:verify` | `node scripts/backup-store.js verify` |
| `npm run backup:restore` | `node scripts/backup-store.js restore` |
| `npm run evidence:pack` | `node scripts/export-evidence-pack.js` |
| `npm run evidence:pack:zip` | `node scripts/export-evidence-pack.js --zip` |
| `npm run evidence:pack:scheduled` | `node scripts/export-evidence-pack.js --schedule` |
| `npm run evidence:pack:install-task` | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/install-evidence-pack-task.ps1` |
| `npm run evidence:pack:run-linux` | `bash scripts/run-evidence-pack.sh` |
| `npm run evidence:pack:install-systemd` | `bash scripts/install-evidence-pack-systemd.sh` |
| `npm run package:extension` | `node scripts/package-extension.js` |
| `npm run release:extension:check` | `node scripts/check-extension-release.js` |
| `npm run package:endpoint-agent` | `node scripts/package-endpoint-agent.js` |
| `npm run package:mcp-guard` | `node scripts/package-mcp-guard.js` |
| `npm run endpoint:check` | `node scripts/check-endpoint-install.js` |
| `npm run mcp:check` | `node scripts/check-mcp-guard-install.js` |
| `npm run docs:demo-guide` | `node scripts/update-demo-guide.js` |
| `npm run docs:demo-guide:check` | `node scripts/update-demo-guide.js --check` |

### Sensor And Evidence Paths

| Path | Demo role | Status |
| --- | --- | --- |
| `server/app.js` | Control plane, API, dashboard, policy, approval, audit | Present |
| `server/routing.js` | Customer-configurable approval owner and SLA routing rules | Present |
| `server/notifiers.js` | Sanitized approval workflow notification adapters | Present |
| `server/workflow.js` | Approval notification status and SLA escalation | Present |
| `server/public/index.html` | Admin dashboard shell | Present |
| `detection-engine/detect.js` | Shared detection engine source of truth | Present |
| `sensors/browser-extension/manifest.json` | Browser extension source manifest | Present |
| `sensors/browser-extension/background.js` | Browser install-health heartbeat and control-plane relay | Present |
| `sensors/browser-extension/content.js` | Browser send, paste, upload enforcement | Present |
| `scripts/check-extension-release.js` | Browser extension release-readiness gate | Present |
| `docs/EXTENSION_RELEASE_CHECKLIST.md` | Chrome, Edge, and Firefox release checklist | Present |
| `sensors/endpoint-agent/agent.js` | Local folder and file sensor | Present |
| `sensors/endpoint-agent/write-handoff.js` | Signed native upload-intent handoff writer | Present |
| `scripts/check-endpoint-install.js` | Endpoint install validation and heartbeat evidence | Present |
| `sensors/mcp-guard/guard.js` | MCP tool-output redaction reference | Present |
| `sensors/mcp-guard/sdk.js` | MCP connector SDK sanitization boundary | Present |
| `sensors/mcp-guard/connectors/microsoft365.js` | Microsoft 365 MCP file-content connector | Present |
| `scripts/check-mcp-guard-install.js` | MCP guard install validation and heartbeat evidence | Present |
| `config/policy.json` | Demo policy defaults | Present |
| `DEMO_INSTALL_GUIDE.md` | Demo guide hub | Present |
| `docs/SALES_DEMO_GUIDE.md` | Sales and client-facing demo script | Present |
| `docs/DEMO_TECHNICIAN_SETUP.md` | Demo machine setup and reset runbook | Present |
| `docs/DEPLOYMENT.md` | Native Node and Docker deployment reference | Present |
| `docs/MANAGED_EXTENSION_DEPLOYMENT.md` | Managed browser extension pilot reference | Present |
| `docs/EVIDENCE_PACK_TASK.md` | Examiner evidence pack scheduled task reference | Present |
| `docs/APPROVAL_ROUTING.md` | Approval owner and SLA routing reference | Present |
| `docs/TECHNICIAN_DEPLOYMENT_GUIDE.md` | Install-day production readiness runbook | Present |
| `docs/AWS_SAAS_DEPLOYMENT.md` | Customer-silo AWS deployment path | Present |
<!-- DEMO_GUIDE_CURRENT_STATE_END -->

## Technician Success Criteria

The demo machine is ready when:

- Commands are run from the active app repo folder.
- `npm run docs:demo-guide:check` passes.
- Server starts on `http://localhost:4000`.
- `/healthz` and `/readyz` are reachable.
- Dashboard login works.
- Chrome extension is loaded and configured with the demo server URL and ingest
  key.
- Policy starts in `block`.
- Synthetic browser prompts and demo files are ready.
- `npm test`, `npm run sync-check`, and audit-chain verification pass.
- No real customer data is on the machine.

For a high-stakes client meeting, prefer `npm run review:ci` as the full gate.

## Machine Requirements

Recommended:

- Windows 11, macOS, or Linux.
- Node.js 22 or newer.
- npm.
- Google Chrome or Chromium.
- Git, if installing from a repository clone.
- Optional Docker Desktop for container demos.

Why:

- The app uses native `better-sqlite3`, built-in `fetch`, and `node --test`.
- The browser sensor is a Chrome Manifest V3 extension.
- SQLite evidence storage should stay on local disk.
- Native Node is easier for demos because code, policy, extension files, and
  SQLite state are visible.
- Docker is useful when the presenter wants a self-contained server.

## Repo Location

Run commands from:

```powershell
cd C:\Users\Eric\Desktop\Coding_Projects\promptsentinel-app\promptwall
```

Do not run source edits, npm commands, commits, hooks, review gates, or pushes
from the workspace wrapper.

Important paths:

| Path | Purpose |
| --- | --- |
| `server/app.js` | Control plane and API |
| `server/public/` | Admin dashboard |
| `sensors/browser-extension/` | Chrome extension |
| `sensors/endpoint-agent/` | Local file sensor demo |
| `sensors/mcp-guard/` | MCP tool-output redaction demo |
| `detection-engine/detect.js` | Shared detection engine |
| `config/policy.json` | Demo policy |
| `data/` | Runtime database and generated local state |

`data/` is runtime state. It is ignored by Git and safe to delete for a clean
demo reset.

## Pre-Demo Cleanup

Stop any server already listening on port 4000:

```powershell
$serverPid = (Get-NetTCPConnection -LocalPort 4000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }
```

Reset local runtime state:

```powershell
Remove-Item -LiteralPath .\data -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\demo-files -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\demo-watch -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\backups -Recurse -Force -ErrorAction SilentlyContinue
```

Check the worktree:

```powershell
git status --short
git ls-files --others --ignored --exclude-standard | Select-Object -First 40
```

Ignored `node_modules/`, `data/`, and generated test output are normal. Do not
commit runtime state.

## Install And Setup

Run:

```powershell
npm run setup
```

This installs dependencies from `package-lock.json`, writes local `.env` values,
initializes SQLite state, and runs deployment preflight.

If Playwright browser checks are needed:

```powershell
npm run setup -- --with-browser
```

For a production-style local smoke:

```powershell
npm run setup:prod
npm run mfa:uri
```

Treat the `mfa:uri` output as a secret.

## Demo Secrets

`npm run setup` writes non-default demo secrets into `.env`. For one-off
shell-only values, use:

```powershell
$env:PORT = "4000"
$env:ADMIN_USER = "admin"
$env:ADMIN_PASSWORD = "DemoOnly!2026"
$env:SENTINEL_SECRET = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
$env:SENTINEL_DATA_KEY = node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
$env:INGEST_API_KEY = "demo-ingest-key"
```

Notes:

- Keep `SENTINEL_SECRET` stable for the demo so admin sessions remain valid.
- Keep `SENTINEL_DATA_KEY` stable so sealed approval records can be revealed.
- Do not screenshot `.env`.
- Do not use production keys in a sales demo.
- For a pilot, use managed storage or customer vault delivery instead of
  hand-typed keys.

## Start The Control Plane

Start the server:

```powershell
npm start
```

Expected output:

```text
PromptWall running on http://localhost:4000
Raw-prompt retention: encrypted at rest (AES-256-GCM), held items only; finalized records purge after 30 day(s).
Ingest key: configured
```

Open:

```text
http://localhost:4000
```

Demo login:

```text
Username: admin
Password: DemoOnly!2026
```

Health checks:

```powershell
Invoke-RestMethod http://localhost:4000/healthz
Invoke-RestMethod http://localhost:4000/readyz
```

If port 4000 is unavailable:

```powershell
$env:PORT = "4100"
npm start
```

Then update extension storage to `http://localhost:4100`.

## Load The Chrome Extension

For a local demo:

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Turn on Developer mode.
4. Click Load unpacked.
5. Select `sensors/browser-extension/`.
6. Pin the PromptWall extension.
7. Open the popup and confirm protection is enabled.

The extension defaults to localhost but has no real ingest key. Configure local
storage from the service worker console:

```javascript
chrome.storage.local.set({ ingestKey: "demo-ingest-key", serverUrl: "http://localhost:4000", enabled: true });
```

Refresh ChatGPT, Claude, Gemini, Copilot, Perplexity, or Poe after changing
extension storage.

For a managed pilot, use:

- `docs/MANAGED_EXTENSION_DEPLOYMENT.md`
- `docs/examples/browser-managed-storage.policy.json`
- `docs/examples/firefox-managed-storage.policy.json`
- `docs/examples/chrome-extension-settings.example.json`
- `docs/examples/edge-extension-settings.example.json`
- `docs/examples/firefox-extension-settings.example.json`

Never ask pilot users to type ingest keys by hand.

## Configure Demo Policy

The default policy is `block`:

```json
{
  "enforcementMode": "block",
  "blockRiskScore": 20,
  "storeRawForApproval": true
}
```

For presenter flow, use this sequence:

1. Start in `block`.
2. Show `justify`.
3. End in `redact`.

Mode behavior:

| Mode | Expected user experience |
| --- | --- |
| `block` | Prompt or file is stopped and may request Security Admin approval. |
| `warn` | User can continue after acknowledging risk. |
| `justify` | User must enter a business reason before continuing. |
| `redact` | Structured values are tokenized before send; category-only content is held. |

Hard-stop entities, such as SSNs, cards, bank accounts, routing numbers,
passports, secrets, private keys, and canary tokens, remain strict. In redact
mode, structured hard stops are tokenized instead of sent raw.

## Prepare Synthetic Prompts

Keep these in presenter notes:

Benign:

```text
Summarize this public blog post into three bullet points.
```

Synthetic SSN:

```text
Draft a denial letter for member John Carter, SSN 524-71-9043, who applied for an auto loan.
```

Justification mode:

```text
Member Sarah Jones at 482 Oakwood Drive, phone 415-555-0182, needs a payoff letter.
```

Redact mode:

```text
Help me summarize this dispute: card 4111 1111 1111 1111 was charged twice on 09/27.
```

Confidential business context:

```text
Between us, we are switching away from our core processor next quarter. Keep this internal and do not forward.
```

Canary token:

```text
This fake member record contains PS-CANARY-DEMO2026ABCDEF and should never leave the institution.
```

## Prepare Synthetic Files

Create a demo file:

```powershell
New-Item -ItemType Directory -Force .\demo-files | Out-Null
Set-Content -LiteralPath .\demo-files\loan-summary.txt -Value "Loan file for member Jane Carter. SSN 524-71-9043. Card 4111 1111 1111 1111."
```

For PDF or Office demos, create a small file with the same synthetic text.
Supported demo file families include:

- Text and config files.
- PDF.
- Word `.docx`.
- Excel `.xlsx`.
- PowerPoint `.pptx`.

Keep files small and obvious so the presenter does not waste time explaining
the fixture.

## Verify Before The Client Arrives

Minimum checks:

```powershell
npm run docs:demo-guide:check
npm test
npm run sync-check
node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"
```

Expected:

```text
Demo guides are current.
tests pass
engine copies identical
{"ok":true,...}
```

Stronger gate:

```powershell
npm run review:ci
```

Browser-extension smoke with screenshots:

```powershell
npm run test:browser-extension
```

Expected:

```text
2 passed
```

This launches Chrome with the unpacked extension, serves controlled ChatGPT and
Poe fixtures, blocks a synthetic SSN before send, verifies no fixture message is
recorded, and writes screenshots to:

```text
test-results/browser-extension/chatgpt-blocked.png
test-results/browser-extension/poe-blocked.png
```

The stable copies used by the sales guide live at:

```text
docs/assets/demo/chatgpt-blocked.png
docs/assets/demo/poe-blocked.png
```

If `npm run simulate` is part of the demo, run it once while the server is up:

```powershell
npm run simulate -- http://localhost:4000
```

Expected output includes `ALLOW` and `BLOCK` decisions. Then reset runtime data
if the presenter wants a clean dashboard.

## API And Proxy Path Demo

With the server running:

```powershell
npm run simulate -- http://localhost:4000
```

Expected output pattern:

```text
ALLOW  [risk   0] jdoe -> chatgpt.com
BLOCK  [risk  34] msmith -> claude.ai
BLOCK  [risk  30] kpatel -> gemini.google.com
```

Then show dashboard activity, pending queue, findings, audit entries, and policy
stats.

## Endpoint Agent Demo

Create a watched folder:

```powershell
New-Item -ItemType Directory -Force .\demo-watch | Out-Null
```

Start the agent in a second terminal:

```powershell
$env:PROMPTWALL_URL = "http://localhost:4000"
$env:INGEST_API_KEY = "demo-ingest-key"
node sensors\endpoint-agent\agent.js .\demo-watch
```

Copy the synthetic file:

```powershell
Copy-Item .\demo-files\loan-summary.txt .\demo-watch\loan-summary.txt
```

Expected:

- The agent extracts and scans the file locally.
- Structured-only findings in redact mode create `.promptwall-redacted` output.
- Semantic or mixed files are held for review.
- Unsupported files fail closed and are recorded without uploading bytes.
- Dashboard records sanitized endpoint evidence.

For a longer Windows pilot:

```powershell
npm run package:endpoint-agent
.\scripts\install-endpoint-agent.ps1 `
  -PromptWallUrl "http://localhost:4000" `
  -IngestKey "demo-ingest-key" `
  -WatchDir "$env:USERPROFILE\PromptWallWatch"
```

Uninstall:

```powershell
.\scripts\uninstall-endpoint-agent.ps1
```

## MCP Guard Demo

Run:

```powershell
node sensors\mcp-guard\guard.js
```

Expected:

- Structured PII is redacted.
- Category-only confidential content is whole-chunk redacted.
- Model-facing text is safe.

Use this only when the presenter needs to discuss agent/tool workflows.

## Evidence Export

After logging into the dashboard:

```text
http://localhost:4000/api/export/evidence
```

The export should include policy, detector inventory, stats, audit integrity,
coverage posture, query metadata, masked findings, and audit hashes. It should
not include prompt bodies or raw audit detail text.

## Optional Docker Demo

Build:

```powershell
docker build -t promptwall-demo .
```

Run:

```powershell
docker run --rm --name promptwall-demo -p 4000:4000 `
  -e ADMIN_USER=admin `
  -e ADMIN_PASSWORD=DemoOnly!2026 `
  -e SENTINEL_SECRET=demo-session-secret-change-me `
  -e SENTINEL_DATA_KEY=demo-data-key-change-me `
  -e INGEST_API_KEY=demo-ingest-key `
  -v promptwall-demo-data:/data `
  promptwall-demo
```

Open:

```text
http://localhost:4000
```

Native Node is better for most live demos. Docker is better when the presenter
wants a clean server container and does not need to inspect local files.

## Reset After Demo

Stop server:

```powershell
$serverPid = (Get-NetTCPConnection -LocalPort 4000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }
```

Delete local runtime state:

```powershell
Remove-Item -LiteralPath .\data -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\demo-files -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\demo-watch -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath .\backups -Recurse -Force -ErrorAction SilentlyContinue
```

Reset Chrome:

1. Go to `chrome://extensions`.
2. Remove PromptWall.
3. Load unpacked again if needed.

Remove Docker state:

```powershell
docker rm -f promptwall-demo 2>$null
docker volume rm promptwall-demo-data 2>$null
```

## Troubleshooting

### Dashboard Does Not Open

Check:

```powershell
Invoke-RestMethod http://localhost:4000/healthz
netstat -ano | findstr :4000
```

Either stop the conflicting process or choose another port:

```powershell
$env:PORT = "4100"
npm start
```

Update extension storage:

```javascript
chrome.storage.local.set({ serverUrl: "http://localhost:4100" });
```

### Extension Does Not Block

Check:

- Chrome Developer mode is on.
- The loaded folder is `sensors/browser-extension/`.
- The extension popup says protection is enabled.
- The AI site tab was refreshed after extension load.
- The site is covered by `sensors/browser-extension/manifest.json`.
- `serverUrl` points to the running server.
- `ingestKey` matches the server.
- Policy is not set to a mode that intentionally allows the example.

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

`better-sqlite3` is native. Use Node.js 22 or newer and run:

```powershell
npm run setup
```

If the local machine cannot build native packages, use Docker for the server
demo.

### Audit Chain Fails

Inspect:

```powershell
node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain(), null, 2))"
```

For a demo machine, reset runtime data:

```powershell
$serverPid = (Get-NetTCPConnection -LocalPort 4000 -State Listen -ErrorAction SilentlyContinue).OwningProcess
if ($serverPid) { Stop-Process -Id $serverPid -Force }
Remove-Item -LiteralPath .\data -Recurse -Force -ErrorAction SilentlyContinue
npm start
```

Do not do this on a real pilot without exporting or preserving evidence first.

## Technician Handoff To Presenter

Tell the presenter:

- Dashboard URL and login.
- Current policy mode.
- Which AI site is ready.
- Which synthetic prompts are ready.
- Which synthetic files are ready.
- Whether endpoint and MCP optional scenes are ready.
- Which checks passed.
- Any limitations, such as Docker unavailable or browser E2E not installed.

## Works Cited

Docker. "Docker Build Overview." *Docker Docs*, Docker,
https://docs.docker.com/build/. Accessed 27 June 2026.

Google. "Hello World Extension." *Chrome for Developers*, Google,
https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world.
Accessed 27 June 2026.

Node.js. "Download Node.js." *Node.js*, OpenJS Foundation,
https://nodejs.org/en/download. Accessed 27 June 2026.

SQLite Consortium. "Appropriate Uses for SQLite." *SQLite Documentation*,
SQLite Consortium, https://www.sqlite.org/whentouse.html. Accessed 27 June
2026.
