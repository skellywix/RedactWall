# RedactWall Demo Guide Hub

This is the entry point for RedactWall demos. The detailed guide is now split by
audience so a presenter can stay focused on the buyer story while a technician
keeps the demo machine clean, repeatable, and verified.

Use synthetic data only. Do not paste real member, patient, cardholder,
customer, employee, source code, contract, credential, or private business data
into any demo.

## Which Guide To Use

| Need | Use |
| --- | --- |
| Client meeting narrative, talk track, objection handling, and timed demo flow | `docs/demo/SALES_DEMO_GUIDE.md` |
| Laptop or demo workstation setup, extension config, verification, reset, and troubleshooting | `docs/demo/DEMO_TECHNICIAN_SETUP.md` |
| Production customer install and handoff | `docs/deployment/TECHNICIAN_DEPLOYMENT_GUIDE.md` |
| Native Node, Docker, and deployment reference details | `docs/deployment/DEPLOYMENT.md` |
| Customer-silo AWS paid deployment | `docs/deployment/AWS_SAAS_DEPLOYMENT.md` |
| Managed Chrome extension rollout | `docs/deployment/MANAGED_EXTENSION_DEPLOYMENT.md` |

For a live client demo, the normal flow is:

1. Technician prepares and verifies the demo machine with
   `docs/demo/DEMO_TECHNICIAN_SETUP.md`.
2. Presenter runs the client story from `docs/demo/SALES_DEMO_GUIDE.md`.
3. Presenter closes on examiner evidence, pilot scope, and production readiness.
4. Technician resets the machine or preserves the approved synthetic evidence
   packet after the meeting.

## Keep These Guides Current

When the app changes, run:

```powershell
npm run docs:demo-guide
npm run docs:demo-guide:check
```

The generated current-state section below is also checked by `npm run review:ci`,
so command, policy, sensor, detector, and supporting-doc drift fails before a
change is handed off.

<!-- DEMO_GUIDE_CURRENT_STATE_START -->
## Current App Snapshot

This section is generated from the app by `npm run docs:demo-guide`. Do not hand-edit between the markers. Run `npm run docs:demo-guide:check` before a client demo and in the review gate so the demo guides move with the product.

| Source | Current value |
| --- | --- |
| App package | `redactwall@0.4.0` |
| Active repo folder | `redactwall` |
| Server entrypoint | `server/app.js` |
| Browser extension | `RedactWall - AI Data Guard` version `0.4.0` |
| Default enforcement mode | `block` |
| Block thresholds | severity `2`, risk score `20` |
| Raw approval retention | enabled for `30` day(s) |
| Governed destinations | `chatgpt.com`, `openai.com`, `claude.ai`, `anthropic.com`, `gemini.google.com`, `copilot.microsoft.com`, `perplexity.ai`, `poe.com`, `chat.deepseek.com`, `deepseek.com`, `chat.qwen.ai`, `qwen.ai`, `tongyi.aliyun.com`, `kimi.com`, `kimi.moonshot.cn`, `doubao.com`, `yuanbao.tencent.com`, `yiyan.baidu.com`, `ernie.baidu.com`, `chatglm.cn`, `z.ai` |
| Browser content hosts | `*.baichuan-ai.com`, `*.bigmodel.cn`, `*.blackbox.ai`, `*.bolt.new`, `*.character.ai`, `*.chatbot.theb.ai`, `*.chatglm.cn`, `*.chatsonic.com`, `*.cohere.com`, `*.copy.ai`, `*.cursor.com`, `*.deepseek.com`, `*.doubao.com`, `*.elevenlabs.io`, `*.flowith.io`, `*.genspark.ai`, `*.grammarly.com`, `*.grok.com`, `*.groq.com`, `*.hailuoai.com`, `*.huggingface.co`, `*.hunyuan.tencent.com`, `*.ideogram.ai`, `*.jasper.ai`, `*.kimi.com`, `*.krea.ai`, `*.lovable.dev`, `*.manus.im`, `*.metaso.cn`, `*.midjourney.com`, `*.minimax.io`, `*.mistral.ai`, `*.monica.im`, `*.moonshot.cn`, `*.notion.so`, `*.phind.com`, `*.pi.ai`, `*.quillbot.com`, `*.qwen.ai`, `*.replicate.com`, `*.replit.com`, `*.runwayml.com`, `*.suno.com`, `*.udio.com`, `*.v0.dev`, `*.wenxiaobai.com`, `*.windsurf.com`, `*.writesonic.com`, `*.x.ai`, `*.you.com`, `*.z.ai`, `ai.360.com`, `aistudio.google.com`, `baichuan-ai.com`, `bard.google.com`, `bigmodel.cn`, `bing.com`, `blackbox.ai`, `bolt.new`, `character.ai`, `chat.openai.com`, `chatbot.theb.ai`, `chatglm.cn`, `chatgpt.com`, `chatsonic.com`, `claude.ai`, `cohere.com`, `copilot.microsoft.com`, `copy.ai`, `cursor.com`, `deepseek.com`, `doubao.com`, `elevenlabs.io`, `ernie.baidu.com`, `flowith.io`, `gemini.google.com`, `genspark.ai`, `grammarly.com`, `grok.com`, `groq.com`, `hailuoai.com`, `huggingface.co`, `hunyuan.tencent.com`, `ideogram.ai`, `jasper.ai`, `kimi.com`, `krea.ai`, `lovable.dev`, `manus.im`, `meta.ai`, `metaso.cn`, `midjourney.com`, `minimax.io`, `mistral.ai`, `monica.im`, `moonshot.cn`, `notebooklm.google.com`, `notion.so`, `perplexity.ai`, `phind.com`, `pi.ai`, `poe.com`, `qianwen.aliyun.com`, `quillbot.com`, `qwen.ai`, `replicate.com`, `replit.com`, `runwayml.com`, `spark.xfyun.cn`, `suno.com`, `tiangong.kunlun.com`, `tongyi.aliyun.com`, `udio.com`, `v0.dev`, `wenxiaobai.com`, `windsurf.com`, `writesonic.com`, `www.bing.com`, `www.perplexity.ai`, `www.poe.com`, `x.ai`, `xinghuo.xfyun.cn`, `yiyan.baidu.com`, `you.com`, `yuanbao.tencent.com`, `z.ai` |
| Browser local control-plane permissions | `127.0.0.1`, `localhost`, `localhost:4000` |
| Hard-stop entities | `US_SSN`, `CREDIT_CARD`, `BANK_ACCOUNT`, `ROUTING_NUMBER`, `IBAN`, `US_PASSPORT`, `US_TIN_EIN`, `US_ITIN`, `US_NPI`, `US_DRIVERS_LICENSE`, `MEMBER_ID`, `LOAN_NUMBER`, `MEDICAL_RECORD_NUMBER`, `HEALTH_INSURANCE_ID`, `UK_NINO`, `UK_NHS_NUMBER`, `CANADA_SIN`, `AUSTRALIA_TFN`, `INDIA_AADHAAR`, `DOB`, `SECRET_KEY`, `PRIVATE_KEY`, `CANARY_TOKEN`, `EXACT_MATCH` |
| Detector inventory | 44 detectors: `AUSTRALIA_TFN`, `BANK_ACCOUNT`, `CANADA_SIN`, `CANARY_TOKEN`, `CONFIDENTIAL_BUSINESS`, `CREDENTIALS`, `CREDIT_CARD`, `DOB`, `EMAIL_ADDRESS`, `EXACT_MATCH`, `FINANCIAL_STATEMENT`, `HEALTH_INSURANCE_ID`, `HEALTH_RECORD`, `HR_RECORD`, `IBAN`, `INDIA_AADHAAR`, `INDIA_PAN`, `IPV6_ADDRESS`, `IP_ADDRESS`, `LEGAL_CONTRACT`, `LOAN_NUMBER`, `MEDICAL_RECORD_NUMBER`, `MEMBER_ID`, `PASSWORD`, `PERSON_NAME`, `PHONE_NUMBER`, `PRIVATE_KEY`, `PROMPT_ATTACK`, `ROUTING_NUMBER`, `SECRET_KEY`, `SOURCE_CODE`, `SWIFT_BIC`, `TAX_FILING`, `UK_NHS_NUMBER`, `UK_NINO`, `US_ADDRESS`, `US_DRIVERS_LICENSE`, `US_ITIN`, `US_LICENSE_PLATE`, `US_NPI`, `US_PASSPORT`, `US_SSN`, `US_TIN_EIN`, `VIN` |
| Semantic categories | `CONFIDENTIAL_BUSINESS`, `CREDENTIALS`, `FINANCIAL_STATEMENT`, `HR_RECORD`, `LEGAL_CONTRACT`, `SOURCE_CODE`, `TAX_FILING` |
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
| `npm run test:console-app` | `node scripts/run-playwright.js admin-console-app.spec.js` |
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
| `console/src/App.tsx` | React admin console shell | Present |
| `detection-engine/detect.js` | Shared detection engine source of truth | Present |
| `sensors/browser-extension/manifest.json` | Browser extension source manifest | Present |
| `sensors/browser-extension/background.js` | Browser install-health heartbeat and control-plane relay | Present |
| `sensors/browser-extension/content.js` | Browser send, paste, upload enforcement | Present |
| `scripts/check-extension-release.js` | Browser extension release-readiness gate | Present |
| `docs/deployment/EXTENSION_RELEASE_CHECKLIST.md` | Chrome, Edge, and Firefox release checklist | Present |
| `sensors/endpoint-agent/agent.js` | Local folder and file sensor | Present |
| `sensors/endpoint-agent/write-handoff.js` | Signed native upload-intent handoff writer | Present |
| `scripts/check-endpoint-install.js` | Endpoint install validation and heartbeat evidence | Present |
| `sensors/mcp-guard/guard.js` | MCP tool-output redaction reference | Present |
| `sensors/mcp-guard/sdk.js` | MCP connector SDK sanitization boundary | Present |
| `sensors/mcp-guard/connectors/microsoft365.js` | Microsoft 365 MCP file-content connector | Present |
| `sensors/mcp-guard/connectors/google-drive.js` | Google Drive MCP file-content connector | Present |
| `sensors/mcp-guard/connectors/slack.js` | Slack MCP conversation and file-content connector | Present |
| `sensors/mcp-guard/connectors/teams.js` | Microsoft Teams MCP message connector | Present |
| `sensors/mcp-guard/connectors/atlassian.js` | Atlassian Jira and Confluence MCP connector | Present |
| `sensors/mcp-guard/connectors/database-readonly.js` | Database read-only MCP connector | Present |
| `scripts/check-mcp-guard-install.js` | MCP guard install validation and heartbeat evidence | Present |
| `config/policy.json` | Demo policy defaults | Present |
| `DEMO_INSTALL_GUIDE.md` | Demo guide hub | Present |
| `docs/demo/SALES_DEMO_GUIDE.md` | Sales and client-facing demo script | Present |
| `docs/demo/DEMO_TECHNICIAN_SETUP.md` | Demo machine setup and reset runbook | Present |
| `docs/deployment/DEPLOYMENT.md` | Native Node and Docker deployment reference | Present |
| `docs/deployment/MANAGED_EXTENSION_DEPLOYMENT.md` | Managed browser extension pilot reference | Present |
| `docs/deployment/EVIDENCE_PACK_TASK.md` | Examiner evidence pack scheduled task reference | Present |
| `docs/identity/APPROVAL_ROUTING.md` | Approval owner and SLA routing reference | Present |
| `docs/deployment/TECHNICIAN_DEPLOYMENT_GUIDE.md` | Install-day production readiness runbook | Present |
| `docs/deployment/AWS_SAAS_DEPLOYMENT.md` | Customer-silo AWS deployment path | Present |
<!-- DEMO_GUIDE_CURRENT_STATE_END -->

## Demo Contract

Every complete RedactWall demo should prove these five points:

1. RedactWall detects sensitive data before it leaves the browser or device.
2. The browser extension, endpoint agent, MCP guard, and server share one local
   detection engine.
3. Policy can warn, require justification, redact, or block.
4. Blocked prompts enter a Security Admin approval queue.
5. The audit log is tamper-evident and useful in examiner conversations.

The strongest 30-minute client story is:

1. Start in `block` mode.
2. Paste a synthetic SSN into ChatGPT or Claude.
3. Show the browser block before the prompt leaves the page.
4. Open the dashboard and show the pending event.
5. Show approval, denial, audit, and password-confirmed release controls.
6. Switch to `justify` mode and show business-reason accountability.
7. Switch to `redact` mode and show tokenized sensitive values.
8. Upload a synthetic file and show file scanning.
9. Show the endpoint agent or MCP guard only if the buyer cares about desktop
   AI apps or agent/tool workflows.
10. End on evidence export, audit integrity, and pilot next steps.

## Roles

| Role | Responsibility |
| --- | --- |
| Presenter | Runs the client narrative, keeps the pace, and ties behavior to risk and compliance. |
| Technician | Owns setup, reset, server health, extension config, synthetic fixtures, and verification evidence. |
| Security Admin actor | Logs into the dashboard, reviews the queue, and demonstrates approval controls. |
| Buyer champion | Validates that the story maps to their AI usage, compliance concerns, and pilot scope. |

One person can play presenter and technician in a small meeting, but keep the
responsibilities separate. It prevents the demo from drifting into terminal
debugging while the buyer is waiting.

## Evidence To Have Ready

Before a serious client meeting, the technician should capture or be ready to
show:

- `npm run docs:demo-guide:check` passing.
- `npm test` passing, or `npm run review:ci` passing if time allows.
- `npm run sync-check` passing.
- `npm run eval` passing.
- `npm run test:browser-extension` passing when the meeting depends on browser
  screenshots or live extension proof.
- `node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"`
  returning `ok:true` on the demo database.
- Browser extension loaded and configured.
- Dashboard login working.
- Synthetic demo files ready.
- No real customer data on the demo machine.

## Source Of Truth

The active repo folder in this checkout is:

```powershell
cd C:\Users\Eric\Desktop\Coding_Projects\redactwall-app\redactwall
```

Do not run source edits, npm commands, commits, hook setup, review gates, or
pushes from the workspace wrapper.

## Works Cited

Google. "Hello World Extension." *Chrome for Developers*, Google,
https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world.
Accessed 27 June 2026.

National Credit Union Administration. "Cybersecurity Resources." *NCUA*,
https://ncua.gov/regulation-supervision/cybersecurity-resources. Accessed 27
June 2026.

Node.js. "Download Node.js." *Node.js*, OpenJS Foundation,
https://nodejs.org/en/download. Accessed 27 June 2026.
