# Customer Missing Features Plan

## Goal And Context

Identify the customer-facing features PromptWall still needs for credible paid
pilots, then connect each feature to the existing architecture so implementation
can happen in scoped, testable passes.

PromptWall already has the right product spine: local browser, endpoint, and MCP
sensors; one shared detection engine; warn, justify, redact, block, approval
release; MFA-backed Security Admin actions; sanitized SIEM events; seat
enforcement; AWS customer-silo deployment; coverage posture; and examiner export.

The missing customer value is not another detector pass first. The missing value
is operational completeness: IT can deploy it, security can route decisions, an
examiner can read the evidence, and employees are covered across the real AI
paths they use.

## 2026 Competitor Refresh

Recent official product pages sharpen the priority order:

- Strac emphasizes browser controls across uploads, downloads, forms, GenAI
  prompts and responses, shadow IT, and admin-managed blocking. PromptWall's
  browser prompt and file-upload controls are now directionally right; the
  remaining paid-pilot gap is proving desktop and file-flow coverage outside the
  browser.
- Nightfall emphasizes fast browser rollout, broad sensitive-data detection,
  real-time redaction, and employee education for AI applications. PromptWall
  should keep inline coaching in the leak moment and add customer-defined
  detector packs before chasing a large connector catalog.
- Check Point AI Security / Lakera treats data leakage and prompt attacks as
  LLM-native risks across user prompts, documents, tool calls, tool responses,
  and tool descriptions. PromptWall's MCP guard should become a connector SDK
  pattern, not just a reference example.
- Cyberhaven emphasizes shadow AI, autonomous agents, endpoint/developer-tool
  use, and data movement visibility. PromptWall should keep lineage, sensor
  health, and coverage posture near the top of the commercial roadmap.

Implication: Option B still wins. Build one real desktop/file-flow collector MVP
first, then routing, identity, fleet posture, scoped policy, scheduled evidence,
customer detectors/OCR states, and MCP connectors. The browser lane now also
needs an explicit default-deny control for new AI destinations plus a repeatable
domain-refresh check so shadow-AI visibility turns into enforceable policy.

## Non-Negotiable Constraints

- Detector logic lives in `detection-engine/detect.js`; browser copies are
  generated with `npm run sync-engine`.
- `alwaysBlock` entities stay hard stops.
- No raw PII, raw prompt text, token vaults, decision secrets, or uploaded file
  bytes in logs, audit details, SIEM payloads, or export packs.
- Native desktop collectors must feed the existing metadata-only handoff writer;
  they must not create their own event format or write file bytes to the spool.
- Customer-silo AWS remains the supported paid deployment shape until the
  datastore and tenant model are deliberately redesigned.
- Every feature must preserve `verifyAuditChain()` and the zero-benign-false-
  positive held-out eval gate.

## What Customers Will Ask For That Is Still Missing

### 1. Real Desktop And File-Flow Interception

Current state: the endpoint package has a local folder watcher, signed
metadata-only native handoff contract, packaged Windows protected-upload shell
action, desktop collector runner, installer/uninstaller scripts, install-health
checks, and package-to-install smoke coverage. It is a pilot-safe user-invoked
collector, not full OS-level interception for every desktop AI app.

Customer ask: "Does this stop files dragged into ChatGPT Desktop, Claude
Desktop, Copilot Desktop, or other AI apps, not just browser text?"

Why it matters: this is the biggest remaining product-promise gap. Browser DLP
is strong, but regulated customers will treat desktop apps and file upload flows
as obvious leakage paths.

Implemented:
- Reuses `sensors/endpoint-agent/write-handoff.js` and
  `sensors/endpoint-agent/native-handoff.js`.
- Adds `sensors/endpoint-agent/collectors/protected-upload.js` as the
  Windows-first collector layer.
- Packages a signed "protected upload" shell action and app-labeled
  file-selection flow that writes handoff events through the packaged writer.
- Surfaces collector readiness through endpoint install validation and package
  manifest checks.

Remaining:
- Follow with higher-friction collectors only after the MVP proves value:
  clipboard observation, native messaging from browser upload surfaces, or app
  specific collectors.
- Add deeper app-specific interception only when a paid pilot needs it.

Acceptance evidence:
- `node --test test/native-handoff.test.js test/native-handoff-writer.test.js test/endpoint-agent.test.js`
- `npm run package:endpoint-agent -- <temp>`
- Manual Windows smoke with synthetic files: protected upload writes only
  metadata, endpoint locally scans, server stores sanitized evidence, and
  `verifyAuditChain()` returns `ok:true`.

### 2. Enterprise Identity, Roles, And Provisioning

Current state: local admin login, optional assignment-aware approver login,
optional auditor login, MFA for Security Admin, managed sensor user identity,
seat-limit enforcement, minimal SCIM user/group provisioning, and SCIM-backed
OIDC login exist. SCIM can deactivate users and map PromptWall group names to
local roles. OIDC validates authorization-code callbacks, state, nonce, RS256
ID-token signatures, issuer, audience, expiry, and active SCIM users before
issuing PromptWall sessions. Full IdP session lifecycle management, IdP-driven
seat lifecycle enforcement, IdP-specific setup UX, and polished MFA enrollment
do not.

Customer ask: "Can we connect this to Microsoft Entra or Okta, map groups to
roles, deprovision users automatically, and avoid shared admin accounts?"

Why it matters: regulated customers will accept a local admin for a demo, not for
production. Identity is also the bridge to group policy and approval routing.

Implemented:
- Extends `server/auth.js` and `server/oidc.js` with an OIDC login path while
  keeping existing local admin, approver, and auditor credentials as break-glass
  or demo options.
- Uses the existing `server/roles.js` guards for IdP-provisioned
  `security_admin`, `approver`, `auditor`, and `operator` users.
- Uses the existing SCIM 2.0-compatible provisioning API at `/scim/v2/Users`,
  `/scim/v2/Groups`, and `/scim/v2/ServiceProviderConfig` as the identity
  lifecycle source for console login.

Remaining:
- Decide whether provisioned identity state should remain in the SQLite evidence
  database for customer-silo installs or move to a separate app config store
  before shared SaaS migration.
- Add IdP-specific setup guides and operator UX for Entra and Okta.
- Decide whether step-up should stay as a fresh OIDC-session window or become a
  dedicated reauthentication flow.

Acceptance evidence:
- `node --test test/auth.test.js test/approver-role.test.js test/auditor-role.test.js test/admin-csrf.test.js`
- `node --test test/scim.test.js` for SCIM create/update/disable and group
  membership role mapping.
- `node --test test/oidc-login.test.js` for OIDC callback validation, JWKS ID
  token verification, active-SCIM-user enforcement, and session role guards.
- Browser E2E: local auditor cannot approve, local approver can approve assigned
  items, Security Admin can edit policy, operator can view deployment health
  only.

### 3. Approval Routing, Escalation, And Notifications

Current state: blocked items enter one queue, approval release requires password
step-up, SIEM alerts are sanitized, and denied or approved decisions are audited.
Held decisions receive owner and SLA routing metadata for security, compliance,
privacy, legal, or customer-defined review groups. Security Admins can configure
metadata-only `approvalRoutingRules` from the Policy tab or admin policy API.
Rules can match SCIM user names, SCIM groups, org ids, detectors, categories,
sources, channels, destinations, severity, and risk. The dashboard, SIEM
payloads, and examiner export expose that sanitized workflow context. The
dashboard approval queue can now filter held items by workflow state,
detector/category, and destination so reviewers can work member-data,
source-code, legal, or app-specific queues without opening every incident.
PromptWall supports best-effort generic JSON, Slack, Microsoft Teams, and SMTP
approval notifications, persists delivery status on the query, audits
notification outcomes, and escalates overdue routed items into tamper-evident
evidence. Ticketing adapters and more granular escalation policies are still
open.

Customer ask: "Can member-services exceptions route to compliance, source-code
events route to security, and urgent approvals notify someone immediately?"

Why it matters: a queue without ownership becomes a backlog. Customers need the
workflow to fit their org chart, not just prove the gate works.

Implementation connection:
- Direct SMTP email is implemented on top of the existing sanitized
  `server/notifiers.js` discipline and refuses prompt bodies, token vaults, raw
  findings, decision notes, and uploaded file bytes.
- Build ticketing adapters on the same notification discipline.

Acceptance evidence:
- Routing, gate, and notifier tests prove sanitized payloads never include
  prompt bodies, token vaults, raw findings, passwords, or decision secrets.
- Browser E2E: blocked synthetic prompt creates an assigned queue item; approve
  and deny remain audited; escalation event appears in evidence export.

### 4. Managed Deployment And Fleet Posture

Current state: extension and endpoint package generation, managed Chrome policy
docs, required-sensor and desired-version posture, default-deny unapproved AI
blocking, AI-domain adapter and browser-manifest coverage checks, AWS
customer-silo deployment, setup preflight, browser extension install-health
heartbeats, endpoint technician install validation heartbeats, MCP guard install
validation heartbeats, and customer-ready fleet reporting by user, org, sensor,
version, and failed check exist. The browser release-readiness gate and private
or unlisted Chrome Web Store checklist now exist. The release gate can also
render a final Chrome `ExtensionSettings` force-install policy when supplied the
stable Web Store extension id. The remaining signed-update gap is a real Web
Store item and customer-controlled publishing workflow.

Customer ask: "How do we force-install it, keep it updated, and prove every
covered user actually has it?"

Why it matters: buyers trust controls they can deploy and monitor. A packaged
zip is useful for pilots, but commercial customers need rollout health.

Implementation connection:
- Use the existing `desiredSensorVersions` and `requiredSensors` policy fields
  as the rollout contract for required browser, endpoint, MCP, proxy, or custom
  sensors.
- Use browser extension install-health heartbeats to report managed config,
  managed identity, tenant id, server URL, ingest-key presence, content-script
  coverage, policy cache, version, and failed check IDs without exposing secrets.
- Use MCP guard install validation to prove runtime files, shared engine,
  Node version, server URL, and ingest-key presence without exposing secrets.
- Keep technician validation output in the dashboard and evidence export:
  browser managed config, endpoint env, ingest-key presence, handoff readiness,
  last seen time, version, and failed check IDs.
- Use `npm run release:extension:check` and the Chrome Web Store private/unlisted
  checklist as the browser rollout handoff gate. After the Web Store item
  exists, rerun with the Chrome Web Store extension id so the handoff packet
  contains the final force-install policy, not a manually edited placeholder.
- Add endpoint package manifest verification to install-day runbook output.

Acceptance evidence:
- `node --test test/extension.test.js test/sensor-heartbeat.test.js test/endpoint-install-check.test.js test/mcp-install-check.test.js test/coverage.test.js test/extension-package.test.js test/endpoint-agent-package.test.js test/mcp-guard-package.test.js`
- `npm run package:extension -- <temp>`
- `npm run release:extension:check -- <temp>`
- `npm run package:endpoint-agent -- <temp>`
- Browser E2E shows coverage posture without page overflow on desktop and mobile.

### 5. Group-Scoped Policy And Time-Bound Exceptions

Current state: policy is centralized, supports templates, destination blocks,
file-upload blocks, destination-scoped browser paste blocks, detector ignores,
scanner controls, server-side `policyScopes`, and server-side
`policyExceptions`. Scopes can tighten
enforcement by user, SCIM group, org, source, channel, destination, detector, or
category. Exceptions can temporarily allow matching non-hard-stop events and are
recorded in evidence. The Policy tab includes guided builders for common scoped
rules and time-bound exceptions, plus advanced JSON editors for exact policy
review and uncommon matcher shapes. Exceptions carry owner group, reviewer role,
review-after, and expiry metadata into sanitized examiner evidence. Local
sensor-side scoped evaluation is still open.

Customer ask: "Can lending have a different approval path than engineering? Can
we allow a specific vendor prompt for 24 hours without weakening the global
policy?"

Why it matters: one global policy is clean for demos, but production controls
need limited exceptions or teams will pressure admins to loosen the baseline.

Implementation connection:
- Keep global policy as the default.
- Keep the guided builders focused on common user, SCIM group, destination,
  detector, and category rules, with advanced JSON editing for edge cases.
- Decide whether sensors should receive a reduced scoped-policy subset once
  group identity is reliable on every endpoint.
- Keep exception lifecycle metadata sanitized: group and role ownership only,
  with review and expiry timestamps but no prompt bodies or matched users.

Acceptance evidence:
- `node --test test/policy-scope.test.js test/templates.test.js test/validation.test.js`
- `node --test test/policy-scope-api.test.js test/policy-history.test.js`
- Regression tests prove expired exceptions fail closed, SCIM groups can drive a
  scoped gate decision, and `alwaysBlock` cannot be downgraded by scoped policy
  or exceptions.
- Browser E2E proves the Policy tab can save scoped rules and exceptions.
- Evidence export includes scope ids, exception ids, and exception review state
  but not prompt bodies.

### 6. Examiner-Ready Evidence Packs And Scheduled Reporting

Current state: sanitized evidence export includes audit integrity, policy, parsed
policy diffs, coverage posture, sensor versions, lineage summaries, report
metadata, backup status, restore-drill status, and control mappings. The
dashboard also exposes prompt-free lineage by user, destination, sensor, channel,
category, and decision through `/api/lineage`. Backup and restore tooling exists,
`npm run evidence:pack` can generate dated JSON or optional zip packs from the
local evidence store,
`npm run evidence:pack:install-task` installs a Windows Task Scheduler wrapper,
and `npm run evidence:pack:install-systemd` installs a Linux systemd timer for
Docker or local-npm hosts.

Customer ask: "Can we hand an examiner a quarterly pack that maps to GLBA, NCUA,
PCI, and HIPAA controls without exporting sensitive prompts?"

Why it matters: this is the wedge. PromptWall should be easier to defend in an
exam than a broad DLP platform that takes months to tune.

Implementation connection:
- Keep `server/control-map.js` stable as new product evidence types are added.
- Keep `server/evidence.js` export fields prompt-free when backup, restore, or
  report metadata expands.
- Use `scripts/export-evidence-pack.js` to generate dated JSON and optional zip
  packs without prompt bodies.
- Use `config/evidence-schedule.example.json` as the customer-silo schedule
  config template.
- Use `scripts/install-evidence-pack-task.ps1` and
  `scripts/run-evidence-pack.ps1` for Windows scheduled examiner-pack exports.
- Use `scripts/install-evidence-pack-systemd.sh` and
  `scripts/run-evidence-pack.sh` for Linux scheduled examiner-pack exports.

Acceptance evidence:
- `node --test test/evidence.test.js test/backup-store.test.js test/policy-history.test.js`
- `node --test test/evidence-pack-task.test.js`
- `node --test test/evidence-pack-systemd.test.js`
- `npm run backup -- <temp>` and `npm run backup:verify -- <backup.db>`
- Evidence pack grep confirms no synthetic SSN, card, API key, release token, or
  raw prompt survives in the export.

### 7. Customer-Defined Sensitive Types And Better File Modalities

Current state: structured detectors, semantic categories, held-out eval, file
processors, response scanning with flag/redact/block policy controls,
customer-owned detector packs, and image `ocr_required` handling exist.
Remaining gaps are an actual endpoint-local OCR runtime and heavier
detector-quality upgrades for scanned PDFs and screenshots.

Customer ask: "Can we detect our member numbers, loan IDs, internal project
codes, screenshots, and scanned loan packets?"

Why it matters: credit unions and healthcare customers have institution-specific
identifiers. They will also have scanned PDFs where extractable text is missing.

Implemented:
- Added `config/custom-detectors.json` with bounded regex and validator hooks
  loaded by the shared engine and distributed to browser, endpoint, and MCP
  sensors through `/api/v1/policy`.
- Added tests that custom detectors cannot create unbounded regex backtracking
  or overwrite built-in detector IDs.
- Added a file-processor result state for `ocr_required` before adding an OCR
  runtime.

Remaining:
- Prototype OCR as an optional endpoint-local processor only, never server-side
  by default.
- Keep ONNX/WASM NER as a later detector-quality upgrade, not the blocker for
  commercial workflow features.

Acceptance evidence:
- `npm run eval`
- `node --test test/custom-detectors.test.js test/processors.test.js`
- Synthetic scanned-file smoke records `ocr_required` or sanitized OCR findings
  without sending image bytes to the control plane.

### 8. First Real MCP Content Connectors

Current state: MCP guard redacts local tool output through a reference guard,
PromptWall ships a small connector SDK that forces future content connectors
through `sanitizeToolResult()` before tool output reaches a model, and
PromptWall now includes a first Microsoft 365 Graph connector for text-readable
OneDrive and SharePoint driveItem content. PromptWall does not yet ship
first-party connectors for Google Drive, Slack, Teams, or Jira content.

Customer ask: "Can it protect agents that pull documents from SharePoint,
OneDrive, Google Drive, Slack, or Teams before the model sees them?"

Why it matters: agent workflows are where customers will move next. Do not chase
30 connectors; ship one or two integrations that prove the reusable pattern.

Implemented:
- Kept `sensors/mcp-guard/guard.js` as the redaction boundary.
- Added `sensors/mcp-guard/sdk.js` with `sanitizeToolResult()`,
  `wrapConnectorTool()`, and `connectorHealthCheck()`.
- Included the connector SDK in the MCP guard package and install-health check.
- Added `sensors/mcp-guard/connectors/microsoft365.js` for Graph driveItem
  content with local SDK sanitization before model delivery.

Remaining:
- Extend Microsoft 365 support to Office/PDF conversion, site search, and
  selected-site grants only after pilot needs are clear.
- Add Google Drive only if an early prospect needs it.
- Require OAuth scopes, tenant ID, and connector health to appear in coverage
  posture without storing raw document content.

Acceptance evidence:
- `node --test test/mcp-guard.test.js test/mcp-connector-sdk.test.js`
- Connector smoke with synthetic docs proves local redaction before tool output
  reaches the model and sanitized evidence in the control plane.

## Recommended Build Order

1. Deepen desktop/file-flow coverage beyond the protected-upload MVP only when
   a pilot needs app-specific interception.
2. Polish enterprise identity UX, IdP recipes, and step-up reauthentication.
3. Signed update channel and commercial rollout posture.
4. Scheduled examiner evidence pack with backup and restore-drill status.
5. Customer-defined detectors plus OCR-required handling.
6. Broaden MCP connectors only after Microsoft 365 pilot scope is clear.

This order closes the most embarrassing buyer gap first, then turns the product
from a strong demo into something IT and compliance can operate. It avoids
spending the next several passes on detection novelty while deployment,
workflow, and identity are still commercial blockers.

## Options

### Option A: Enterprise Operations First

Build SSO on top of SCIM, roles, notifications, and signed-update operations
before deeper desktop collection.

Pros:
- Strong for IT/security procurement.
- Makes future group policy and routing cleaner.
- Lower OS-hook risk than desktop interception.

Cons:
- Leaves the current desktop/file-flow promise gap open.
- Less visually compelling in sales demos.

### Option B: Coverage Reality First

Build the native desktop/file-flow collector MVP, then connect routing,
notifications, identity, and signed-update deployment posture.

Pros:
- Closes the obvious "what about desktop AI?" objection.
- Reuses the existing handoff writer and endpoint package.
- Produces a clear demo: browser prompt, desktop file, MCP output, one queue.

Cons:
- Windows collector behavior needs careful pilot scoping.
- Full OS-level interception is a later product, not the MVP.

### Option C: Connector Breadth First

Build Microsoft 365, Google Drive, Slack, Teams, and Jira connectors immediately.

Pros:
- Broad coverage story.
- Matches where agent workflows are heading.

Cons:
- High integration surface before identity and policy scoping are ready.
- Risks becoming the broad DLP platform PromptWall is trying not to be.

## Recommendation

Use Option B. Ship one real desktop/file-flow collector MVP, then immediately
add routing, notifications, identity, and signed-update rollout posture. Defer
connector breadth until the operating model is strong enough to support it.

## Decisions For Eric

- First IdP target: Microsoft Entra, Okta, or both.
- First notification target: email, Slack, or Microsoft Teams.
- First desktop collector scope: protected upload shell action, clipboard,
  app-specific upload collector, or native messaging bridge.
- First content connector: Microsoft 365/SharePoint/OneDrive or Google Drive.
- Whether group-scoped policy should use IdP groups only or also local groups.
- Whether scheduled evidence packs should be generated by the app process or an
  external technician-managed task.

## Cross-Feature Acceptance Gate

Every implementation pass should finish with the smallest focused tests plus
the product gate below when relevant:

```powershell
npm run sync-check
npm test
npm run eval
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

Feature-specific gates:

```powershell
npm run test:browser
npm run package:extension -- <temp-output-dir>
npm run release:extension:check -- <temp-output-dir>
npm run package:endpoint-agent -- <temp-output-dir>
npm run package:mcp-guard -- <temp-output-dir>
npm run backup -- <temp-output-dir>
npm run backup:verify -- <backup-db>
```

Manual evidence before a paid pilot:

- Browser prompt block, warn, justify, redact, and approval release with
  synthetic data.
- Desktop file-flow collector feeds only metadata to the handoff spool and local
  endpoint scanning records sanitized evidence.
- MCP tool output is redacted before model use.
- SSO login maps the expected SCIM-provisioned role and local break-glass login
  still works.
- Notification payloads omit raw prompt text and raw findings.
- Evidence pack contains coverage, policy, lineage, audit integrity, backup
  status, and control mapping without sensitive bodies.

## Works Cited

Federal Trade Commission. "Gramm-Leach-Bliley Act." *Federal Trade Commission*,
https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act.
Accessed 28 June 2026.

Google. "Chrome Enterprise Policy List and Management." *Chrome Enterprise*,
https://chromeenterprise.google/policies/. Accessed 28 June 2026.

Microsoft. "Microsoft Purview Data Security and Compliance Protections for
Generative AI Apps." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/purview/ai-microsoft-purview. Accessed 28
June 2026.

Microsoft. "Get DriveItem Content." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0.
Accessed 28 June 2026.

Microsoft. "Microsoft Graph Permissions Reference." *Microsoft Learn*,
Microsoft, https://learn.microsoft.com/en-us/graph/permissions-reference.
Accessed 28 June 2026.

Microsoft. "Tutorial: Develop and Plan Provisioning for a SCIM Endpoint in
Microsoft Entra ID." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups.
Accessed 28 June 2026.

National Institute of Standards and Technology. "AI Risk Management Framework."
*NIST*, U.S. Department of Commerce,
https://www.nist.gov/itl/ai-risk-management-framework. Accessed 28 June 2026.

OWASP Foundation. "OWASP Top 10 for Large Language Model Applications."
*OWASP Gen AI Security Project*, OWASP Foundation,
https://genai.owasp.org/llm-top-10/. Accessed 28 June 2026.

Check Point AI Security. "Data Leakage Prevention." *Check Point AI Security
Docs*, Check Point, https://docs.lakera.ai/docs/data-leakage-prevention.
Accessed 28 June 2026.

Check Point AI Security. "Prompt Defense." *Check Point AI Security Docs*,
Check Point, https://docs.lakera.ai/docs/prompt-defense. Accessed 28 June 2026.

Cyberhaven. "AI Security for the Age of Autonomous Agents." *Cyberhaven*,
Cyberhaven, https://www.cyberhaven.com/product/ai-security. Accessed 28 June
2026.

Nightfall AI. "AI Applications." *Nightfall AI*, Nightfall AI,
https://www.nightfall.ai/integrations/ai-applications. Accessed 28 June 2026.

Strac. "Browser DLP (Data Loss Prevention)." *Strac*, Strac,
https://www.strac.io/integration/browser-dlp. Accessed 28 June 2026.
