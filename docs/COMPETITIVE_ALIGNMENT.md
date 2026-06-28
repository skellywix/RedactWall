# PromptWall Competitive Alignment

## Goal

PromptWall should win the first regulated pilots by being easier to deploy,
easier to verify, and easier to explain to an examiner than broad enterprise
DLP platforms. The product should not chase every connector first. It should
prove that prompt, file, and agent traffic headed to AI tools is governed by one
policy, one local detection engine, and one tamper-evident evidence trail.

## Current Market Bar

- Strac sets the browser-DLP expectation: monitor and block uploads, downloads,
  forms, prompt entry, and GenAI leakage in real time, with admin reporting.
  PromptWall should keep its lighter install story, but browser prompts and file
  uploads must remain first-class policy surfaces.
- Nightfall sets the buyer expectation for fast browser rollout, broad sensitive
  data coverage, real-time redaction, and employee education. PromptWall should
  keep category-specific coaching inline and make every block teach the safe
  substitute, without expanding into a broad cloud-DLP project first.
- Check Point AI Security / Lakera raises the bar for LLM-native controls:
  data-leakage checks apply to LLM inputs, outputs, tool calls, and tool
  responses; prompt attacks can arrive from user messages, reference documents,
  tool responses, and tool descriptions. PromptWall should keep prompt-injection
  defense, response scanning, MCP redaction, and tool-output sanitization inside
  the core acceptance gate.
- Cyberhaven raises the visibility bar beyond chat-only browser tools: security
  teams need shadow-AI, agent, endpoint, developer-tool, and data-flow visibility
  plus risk-based controls. PromptWall should make coverage posture and lineage
  visible without storing raw prompt bodies.
- OWASP's LLM risk work reinforces that prompt injection and sensitive
  information disclosure are first-class product risks, not edge cases. The
  acceptance gate must keep testing both.

## Product Direction

Keep:

- Local-first browser, endpoint, and MCP sensors.
- One shared detection engine synced into the browser extension.
- Warn, justify, redact, block, approval release, and audited admin step-up.
- Shadow-AI discovery and coverage posture as control metadata only.
- Customer-silo AWS deployment until shared multi-tenant storage is deliberately
  redesigned.

Build next:

- Native desktop collector feeding the existing metadata-only endpoint handoff.
- Broader app/action policy controls beyond the current destination,
  file-upload, response-scanning, and browser-paste controls.
- Ticketing adapters on top of provisioned users, groups, identity-backed
  ownership, direct SMTP, and the sanitized approval workflow.
- Exception lifecycle ownership and expiry review beyond the guided builder's
  time-bound allow rules.

## Recent Completed Passes

- Rebrand the visible project from PromptSentinel to PromptWall.
- Rename the endpoint installer surface to `-PromptWallUrl` while keeping
  `-SentinelUrl` as a compatibility alias for existing technician scripts.
- Add a Chrome extension release-readiness gate and private or unlisted Web
  Store checklist so managed browser rollout has package, policy, update URL,
  generated ExtensionSettings force-install policy, and install-health evidence
  before handoff.
- Add guided Policy-tab builders for common scoped enforcement rules and
  time-bound exceptions while preserving exact JSON review before save.
- Add a dashboard Lineage tab backed by `/api/lineage` so admins and auditors
  can see which users, sensors, destinations, channels, categories, and
  decisions were involved without retaining sensitive content.
- Add Policy-tab response scanning controls so `/api/v1/scan-response` can
  flag, redact, or block sensitive AI replies while storing only sanitized
  evidence.
- Add destination-scoped browser paste blocking so admins can stop clipboard
  paste into selected AI tools while storing only sanitized `action_blocked`
  evidence.
- Add approval owner and SLA routing so held decisions reach security,
  compliance, privacy, or legal queues with sanitized workflow metadata in the
  dashboard, SIEM alerts, and examiner evidence.
- Add best-effort approval notification adapters for generic JSON webhooks,
  Slack, Microsoft Teams, and SMTP reviewer distribution lists, plus persisted
  notification status and SLA escalation audit events.
- Add Windows Task Scheduler and Linux systemd ownership for recurring sanitized
  examiner evidence packs, including Docker customer-silo mode and local-npm
  mode without putting secrets or prompt content into scheduler definitions.
- Add customer-configurable approval routing rules so Security Admins can route
  held decisions by SCIM user, SCIM group, org id, detector, category, source,
  channel, destination, severity, and risk without exposing prompt or file
  content to sensors.
- Add approval queue filters by workflow state, detector/category, and
  destination so reviewers can triage held items without opening every record.
- Add an optional local approver role so assigned reviewers can approve or deny
  their own queue items without receiving Security Admin privileges or raw
  prompt reveal access.
- Add minimal SCIM 2.0 provisioning for users and groups, with bearer auth,
  deactivation, group membership patches, audit entries, and PromptWall group
  display names mapped onto local route roles.
- Add SCIM-backed OIDC console login that validates authorization-code
  callbacks, state, nonce, RS256 ID-token signatures, issuer, audience, expiry,
  and active provisioned users before issuing normal PromptWall sessions.
- Add server-side scoped policy and time-bound exceptions that use metadata such
  as user, SCIM group, source, channel, destination, detector, and category while
  preserving hard-stop entities.
- Add dashboard Policy-tab editors for scoped policy and time-bound exceptions,
  so customer-specific rules can be configured without direct file edits.
- Keep compatibility-sensitive runtime contracts stable where breaking them
  would damage existing installs or retained evidence.
- Add active Poe browser protection because Poe was already a governed
  destination in policy and adapters.
- Add blocked destination policy controls across browser, endpoint, gate, file,
  and response paths, with `destination_blocked` evidence that does not retain
  prompt or file content.
- Add per-destination file-upload blocking so customers can allow chat while
  forbidding document uploads to selected tools, with `file_upload_blocked`
  evidence that does not retain uploaded bytes, extracted text, or sensitive
  filenames.
- Add inline employee coaching to the browser block/warn/justify banner so the
  user gets a concrete safe alternative for SSNs, credentials, confidential
  business context, source code, contracts, canary tokens, and other sensitive
  categories before anything leaves the page.
- Preserve legacy canary token compatibility while adding the PromptWall canary
  prefix.
- Add tested `PROMPTWALL_*` runtime aliases so new PromptWall deployments can
  use the renamed prefix without breaking existing `SENTINEL_*` installs.
- Issue fresh admin sessions as `promptwall_session` while accepting legacy
  `sentinel_session` cookies during migration, and clear both cookie names on
  logout.
- Normalize scanner byte limits to integers across policy load/save, default
  config, and endpoint-agent scanner config so the admin policy API can
  round-trip its own payload.
- Add policy-driven required-sensor and desired-version fleet posture so the
  dashboard, SIEM version-gap alerts, and examiner export can show missing or
  outdated sensors without prompt bodies.
- Add default-deny unapproved AI destination blocking with an admin review reason
  so shadow-AI sightings can become explicit govern, allow, or block policy
  decisions without retaining prompt bodies.
- Add an AI-domain watchlist and CI check so adapter coverage, browser manifest
  coverage, and shadow-AI/default-deny inventory do not silently age out as new
  tools appear.
- Expand the sanitized examiner evidence export with coverage posture, sensor
  versions, parsed policy history, and prompt/file lineage summaries by user,
  destination, sensor, category, channel, and decision.
- Add customer-defined detector packs plus an `ocr_required` file outcome so
  pilots can model local member IDs and scanned/image uploads before shipping a
  heavier endpoint-local OCR runtime.
- Add endpoint install validation heartbeats so technicians can prove endpoint
  env, runtime, watch directory, and native handoff readiness in Coverage and
  examiner evidence without exposing keys or prompt/file content.
- Add MCP guard install validation heartbeats so agent/tool-output coverage can
  prove runtime, shared-engine, Node, and control-plane config health without
  exposing ingest keys or tool output.
- Add browser extension install-health heartbeats so managed Chrome coverage can
  prove MV3 wiring, content-script coverage, managed config, tenant identity,
  server URL, ingest-key presence, and policy cache health without exposing
  ingest keys, prompt text, file content, or page content.
- Add customer-ready fleet reporting that aggregates browser, endpoint, and MCP
  install-health state by user, org, sensor version, and failed check in
  Coverage and sanitized examiner evidence.
- Add the MCP connector SDK pattern that forces `sanitizeToolResult()` before
  model delivery, packages the SDK with the guard runtime, and exposes
  connector health check objects for future coverage posture.
- Add the first Microsoft 365 Graph MCP content connector for text-readable
  OneDrive and SharePoint driveItems, with SDK sanitization before model
  delivery and connector runtime/package health evidence.

## Acceptance Evidence

Run before accepting a completed pass:

```powershell
npm run sync-check
npm test
npm run eval
node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"
```

When browser behavior changes, also run:

```powershell
npm run test:browser
npm run package:extension -- <temp-output-dir>
npm run release:extension:check -- <temp-output-dir>
```

For examiner export changes, also run:

```powershell
npm test -- test/evidence.test.js test/policy-history.test.js
```

## Works Cited

Check Point AI Security. "Data Leakage Prevention." *Check Point AI Security
Docs*, Check Point, https://docs.lakera.ai/docs/data-leakage-prevention.
Accessed 28 June 2026.

Check Point AI Security. "Prompt Defense." *Check Point AI Security Docs*,
Check Point, https://docs.lakera.ai/docs/prompt-defense. Accessed 28 June 2026.

Cyberhaven. "AI Security for the Age of Autonomous Agents." *Cyberhaven*,
Cyberhaven, https://www.cyberhaven.com/product/ai-security. Accessed 28 June
2026.

Cyberhaven. "Enable Safe AI Adoption Without Blocking Teams." *Cyberhaven*,
Cyberhaven, https://www.cyberhaven.com/use-cases/secure-ai-usage. Accessed 28
June 2026.

Nightfall AI. "AI-First Data Leak Prevention (DLP) for ChatGPT." *Nightfall AI*,
Nightfall AI, https://www.nightfall.ai/lp/chatgpt-dlp. Accessed 28 June 2026.

Nightfall AI. "AI Applications." *Nightfall AI*, Nightfall AI,
https://www.nightfall.ai/integrations/ai-applications. Accessed 28 June 2026.

OWASP Foundation. "OWASP Top 10 for Large Language Model Applications." *OWASP
GenAI Security Project*, OWASP Foundation, https://genai.owasp.org/llm-top-10/.
Accessed 28 June 2026.

Strac. "Browser DLP (Data Loss Prevention)." *Strac*, Strac,
https://www.strac.io/integration/browser-dlp. Accessed 28 June 2026.

Strac. "Chrome DLP (Data Loss Prevention)." *Strac*, Strac,
https://www.strac.io/integrations/chrome-dlp. Accessed 28 June 2026.

Strac. "ChatGPT DLP." *Strac*, Strac,
https://www.strac.io/integration/chatgpt-dlp. Accessed 28 June 2026.
