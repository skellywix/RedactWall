# RedactWall Competitive Alignment

## Goal

RedactWall should win the first regulated pilots by being easier to deploy,
easier to verify, and easier to explain to an examiner than broad enterprise
DLP platforms. The product should not chase every connector first. It should
prove that prompt, file, and agent traffic headed to AI tools is governed by one
policy, one local detection engine, and one tamper-evident evidence trail.

## July 4, 2026 Market Bar

The current leaders set a broader bar than "ChatGPT prompt scanner." They are
selling AI usage visibility, real-time DLP, shadow-AI discovery, guided posture
dashboards, agent and MCP controls, and compliance reporting.

- Microsoft Purview sets the posture-management bar: AI app governance is
  framed as data security objectives, guided workflows, posture metrics,
  trends, activity explorer, audit, DLP, insider risk, retention, eDiscovery,
  and compliance templates for third-party AI apps.
- Netskope sets the unified AI-control bar: the platform markets visibility and
  control across users, apps, private models, MCP, and agents, including an AI
  Command Center, GenAI app security, AI Gateway, AI Guardrails, prompt and
  response sanitization, shadow-AI discovery, and access controls.
- Nightfall sets the fast browser DLP bar: secure browser plugins,
  pre-submission filtering, real-time redaction, broad sensitive-data
  detection, and employee coaching before prompts are submitted. It is now a
  five-pillar platform (SaaS DLP, exfiltration prevention, discovery/audit,
  Gmail encryption, developer APIs) plus **MCP & AI Agent Security** (IDE/CLI
  hooks, shell-command blocking, shadow-MCP discovery, OpenTelemetry audit
  trails, Claude Compliance API) and the **Nyx** LLM analyst. Its
  prompt-sanitization sample repo advertises ≤100 ms p99 / ≥1000 rps, while the
  customer API is rate-limited to 5–10 rps; raw LLM responses are **monitor-only
  (no inline block)**; hosting is US-only AWS multi-tenant with 24 h encrypted
  retention of uploaded developer-platform files; endpoint rollout is MDM-heavy
  (Full-Disk-Access mobileconfig). Commercially it ships four masked-price
  bundles metered on users/apps/TB-scanned/API-calls with an enterprise-led,
  MSSP/VAR go-to-market. RedactWall's counters: on-device zero-egress detection
  (air-gapped default; connected mode is opt-in),
  a gateway that **blocks** responses, transparent per-seat pricing, and a
  lighter force-install browser rollout.
- Zscaler sets the SSE/browser-isolation bar: interactive dashboards, AI app
  trend visibility, granular DLP controls, prompt categorization, and controls
  over how users interact with generative AI tools.
- SentinelOne Prompt Security sets the AI-security-platform bar: real-time
  governance, DLP, threat protection, shadow-AI discovery, prompt injection,
  unsafe output, autonomous agent, code assistant, and homegrown app coverage.
- OWASP's LLM risk work reinforces that prompt injection, sensitive
  information disclosure, and unsafe tool behavior remain first-class product
  risks that the acceptance gate must continuously test.

RedactWall's wedge is not to outspend the platforms on every cloud connector.
It should beat the top three for regulated credit-union pilots by making the
examiner story clearer: one local detection engine, browser plus endpoint plus
MCP sensors, default-deny AI destinations, privacy-preserving evidence, and a
dashboard that proves control without storing prompt bodies by default.

## Gap Closure Added In This Pass

- Added `/api/posture`, a sanitized AI security posture API that combines live
  query evidence, coverage posture, policy controls, shadow-AI sightings,
  approval SLA state, and audit-chain integrity without returning raw prompt
  bodies.
- Reworked the former Signal Monitor into an AI Security Command Center with
  live objective cards, control-outcome breakdowns, seven-day activity trends,
  sensor surfaces, shadow-AI posture, and action buttons into Queue, Coverage,
  Policy, Lineage, and Audit.
- Added a guided Operator Flow rail that turns the command center into a
  five-step triage path: threat review, hardening actions, AI surface review,
  control-graph mapping, and SOC handoff. It lets an admin move through the
  strongest competitive surfaces without hunting through the dashboard.
- Added guided Configuration builders for MCP tool decisions and approval
  routing, so admins can turn agent/tool governance and queue ownership into
  validated policy without hand-authoring JSON.
- Added a privacy-safe AI Control Graph that connects people, gateways, AI
  assets, controls, and the three competitive hardening lanes from sanitized
  metadata only. This gives operators the "360-degree AI footprint" view
  competitors sell without adding prompt-body exposure to the dashboard.
- Added an Agentic MCP Control posture surface that turns MCP guard rows into
  active agents, invoked tools, policy-registry state, blocked tool actions,
  redacted tool-output counts, and request-class summaries. This closes the
  Netskope-style MCP dashboard gap while keeping prompt and tool bodies out of
  the posture API.
- Added an AI Threat Guardrails posture surface that maps prompt injection,
  sensitive disclosure, unsafe AI responses, excessive agent/tool agency,
  shadow AI, and unscanned-content holds into OWASP-style categories, MITRE
  ATLAS-style labels, readiness controls, recent threat metadata, SOC posture
  fields, and evidence-pack exports without returning prompt or response
  bodies.
- Added posture data to examiner evidence packs through an allowlisted export
  shape, so regulated buyers get the same executive posture story offline
  without leaked prompts, secrets, file names, paths, or raw audit details.
- Added a dedicated Endpoint File Flow coverage surface and evidence export so
  admins can review named desktop watcher profiles, missing-profile gaps, and
  deployment state without exposing local file paths.
- Added a Decision Quality posture surface that tracks approval SLA health,
  coaching completion, override watch, sensitive-control quality, and
  metadata-only hotspots for operator and examiner review.
- Added a Detection Feedback loop so authorized reviewers can mark detections
  valid, noisy, too sensitive, or missed, then see detector-level tuning signals
  and auditor-safe evidence without storing prompt bodies.
- Added a monitor-only AI chat proxy lab that scans AI-domain cleartext request
  bodies locally, records `proxy_observed` evidence, and forwards traffic while
  sending only redacted labels and masked metadata to the control plane.
- Added a deployable AI LLM Gateway with OpenAI-compatible, Anthropic Messages,
  Gemini `generateContent`, and Amazon Bedrock Runtime Converse/InvokeModel
  coverage; client auth; fail-closed prompt gating; buffered streamed-response
  scanning; response scanning; rate-limit headers; model allowlists; readiness
  probes; AWS SigV4 upstream signing; upstream credential isolation; non-text
  payload blocking; and sanitized model/content-block evidence.
- Added an opt-in SQLite-backed AI LLM Gateway rate limiter that shares
  hashed per-client counters across same-host gateway workers, exposes limiter
  readiness metadata, and keeps the default memory limiter for simple pilots.
- Added an opt-in HTTP-backed AI LLM Gateway limiter mode for multi-host
  deployments. It delegates only hashed gateway-client keys to a shared
  Redis/KV/Postgres-backed limiter service, returns rate-limit headers, and
  fails closed before control-plane or upstream model calls if the shared
  limiter is unavailable.
- Added a shipped reference shared limiter service via
  `npm run gateway:rate-limiter`. It exposes authenticated `/check`, `/healthz`,
  and `/readyz` endpoints, centralizes AI gateway counters for multi-worker and
  multi-host deployments, persists only hashed limiter keys, and is covered by
  direct and gateway-integration tests.
- Added a pilot-ready AI gateway HA compose stack with two gateway replicas, a
  private shared limiter, a no-access-log Nginx balancer, read-only hardened
  containers, and `npm run gateway:ha:smoke` proving cross-replica limiter
  sharing without calling an external LLM provider.
- Added a built-in Redis/Valkey backend for the shared limiter service so
  pilots can run active-active private limiter replicas behind the same HTTP
  contract. The backend uses atomic Redis `EVAL`, TTL-bound prefixed hashed
  keys, readiness reporting, and no new production dependency.
- Added `/api/v1/discovery`, a sensor-key protected AI asset discovery import
  path for proxy, firewall, SSE, and browser-isolation inventories. It accepts
  host-only destinations and bounded observation counts, rejects prompt bodies
  and raw URL paths, and feeds shadow-AI coverage, posture trends, and the AI
  Control Graph as sanitized evidence.
- Added `npm run discovery:import`, a local CSV/JSON importer with Zscaler,
  Netskope, Purview, firewall, and generic export profiles. It strips URL paths
  before upload, aggregates duplicate observations, supports dry-run review, and
  posts only sanitized host-level sightings to `/api/v1/discovery`.
- Added automatic sanitized posture subscriptions for SOC/SIEM use. When
  enabled, meaningful control-posture changes emit a throttled
  `POSTURE_FEED` snapshot to the existing HTTPS webhook without prompt bodies,
  raw findings, token vaults, freeform gap text, or audit details.
- Added `/api/integrations/siem/package`, a Security Admin-only offline SOC
  integration package generator for Splunk, Microsoft Sentinel, Google
  Security Operations/Chronicle, and ServiceNow. The command center can preview
  and download sanitized field mappings, saved searches, dashboard/workbook
  panels, UDM/incident mappings, sample payloads, and setup checklists without
  calling any external SIEM or exposing secrets.
- Promoted the SOC integration package from a single JSON blob to a
  marketplace-style offline ZIP with a manifest, README, privacy contract, and
  per-vendor artifacts for Splunk, Microsoft Sentinel, Google Security
  Operations, and ServiceNow while keeping the JSON API for automation.
- Added metadata-only posture segmentation for organization ids, SCIM identity
  groups, workflow review queues, and sensor surfaces. The AI Security Command
  Center can compare segments, then filter objectives, inventory, graph,
  trends, and controls through one segment lens without exposing prompt bodies.
- Added saved owner views for Security Ops, Lending, Call Center, IT, and the
  Executive Office on top of the same metadata-only segment lens. Each view
  maps to the best available segment and carries reviewer-role/owner hints
  without creating another prompt-body exposure path.
- Added a live Competitive Readiness matrix in `/api/posture`, examiner
  evidence packs, and the AI Security Command Center. It scores RedactWall
  against six market bars: real-time AI DLP, AI usage visibility, shadow-AI
  governance, agent/MCP controls, desktop/file-flow coverage, and SOC/examiner
  handoff, then shows the next gaps without returning prompt bodies.
- Added a Market Hardening Flow that narrows the top competitive push to three
  evidence-backed lanes: continuous shadow-AI discovery, MCP/SaaS connector
  coverage, and detection quality proof. Each lane shows competitor context,
  proof, remaining gaps, and the next operator action from sanitized posture
  metadata.
- Added a metadata-only MCP connector registry that distinguishes shipped
  runtime from connector profile templates. Microsoft 365 Graph and Google
  Drive are shipped document-repository connectors, Slack and Microsoft Teams
  are shipped collaboration connectors, Atlassian Jira/Confluence is a shipped
  knowledge-base connector, and database read-only is a shipped bounded SQLite
  query/schema connector. The current catalog has no template-only profiles.
  MCP install checks can now emit registry proof through heartbeat evidence
  without tokens, DSNs, SQL text, document IDs, message IDs, raw tool output,
  private file URLs, or request bodies.
- Added a held-out detector quality scoreboard to posture, evidence exports,
  and the Detection Feedback panel. It summarizes semantic precision/recall,
  structured recall, false-positive floors, and eval floor status from the
  synthetic held-out corpus without returning eval prompt text.
- Added discovery-feed freshness to coverage, posture, evidence exports, and
  the coverage dashboard. RedactWall now reports fresh versus stale proxy/SSE/
  firewall/browser-isolation import feeds, last discovery import time, source
  labels, and host-only observation counts without URL paths or prompt bodies.
- Added a local endpoint git pre-push guard that scans outbound diffs before
  source code leaves the workstation, blocks unbounded or sensitive pushes,
  supports sanctioned Git host allowlists, ships with a managed pre-push hook
  installer, and records only masked `action_blocked` evidence with
  `channel: "git_push"`.
- Added a Security Trust Package for vendor-risk and procurement review. The
  dashboard, `/api/security/package`, and `npm run security:package:zip` now
  export sanitized control coverage, validation commands, security
  questionnaire answers, documentation pointers, and a CycloneDX-style SBOM
  inventory without prompt bodies, secrets, token vaults, raw audit details,
  raw URLs, local file paths, or package-lock filesystem paths.
- Added named endpoint file-flow watcher profiles so pilots can map multiple
  local app/drop/staging folders to explicit AI destinations, validate them via
  install-health, and see `Endpoint file-flow profiles` posture in Coverage
  without posting watched paths, file names, file bytes, or extracted text.
- Added regression coverage proving posture summaries, dashboard/API linkage,
  proxy-lab sanitization, evidence-pack sanitization, posture-feed privacy, and
  monitor privacy behavior.

## Product Direction

Keep:

- Local-first browser, endpoint, and MCP sensors.
- One shared detection engine synced into the browser extension.
- Warn, justify, redact, block, approval release, and audited admin step-up.
- Shadow-AI discovery and coverage posture as control metadata only.
- Customer-silo AWS deployment until shared multi-tenant storage is deliberately
  redesigned.

Build next:

- Add managed KV/Postgres limiter adapters for customers whose preferred
  control plane is not Redis/Valkey, plus region-aware failover guidance after
  pilot infrastructure choices are known.
- Turn the marketplace-style SOC package into vendor-native app submissions
  once pilot customers choose their exact SOC toolchain and app-store
  requirements.
- Add native desktop collectors beyond the current protected-upload shell
  action, metadata-only endpoint handoff, named file-flow profile watchers,
  one-shot clipboard guard, and local git pre-push guard.
- Add deeper desktop/file-flow collection once protected upload needs to expand
  into app-specific upload paths.

## Recent Completed Passes

- Rebrand the visible project from PromptWall/PromptSentinel to RedactWall.
- Add provider-specific Microsoft Entra and Okta identity setup handoff through
  the dashboard Identity tab, an authenticated secret-free API, and
  `npm run identity:setup`, so SCIM/OIDC pilot setup has exact callback, issuer,
  role-group, and preflight values without exposing tokens or client secrets.
- Extend destination-scoped browser action controls from paste-only to
  drag-and-drop file uploads, with sanitized `action_blocked` evidence before
  the browser reads file bytes.
- Move browser text upload inspection into the extension so managed browser
  uploads report only sanitized labels and masked findings to `/api/v1/gate`
  without sending file bytes, raw filenames, or `contentBase64` to the control
  plane.
- Extend destination-scoped browser action controls to AI response copy events,
  with sanitized `action_blocked` evidence before selected response text reaches
  the clipboard.
- Extend destination-scoped browser action controls to browser downloads, with
  host-only `action_blocked` evidence and no raw filename, URL, MIME, or file
  bytes in the control plane.
- Add a sanitized approval ticket bridge with deterministic dedupe keys,
  ticket system/project metadata, and no prompt bodies so Jira, Linear, SOAR, or
  internal middleware can create reviewer-owned tickets from the approval
  workflow.
- Add native Jira and Linear issue-creation adapters that reuse the same
  sanitized workflow summary and description when a customer does not want to
  operate ticket middleware.
- Add a one-shot endpoint clipboard guard that inspects locally, reports only
  masked findings as `paste_flagged`, and can clear sensitive clipboard content
  while recording sanitized `action_blocked` evidence.
- Add owner group, reviewer role, review-after metadata, dashboard builder
  fields, and sanitized examiner evidence for time-bound exception lifecycle
  review.
- Rename the endpoint installer surface to `-RedactWallUrl` while keeping
  `-SentinelUrl` as a compatibility alias for existing technician scripts.
- Rename fresh endpoint runner config handoff to `REDACTWALL_ENV_PATH` while
  keeping `REDACTWALL_ENV_PATH` accepted for existing installs.
- Add a browser extension release-readiness gate and managed release checklist
  so Chrome, Edge, and Firefox rollouts have packages, policies, update or
  install URLs, generated ExtensionSettings force-install policies, and
  install-health evidence before handoff.
- Add guided Policy-tab builders for common scoped enforcement rules and
  time-bound exceptions while preserving exact JSON review before save.
- Add a dashboard Lineage tab backed by `/api/lineage` so admins and auditors
  can see which users, sensors, destinations, channels, categories, and
  decisions were involved without retaining sensitive content.
- Add Policy-tab response scanning controls so `/api/v1/scan-response` can
  flag, redact, or block sensitive AI replies while storing only sanitized
  evidence.
- Add destination-scoped browser paste, file-drop, response-copy, and download
  blocking so admins can stop high-risk browser actions in selected AI tools
  while storing only sanitized `action_blocked` evidence.
- Make local browser blocks evidence-aware: sends, sensitive paste blocks,
  destination/file-upload blocks, file-drop blocks, response-copy blocks, and
  download blocks now only claim a recorded decision after the control plane
  returns the expected evidence id and status.
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
  deactivation, group membership patches, audit entries, and RedactWall group
  display names mapped onto local route roles.
- Add SCIM-backed OIDC console login that validates authorization-code
  callbacks, state, nonce, RS256 ID-token signatures, issuer, audience, expiry,
  and active provisioned users before issuing normal RedactWall sessions.
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
- Preserve legacy canary token compatibility while adding the RedactWall canary
  prefix.
- Add tested `REDACTWALL_*` runtime aliases so new RedactWall deployments can
  use the renamed prefix without breaking existing `PROMPTWALL_*`/`SENTINEL_*` installs.
- Issue fresh admin sessions as `redactwall_session` while accepting legacy
  `promptwall_session`/`sentinel_session` cookies during migration, and clear all
  cookie names on logout.
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
- Expand the sanitized examiner evidence export with full-history coverage
  posture, sensor versions, parsed policy history, and prompt/file lineage
  summaries by user, destination, sensor, category, channel, and decision.
- Add customer-defined detector packs plus an `ocr_required` file outcome so
  pilots can model local member IDs and scanned/image uploads before shipping a
  packaged endpoint OCR binary and install workflow.
- Add an optional endpoint-local OCR command bridge so configured workstations
  can inspect image files locally while server-side uploads still fail closed as
  `ocr_required` and evidence remains sanitized.
- Add endpoint install validation heartbeats so technicians can prove endpoint
  env, runtime, watch directory, and native handoff readiness in Coverage and
  examiner evidence without exposing keys or prompt/file content.
- Add sanitized endpoint AI tool inventory to install-health heartbeats and
  surface it in Coverage, dashboard posture, and examiner evidence by stable id
  without uploading paths, process args, prompts, or files.
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

Microsoft. "Microsoft Purview data security and compliance protections for
Microsoft 365 Copilot and other generative AI apps." *Microsoft Learn*,
https://learn.microsoft.com/en-us/purview/ai-microsoft-purview. Accessed 4 July
2026.

Microsoft. "Learn about Microsoft Purview Data Security Posture Management
(DSPM)." *Microsoft Learn*,
https://learn.microsoft.com/en-us/purview/data-security-posture-management-learn-about.
Accessed 4 July 2026.

Microsoft. "Use Microsoft Purview to manage data security & compliance for
other AI apps." *Microsoft Learn*,
https://learn.microsoft.com/en-us/purview/ai-other-apps. Accessed 4 July 2026.

Netskope. "AI Security." *Netskope Knowledge Portal*,
https://docs.netskope.com/en/ai-security/. Accessed 4 July 2026.

Netskope. "AI Guardrails Dashboard." *Netskope Knowledge Portal*,
https://docs.netskope.com/en/ai-guardrails-dashboard. Accessed 4 July 2026.

Netskope. "Securing AI with Netskope One." *Netskope*,
https://www.netskope.com/solutions/netskope-one-ai-security. Accessed 4 July
2026.

Nightfall AI. "AI applications." *Nightfall AI*,
https://www.nightfall.ai/integrations/ai-applications. Accessed 4 July 2026.

Zscaler. "Securely Use Generative AI with Zscaler Zero Trust Exchange."
*Zscaler*, https://www.zscaler.com/products-and-solutions/securing-generative-ai.
Accessed 4 July 2026.

SentinelOne. "Prompt Security." *SentinelOne AI Security Platform*,
https://www.sentinelone.com/platform/securing-ai-prompt/. Accessed 4 July 2026.

OWASP. "LLM01:2025 Prompt Injection." *OWASP GenAI Security Project*,
https://genai.owasp.org/llmrisk/llm01-prompt-injection/. Accessed 4 July 2026.

Splunk. "Format events for HTTP Event Collector." *Splunk Enterprise
Documentation*, https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/get-data-with-http-event-collector/format-events-for-http-event-collector.
Accessed 4 July 2026.

Microsoft. "Custom data ingestion and transformation in Microsoft Sentinel."
*Microsoft Learn*, https://learn.microsoft.com/en-us/azure/sentinel/data-transformation.
Accessed 4 July 2026.

Google Cloud. "UDM overview." *Google Security Operations Documentation*,
https://docs.cloud.google.com/chronicle/docs/event-processing/udm-overview.
Accessed 4 July 2026.

ServiceNow. "Table API." *ServiceNow REST API Reference*,
https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html.
Accessed 4 July 2026.

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

"Nightfall AI Technical Research Report." Competitive research report (internal;
public-documentation analysis of nightfall.ai, help.nightfall.ai, and the
Developer Platform). Accessed 5 July 2026.

OWASP Foundation. "OWASP Top 10 for Large Language Model Applications." *OWASP
GenAI Security Project*, OWASP Foundation, https://genai.owasp.org/llm-top-10/.
Accessed 28 June 2026.

Strac. "Browser DLP (Data Loss Prevention)." *Strac*, Strac,
https://www.strac.io/integration/browser-dlp. Accessed 28 June 2026.

Strac. "Chrome DLP (Data Loss Prevention)." *Strac*, Strac,
https://www.strac.io/integrations/chrome-dlp. Accessed 28 June 2026.

Strac. "ChatGPT DLP." *Strac*, Strac,
https://www.strac.io/integration/chatgpt-dlp. Accessed 28 June 2026.
