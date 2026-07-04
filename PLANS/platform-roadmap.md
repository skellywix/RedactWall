# PromptWall Platform Roadmap: From AI DLP Control Plane to Regulated AI Security Platform

## Summary

PromptWall is already a strong local-first AI DLP control plane. The goal now is
to advance it into a credible **regulated-market AI security platform** — the
bundle competitors advertise: gateway enforcement, AI app discovery, prompt and
response governance, SaaS/agent coverage, posture management, identity
lifecycle, packaged rollout, and compliance evidence.

The differentiator is not "better prompt scanner." It is that a regulated credit
union can prove — to an examiner — that prompts, files, model responses, agent
tool outputs, and AI app usage are all governed by **one policy, one
privacy-preserving evidence trail, and one operator console** across browser,
desktop, private LLM apps, SaaS connectors, and MCP agents. We win where the
platform incumbents are weak: local-first inference (no prompt egress),
tamper-evident hash-chained evidence, signed proof-of-scan receipts, and a
deployable-in-an-afternoon story — while reaching feature parity on the surfaces
buyers now expect.

### Competitor bar (evidence basis)

- **Netskope AI Gateway** — intercept layer between agents/apps and LLMs with
  auth, rate limits, prompt/response filtering, moderation, DLP, searchable API
  logs, authenticated agent tokens, unified control across OpenAI/Gemini/Claude.
- **Zscaler GenAI** — dashboards, prompt-level visibility, app allow/deny,
  browser interaction controls, DLP blocking across GenAI interactions.
- **Microsoft Purview DSPM for AI** — posture management for Copilots, agents,
  third-party AI apps; risky prompt/response capture; regulatory control mapping;
  adaptive protection.
- **Microsoft Defender app catalog** — large app catalog, traffic-log discovery,
  shadow-IT visibility, risk scores, custom apps, app-review workflow.
- **Nightfall** — coverage across SaaS/endpoint/email/browser/AI apps/custom
  LLMs, 100+ file types including images, OCR/computer vision, EDM, API/SDK,
  employee remediation.

---

## Current baseline (honest starting point, updated)

What already exists in the repo, so this plan builds on reality, not aspiration:

| Area | Shipped today |
| --- | --- |
| Detection engine | Regex+validator PII; on-device logistic-regression semantic classifier; **prompt-attack/jailbreak intent (`PROMPT_ATTACK`)**; **international PII (UK/CA/AU/IN) with real checksums**; **Exact Data Match via salted fingerprints (`EXACT_MATCH`)**; expanded secrets; **tiered confidence**; unicode-injection stripping. Byte-identical browser copy via `sync-engine`. |
| Enforcement | block / redact(tokenize+local rehydrate) / warn / justify / approve; hard-stop `alwaysBlock`; policy scopes + time-bound exceptions; response scanning (`/api/v1/scan-response`); MCP tool-output guard. |
| Gateway primitives | `/api/v1/gate`, `/api/v1/scan-response`, `/api/v1/rehydrate`, `/api/v1/status/:id`, release tokens, fail-closed sensor policy cache, Squid/ICAP bridge script. **No first-class reverse-proxy LLM gateway service yet.** |
| Discovery | Shadow-AI events; coverage posture; **AI app-risk catalog (`server/ai-app-catalog.js`)** with trains-on-data / personal-tier / data-residency attributes. **Catalog is static + in-memory; no persistence, ingestion, or review workflow yet.** |
| Console | 10 tabs incl. **new Insights dashboard** (`/api/insights`): activity-over-time, decision mix, risk distribution, top data types, categories, destinations w/ risk, shadow-AI by provider, top users. Dependency-free SVG charts. |
| Sensors | Browser MV3 extension; endpoint agent (protected-upload, clipboard-guard, ai-tool-inventory, metadata-only native handoff); MCP guard + connector SDK (Microsoft 365 only). |
| Enterprise | Local admin + distinct approver/auditor; OIDC; SCIM 2.0; RBAC; TOTP MFA + password step-up; hash-chained audit; signed safe-to-send receipts; single SIEM webhook (`schemaVersion 1`); notifiers (Slack/Teams/Jira/Linear/SMTP/webhook); retention purge; AES-256-GCM at rest; customer-silo AWS. |
| Compliance | Evidence pack with control mappings for GLBA/NCUA/HIPAA/PCI **plus new AI-framework mappings** (NIST AI RMF, ISO 42001, EU AI Act, OWASP LLM Top 10, MITRE ATLAS). |
| Data store | `better-sqlite3` single-node. Customer-silo only; no shared multi-tenant. |
| OCR | `ocr.js` bridge exists but unbundled (needs `ENDPOINT_AGENT_OCR_COMMAND`). |

Everything below is sequenced so each slice is independently deployable and
provable, and so no slice weakens the audit/privacy guarantees the product sells.

---

## Non-negotiable invariants (apply to every slice)

1. **Fail closed where enforcement is promised.** If the control plane, gateway,
   or a required scan is unavailable, the governed path blocks — it never
   silently allows. Every fail-open branch is an explicit, audited, policy-gated
   decision.
2. **Prompt-free by default.** Dashboards, logs, SIEM/SOAR payloads, catalog
   entries, evidence packs, posture APIs, and delivery history carry masked
   findings, hashes, and bounded metadata — never raw prompt/file/response/OCR
   content — unless approval retention is explicitly enabled and encrypted.
3. **One engine, synced.** Detector logic lives in `detection-engine/detect.js`;
   `npm run sync-engine` regenerates the browser copy; `sync-check` gates parity.
   Never hand-edit the sensor copy.
4. **Stable detection-engine public API.** All sensors depend on it; additive
   changes only.
5. **Hot path stays cheap.** Allocation-light, no catastrophic regex; the gate
   runs on every keystroke and paste.
6. **Examiner-ready.** Every new capability that produces evidence maps to a
   control family and appears in the evidence pack.

---

## Milestones (deployable slices, in order)

- **M1 — Platform Core:** AI Gateway service + persistent App Catalog & review
  workflow + posture subscriptions with delivery history. These are the clearest
  competitor-backed gaps and together constitute the first "platform" proof.
- **M2 — Coverage Depth:** desktop file-flow collectors + two more first-party
  connectors + turnkey OCR.
- **M3 — Trust & Scale:** signed/versioned sensor policy bundles + identity
  lifecycle hardening + commercial extension rollout + compliance packaging.
- **M4 — Scale-Out (staged):** on-device semantic (ONNX/WASM) model path +
  Postgres multi-tenant control plane + HA/DR.

Detailed priorities follow; each notes competitor parity, the PromptWall build,
the "better than" angle, and acceptance.

---

## Priority 1 — Production AI Gateway (M1)

**Competitor bar:** Netskope AI Gateway intercepts agent/app→LLM traffic with
auth, rate limits, prompt/response filtering, logging, moderation, DLP;
authenticated agent tokens; unified across providers.

**What we build.** Promote the existing gate primitives into a first-class
deployable reverse-proxy service, `gateway/` (own process, shares
`detection-engine` and calls the control plane).

- **Service shape.** `gateway/server.js` exposes an OpenAI-compatible surface
  (`POST /v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, streaming
  via SSE). A `gateway/adapters/` seam normalizes request/response for
  `openai`, `anthropic`, `azure-openai`, `bedrock`, and `internal-http` so one
  policy governs all. Adapter interface: `toCanonical(req)`,
  `fromCanonical(upstreamResp)`, `streamTransform(chunk)`.
- **Request path (fail-closed).** Extract prompt/messages → call control plane
  `/api/v1/gate` → on `block`/`pending` return a structured refusal (or hold +
  `/api/v1/status/:id` poll) **before any upstream call**; on `redact` forward
  the tokenized prompt and keep the vault id; on `allow` forward with a signed
  receipt header (`x-promptwall-receipt`).
- **Response path (fail-closed).** Buffer or stream-scan the upstream response
  through `/api/v1/scan-response`; block/redact model output before it reaches
  the caller; auto-`/api/v1/rehydrate` tokenized responses using the sealed
  vault so the caller gets real values only after the scan passes.
- **Streaming.** Scan on a sliding window with a bounded look-back buffer;
  hold-and-release chunks so a leak mid-stream is caught before egress. If the
  scanner can't keep up, the stream fails closed (truncate + refusal event).
- **Auth & limits.** Per-caller **agent tokens** (scoped, revocable, mapped to a
  managed identity + orgId; issued/rotated from the console, stored hashed).
  Per-token and per-org **rate limits** and **max-body** guards. Every request
  carries orgId + agent identity into evidence.
- **Ops.** `/healthz` (self), `/readyz` (control-plane reachable + policy fresh),
  structured request logs (prompt-free: decision, risk, findings-count,
  latency, upstream, token id), Prometheus-style `/metrics`, config via env +
  `gateway/config.example.json`, Docker service in compose, operator runbook
  `docs/AI_GATEWAY.md`.

**Better than competitors:** the gateway inherits PromptWall's on-device
detection and **hash-chained receipts** — every gated request produces a signed,
prompt-free proof-of-scan the caller (or examiner) can verify later, which the
network-proxy incumbents don't offer. And it's deployable as a single container
next to an app, not a SASE rollout.

**Acceptance.**
- Private app traffic cannot reach upstream until PromptWall gates it (integration
  test: gateway with control plane stopped → request blocked, not forwarded).
- Model output cannot reach the caller until response scanning passes (test:
  upstream returns seeded SSN → gateway blocks/redacts before returning).
- Streaming leak caught mid-stream (test: upstream streams a secret in chunk 3 →
  stream fails closed by chunk 3-4, not after completion).
- Agent token revocation takes effect within policy TTL; unauthenticated request
  rejected.

---

## Priority 2 — Shadow AI Discovery & App Catalog (M1)

**Competitor bar:** Defender/Netskope/Purview ship large app catalogs with
traffic-log discovery, risk scores, sanctioned status, custom apps, and review
workflow.

**What we build.** Promote the static `server/ai-app-catalog.js` into a
persistent, reviewable catalog.

- **Schema (`ai_apps` table / `server/app-catalog.js`).** `id, canonicalHost,
  aliases[], appName, provider, category, riskTier(1-4), riskAttributes{trains
  OnData, personalTier, dataResidency, certs[]}, sanctionedStatus(sanctioned|
  tolerated|unsanctioned|blocked|under_review), owner, notes, firstSeen,
  lastSeen, evidenceSources[], eventCount`. Ships seeded from the current
  reviewed catalog; operator-editable.
- **Ingestion sources → `server/discovery.js`.** (1) browser sightings
  (existing shadow-AI events), (2) gateway logs, (3) **DNS/proxy CSV import**
  (`POST /api/discovery/import`, bounded, dedup by canonical host), (4) endpoint
  AI-tool inventory, (5) MCP connector endpoints, (6) manual entry. Each sighting
  is prompt-free (host + count + first/last seen + source), matched to a catalog
  entry via the existing `normalizeHost`/alias logic.
- **Review workflow.** `GET/POST /api/catalog`, `/api/catalog/:id/review`
  (govern | allow | block | mark-sanctioned | assign-owner). A decision writes
  policy (governed/allowed/blocked destinations) atomically, is audited, and
  emits a posture event. Surfaced as a new **App Catalog** console tab and woven
  into the Insights "Top Destinations" and shadow-AI panels.
- **Risk scoring.** Deterministic score from attributes (trains-on-data +
  personal-tier + non-US residency + unsanctioned) so it's explainable to an
  examiner — no opaque ML score.

**Better than competitors:** discovery evidence is **prompt-free by
construction** and the risk score is a transparent, examiner-defensible formula
rather than a black box. CSV import means it works from an existing
proxy/firewall log with zero new network infrastructure.

**Acceptance.**
- New AI app usage (browser sighting, gateway log, or CSV row) creates a
  prompt-free catalog entry and evidence.
- An operator can govern/allow/block/queue an app; the decision updates policy,
  is audited, and changes enforcement on the next sensor policy refresh.
- Catalog and discovery APIs pass the prompt-free regression test.

---

## Priority 3 — Posture, SIEM/SOAR & Compliance Packaging (M1→M3)

**Competitor bar:** Purview posture management + regulatory mappings; broad SIEM
export (Sentinel/Splunk/Chronicle/QRadar/Datadog) and SOAR/ticket integration.

**What we build.**

- **Posture subscriptions (`server/subscriptions.js`, M1).** Named destinations
  (Sentinel, Splunk HEC, Chronicle, QRadar, Datadog, Slack/Teams, Jira/
  ServiceNow, generic SOAR webhook), each with filters (min risk/severity, event
  types), an **outbound queue with retry + exponential backoff + dedupe key**,
  **delivery history** (status, attempts, last error — no payload bodies), and a
  console **delivery dashboard**. Reuse `url-policy.js` HTTPS enforcement and the
  existing sanitized `alerts.js` shape; bump to `schemaVersion 2` with an
  explicit versioned event contract (`docs/EVENT_SCHEMA.md`).
- **Two-way ticket state (M3).** Where the connector supports it (Jira/
  ServiceNow), poll/receive ticket status back onto the query so an approval's
  external lifecycle is visible — metadata only.
- **Compliance packaging (M3).** Expand evidence packs with SOC 2 readiness
  matrix, SBOM (from `package-lock`), vulnerability/patch policy, DPA/BAA
  posture, GLBA/NCUA control mappings (already partly present), incident-response
  runbook pointer, retention/legal-hold state, and a security whitepaper
  artifact. All generated, prompt-free, examiner-addressed.

**Better than competitors:** every exported event and posture artifact is
prompt-free by default and cross-checkable against the hash-chained audit log —
an examiner can verify the SIEM stream wasn't edited. Delivery history is itself
tamper-evident.

**Acceptance.**
- A customer can subscribe a SIEM/SOAR destination and see delivery history with
  retries; a forced failure retries and surfaces the error without leaking
  payloads.
- Evidence pack exports the expanded artifact set; privacy regression confirms no
  raw content.

---

## Priority 4 — Desktop / File-Flow Coverage (M2)

**Competitor bar:** Nightfall/Purview cover endpoint file flows into AI apps,
including images.

**What we build.** Extend the endpoint agent beyond protected-upload and
clipboard into **app-specific file-open/upload/drag-drop evidence** for ChatGPT
Desktop, Claude Desktop, Copilot, Cursor, and common agent tools.

- Per-app collectors under `sensors/endpoint-agent/collectors/` using OS file
  events + the app-inventory signatures already present; each intercept scans
  locally via `scanFile`/`processors.js`, blocks or redacts before app delivery,
  and reports **masked findings + file type + app identity + outcome** only.
- File content stays local; raw retained only when approval retention is
  explicitly enabled and encrypted (existing crypto path).
- Report into Coverage/Posture as a required sensor with health checks.

**Better than competitors:** metadata-only handoff contract (already HMAC-signed)
means desktop coverage produces examiner evidence without a raw-content DLP data
lake.

**Acceptance.** A synthetic PDF/image/source file dragged into a covered AI app
is blocked or redacted before delivery, with sanitized evidence and a coverage
health signal.

---

## Priority 5 — SaaS & Agent Connectors (M2)

**Competitor bar:** deep first-party SaaS coverage (M365, Drive, GitHub, Slack).

**What we build.** 2–3 high-value first-party connectors on the existing MCP
connector SDK (`sensors/mcp-guard/sdk.js`), not 30 shallow ones: **deepen
Microsoft 365** (SharePoint/OneDrive beyond driveItem text), add **Google
Drive**, and add **GitHub or Slack**. Each sanitizes tool output before model
delivery via `sanitizeToolResult`/`wrapConnectorTool` and reports connector
health into Coverage/Posture. A Google Drive MCP server is available in this
session for building/testing the Drive connector against real API shapes.

**Acceptance.** MCP/tool-output protection is proven with a real sanitized
connector smoke per connector (seeded sensitive content in a fetched doc →
sanitized before it reaches the model), plus connector health in posture.

---

## Priority 6 — Detection Quality & OCR (M2→M4)

**Competitor bar:** Nightfall OCR/computer vision on images; Harmonic fine-tuned
SLMs.

**What we build.**

- **Turnkey OCR (M2).** Packaged OCR install/check flow (bundled tesseract WASM
  or a vetted binary) so `ENDPOINT_AGENT_OCR_COMMAND` is set up by the installer,
  with `endpoint:check` verifying it. Closes the screenshot/image-paste bypass.
- **On-device semantic upgrade (M4).** Add an ONNX/WASM small-model path behind
  the existing `classifySemantic` seam (max-combine with current heuristics +
  logistic regression), for confidential-business, contracts, source code,
  credentials, insider-risk language, and document context. Keep the current
  zero-dependency model as fallback; ship both so there's no regression.
- **Eval discipline (always).** Every detector/model change extends
  `test/fixtures/semantic-eval.json` and must hold the floors: semantic
  precision ≥0.90, recall ≥0.70, **benign FP = 0**, structured recall ≥0.95,
  **bait FP = 0**. New categories get held-out positives + hard negatives.

**Better than competitors:** the SLM path stays **on-device** (no prompt egress),
unlike cloud-inference detection — a data-residency win — while the eval gate
keeps false positives at zero so the control stays switched on.

**Acceptance.** OCR is turnkey for endpoint installs (installer + check pass);
semantic detection has held-out evals with explicit false-positive gates that
CI enforces.

---

## Priority 7 — Identity, Policy Bundles, Rollout & Scale (M3→M4)

**Competitor bar:** enterprise identity lifecycle, managed extension rollout,
scalable multi-tenant control plane.

**What we build.**

- **Identity lifecycle (M3).** Harden SCIM/OIDC: durable provisioned-identity
  state, deactivation → session/seat revocation, seat lifecycle, MFA
  enrollment/recovery flow, step-up reauth as a dedicated flow (not inline).
- **Signed/versioned sensor policy bundles (M3).** A signed, versioned policy
  bundle (`server/policy-bundle.js`, Ed25519 or HMAC over canonical policy +
  version + issuedAt + expiry) that browser/endpoint/MCP sensors verify and
  evaluate **locally**, with offline expiry and fail-closed rules when a bundle
  is stale or unverifiable. Moves scope evaluation to the sensor edge.
- **Commercial extension rollout (M3).** Stable extension IDs; Chrome/Edge/
  Firefox publishing checklist; MDM force-install packets (existing managed
  schema); signed update flow + rollback; adoption dashboard (from heartbeats);
  tamper guidance.
- **Scale-out (M4, staged).** Postgres backend behind the current db seam with
  migrations, row-level tenant isolation, HA, backup/restore drills, key
  rotation, immutable audit, load/soak + chaos-recovery tests. Preserve the
  audit-chain and prompt-free guarantees through the migration (the hard part —
  do it deliberately, not half-way).

**Acceptance.** Deactivating an IdP user revokes sessions/seat; a stale/forged
policy bundle makes sensors fail closed; extension force-install + signed update
+ rollback verified; Postgres path passes concurrency/restart/backup-restore and
audit-chain verification under load.

---

## Test Plan

- **Unit/integration** for each new gateway adapter, catalog/discovery path,
  subscription delivery path, connector, policy-bundle verify, and identity
  lifecycle transition.
- **End-to-end synthetic smokes**: browser gate; endpoint desktop file-flow;
  gateway request+response (incl. streaming leak); MCP connector sanitization;
  evidence export; SIEM/SOAR delivery with retry.
- **Privacy regression** (extend the existing pattern): dashboards, logs,
  SIEM/SOAR payloads, catalog entries, discovery imports, gateway logs, evidence
  packs, and posture APIs never expose raw prompt/file/response content by
  default. Assert on real payloads, not just code review.
- **Fail-closed regression**: control plane down → gateway blocks; policy bundle
  stale → sensors block; scanner backpressure → stream truncates. Each is an
  explicit test, because fail-open is the most dangerous silent regression.
- **Production-readiness**: throughput, latency, queue backpressure, DB
  concurrency, service restart recovery, offline endpoint retry, large
  evidence-store export, audit-chain verification, gateway streaming under load.
- **Detector eval floors** enforced in CI on every engine change (see Priority 6).

---

## Sequencing rationale & assumptions

- **First platform slice = Gateway + Discovery/Catalog + Posture subscriptions
  (M1),** because those are the clearest competitor-backed platform gaps and
  together they let us say "PromptWall is a platform," not a point product.
- Desktop file-flow, connectors, and OCR (M2) deepen coverage once the platform
  spine exists.
- Trust/scale hardening (M3) and the heavy scale-out items — ONNX/WASM semantic
  models and Postgres multi-tenancy (M4) — are staged **after** the first
  deployable platform proof is stable, so we don't half-build the migration and
  weaken the audit/privacy guarantees we sell.
- Priority remains **regulated credit-union pilots**, not day-one enterprise
  parity on every connector.
- The durable differentiator stays **local-first detection, prompt-free evidence
  by default, fail-closed enforcement, simple deployment, and an
  examiner-friendly story** — every slice above is designed to reinforce it, not
  trade it away for breadth.
