# PromptWall Competitive Benchmark (2026)

This document compares PromptWall to the three industry-leading GenAI-DLP /
AI-usage-governance products and records the capabilities added to bring
PromptWall to parity-or-better on the "employees using AI tools safely" use
case. It is a feature benchmark, not a marketing claim; every PromptWall row
below is backed by code in this repository and by the test gate (`npm run
review:ci`).

## The field

Gartner now tracks this as a distinct **AI Usage Control** market, separate from
model-side guardrails. The three leaders for the workforce use case:

1. **Prompt Security (SentinelOne)** — broadest purpose-built coverage
   (browser + endpoint + gateway + IDE + MCP); semantic redaction; MCP gateway.
2. **Harmonic Security** — pre-egress detection quality via fine-tuned small
   language models; the most explicit compliance-framework mappings
   (NIST AI RMF, ISO 42001, EU AI Act, OWASP LLM Top 10); app-risk catalog.
3. **Nightfall AI** — the strongest pure-detection story: 100+ ML detectors,
   Exact Data Match (EDM), image/OCR, tiered confidence, broad SaaS coverage.
   Now a five-pillar platform (SaaS DLP, exfiltration prevention, discovery/
   audit, Gmail encryption, developer APIs) plus **MCP & AI Agent Security**
   (IDE/CLI hooks for Cursor/Claude Code/VS Code, shell-command blocking,
   shadow-MCP discovery, OpenTelemetry audit trails, Claude Compliance API) and
   **Nyx**, an LLM "autonomous DLP analyst." Cloud-required and US-only hosted;
   monitor-only for raw LLM responses; customer API rate-limited to 5–10 rps.

Runners-up referenced for specific features: WitnessAI (intent classification,
allow/warn/block/route), Microsoft Purview DSPM for AI (adaptive protection,
personal-vs-corporate account), Netskope (real-time coaching, app-risk index).

## Where PromptWall already led

- **Fully on-device detection.** No prompt text leaves the org for
  classification — the semantic classifier, PII detectors, and now EDM and
  prompt-attack intent all run locally. Prompt Security, Harmonic, and Nightfall
  all perform at least some inference in their cloud. This is a privacy and
  data-residency advantage PromptWall keeps.
- **Tamper-evident evidence.** Hash-chained audit log plus signed, prompt-free
  "safe-to-send" receipts that an examiner can verify after the fact. None of
  the three publish an equivalent cryptographic proof-of-scan.
- **One engine, three sensors, one policy.** The same `detection-engine/`
  drives the browser extension, endpoint agent, and MCP guard, byte-identical.

## Capabilities added in this work

Each closed a specific gap versus a named leader.

| Capability | Leader that had it | PromptWall now | Where |
| --- | --- | --- | --- |
| Prompt-injection / **jailbreak intent** detection (direct + indirect) | Prompt Security, WitnessAI, Lakera | `PROMPT_ATTACK` category — instruction-override, persona-jailbreak, guardrail-bypass, and "AI reading this" indirect-injection signals, on prompts **and** AI responses **and** MCP tool output | `detection-engine/detect.js`, `test/prompt-attack.test.js` |
| **International PII** with real checksums | Nightfall (100+ detectors) | UK NINO, UK NHS (mod-11), Canada SIN (Luhn), Australia TFN (weighted mod-11), India Aadhaar (Verhoeff) + India PAN, all context-anchored | `detection-engine/detect.js`, `test/international-pii.test.js` |
| **Exact Data Match (EDM)** | Nightfall | On-device salted one-way fingerprints — the org's watchlist plaintext never reaches a sensor; a `edm:fingerprint` CLI builds the list and discards the plaintext | `server/exact-match.js`, `scripts/edm-fingerprint.js`, `test/exact-match.test.js` |
| Expanded **secrets** coverage | Nightfall, Prompt Security | npm, Hugging Face, DigitalOcean, Shopify, Twilio, PyPI tokens added to the secret detector | `detection-engine/detect.js` |
| **Tiered confidence** (Possible / Likely / Very Likely) | Nightfall | Every finding carries `confidence` / `confidenceLabel`; surfaced in the gate API and console | `detection-engine/detect.js`, `server/app.js` |
| **AI-governance compliance mappings** | Harmonic | NIST AI RMF, ISO/IEC 42001, EU AI Act (Art. 12), OWASP LLM Top 10, MITRE ATLAS mapped in the examiner evidence pack | `server/control-map.js` |
| **App-risk catalog** (trains-on-data / personal-tier / data-residency) | Harmonic, Netskope, Palo Alto | Reviewed risk metadata per AI destination, surfaced on shadow-AI and Insights views | `server/ai-app-catalog.js`, `server/coverage.js` |
| **AI-usage analytics dashboard** with charts | Prompt Security, Netskope, Purview | New Insights tab: activity-over-time, decision mix, risk distribution, top data types, sensitive categories, top destinations with risk attributes, shadow-AI by provider, highest-risk users | `server/insights.js`, `/api/insights`, `server/public/` |

## Head-to-head matrix

Legend: ● full · ◐ partial · ○ none.

| Capability | PromptWall | Prompt Sec. | Harmonic | Nightfall |
| --- | :---: | :---: | :---: | :---: |
| Structured PII detection (regex + validators) | ● | ● | ● | ● |
| International PII with checksums | ● | ● | ◐ | ● |
| Secrets / API-key detection | ● | ● | ◐ | ● |
| Semantic / business-context classification | ● | ● | ● | ● |
| Prompt-injection + jailbreak intent | ● | ● | ◐ | ◐ |
| Indirect injection (docs / tool output) | ● | ● | ◐ | ◐ [1] |
| Secrets vendor labeling | ● | ◐ | ○ | ● |
| Document-class categories (financials, tax, HR) | ● | ◐ | ◐ | ● |
| Exact Data Match | ● | ◐ | ○ | ● |
| Tiered confidence levels | ● | ◐ | ◐ | ● |
| On-device inference (no prompt egress) | ● | ◐ | ◐ | ○ |
| Redact / tokenize + local rehydration | ● | ● | ◐ | ● |
| Block / warn / justify / approve | ● | ● | ● | ◐ |
| Response (model-output) scanning | ● | ● | ◐ | ◐ [2] |
| Personal-vs-corporate AI account detection | ● | ◐ | ◐ | ○ |
| Coding-agent hooks (prompts, shell, MCP calls) | ● | ◐ | ○ | ● |
| Shadow-MCP server discovery | ● | ○ | ○ | ● |
| Browser sensor | ● | ● | ● | ● |
| Endpoint sensor | ● | ● | ◐ | ◐ |
| MCP / agent tool-output guard | ● | ● | ● | ◐ [3] |
| API/agent gateway (fail-closed prompt + response) | ● | ● | ◐ | ◐ [2] |
| OpenTelemetry / OTLP event export | ● | ○ | ○ | ● |
| Reviewable app catalog + one-click govern | ● | ◐ | ● | ● |
| Multi-target SIEM/SOAR subscriptions + delivery history | ● | ◐ | ◐ | ● |
| Signed edge-verified policy bundles | ● | ○ | ○ | ○ |
| Shadow-AI discovery | ● | ● | ● | ● |
| App-risk attributes (trains-on-data, tier, residency) | ● | ◐ | ● | ◐ |
| AI-usage analytics dashboard | ● | ● | ● | ● |
| User risk scoring | ● | ● | ● | ◐ |
| SSO / SCIM / RBAC / MFA | ● | ● | ◐ | ◐ |
| Tamper-evident hash-chained audit | ● | ○ | ○ | ○ |
| Signed proof-of-scan receipts | ● | ○ | ○ | ○ |
| Compliance mappings incl. AI frameworks | ● | ◐ | ● | ◐ |
| Examiner evidence export | ● | ◐ | ● | ◐ |

Notes:

- **[1]** Nightfall's agent hooks let it scan tool responses, but it does not
  sanitize MCP tool output *before the model consumes it* the way PromptWall's
  MCP guard `sanitizeToolResult()` does.
- **[2]** Nightfall is **monitor-only for raw LLM responses** — it can alert but
  not block a bad model response. PromptWall's gateway returns `403` on a
  blocked response (`gateway/server.js` `BLOCK_STATUSES` / `responseBlocked`).
- **[3]** Nightfall now hooks agent actions and discovers shadow MCP servers,
  but its tool-output handling is detection/alerting, not pre-model
  sanitization.

## Nightfall AI Agent Security vs PromptWall

Nightfall's newest pillar and PromptWall's equivalents:

| Nightfall | PromptWall |
| --- | --- |
| IDE/CLI hooks (Cursor, Claude Code, VS Code) scan+block prompts, shell commands, MCP tool calls | `sensors/agent-hooks/` — Claude Code `UserPromptSubmit` + `PreToolUse` (Bash + `mcp__*`) hooks, decided on-box; blocks locally, reports label-only |
| Shadow-MCP discovery (local stdio + remote) | `sensors/endpoint-agent/collectors/mcp-inventory.js` — enumerates MCP server configs across clients, metadata-only, unapproved-server posture |
| Monitor-only for raw LLM responses | Gateway **blocks** streamed responses (`403`), not just alerts |
| OpenTelemetry audit trails | `otlp` subscription type streams AI activity to any OTel collector |
| Content flows through Nightfall's US-only AWS | Zero egress — detection is in-process on-device |

Genuine gaps we still concede (see below): a Nyx-class LLM analyst, and
Nightfall's Claude Compliance API tenant ingestion.

## Honest remaining gaps

These are deliberately not yet built and are called out so the benchmark stays
truthful:

- **CV-model OCR depth.** The endpoint agent now bundles an offline WASM OCR
  engine, so screenshots and document scans are read on-box with no configured
  command and no egress. Nightfall's CV transformers still go deeper on hard
  inputs — photos, handwriting, and heavily-degraded scans — and PromptWall's OCR
  stays endpoint-only (server-side images remain `ocr_required` by design).
- **Fine-tuned SLM detectors.** Harmonic's per-category small language models
  generalize further than PromptWall's logistic-regression classifier on novel
  phrasings. PromptWall trades some recall on unseen paraphrases for zero
  dependencies and a few-KB model.
- **"Route to sanctioned model" enforcement.** WitnessAI can redirect a risky
  prompt to an approved internal LLM. PromptWall blocks/redacts but does not yet
  proxy to an alternate model.
- **LLM security analyst.** Nightfall's Nyx investigates incidents and drafts
  reports via natural language. PromptWall surfaces analytics and evidence packs
  but has no built-in agentic analyst — and, by design, never sends prompts to
  any LLM.
- **Sanctioned-tenant compliance ingestion.** Nightfall ingests the Claude
  Compliance API to see inside enterprise tenants; PromptWall intercepts at the
  edge instead of ingesting tenant logs.
- **Shared multi-tenant SaaS.** PromptWall ships customer-silo; shared tenancy
  needs the Postgres migration already on the roadmap.

Now shipped (previously gaps): vendor-labeled secrets, document-class
categories, personal-vs-corporate account detection, coding-agent hooks,
shadow-MCP discovery, OTLP export, published detection benchmarks
(`docs/DETECTION_BENCHMARKS.md`), the offline license verifier, a machine-readable
OpenAPI 3.1 spec (`docs/API_REFERENCE.md`), and bundled offline endpoint OCR.

## How to verify these claims locally

```bash
npm run review:ci      # full gate: tests, engine sync, detector eval, browser E2E
npm run eval           # detector precision/recall/false-positive floors
npm run edm:fingerprint --  --in watchlist.txt   # build an EDM list (plaintext discarded)
```

The Insights dashboard is at `/index.html?tab=insights` after login. The
detector inventory and hard-stop list in `DEMO_INSTALL_GUIDE.md` are generated
from the running app by `npm run docs:demo-guide`.
