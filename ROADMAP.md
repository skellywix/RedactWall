# RedactWall Roadmap

Grounded in a July 2026 competitive sweep of the AI-DLP / GenAI-security market.
Detailed engineering plans live in `PLANS/platform-roadmap.md` (M1–M4 are
shipped); this file is the forward-looking product roadmap and the source the
`STATUS.md` TODO list is cut from. Competitive detail and citations live in
`docs/COMPETITIVE_BENCHMARK_2026.md` and `docs/COMPETITIVE_ALIGNMENT.md`.

## Where the market moved (2025–2026)

- The pure-play field consolidated: Prompt Security → SentinelOne (~$250M),
  Lakera → Check Point (~$300M), LayerX → Akamai. Independents left standing:
  Harmonic, WitnessAI, Nightfall.
- Platform bundles (Zscaler, Netskope, Palo Alto AI Access, Microsoft Purview
  DSPM for AI) are what most regulated SMBs now compare against. Purview is the
  default rival at Microsoft-centric credit unions but requires E5-class
  licensing for the full experience.
- The 2026 battlegrounds: agentic AI / MCP governance, redact-and-coach instead
  of hard blocking, personal-vs-corporate account awareness, and AI usage
  reporting as a board/examiner deliverable. NCUA made AI an explicit 2026
  supervisory priority.
- Nobody owns the credit-union/community-bank vertical. Examiner-ready
  evidence (NCUA/FFIEC/GLBA-mapped) remains RedactWall's open wedge.

## Positioning (unchanged, sharpened)

RedactWall competes as: (a) the only **self-hostable** option in a category now
owned by cloud platforms — prompt data never leaves the institution; (b) the
only product with **examiner-ready evidence** as its spine (hash-chained audit,
signed safe-to-send receipts, regulation-mapped evidence packs); (c) mid-market
pricing below Nightfall's ~$25–60K band and far below an E5 uplift. We do not
chase Island/Zscaler breadth.

## Now (next quarter) — highest ROI for regulated-SMB buyers

| # | Item | Competitors with it | Why it matters | Effort |
|---|------|--------------------|----------------|--------|
| N1 | **Inline redaction with "coach, don't block" UX** in the browser sensor: replace sensitive spans in the composer, explain why, let the user proceed with the redacted text. | Prompt Security, Nightfall, Island, Netskope, Zscaler | Blocking-only tools get ripped out for user friction; redaction keeps productivity and keeps NPI out of prompts. Detector spans and tokenization already exist in `detection-engine` — this is UX wiring, not new detection. | M |
| N2 | **Examiner report pack**: auto-generated quarterly report mapping AI usage, enforcement outcomes, and evidence artifacts to NCUA 2026 exam priorities, FFIEC handbook controls, GLBA safeguards, and NIST AI RMF. | None — this is the wedge | NCUA examiners will probe AI inventories and policy-to-evidence traceability in 2026 exams. Extends the existing evidence pack (`server/evidence.js`, schemaVersion 2). | S–M |
| N3 | **Coaching acknowledgment audit trail**: record "user was warned, acknowledged policy X, proceeded/canceled" into the hash-chained audit. | Prompt Security, Netskope, Zscaler | Turns every warning into examiner-grade training evidence. Pairs with N1; warn/justify paths already exist. | S |
| N4 | **Personal vs. corporate account detection** on AI sites; policy to allow corporate tenants and flag/block personal logins. | LayerX, Harmonic, Island | Most leakage happens through personal ChatGPT/Gemini accounts (LayerX telemetry: ~82% of paste activity). Direct GLBA-safeguarding resonance. | M |
| N5 | **AI browser-extension governance**: inventory installed GenAI browser extensions via the sensors, flag them in Coverage/posture. | LayerX | ~20% of users run GenAI extensions that bypass controls; cheap, differentiating telemetry for shops with no CASB. | S |
| N6 | **Published detection benchmarks + self-service red-team harness**: publish precision/recall/latency from the held-out eval; ship a runnable detector test kit. | Lakera publishes 98%/<50ms/<0.5% FP | Regulated buyers must document vendor due diligence; a benchmark is sales collateral and the buyer's due-diligence artifact. Builds on `npm run eval` and the new `suite/` regression suite. | S–M |
| N7 | **Commercial readiness**: offline Ed25519-signed license files with seat true-up and grace periods, monthly release train with signed artifacts + SBOM, SOC 2 readiness posture. | Standard practice (GitLab, HashiCorp, Keygen patterns) | Procurement at financial institutions stalls without licensing, support SLAs, and supply-chain answers. See `docs/CUSTOMER_LICENSING.md`, `docs/RELEASE_PROCESS.md`, `docs/SUPPORT_POLICY.md`. | M |

## Next (two quarters out)

| # | Item | Competitors with it | Why it matters | Effort |
|---|------|--------------------|----------------|--------|
| X1 | **MCP server catalog with risk scoring + per-tool RBAC**: approved-server allowlist, tool-level permissions, per-tool audit views. | Prompt Security (13k-server catalog), WitnessAI (OWASP/CVE-scored catalog) | NSA's 2026 MCP guidance makes "which MCP servers are approved and what can each tool do" an audit question. RedactWall already sits in the MCP path. | M |
| X2 | **Prompt-injection hardening on the gateway path**: benchmark and extend the existing `PROMPT_ATTACK` detector for gateway request/response and MCP tool-result flows; publish accuracy. | Lakera/Check Point, Prompt Security, WitnessAI | As credit unions deploy member-facing chatbots, examiner questions shift from "data out" to "instructions in." | M–L |
| X3 | **Copilot/M365-native interaction coverage** via Graph/audit-log ingestion through the existing M365 connector. | Microsoft Purview (native) | Credit unions are M365 shops; without Copilot visibility, Purview wins the bake-off by default. Ingest, don't intercept. | M |
| X4 | **Gateway tokenization with response de-tokenization**: reversible tokens to OpenAI/Anthropic/Bedrock, restored in responses after scanning. | Prompt Security, WitnessAI | Enables safe AI use on real member data instead of blocking it. Vault + rehydrate primitives already exist (`/api/v1/rehydrate`). | M–L |
| X5 | **Extend Exact Data Match to core-banking exports**: k-anonymized/bloom-filter fingerprints of member records shipped to sensors, raw PII never leaves the control plane. | Island, enterprise DLPs | Regex catches SSN formats; EDM catches *your members'* data — decisive accuracy for FIs. Salted-fingerprint EDM (`EXACT_MATCH`) already shipped; this scales it to member-database size. | L |
| X6 | **AI-assisted incident triage** in the approval queue: auto-summarized timelines and suggested dispositions, run through RedactWall's own enforced gateway. | Nightfall ("Nyx") | Credit unions run 1–3 person security teams; attacks the alert-fatigue objection. Dogfoods the gateway. | M |
| X7 | **Desktop app file-open/drag-drop interception** beyond the protected-upload shell action and clipboard guard (app-specific native collectors, browser native-messaging handoff). | Nightfall, Purview endpoint | The endpoint package is not yet universal file-open interception for every desktop AI app — the longest-standing open product gap (`STATUS.md`). | L |

## Later

- **On-device semantic model upgrade** (ONNX/WASM SLM behind the existing
  `classifySemantic` seam; cloud-classifier seam already exists) — answers
  Harmonic/Nightfall ML-classification depth while staying local-first.
- **Route-to-sanctioned-model enforcement** (WitnessAI has it): redirect
  traffic from unsanctioned AI apps to the governed gateway.
- **Shared multi-tenant SaaS** on the Postgres seam + managed-infra failover
  drills (multi-AZ, load-balancer cutover) — needs the AWS environment.
- **Commercial extension-store publishing** (Chrome/Edge/Firefox listings;
  checklists shipped in `docs/EXTENSION_RELEASE_CHECKLIST.md`).
- **EU AI Act deployer-reporting module** (cheap once N2's report generator
  exists; transparency obligations land 2 Aug 2026).

## What we deliberately do not build

- SASE/network-proxy breadth (Zscaler/Netskope territory) — the ICAP backstop
  and gateway cover unmanaged paths; we don't build a proxy platform.
- A replacement enterprise browser (Island territory).
- Connector count for its own sake — connectors ship only with sanitize-before-
  model proof and posture health (see `PLANS/platform-roadmap.md` Priority 5).
- Cloud-inference detection as the default — on-device detection with no prompt
  egress is the product's spine; any cloud/SLM path stays opt-in and seam-gated.
