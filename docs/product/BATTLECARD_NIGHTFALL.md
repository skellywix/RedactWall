# Battlecard: RedactWall vs. Nightfall AI

**Internal sales use only.** Not for customer or examiner distribution. Every
claim below is anchored to a file or command so it can be defended live. Do not
invent performance numbers — cite `docs/product/DETECTION_BENCHMARKS.md`.

## When you're up against Nightfall

A regulated buyer (credit union / community bank) that has short-listed
Nightfall for "AI-native DLP." Nightfall is a strong, well-funded enterprise
platform — do not disparage it. Win on **where the data goes**, **deploy
friction**, **pricing transparency**, and **examiner evidence**.

## Their pitch

Five-pillar platform (SaaS DLP, exfiltration prevention, discovery/audit, Gmail
encryption, developer APIs) plus MCP & AI Agent Security and the Nyx LLM
analyst. 100+ ML detectors, OCR/CV, ~95% precision. Cloud-delivered, AWS-hosted.

## Our wins (each carries proof)

| Claim | Proof |
| --- | --- |
| **Zero egress.** Prompts are classified on-device; nothing leaves the institution to be scanned. Nightfall routes content through their US-only AWS and retains uploaded dev-platform files encrypted for 24h. | `detection-engine/detect.js` runs in the browser/endpoint/gateway; `docs/process/CUSTOMER_LICENSING.md` "fully functional with zero egress" |
| **We block bad model responses; they only monitor.** | Gateway returns `403` on a blocked streamed response — `gateway/server.js` `BLOCK_STATUSES` / `responseBlocked`. Nightfall's own docs say monitor-only for raw LLM responses. |
| **No per-scan rate limit.** Detection is an in-process function call, not a metered API. Nightfall rate-limits customers to 5–10 rps. | `docs/product/DETECTION_BENCHMARKS.md` (in-process p95; state the apples-to-oranges caveat vs their cloud figure) |
| **Transparent, per-seat annual pricing.** No usage metering. Nightfall meters on users/apps/TB-scanned/API-calls with masked list prices. | `docs/process/CUSTOMER_LICENSING.md`; offline Ed25519 license (`server/license.js`) |
| **Light rollout.** Browser force-install policy; no MDM Full-Disk-Access mobileconfig required to start. | `docs/deployment/MANAGED_EXTENSION_DEPLOYMENT.md`, `npm run release:extension:check` |
| **Examiner-grade evidence.** Tamper-evident hash-chained audit + signed proof-of-scan receipts + regulation-mapped packs. | `node -e "require('./server/db').verifyAuditChain()"`; `server/receipts.js`; `npm run evidence:pack` |
| **Vendor-labeled secrets + document-class categories.** | `secretVendor()` and FINANCIAL_STATEMENT/TAX_FILING/HR_RECORD in `detection-engine/detect.js` |
| **Coding-agent + shadow-MCP coverage, zero-egress.** | `sensors/agent-hooks/` and `sensors/endpoint-agent/collectors/mcp-inventory.js` |

## Where they win / how to answer

| They say | We answer |
| --- | --- |
| "100+ detectors vs your ~44." | Ours are checksum- and context-validated with **published, CI-enforced floors** (`npm run eval`, `docs/product/DETECTION_BENCHMARKS.md`) and EDM + custom detector packs. Count is not precision; a DLP that cries wolf gets turned off. |
| "Nyx investigates incidents for you." | Roadmap (`ROADMAP.md` X6). And we will **never** send prompts to an LLM to analyze them — that would break the zero-egress promise your examiner cares about. |
| "We have IDE hooks and shadow-MCP." | So do we (`sensors/agent-hooks/`, `mcp-inventory.js`) — on-box, and we can **block** a response where they only monitor. |
| "We have OCR/CV." | Our endpoint OCR bridge covers screenshots; bundled WASM OCR is on the roadmap. For a bank, the higher-value question is where the image bytes go — with us, nowhere. |

## Landmines to plant (ask the buyer to ask Nightfall)

- "When I paste a member SSN, **where does the prompt text go** to be scanned?"
- "What happens to my traffic **above your rate limit**?"
- "Can you **block** a bad model response inline, or only alert on it?"
- "What exactly does my **NCUA examiner** get — a hash-chained, tamper-evident
  trail, or a dashboard export?"
- "What's the **list price per seat**, in writing, today?"

Keep pricing framing consistent with `ROADMAP.md` (below Nightfall's ~$25–60K
band, far below a Microsoft E5 uplift).
