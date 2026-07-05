# Competitive Improvement Plan: PromptWall vs. Nightfall AI

## Implementation status (2026-07-05)

All 13 engineering work items are shipped on branch
`claude/competition-analysis-plan-x43u6v`; item 14 remains a design-only
placeholder by decision (not fed to implementation).

| # | Item | Status |
| --- | --- | --- |
| 1 | secrets-vendor-labeling | ✅ shipped |
| 2 | doc-class-categories (FINANCIAL_STATEMENT, TAX_FILING, HR_RECORD) | ✅ shipped |
| 3 | eval-corpus-expansion (→ 500+, decontaminated, floors raised) | ✅ shipped |
| 4 | bench-latency (benchmark + CI budget + doc) | ✅ shipped |
| 5 | agent-hooks-sensor (Claude Code hooks) | ✅ shipped |
| 6 | shadow-mcp-discovery | ✅ shipped |
| 7 | n4-account-detection (personal vs corporate) | ✅ shipped |
| 8 | competitive-refresh (benchmark docs + battlecard) | ✅ shipped |
| 9 | otel-audit-export (OTLP/HTTP) | ✅ shipped |
| 10 | clipboard-provenance (origin-app metadata) | ✅ shipped |
| 11 | license-verifier (Ed25519 offline license) | ✅ shipped |
| 12 | bundled-ocr (WASM tesseract + strict mode) | ✅ shipped |
| 13 | openapi-devsurface (OpenAPI 3.1 + API reference) | ✅ shipped |
| 14 | compliance-ingestion | ⏸ design-only, deferred by plan |

Item 12 was briefly blocked (the agent proxy denies the raw GitHub tessdata
download); it was unblocked by vendoring the language data through the allowed
npm registry (`@tesseract.js-data/eng`, `best_int` build) and confirming the
WASM engine runs fully offline with hard-pinned local model paths.

## Context

We received a 20-page technical research report on Nightfall AI, a direct competitor in the DLP / AI-data-security space. The goal is to mine that report for concrete, prioritized improvements to PromptWall — engineering work items implementable by Claude Code — that play to our strengths rather than chasing Nightfall feature-for-feature.

**How this plan was built:** the report was read in full; two exploration agents mapped the product surface and detection-engine internals; 12 candidate work items were each verified against the codebase by dedicated read-only agents (does it already exist? are the file anchors real? feasibility? what to reuse?); then an adversarial constraint reviewer re-verified every anchor, command, and CLAUDE.md rule across all specs, and a coverage reviewer hunted for misses. The reviewer verdict: zero invented commands; all anchors verified except one item's (corrected below); sequencing conflicts identified and resolved in the ordering below.

## What the report says about Nightfall (key intelligence)

**Product surface (five pillars + add-ons):**
- Data Detection & Response — real-time SaaS DLP (Slack, Drive, Gmail, GitHub, Jira, Confluence, Teams, OneDrive, SharePoint, Salesforce, Zendesk, Notion) with native remediation (block/encrypt/redact/quarantine/delete/restrict).
- Data Exfiltration Prevention — native macOS/Windows endpoint agents + browser extensions (Chrome, Firefox, Edge, Safari); uploads/downloads, clipboard, print, USB, cloud sync, "Shadow AI" apps; data lineage; MDM deployment (Jamf, Intune, etc.).
- Data Discovery & Classification — batch/historic audits, immutable audit jobs, posture-only vs posture+content modes.
- Data Encryption for Gmail — inline scan, AES-GCM-256 auto-encryption, secure reader, one-time recipient codes.
- Developer Platform — REST APIs at api.nightfall.ai/v3/scan, Bearer keys, chunked file uploads (100+ file types, up to 1 GB), OCR/CV, webhooks, SDKs (Python/JS/Go/Java), free tier 3 GB/month; files stored encrypted, deleted after 24h.
- MCP & AI Agent Security — hooks for Cursor, Claude Code (IDE+CLI), VS Code; scans/blocks prompts, MCP tool calls, tool responses, shell commands; **monitor-only for raw LLM responses**; local stdio + remote HTTP/SSE MCP discovery ("shadow MCP"); OpenTelemetry audit trails; Claude Compliance API coverage.
- Nyx — LLM "autonomous DLP analyst" over incident/event data.

**Detection engine claims:** 100+ AI-based models, LLM file classifiers (financial statements, tax filings, HR records...), CV transformer + OCR, advanced secrets detection with vendor labeling and active-risk identification, ~95% precision claim. Prompt-sanitization sample repo targets ≤100 ms p99, ≥1000 rps — while customer rate limits are 5 rps free / 10 rps enterprise.

**Architecture:** shared control plane (detectors → detection rules → policies → incidents/events), normalized incident schema, AWS-hosted multi-tenant SaaS (US-only), SOC 2 Type II, SAML SSO, RBAC, directory sync (Entra/Google/Okta, 4h), webhook/SIEM export (Splunk, Sumo, LogRhythm, Slack, PagerDuty).

**Go-to-market:** enterprise-led ("Get a demo"), 4 bundles, pricing mostly masked, dedicated CSM at higher tiers, MSSP/VAR motion. Positions against Cyberhaven, Code42, Netskope, Purview, Proofpoint, Forcepoint, DTEX on AI-native detection, coverage breadth, faster implementation, native remediation. Packaging metered on users/apps/TB-scanned/API-calls.

**Weaknesses / openings the report exposes:**
1. **Cloud-required, US-hosted multi-tenant SaaS** — all customer content flows through Nightfall's AWS. Structurally cannot serve buyers who can't send prompt text to a third party.
2. **Opaque pricing, enterprise-only sales motion** — no self-serve for the core product.
3. **Heavy endpoint deployment** — native agents + MDM + mobileconfig with Full Disk Access and tamper resistance.
4. **Cloud-inference cost structure** (their replica estimate: $45k–$178k/month to operate) — an on-device engine has ~zero marginal inference cost.
5. **LLM response handling is monitor-only** — they cannot block a bad model response; our gateway already does (403 on blocked output).
6. **Latency envelope** — cloud round-trip ≥ tens of ms + 5–10 rps customer rate limits; our engine is in-process and unmetered.

## What PromptWall is today (from codebase exploration)

**Identity:** Inline DLP gateway for AI chat prompts — on-device detection, no prompt egress, built for compliance (NCUA/GLBA/PCI/HIPAA) at credit unions and community banks. "One policy, three sensors, one shared detection engine, one tamper-evident evidence trail." Node ≥22, v0.3.0, self-hosted/single-tenant.

**Surfaces:**
- `sensors/browser-extension/` — MV3 extension covering ~70 AI hosts; intercepts typing/paste/file-drop/response-copy/downloads; sends only masked findings; native-messaging handoff to endpoint agent for large/OCR files.
- `sensors/endpoint-agent/` — file watchers, clipboard guard, git pre-push guard, guarded drop folders, AI-tool inventory, optional local OCR bridge (native tesseract auto-discovery already built).
- `sensors/mcp-guard/` — guards MCP tool results (indirect injection + PII); connectors: M365 Graph, Google Drive, Slack, Teams, Atlassian, read-only SQLite.
- `gateway/` — OpenAI-compatible fail-closed reverse proxy (OpenAI/Anthropic/Gemini/Bedrock), buffers + scans + **blocks** streamed responses, local tokenization; HA compose stack.
- `server/` — Express 5 control plane: approval queue w/ SLA routing + step-up auth, hash-chained append-only audit with evidence binding, examiner evidence packs, SIEM/SOAR exports (Splunk HEC, Sentinel, Chronicle, QRadar LEEF, Datadog, Slack, Teams), SSO/OIDC/SCIM/RBAC/MFA, posture/insights/risk, Competitive Readiness matrix; legacy dashboard being strangler-migrated to React console (`console/`).
- Storage: SQLite default + Postgres w/ RLS tenant isolation. ICAP/Squid backstop; discovery import from Zscaler/Netskope/Purview exports.

**Detection engine (`detection-engine/detect.js`, 837 lines, synced to sensors via `npm run sync-engine`):** 41 detectors total per the generated inventory — ~30 structured (regex + real checksums: Luhn+BIN, SSN plausibility, ABA, IBAN mod-97, VIN, NPI, UK NINO/NHS, Canada SIN, Australia TFN, India Aadhaar/PAN) with ±40-char context windows; secrets (`SECRET_KEY` provider alternation, `PRIVATE_KEY`, `PASSWORD`, `CANARY_TOKEN`); 7 semantic categories (keyword heuristics max-combined with embedded hashing-trick logistic regression, trained by `scripts/train-semantic.js`, deterministic); EDM salted fingerprints; custom regex detectors w/ ReDoS linter; confidence tiers; per-detector regulation citations surfaced in block reasons; reversible tokenization (AES-256-GCM vault, audit-logged rehydrate). Policy: block/warn/redact/justify + `alwaysBlock` hard-stops (un-suppressible, tested invariant) + per-user/group/destination scopes (stricter-wins) + MCP tool allow/block lists. Eval harness with CI floors (semantic P≥0.90 R≥0.70, structured recall ≥0.95, benign/bait FP=0) — but corpus is only ~105 cases with verified train/eval contamination, and **no latency benchmark exists anywhere**.

**Confirmed gaps vs Nightfall (from code, not marketing):** no vendor labeling on secret findings + verified missing token patterns (Stripe `sk_live_`, Slack `xapp-`, Databricks, Terraform, Postman, Azure, GCP, context-anchored AWS); no document-class classifiers; no server-side OCR/CV (endpoint OCR is BYO-engine); no coding-agent hook coverage (mcp-guard covers tool results only); no shadow-MCP discovery; no personal-vs-corporate account detection (ROADMAP N4, zero code); no OTel export; no published benchmarks; license verifier designed but not shipped; no machine-readable API spec. Extension asset budget nearly exhausted (99,290 / 105,000 raw bytes) — blocks naive ML additions.

## Strategy: how to use this report

Three moves, in order of leverage:

1. **Weaponize their structural weaknesses** (cloud-required, monitor-only responses, opaque pricing, 5–10 rps rate limits, MDM-heavy deployment). These are things Nightfall *cannot* fix without abandoning their architecture. We turn them into published, code-backed proof: benchmarks, battlecard, transparent licensing.
2. **Close the gaps on their newest pillar — MCP & AI Agent Security** (IDE/CLI hooks, shell-command blocking, shadow-MCP discovery). It maps directly onto "three sensors, one brain", and our zero-egress version is *stronger* than theirs (they ship agent content to AWS; we scan on-box, and we block LLM responses where they only monitor).
3. **Neutralize their detection-marketing edge** ("100+ ML detectors, vendor-labeled secrets, file classifiers, 95% precision") with precision-first equivalents: vendor-labeled secrets, document-class categories, a 5× bigger decontaminated eval corpus, published floors.

**Explicitly do NOT chase** (confirmed against ROADMAP non-goals by adversarial review): SaaS data-at-rest connectors; active secret verification (live-key probing = egress, kills the zero-egress spine — even opt-in); a cloud scan API/free tier; USB/print/cloud-sync endpoint breadth; Gmail-style inline encryption; MDM/Full-Disk-Access agent parity (their heavy deployment is a weakness to attack, not a gap to close).

---

## Work items (4 waves — feed to Claude Code strictly in this order)

### Cross-cutting rules (apply to every item)

- Detector logic changes go in `detection-engine/detect.js`, then `npm run sync-engine`; NEVER hand-edit `sensors/browser-extension/lib/detect.js` (same for `adapters.js` — it is synced too). Note: `detect.js` contains embedded model weights with a NUL byte (~offset 28729) — ripgrep treats it as binary; use `grep -a` or exact Read offsets, and careful Edit anchors.
- Hot detection path (runs per keystroke) stays allocation-light: no per-call object/array allocation in `classifySemantic` branches or finding enrichment; frozen module-level constants.
- Never log, store, or transmit raw prompt text, PII, or secret values — labels and `maskValue` output only. Every new payload path needs a canary test asserting planted synthetic values never appear in any outbound body.
- Detection-engine public API is stable; additions OK, changes/removals not.
- **Wave 1 items are strictly serial** (all four touch `test/fixtures/semantic-eval.json` and/or the eval floors). Items 5 and 6 both touch `server/coverage.js` and the heartbeat surface — serial, not parallel branches.
- Full gate after each item: `npm run review:ci` (docs check, console build, npm test, browser tests, sync-check, eval). Note `review:ci` does NOT run the suite tiers — run `npm run suite` at wave boundaries.

---

### WAVE 1 — Detection core (strictly serial; ordering resolves verified fixture/floor conflicts)

#### 1. `secrets-vendor-labeling` — Vendor-labeled secrets + expanded token catalog (effort M)

**Why:** Nightfall markets "advanced secrets detection" with vendor labeling and active-risk identification. Our `SECRET_KEY` detector matches many providers but findings don't say WHICH — and verified live gaps exist: Stripe `sk_live_`/`sk_test_`, Slack `xapp-`, Databricks `dapi`, Terraform `.atlasv1.`, Postman `PMAK-`, Azure `AccountKey=`/SAS, GCP service-account JSON, and context-anchored AWS 40-char secret keys all return NO MATCH today.

**Build (all detector work in `detection-engine/detect.js` + `npm run sync-engine`):**
- Extend the single-pass alternation at `detect.js:281` (keep ONE regex = one text pass; every branch keyed by a distinctive literal prefix, no nested quantifiers): `sk_live_`/`sk_test_[A-Za-z0-9]{16,}`, `xapp-`, `dapi[0-9a-f]{32}`, `.atlasv1.`, `PMAK-`, optional `ya29.`. Add at most 2–3 extra SECRET_KEY DETECTORS rows (multi-row precedent: US_SSN at :240/:243, BANK_ACCOUNT :253/:254) for context-dependent formats: Azure `AccountKey=|SharedAccessKey=|SharedAccessSignature=` (group-extracted); AWS 40-char secret key with `ctx:/\baws.{0,12}secret|secret[_ ]?access[_ ]?key\b/i` via existing `ctxOk` (:468) — **reviewer correction: do NOT use `\b` anchors around the 40-char class (unreliable `\b` semantics next to `+`/`/`); use lookarounds `(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])`**; GCP `"type": "service_account"` marker row. Skip Stripe `pk_live_` (publishable, not secret).
- Vendor labeling, allocation-light: module-level frozen ordered `[prefix, vendorId, label]` table + `secretVendor(value)` (<30 lines) near `CONFIDENCE_LABEL` (:233). **Order-sensitive:** `sk-ant-`→anthropic BEFORE `sk-`→openai; `sk_live_`→stripe (label contains "live"), `sk_test_`→"(test)"; AKIA/ASIA→aws; ghp_/github_pat_→github; xox/xapp-→slack; SG.→sendgrid; AIza/ya29.→google; npm_; hf_; dop_v1_; shpat_/shpss_; pypi-; PMAK-; dapi. Non-prefix checks: Twilio `/^SK[0-9a-fA-F]{32}$/`, `.atlasv1.`→terraform, `eyJ`→jwt. For ctx/group rows, per-row `vendorTag: {vendor, label}` preferred over `secretVendor()`. Attach in `analyze()`'s accepted loop (:748-753) exactly where confidence/regulations attach: optional `f.vendor`/`f.vendorLabel`, frozen constants, omit when unknown (env-var generic branch at :282 gets none). Export `secretVendor` in the api object (:834) — additive only.
- Surface (additive optional field, spread-guarded): server mappers `server/app.js:824-829, 1111-1114, 1480, 1552, ~2595`; sensor mappers — `publicFindings` at `sensors/browser-extension/content.js:253`, `sensors/endpoint-agent/agent.js:148`, `sensors/mcp-guard/guard.js:147` (corrected anchors); hard-stop reason in `server/policy.js:740` appends label only — e.g. `Hard-stop entity present: SECRET_KEY (Stripe secret key (live))` — never the value; dashboard chip `server/public/dashboard.js:2083`; console `console/src/api/queries.ts:13-19` (QueryFinding + `vendor?`, `vendorLabel?`) and `console/src/components/queue/FindingChips.tsx:17`.
- **REJECT active-risk/live-key verification** (even opt-in): egress of captured secrets contradicts the zero-egress promise (`docs/CUSTOMER_LICENSING.md:16`) and never-store-raw-secrets rule. Offline substitute: live/test encoded in vendorLabel. Record the rejection in `DECISIONS.md`.
- Tests: new blocks in `test/detect.test.js` (each new pattern fires with synthetic keys; vendor precedence pinned; env-var branch carries no vendor; FP guards — 40-char base64 WITHOUT aws context does not fire; 'dapi' as substring of a longer word does not fire). Eval fixtures: one structured entry per new pattern + 2–3 bait entries in `test/fixtures/semantic-eval.json`.

**Accept:** all new patterns fire SECRET_KEY; vendor precedence correct; zero hot-path allocation added; raw values never surface anywhere (queue/audit/SIEM/dashboard/console = masked+label only); SECRET_KEY stays in default alwaysBlock (`server/policy.js:40`, `config/policy.json:26`) and the alwaysBlock invariant tests pass; `npm run eval` floors green; sync-check green.

**Verify:** `npm test` · `npm test -- test/detect.test.js` · `npm run eval` · `node scripts/eval-detect.js --ci` · `npm run sync-engine && npm run sync-check` · `npm run suite:detector` · `npm run console:build` · `npm run review:ci`

**Risks:** FPs hard-block immediately (SECRET_KEY is alwaysBlock — AWS/Azure formats MUST stay context-gated; bait fixtures are the guardrail); vendor-precedence bugs (pin with tests); `sk_test_` keys block developers (acceptable for a bank DLP; the "(test)" label gives reviewers context — don't lower severity without a policy decision).

#### 2. `doc-class-categories` — FINANCIAL_STATEMENT, TAX_FILING, HR_RECORD semantic categories (effort M)

**Why:** Nightfall markets LLM file classifiers for exactly these document classes. We counter with zero-egress on-device categories. Scope: keyword-heuristic first (HEALTH_RECORD pattern), LR-ready but untrained; **drop CUSTOMER_DATA_EXPORT** (structured detectors + EDM already catch bulk exports per-row; a "looks like CSV" signal risks benign FPs).

**⚠ Corrected anchors (constraint reviewer verified the original spec's detect.js offsets were wrong; the file defeats ripgrep, so navigate by these):** `classifySemantic` spans **:638-704**; the HEALTH_RECORD keyword-only template branch is at **:695-702**; the CONFIDENTIAL_BUSINESS LR-ready max-combine template is at **:678-689**. (`:722-729` is inside `analyze()`'s accepted-findings loop; `:707-716` is `breakdownEntry` — do not edit those.) File-scan analyze call is `server/app.js:1476`.

**Build:**
- `detection-engine/detect.js`: add 3 ids to `SEMANTIC_DETECTOR_IDS` (:289); SEVERITY map (~:179) all at 3 (high); REGULATIONS map (:186-229): FINANCIAL_STATEMENT → `['GLBA 501(b)', 'company confidentiality']`, TAX_FILING → `['IRS Pub 1075', 'GLBA 501(b)']`, HR_RECORD → `['company confidentiality', 'state employment-privacy laws']`.
- `classifySemantic()` branches before `return cats`, following the HEALTH_RECORD branch (:695-702) style — TWO independent cue families ANDed + negation cues + fixed score 0.72, max-combined LR-ready like CONFIDENTIAL_BUSINESS (:678-689): `kwFires || p >= _lrThresh(cat)`, score `Math.min(1, Math.max(kwFires ? 0.72 : 0, p))` (`_lrProb`/`_lrThresh` at :610-617 cost nothing untrained). Inline alternation-regex literals, NOT per-call arrays (hot path). Cue families: FINANCIAL_STATEMENT = docCue (balance sheet|income statement|statement of cash flows|P&L|trial balance|general ledger|10-K/Q|call report|form 5300) AND lineItemCue (total assets/liabilities/equity|net income|retained earnings|allowance for loan losses|provision|charge-offs|operating expenses|delinquen), negate general-ask unless `$[\d,]+` present; TAX_FILING = formCue (W-2|W-4|W-9|1099*|1040|941|940|1120|1065|schedule A–E|K-1|990) AND fieldCue (wages|withholding|taxable income|AGI|filing status|box \d|tax year 20\d\d|EIN|refund); HR_RECORD = hrDocCue (performance review|PIP|disciplinary write-up|termination letter|offer letter|salary history/increase|compensation review|HR file/case|employee id/record|FMLA|accommodation request|background check|exit interview) AND employeeCue (employee|staff member|direct report|teller|loan officer + name/salary nearby), negate job-posting/template/handbook/policy asks. Exact regexes tunable — the contract is: two cue families + negations + 0.72 + LR-ready.
- `scripts/eval-detect.js:21`: add all 3 to SEM_CATS (floor-enforced — they're the deliverable). Fixtures: ~10–12 positives per category phrased differently from chosen keywords + ~6 benign hard-negatives ("Explain what appears on a balance sheet for a financial-literacy class"). **CRITICAL: multi-label** any example that legitimately co-fires CONFIDENTIAL_BUSINESS or its precision floor breaks; check whether the existing "Internal salary bands…" entry (fixture line ~12) now fires HR_RECORD and label it if so.
- Surfaces: `sensors/browser-extension/content.js` LABELS (:154) + COACHING (:190) maps (direct edit correct — content.js is NOT a synced engine copy); `server/routing.js` — FINANCIAL_STATEMENT + TAX_FILING into FINANCIAL_MEMBER_LABELS (compliance group, :239-245), new HR_LABELS set routing to 'privacy' (mirror health branch :232-238); update `test/routing.test.js` + `test/approval-routing.test.js`. Optionally `scripts/update-demo-guide.js:14` SEMANTIC_CATEGORIES + `npm run docs:demo-guide`.
- NO changes to: config/policy.json (severity 3 ≥ blockMinSeverity 2 blocks by default; semantic categories deliberately NOT in alwaysBlock), console (renders ids generically), validation.js/semantic-remote.js (derive ids), processors/file-scan/gateway/MCP paths (all call `analyze` generically — file scans benefit automatically).
- **Phase 4 (deferred, only if a category's recall <0.70 with keywords):** LR training via `scripts/train-semantic.js`. HARD CONSTRAINT verified: `test/asset-budget.test.js:105` caps synced `lib/detect.js` at 105,000 raw / 37,000 gzip; currently 99,290 raw / 35,711 gzip and each trained model is ~6.5–10.6KB — training 3 models does NOT fit without raising the sparsify cutoff (`train-semantic.js:249`) or deliberately bumping budgets. Trainer cross-negatives (:239-241) can depress CONFIDENTIAL_BUSINESS recall — keep templates lexically distinct.

**Accept (against the CURRENT floors P≥0.90/R≥0.70 — the floor raise happens in item 3, after this lands):** three categories fire on realistic positives at ≥0.7; benign gauntlet (`test/detect.test.js:287-297`) still zero categories; eval `--ci` green incl. no CONFIDENTIAL_BUSINESS regression; micro floors in `test/eval.test.js` hold; determinism gate green (`npm run train-semantic && git diff --exit-code -- detection-engine/detect.js sensors/browser-extension/lib/detect.js` — CI runs this every build); asset budget green; routing tests updated; extension LABELS/COACHING present.

**Verify:** `npm run eval` · `node scripts/eval-detect.js --ci` · `npm test` · `npm run suite:detector` · `npm run sync-check` · `npm run train-semantic && git diff --exit-code` · `npm run docs:demo-guide:check` · `npm run review:ci`

**Risks:** unforgiving precision floors (two-cue AND + negations + fixture tuning); label bleed vs CONFIDENTIAL_BUSINESS (multi-label fixtures); HR_RECORD overlaps everyday manager prompts — if it can't hold P≥0.90, **ship FINANCIAL_STATEMENT + TAX_FILING and defer HR_RECORD rather than weakening floors**.

#### 3. `eval-corpus-expansion` — Grow the labeled corpus ~105 → 500+, decontaminate, THEN raise floors (effort L; keystone)

**Why:** Nightfall claims ~95% precision; our floors are enforced on only 105 cases — weak published evidence. Verified problems: **train/eval contamination** (fixture entries at `semantic-eval.json` lines 18, 30-32, 40 are verbatim/near-verbatim copies of `scripts/train-semantic.js` templates :84, :97-99, :134 — reviewer confirmed byte-level); HEALTH_RECORD is live but absent from `SEM_CATS` (zero eval coverage); every structured type has exactly ONE positive (all-or-nothing recall). Measured headroom: semantic micro P=1.00 R=0.976. Full 105-case pass costs ~31ms — 500+ cases is CI-negligible. **Sequenced after items 1–2 so the corpus covers their new detectors/categories and the floor raise is measured against the final category set.**

**Build (phases):**
1. Decontaminate (replace the 5 contaminated entries with fresh phrasings) + grow to ≥500: ≥30 positives per semantic category ×9 (original 6 incl. HEALTH_RECORD + the 3 from item 2), ≥120 benign incl. per-category hard negatives + synthetic credit-union transcripts + 5–10 non-English; ≥3 positives per structured type (incl. item 1's new secret patterns; format variants; synthetic values only — AKIAIOSFODNN7EXAMPLE-class); ≥60 adversarial bait with **checksum near-misses for every validated type, authored with the exported validators** (`luhnValid`, `ssnPlausible`, `abaValid`, `ibanValid`, `vinValid`, `npiValid`, `ninoValid`, `nhsValid`, `sinValid`, `tfnValid`, `aadhaarValid`, `itinPlausible`, `bankAccountPlausible` — all verified exported at detect.js:834) so each bait genuinely fails its checksum. Do NOT delete the two strings pinned by `test/detection-quality.test.js:35-36` ("Leadership has decided", "412-22-7843").
2. Add HEALTH_RECORD to `SEM_CATS` (`scripts/eval-detect.js:21`) — verified zero retroactive FPs on the current corpus.
3. NEW `test/eval-corpus.test.js` meta-invariants: labels ⊆ SEM_CATS; types ⊆ `listDetectors()` ids; composition minima; no duplicate normalized texts; bait entries actually fail their validators.
4. Fix what the corpus exposes — detector fixes in `detection-engine/detect.js` + sync-engine only; if structured micro recall can't hold exactly 1.0 at ~100+ positives, deliberately relax `test/eval.test.js:27` `strictEqual(recall, 1)` → `>= FLOORS.structuredRecall` with justification.
5. **Floor raise (was a conflict — now safe because items 1–2 landed):** raise FLOORS only where ≥5pt measured margin per category (target semanticPrecision 0.90→0.95, semanticRecall 0.70→0.80; keep benignFP=0, baitFP=0). Add corpus-size counts to `summaryJson()` so published metrics state n. Sync numbers in `docs/TESTING_STRATEGY.md:46-49` + `AGENTS.md:22`.
- Keep single-file fixture (referenced by name in `server/detection-quality.js:110,137`, AGENTS.md, README). Optional separate PR: extract trainer templates into a requireable module + automated contamination test (risks RNG-order drift; CI determinism check catches it).

**Accept:** composition minima met, all synthetic; contaminated entries replaced; meta-test green; `--ci` exits 0 with per-type tp+fn ≥3; floors raised per measured headroom; docs updated.

**Verify:** `npm run eval` · `node scripts/eval-detect.js --ci` · `node scripts/eval-detect.js --json` · `npm test` · `npm run suite:detector` · `npm run sync-check` · `npm run train-semantic` · `npm run review:ci`

**Risks:** authoring quality (write cases blind first, then triage failures as detector bugs vs out-of-scope); expansion will expose real detector gaps → budget for it or split follow-ups; over-raised floors make every future change fight CI (5pt-margin rule); if HR_RECORD margin is thin, the raised floor may exclude it — acceptable per item 2's fallback.

#### 4. `bench-latency` — Detection latency/throughput benchmark + CI budget + published doc (effort S, tight — CI-flake-proofing is where time goes)

**Why:** Nightfall advertises ≤100ms p99 / ≥1000 rps for prompt sanitization (cloud round-trip) while rate-limiting customers to 5–10 rps. Our engine runs in-process: measured on a dev box, `analyze()` p50/p95/p99 = 0.26/0.37/0.43ms for a 200B prompt (~3,700 scans/s/core), 5.1/5.4/5.8ms for 10KB, 50.7/53.3/55.2ms for 100KB — even the 100KB worst case beats their p99 target. Nothing measures or publishes this today (ROADMAP N6). **Sequenced after item 3 so the corpus-replay workload and the published floors table are stable.** No detection-engine changes.

**Build:**
- NEW `scripts/bench-detect.js` — clone `scripts/eval-detect.js` structure (injectable `main(argv, deps)` :141-155, `--json`/`--ci`, `module.exports`, require.main guard). Deterministic workloads (no unseeded randomness; synthetic PII per `test/README.md`): `benign-short` (~200 chars), `pii-short`, `paste-10kb`, `file-100kb`, `eval-corpus` (replay all fixture texts — now 500+). Warmup ≥20 iters, then timed `D.analyze(text)` with `process.hrtime.bigint()`; p50/p95/p99/mean + scansPerSec. Build all workload strings BEFORE timing. Output never prints workload text.
- Exported `BUDGETS` with 10–20× headroom (CI never flakes; catastrophic regex backtracking still caught): benign/pii-short p95 ≤ 10ms, 10KB p95 ≤ 100ms, 100KB p95 ≤ 1000ms, throughput ≥ 100 scans/s. **Gate on p95, not p99** (GC-noisy at small N). `failures(results)` mirrors `eval-detect.js:95`. Optional `PROMPTWALL_BENCH_BUDGET_SCALE` env for slow environments.
- NEW `test/bench-latency.test.js` (quick preset, <10s, auto-discovered — `scripts/run-node-tests.js` walkTestFiles; no CI workflow edit) + NEW `suite/detector/latency-budget.suite.js` (model: `suite/detector/eval-floors.suite.js`).
- NEW `docs/DETECTION_BENCHMARKS.md`: methodology (hardware/Node/date pinned), results table, accuracy floors + corpus-size n from item 3, CI enforcement, **explicit apples-to-oranges caveat** (in-process call vs their network-inclusive figure), reproduction commands. Keep OUT of the `docs:demo-guide` drift check. Index in `docs/README.md`; add `npm run bench` to `scripts/README.md`; package.json `"bench": "node scripts/bench-detect.js"`.
- OPTIONAL stretch: response-path enforcement benchmark — the gateway blocks streamed responses (`gateway/server.js:89-91` BLOCK_STATUSES, 403 at :196-198) where Nightfall is monitor-only; measure and publish block latency in the same doc.

**Accept:** bench prints per-workload percentiles + scans/sec (never text); `--ci` exits 1 iff a BUDGET fails; test <10s in serial `npm test` and reliable on shared runners; sync-check green (no engine edits); doc indexed with caveat + pinned environment.

**Verify:** `node scripts/bench-detect.js --ci` · `npm test` · `npm run suite:detector` · `npm run sync-check` · `npm run review:ci`

**Risks:** CI timing flakiness (p95 gating, 10×+ headroom, env scale override); published numbers going stale (pin hardware/date); dishonest comparison (caveat is an acceptance criterion).

---

### WAVE 2 — Close the AI Agent Security pillar (their newest front; our zero-egress version is stronger)

#### 5. `agent-hooks-sensor` — Fourth sensor: Claude Code hook integration (prompts, shell commands, MCP tool calls) (effort M→L boundary)

**Why:** Nightfall's sixth pillar ships hooks for Cursor/Claude Code/VS Code that scan+block prompts, MCP tool calls, tool responses, and shell commands. We have NOTHING on this path (verified: zero PreToolUse/UserPromptSubmit integration anywhere) — yet ~70% of the machinery is already shipped: `mcpToolDecision()` wildcard tool policy (`sensors/mcp-guard/guard.js:188`), the installable-local-hook precedent (`sensors/endpoint-agent/collectors/git-push-guard.js` — stdin-driven, label-only reporting, exit-code semantics), the local block/warn decision pattern (`sensors/browser-extension/content.js:132-147`), and `/api/v1/gate` accepts free-form source/channel with NO server schema changes (`server/validation.js:162-177`; clientOutcome enum already has `action_blocked`/`paste_flagged`). Fully local scanning — Nightfall must ship agent content to AWS.

**Build:** NEW `sensors/agent-hooks/` (source id `agent_hooks`), v1 = Claude Code; Cursor documented follow-up.
- `sensors/agent-hooks/hook.js` — single CLI invoked by Claude Code hooks; reads one JSON event from stdin (pattern: `git-push-guard.js:186`). Dispatch on `hook_event_name`: `UserPromptSubmit` → analyze prompt (bounded 200k chars), channel `agent_prompt`; `PreToolUse` + `Bash` → analyze command+description, channel `agent_shell`; `PreToolUse` + `mcp__<server>__<tool>` → map to `<server>.<tool>`, reuse `guard.mcpToolDecision()` (do NOT reimplement wildcards) + analyze stringified tool_input. Emit Claude Code protocol JSON (`permissionDecision: deny/ask`; `{decision:"block"}` for UserPromptSubmit) AND exit-code-2 + label-only stderr as the version-stable fallback. Reasons ONLY from finding types + `maskValue` — never raw text.
- **Decision logic (reviewer mandate — CLAUDE.md "don't duplicate more than twice"):** a local `decide()` would be the THIRD copy of the evaluate pattern (content.js:132-147, agent.js). Extract the ~15-line shared helper into a sensor-shared module (e.g. `sensors/shared/decision.js`, or exported additively from mcp-guard) consumed by hook.js — do NOT widen the detection-engine API for it; refactoring content.js/agent.js onto the helper is an optional follow-up (content.js is browser-side and synced differently).
- Policy per fresh process: persist normalized policy to `~/.promptwall/agent-hooks-policy.json` (0600), 15-min refresh via `guard.fetchPolicy` (:93); on fetch failure use cache; no cache → conservative built-in default (copy `browser-extension/background.js:17` defaults). **Enforcement fully local — no network on the decision path.**
- Reporting best-effort after decision: export `logEvent` from `guard.js` (:238; confirmed not currently exported — additive) and post gate records shaped like `gitPushRecord` (:286): label-only prompt, `clientPreRedacted:true`, `destination:'claude-code'`, outcomes `action_blocked`/`paste_flagged`. Only report warn/block. All failures swallowed; **fail-open on internal errors (exit 0), exit 2 only for deliberate blocks** — the hook must never break the agent.
- `scripts/install-agent-hooks.js`: idempotent merge into `~/.claude/settings.json` (or `--project`) — `UserPromptSubmit` + `PreToolUse` matcher `Bash|mcp__.*`; `--uninstall` removes only PromptWall-owned entries; `--print` emits snippet; **NEVER writes INGEST_API_KEY into settings.json** (env / `~/.promptwall/agent-hooks.env`).
- `scripts/check-agent-hooks-install.js` (mirror `check-mcp-guard-install.js`; heartbeat `source:'agent_hooks'`) + `scripts/package-agent-hooks.js` (clone `package-mcp-guard.js` incl. privacy lint). npm scripts `agent-hooks:check`, `package:agent-hooks`.
- Server visibility: `server/coverage.js:10-16` SENSOR_LABELS + `server/fleet.js:12` TRACKED add `agent_hooks`. **NOT in DEFAULT_REQUIRED_SENSORS** (`coverage.js:19`) — must not flag existing customers as gapped. Update `test/fleet.test.js`/`test/sensor-heartbeat.test.js` if they pin TRACKED.
- Tests `test/agent-hooks*.test.js`: block SSN prompt; block Bash w/ secret; `mcpBlockedTools:['jira.*']` denies `mcp__jira__create_issue`; approval-required → ask; warn → ask + paste_flagged; alwaysBlock overrides warn; **canary: synthetic values absent from every mock-fetch body/output**; offline → still blocks; malformed stdin → exit 0; installer idempotence/uninstall/never-writes-key.
- `docs/AGENT_HOOKS.md` + `sensors/README.md` row. No engine changes → no sync-engine.

**Accept:** `echo '{"hook_event_name":"UserPromptSubmit","prompt":"ssn 524-71-9043"}' | node sensors/agent-hooks/hook.js` exits 2 with label-only reason, offline, no server; MCP tool-policy denial reuses guard wildcards; no raw content in any payload; fleet shows the sensor; package lint passes.

**Verify:** `npm test` · `npm run suite:smoke` · `npm run suite:contract` · `npm run sync-check` · `npm run eval` · the echo-pipe smoke test above · `npm run review:ci`

**Risks:** Claude Code hook protocol drift (exit-code fallback always emitted, both paths tested); per-invocation cold start (fresh node loads detect.js — bound input, target <500ms, lazy-skip semantic pass for short shell commands if needed); not tamper-proof (position as coverage+audit; heartbeat detects absence — same posture as other sensors); ingest-key distribution to dev workstations (per-sensor env-file + rotation docs).

#### 6. `shadow-mcp-discovery` — Enumerate configured MCP servers across IDEs/agents (effort M)

**Why:** Nightfall advertises local stdio + remote HTTP/SSE shadow-MCP discovery. Our endpoint agent inventories AI tool *installs* (`ai-tool-inventory.js`) but never parses their MCP configs. This is the discovery half of ROADMAP X1 and answers the NCUA "AI inventory" exam question. **Ride the heartbeat installChecks pipeline — NOT `/api/v1/discovery`/`ai_apps`** (host-sighting-based, `isAiHost`-gated at `server/app.js:895-901` — verified wrong channel).

**Build:**
- NEW `sensors/endpoint-agent/collectors/mcp-inventory.js` mirroring `ai-tool-inventory.js` (import its exported `normalizeToolId`, `parseApprovedTools`, `basenameAny` — verified exported; don't duplicate). `wellKnownMcpConfigPaths({home, platform, env})`: Claude Code `~/.claude/settings.json` + `~/.claude.json`; Claude Desktop `claude_desktop_config.json` (per-OS app-support dirs); Cursor `~/.cursor/mcp.json`; Windsurf `~/.codeium/windsurf/mcp_config.json`; VS Code user `settings.json`/`mcp.json`; optional project roots via `ENDPOINT_AGENT_MCP_PROJECT_ROOTS`. `parseMcpServers(jsonText, client)`: `mcpServers` object or VS Code `servers`/JSONC (strip comments conservatively; fail closed to skipped-config; never throw; never include file content). **METADATA ONLY:** normalized id, client, transport (stdio/http/sse), command basename OR url hostname. **NEVER read/emit env values, args, headers, full URLs, or paths** — MCP configs are the most secret-dense files on a dev machine.
- Checks: `mcp_inventory` summary + up to 12 `mcp_server_<id>` checks; approved-list via `ENDPOINT_AGENT_APPROVED_MCP_SERVERS` (empty = all approved).
- **Sharpest edge (verified):** `server/validation.js:220` caps heartbeat checks at 40; installs already emit ~25–32 — MCP checks overflow and zod 400s the ENTIRE heartbeat. Raise 40→80 + matching slices `server/coverage.js:234` (`cleanInstallChecks`), `server/evidence.js:76`; regression test posting a 41+-check heartbeat.
- `server/install-checks.js` (:3-27 split verified): `mcp_server_*` policy-check namespace excluded from `failedInstallCheckIds` (mirror `ai_tool_*`) — unapproved servers = inventory attention, not sensor failure. `server/app.js` heartbeat handler (:1282-1346): `ENDPOINT_MCP_SERVER_ATTENTION` audit (sanitized ids only; mirror :1323-1330).
- `server/coverage.js`: `mcpServerInventoryForChecks` + `endpointMcpServerRows` + totals + posture row `endpoint_mcp_servers` (mirror patterns at :265, :491, :785). Policy overlay: unapproved if blocked by `policy.mcpBlockedTools` server-segment match or absent from non-empty `mcpAllowedTools` — small `mcpServerPolicyState()` helper in `server/policy.js` (owns `normalizeMcpToolList` :374-401) reusing guard wildcard semantics, **normalizing hyphens/underscores both sides** (`github-mcp` pattern must match `github_mcp` id).
- Wire into `scripts/check-endpoint-install.js` (after ai-tool block ~:139); dashboard panel next to `endpointAiToolRows` (`server/public/dashboard.js:3630+`, `index.html:3006`); packaging manifest (`scripts/package-endpoint-agent.js`); `.env.example`.
- Tests incl. **canary: fixture configs contain planted secrets in env blocks/args/URL query strings; JSON.stringify of the entire collector output contains none of them**, no path separators, no URL paths/queries.
- Non-goals (state in PR): live remote endpoint probing; feeding into ai_apps; runtime MCP interception (mcp-guard owns that). No engine changes; no DB migration. Coordinate `server/coverage.js` edits with item 5 (serial).

**Accept:** fixture configs for all 5 clients enumerate correctly (id/client/transport/basename-or-hostname only); canary passes; unapproved servers → attention audit + posture 'attention', never SENSOR_HEALTH failure; 80-check heartbeats validate, ≤40 unchanged; policy tie-in flags blocked/unlisted servers even when sensor-side check ok; packaging + dashboard green.

**Verify:** `npm test` · `npm run endpoint:check` · `npm run package:endpoint-agent` · `npm run suite:contract` · `npm run sync-check` · `npm run review:ci`

**Risks:** heartbeat cap overflow (regression-tested); secret leakage (canary mandatory; detail strings from fixed vocabulary only); id-normalization mismatches → false unapproved flags; VS Code JSONC corruption (conservative stripper, fail closed); scope creep toward X1 catalog/RBAC (discovery + flagging only).

#### 7. `n4-account-detection` — Personal vs corporate account detection on AI sites (ROADMAP N4, effort M)

**Why:** ROADMAP N4 ("Now" item, zero code — `accountType` has no hits): detect whether the user is signed into ChatGPT/Claude/Gemini/Copilot with a personal vs corporate account; LayerX pegs ~82% of paste-leakage on personal accounts. The catalog's `personal_account_tier` flag (`server/ai-app-catalog.js:56-74`) says "this host *offers* a personal tier" — N4 closes the gap to "this user *is on* one". Direct GLBA-safeguards/examiner story. Flagged by adversarial review as the largest coverage miss.

**Design principles (locked):** classification is **local DOM heuristics only**, computed on page load (retries ~2s/6s/15s for SPA render + focus-throttled re-probe per 5 min) and cached per tab; only the enum `{type: personal|corporate|unknown, signal}` ever leaves the page — **no raw email, no hashed email** (freemail hashes are dictionary-attackable). Unmatched email domain ⇒ `unknown`, never `personal`. **Never block on `unknown`.** Default action `allow` (telemetry-only); `coach` and `block` are explicit policy opt-ins. No new query status (reuse `destination_blocked` + distinct reason — avoids the ~10-file status-enum fan-out across db/routing/workflow/coverage/evidence/insights/alerts/console).

**Build:**
- `detection-engine/adapters.js` (canonical; then `npm run sync-engine` — adapters.js is synced/drift-checked too): `PERSONAL_EMAIL_DOMAINS` (~15 freemail domains); `ACCOUNT_MARKERS` per host mirroring the `SEND_BUTTONS` data pattern (:15-33) — emailSelectors + corporateBadges + personalBadges for chatgpt.com (`/chatgpt (team|enterprise|edu)/i` vs `/upgrade|plus|free plan/i`), claude.ai (`/claude for work|team|enterprise/i` vs `/free|pro plan/i`), gemini.google.com (`a[aria-label*="Google Account" i]` — best-effort; chooser nuance documented in marker comments), copilot.microsoft.com (`[id^="mectrl"]`; `/work account/i` vs `/personal account/i`); pure `classifyAccount({emails, badgeText}, orgEmailDomains)` with precedence: corporate badge → org-domain email → freemail → consumer badge → unmatched domain = `unknown/unrecognized_email_domain`. Additive exports only.
- `sensors/browser-extension/content.js` (~60 lines): `probeAccount()` — bounded DOM query (cap ~20 elements, 512-char slices), extract → classify → cache enum, discard raw strings. **Never inside keydown/paste/click handlers** — `interceptSend` (:460-521) reads only the cached object. Attach `clientAccount` to every `report()` payload (:274-285). UX per new policy field `corporateAiAccounts.personalAccountAction: allow|coach|block`: coach = one toast per page load; block = prevent send after the `destinationBlocked()` check + report `clientOutcome:'destination_blocked'`.
- `sensors/browser-extension/background.js`: add `clientAccount` to the explicit relay whitelist (:408-429).
- `server/policy.js`: `DEFAULT_POLICY.corporateAiAccounts = { orgEmailDomains: [], personalAccountAction: 'allow' }` + normalizer (domains ≤40, host-validated) + AUDIT_FIELDS; new scope matcher `accountTypes` in `normalizePolicyMatchers` (:206-225) / `hasPolicyMatcher` / `policyRuleMatches` (:658-676) — the stricter-wins engine gives "personal ⇒ block-grade thresholds" with zero new evaluation code; helper `personalAccountBlocked(accountType, pol)`.
- `server/app.js`: destructure + normalize `clientAccount` in gate; **server-side enforcement mirror** after destination checks (~:1052-1066) via `blockDestinationByPolicy` with reason "Personal AI account blocked by policy…"; `accountType` into `policyContext()` (:343-352) and the `base` row (:1117-1124 — JSON blob, no migration); expose `corporateAiAccounts` in `sensorSafePolicy()` (:1367).
- `server/validation.js`: strict `clientAccountSchema` enum object in gateSchema — **a raw email field is rejected at the boundary by construction**; `accountTypes` in `policyMatcherFields` (:481-517); `corporateAiAccounts` in `policyUpdateSchema`.
- Stats/examiner surfaces: `server/insights.js` `accountTypes` totals + `personalAccountTopDestinations` + `personalBlocked` counter (the LayerX-comparable "% of AI activity on personal accounts" number); `server/coverage.js` per-destination `personalAccountEvents` (:132-149); `server/evidence.js` `safeQuery` enum-bounded `accountType` (:91-125) + `byAccountType` lineage (:778-788) + policy audit field; `server/posture.js` new `personal_account` guardrail row (mirror `shadow_ai` :689-697). `docs/POLICY_SCOPES.md` matcher row + trust-boundary note (client-asserted signal can only forfeit tightening — never weakens alwaysBlock/base). Optional console follow-up: accountType chip in Queue, personal-usage tile in Overview.
- Tests: `test/adapters.test.js` precedence table + "result never contains an email"; `test/extension-content.test.js` (vm harness) probe caching + payload + block/coach + no-probe-on-keystroke; `test/policy-scope.test.js` tighten-only; `test/validation.test.js` rejects `{email:…}`; insights/evidence aggregation + **serialized-pack-contains-no-@-address assertions**; `e2e/browser-extension.spec.js` fixtures (`jane@gmail.com` profile button vs "ChatGPT Team" badge → coach toast / blocked send / corporate passes).

**Accept:** fixture matrix classifies personal/corporate/unknown with signals; no email (raw or hashed) in any request body, stored row, API response, audit detail, or evidence pack; coach/block/allow semantics exact incl. never-block-on-unknown; `accountTypes` scope tightens, never loosens; insights/evidence/posture populated; hot path untouched; sync-check green; eval floors + alwaysBlock invariant green.

**Verify:** `npm run sync-engine && npm run sync-check` · `npm test` · `npm run test:browser-extension` · `npm run eval` · `npm run suite:smoke` · `npm run review:ci`

**Risks:** selector brittleness (default-to-unknown + signal recorded + e2e fixtures pin behavior; consider an "unknown-rate per destination" posture signal later); misclassification → wrongful block (structural mitigations: unknown-never-blocks, allow default, coach-first rollout); client-asserted trust boundary (documented; tighten-only); Gemini account-chooser ambiguity (best-effort, fallback unknown).

---

### WAVE 3 — Collateral + evidence (sales material now claims what waves 1–2 shipped)

#### 8. `competitive-refresh` — Update competitive docs + new Nightfall battlecard (effort S, docs-only)

**Why:** `docs/COMPETITIVE_BENCHMARK_2026.md` has stale Nightfall cells the report contradicts (verified: line 75 "MCP / agent tool-output guard | Nightfall ○" — their sixth pillar now covers agent hooks; line 66 indirect-injection ○ likely ◐). No battlecard exists. COMPETITIVE_ALIGNMENT.md ships to customers in the Security Trust Package (`server/security-package.js:456`) — claims must stay truthful. **Sequenced here deliberately (reviewer): items 1–7 falsify the concessions an early version would have made, and item 4's benchmark doc supplies citable numbers.** (If sales needs a battlecard before wave 2 completes, write it early with honest concessions and refresh — but the default is this slot.)

**Build:**
- `docs/COMPETITIVE_BENCHMARK_2026.md`: rewrite Nightfall field entry (:20-21) to cover five pillars + MCP & AI Agent Security + Nyx; update the matrix Nightfall column (line 75 ○→◐ etc.) with a Notes list under the matrix (they hook agent actions and discover shadow MCP but don't sanitize MCP tool output pre-model like `sanitizeToolResult()`); notes on response rows: **Nightfall is monitor-only for raw LLM responses; our gateway returns 403 on blocked output** (`gateway/server.js:89-91`, :196-198). New section "Nightfall AI Agent Security vs PromptWall" — now claiming items 5–7 with file anchors (agent-hooks sensor, shadow-MCP inventory, personal-account detection) and keeping honest concessions for what's still missing (Nyx-class analyst → roadmap X6; CV-model OCR depth until item 12; SaaS data-at-rest connectors by design). Update PromptWall matrix cells that items 1–4 changed (vendor-labeled secrets, doc-class categories, published benchmarks).
- `docs/COMPETITIVE_ALIGNMENT.md`: update Nightfall market-bar bullet (:25-27) — agent-security pillar, Nyx, ≤100ms p99/≥1000rps marketing targets vs 5–10 rps customer rate limits, monitor-only responses, US-only AWS multi-tenant + 24h dev-platform file retention, MDM Full-Disk-Access deployment, four masked-price bundles/MSSP motion, usage-metered packaging; add the report to Works Cited (:396+, MLA, accessed date).
- NEW `docs/BATTLECARD_NIGHTFALL.md` (one page, **internal-sales-only marker, NOT added to `server/security-package.js` docs()**): their pitch / our wins with repo anchors (zero-egress engine; gateway blocks responses; no per-scan rate limit — cite item 4's measured p95 WITH the apples-to-oranges caveat; per-seat offline license `docs/CUSTOMER_LICENSING.md` vs usage-metered opacity; force-install browser rollout `docs/MANAGED_EXTENSION_DEPLOYMENT.md` vs MDM+FDA; hash-chained audit `verifyAuditChain()`; vendor-labeled secrets; doc-class categories; agent hooks + shadow-MCP + personal-account detection) / where they win + objection handling (100+ detectors vs our 44+ checksummed — cite `npm run eval` floors + corpus n; Nyx → X6 and "we never send prompts to any LLM"; CV/OCR depth) / landmines (where does prompt text go? what happens above your rate limit? can you block a bad response or only alert? what does the examiner get?).
- Index battlecard in `docs/README.md`. Pricing phrasing consistent with ROADMAP's "~$25–60K band" (:31).

**Verify:** `npm run docs:demo-guide:check` · `git diff --check` · `npm run review:ci`

**Risks:** credibility — COMPETITIVE_ALIGNMENT.md is customer-facing; ◐+notes instead of silent cell flips; battlecard stays out of the trust package; every number traces to `npm run bench`/`npm run eval` output.

#### 9. `otel-audit-export` — OTLP/HTTP(JSON) export for AI activity events (effort S)

**Why:** Nightfall advertises OTel audit trails. Our SIEM pipeline (`server/siem-formats.js` ADAPTERS registry :133 + `server/subscriptions.js` deliver/retry/dedupe engine) makes this a pure pattern-following adapter — zero new dependencies, and the type whitelist/console/docs propagate automatically from `supportedTypes()` (verified literally true). Pairs with items 5–6 for "agent activity to your observability stack". **Scope honesty:** exports gate/security/admin/digest/sensor-stale events, NOT the hash-chained audit ledger — market as "AI activity events via OTLP"; full audit-chain streaming is a separate follow-up (needs a `db.appendAudit` hook + fresh PII review).

**Build:** add `otlp` adapter to ADAPTERS (helpers `otlpAttr`, `otlpSeverity` — maxSeverity 0/1→9 INFO, 2→13 WARN, 3→17 ERROR, 4→21 FATAL, matching `statusLevel` :135 thresholds; each <30 lines): POST to `joinUrl(dest.url, '/v1/logs')` (verified no double-suffixing), optional Bearer token, body = OTLP/HTTP JSON LogsData — **int64 fields (`timeUnixNano`, intValue) MUST be JSON strings per proto3 JSON mapping**; `body.stringValue = summaryLine(event)` (:28); attributes in the `promptwall.*` namespace (NOT still-evolving `gen_ai.*`): event_type, action, query_id, schema_version, enduser.id, destination, source, channel, risk_score, max_severity, finding_types (labels only). `normalizeDestination` passes optional `serviceName` (≤120 chars; chronicle-extras precedent :110-111). Update `config/subscriptions.json` `_comment` (collector must accept OTLP/HTTP JSON; no protobuf/gRPC/gzip), CHANGELOG (:57-59), `docs/INCIDENT_RESPONSE.md:23`. Tests: existing supportedTypes() PII-free loop (`test/subscriptions.test.js:32-40`) auto-covers it; add envelope test (url suffixing, Bearer header, string timeUnixNano, severity 21 for maxSeverity 4, service.name attr, no `412-22-7843` anywhere; no-token → no auth header).

**Verify:** `node --test test/subscriptions.test.js` · `npm test` · `npm run review:ci`

#### 10. `clipboard-provenance` — Origin-app metadata on clipboard events (effort S; **scout first**)

**Why (reviewer-proposed, not yet agent-verified):** Nightfall markets endpoint data lineage. `server/evidence.js` aggregates lineage byUser/byDestination/bySensor (`buildLineage` ~:779), but `sensors/endpoint-agent/collectors/clipboard-guard.js` never captures the copied-from application. Bounded origin-app metadata (sanitized app id from the existing KNOWN_AI_TOOLS-style catalog — **never window titles, never content**) lets the examiner report say "NPI copied from the core-banking client into ChatGPT" — a materially stronger N2 narrative.

**Build (scout pass first):** confirm what OS-level foreground-app signal the clipboard guard can access per platform; extend the clipboard gate record with `originApp` (sanitized id, fixed vocabulary or basename only); thread through gate → lineage aggregation → evidence pack; canary test that no window titles/paths/content leak. If the signal proves unreliable cross-platform, ship Windows-only first or drop with a DECISIONS.md note.

**Verify:** `npm test` · `npm run evidence:pack` · `npm run review:ci`

---

### WAVE 4 — Commercial + platform readiness

#### 11. `license-verifier` — Ship the Ed25519 offline license verifier (ROADMAP N7) (effort M→L boundary)

**Why:** Nightfall's pricing is opaque and enterprise-gated; our counter is transparent self-serve pricing — which requires the licensing mechanism to exist (`docs/CUSTOMER_LICENSING.md` is design-of-record; verifier not shipped; pilots run on signed order forms). De-risked: `server/policy-bundle.js:25-93` is a complete Ed25519 sign/verify template (node:crypto, fail-closed enum reasons, NaN-safe expiry :85); seat counting works (`server/tenant.js:73-91`, `/api/billing/seats` :1955).

**Build:**
- NEW `server/license.js` (model on policy-bundle.js). Format: `promptwall.lic` = `base64(payload JSON).base64(Ed25519 sig over the base64-payload bytes)` — signing the encoded string avoids JSON canonicalization. `verifyLicenseText` (embedded SPKI public-key PEM const + `SENTINEL_LICENSE_PUBLIC_KEY` env override as the test seam — design it in from the start), enum-reason failures only, never echo file content. State machine per the doc **exactly** (verified word-for-word: absence = demo :48, warn at 100% :56, grace 30 :66, past-grace read-only with approvals working :67): missing/invalid → `unlicensed` (ZERO gating); active; `grace` (banner); `readonly`. `requireWritable()` middleware: 403 `license_readonly` on adminWrite/operatorWrite EXCEPT the `/api/queries/` prefix (reveal/assign are genuinely adminWrite routes under it — verified; the approval workflow is never impaired).
- `server/app.js`: `requireWritable()` appended to adminWrite + operatorWrite arrays (:1672-1678) — **NOT decisionWrite, NOT `/api/v1/*` ingest, NOT SCIM** (deactivation is a security function); boot check in `startServer()` (:2761) + daily unref'd interval (mirror retentionTimer :2783-2792) + `logStartup` (:2739) warning line; `GET /api/billing/license`; `POST /api/billing/license` (security_admin + CSRF, deliberately WITHOUT requireWritable so a renewal can always be installed; verify-before-write 0600; audit `LICENSE_INSTALLED`/`LICENSE_INSTALL_REJECTED` metadata-only); extend `/api/billing/seats` with license block. `server/validation.js` `licenseInstallSchema` (zod `.strict()`); `server/env.js` ENV_ALIASES (:9) + `SENTINEL_LICENSE_PATH` (default next to `.env` via `defaultEnvPath` :71).
- NEW `scripts/license-issue.js` (vendor-side): `--init-keypair` (private key 0600, NEVER committed; prints public PEM to embed) + issuance flags + self-verify round-trip before exit 0.
- Console: License card in Configuration tab (`index.html:3347`, paste+install via existing csrf helper), grace/readonly banner, seats tile used-vs-licensed with warn at 100% (`dashboard.js:2038-2060`).
- Tests: `test/license.test.js` (tamper/expiry/wrong-key/garbage-never-throws) + `test/license-api.test.js` asserting **the never-disable invariant: with a past-grace license, `/api/v1/gate` still blocks, approve/deny still 200, audit/evidence export still 200, PUT /api/policy → 403, installing a fresh license clears readonly**. Update `test/admin-csrf.test.js:16-19` (regex-pins the middleware-array source shapes — verified) + `suite/contract/admin-routes.suite.js:23` together or review:ci fails.
- v1 displays but does NOT enforce feature flags (hard-disabling a sensor over plan tier skirts "never disable the security function" — defer). Do NOT couple license.seats to `SENTINEL_SEAT_LIMIT` hard enforcement (warn-and-true-up stays default).

**Verify:** `npm test` · `node --test test/license.test.js test/license-api.test.js` · `npm run suite:contract` · keypair round-trip via `scripts/license-issue.js` · `npm run review:ci`

**Risks:** gating-scope judgment (the `/api/queries/` exemption is pinned by tests); three files assert middleware shape — update together; real vendor keypair generated offline before first commercial release (repo gets public key only; key rotation = known follow-up); air-gapped clock skew (30-day grace is the mitigation — no stricter time checks).

#### 12. `bundled-ocr` — WASM tesseract fallback in the endpoint agent (effort M; deliberate ROADMAP pull-forward)

**Why:** Nightfall has server-side OCR + CV. Our images dead-end at `ocr_required` unless a workstation has native tesseract (auto-discovery already exists, `sensors/endpoint-agent/ocr.js:52-84`). ROADMAP :63-64 lists bundled OCR under "Later" — the report justifies pulling it forward. Endpoint-agent-only (server-side is a separate follow-up; `PLANS/customer-missing-features.md:366` deliberately keeps server OCR off).

**Build:**
- `tesseract.js ^6` as **optionalDependency** (Apache-2.0; attribution note; guarded require so install failure degrades to today's behavior — npm ci installs optional deps by default so CI exercises the real path).
- **Vendor `sensors/endpoint-agent/tessdata/eng.traineddata.gz` (~1.9MB, committed) and hard-pin `langPath`/`corePath`/`workerPath` to local files — tesseract.js's default langPath is a remote CDN; a bank endpoint must NEVER phone home. Missing local tessdata → report unavailable, stay ocr_required, never fetch.**
- NEW `sensors/endpoint-agent/ocr-wasm.js` (separate file keeps the packaging token guard clean — `scripts/package-endpoint-agent.js:117-123` forbids `fetch(`/`https://`/`readFileSync` in ocr.js, verified): `wasmOcrAvailable()` (env kill-switch `ENDPOINT_AGENT_OCR_WASM` default on; require.resolve probe; tessdata stat; module cache + `resetWasmOcr()` mirroring `resetOcrDiscovery` :82); `extractImageTextWasm()` — ONE shared lazy worker, reused, idle-terminated (~60s unref'd) + on exit; timeout race that `worker.terminate()`s (tesseract.js has no built-in timeout; default 30s — first-run model load 1–3s).
- Wire into `ocr.js extractImageFile` (:158-186) `!settings.configured` branch: lazy-require, same bounded maxChars/timeout (`boundedPositiveInt` :25), return EXACT existing result shape + additive `ocrEngine:'wasm'`; any throw → `fail('extract_failed')` (:147, fail closed, no text in logs). **Precedence: explicit env command > native discovered tesseract > WASM > ocr_required.**
- **Strict mode (user decision):** add `ENDPOINT_AGENT_OCR_STRICT` env (default off, `PROMPTWALL_` alias): when on, an image whose OCR (native or WASM) yields little/no text (below a small char threshold) is still routed to `ocr_required`/the approval queue instead of being allowed on sparse extraction. Document in .env.example + DEPLOYMENT.md; test both modes.
- Packaging: add ocr-wasm.js + tessdata to PACKAGE_FILES; validator guard on ocr-wasm.js (must contain `langPath`+`terminate`, must not match network tokens); exclude the binary .gz from the utf8 token scan deliberately; `endpointWasmOcrIncluded:true` manifest check. Install check: `ocrExtractionCheck` (:172-186) runs the real fixture (`fixtures/ocr-sample.png`, `/PROMPTWALL/i`) through WASM when no native engine. Tests: precedence, kill-switch (byte-for-byte today's ocr_required result), missing-dep degradation, real fixture extraction (skip-gated), timeout-terminates-worker. Docs: .env.example, DEPLOYMENT.md, README, ROADMAP (out of Later), CHANGELOG; decide Dockerfile `--omit=optional` for the server image.

**Verify:** `npm test` · `npm run package:endpoint-agent` · `node scripts/check-endpoint-install.js --json` · `npm run endpoint:check` · `npm run sync-check` · `npm run review:ci`

**Risks:** **posture change** — today unreadable images hard-block to the queue; with fallback, a low-quality photo whose PII tesseract can't read yields sparse text and is ALLOWED (parity with the existing native-command path, but call out in CHANGELOG + consider a strict-mode env); zero-egress regression hazard (hard-pinned paths + packaging guard + refuse-without-tessdata); ~150–300MB transient RSS on old credit-union workstations (single worker + idle terminate; pilot canary); don't oversell vs their CV transformers (screenshots/scans yes, photos/handwriting no).

#### 13. `openapi-devsurface` — OpenAPI 3.1 spec + developer reference for the sensor/scan API (effort M)

**Why:** Nightfall's Developer Platform is their most replicable surface and a top-of-funnel motion. Our `/api/v1` surface (11 routes, verified at `server/app.js:902-1581`) has Zod-validated requests (`server/validation.js:162-433`, exports :638) but no machine-readable spec. **Zod 4.4.3 (package.json:99) ships native `z.toJSONSchema` targeting draft 2020-12 = exactly what OpenAPI 3.1 embeds — zero new dependencies.** STACK_REVIEW.md:67 already wants this.

**Build:**
- NEW `server/openapi.js`: `document()` with module-level cache (built once, cold route). Request component schemas GENERATED from the exported Zod schemas (single source of truth). **Known caveat:** `z.preprocess`-wrapped fields (optionalString :71, stringDefault :78, nullableString :85) may throw or degrade under `io:'input'` — fall back to `io:'output'` per-schema; the contract test keeps examples honest either way. Hand-author response schemas (ad-hoc `res.json()` shapes today) **with `additionalProperties: true`** so the spec never over-constrains the stable API. Security schemes: IngestKey (`x-api-key`, `checkIngestKey` :266) + ReleaseToken (`x-release-token` on status/rehydrate). Static PATHS table with operationIds, error responses (400/401/403/404/409/413/429 → ErrorResponse), one synthetic example per POST op. SensorPolicy response from the `sensorSafePolicy` key list (:1367-1391).
- `server/app.js`: `GET /api/v1/openapi.json` served WITHOUT checkIngestKey (public like `/healthz`; contents already public in-repo — flag the choice in the PR; flipping is one line).
- NEW `suite/contract/openapi.suite.js` (`// @tier smoke` first line — verified necessary because `review:ci` does NOT run suite tiers): 200 + version match; **two-way parity** — every documented op answers 401 without key AND the canonical `SENSOR_ROUTES` list (`sensor-routes.suite.js:15-27`) ⊆ spec paths; every embedded example `safeParse()`s against its validation.js schema and a mutated invalid example fails; hygiene — spec JSON matches no SSN/PAN patterns, no ingest key.
- NEW `docs/API_REFERENCE.md` (auth, release-token flows, decision/status semantics, receipt verification, curl per POST route, privacy contract) + `docs/README.md` index row. Out of scope: Swagger UI (fights dependency-light stance), admin console routes, SCIM (own RFC contract + suite).

**Verify:** `npm run suite:contract` · `npm run suite:smoke` · `npm test` · `npm run review:ci` · manual `curl -s localhost:4000/api/v1/openapi.json | head`

**Risks:** toJSONSchema fidelity on preprocess-wrapped fields (per-schema fallback); publishing converts ad-hoc responses into an external contract (permissive schemas).

#### 14. `compliance-ingestion` (DEFERRED — design-first) — Sanctioned-tenant compliance-log ingestion (Claude/ChatGPT Enterprise)

**Why (adversarial review):** Nightfall ingests the Anthropic Claude Compliance API to see inside sanctioned tenants. Pairs with item 7: once corporate accounts are allowed, the institution still owes examiners visibility into what those accounts did. ROADMAP X3 establishes the "ingest, don't intercept" pattern (scoped to M365 Copilot). Pull runs from the customer's network against their own tenant — zero-egress-consistent — reusing the incident/evidence pipeline. **Not yet spec'd against the codebase: run a scout/design pass (like the ones behind items 1–13) before implementation. Do not feed to Claude Code as-is.**

---

## Sequencing summary

```
Wave 1 (strictly serial — shared fixture/floors):
  1 secrets-vendor → 2 doc-class (at current 0.90/0.70 floors) → 3 eval-corpus (incl. floor raise, now safe) → 4 bench (stable corpus + floors to publish)
Wave 2 (serial — 5 & 6 both touch coverage.js/heartbeat):
  5 agent-hooks (shared decide() helper mandate) → 6 shadow-mcp (checks-cap 40→80 also benefits 5's checker) → 7 n4-accounts
Wave 3:
  8 competitive-refresh (claims waves 1–2, cites bench) → 9 otel → 10 clipboard-provenance (scout first)
Wave 4 (independent, any order):
  11 license-verifier → 12 bundled-ocr → 13 openapi → (14 design pass only)
```
After wave 4, touch up `docs/COMPETITIVE_BENCHMARK_2026.md` again: items 12–13 flip the OCR and developer-platform cells.

## Verification (plan-level)

- Per item: the Verify list in its section (constraint reviewer confirmed zero invented commands — everything exists in package.json).
- After each wave: `npm run review:ci` (full gate) + `npm run suite` (full tiered suite — review:ci does not run suite tiers).
- Detection changes end-to-end: `npm run eval` floors + `node scripts/bench-detect.js --ci` (after item 4) + `npm run test:browser` / `npm run test:browser-extension`.
- Marketing claims: every number in docs must trace to `npm run bench`/`npm run eval` output or a file anchor — no invented figures.

## Resolved decisions (user-confirmed 2026-07-05)

1. **HR_RECORD fallback pre-approved** (item 2): if it can't hold the 0.90 precision floor, ship FINANCIAL_STATEMENT + TAX_FILING and defer HR_RECORD. Floors are never weakened.
2. **openapi.json is public** (item 13): served like /healthz, no ingest key.
3. **Bundled OCR ships WITH a strict-mode env** (item 12): `ENDPOINT_AGENT_OCR_STRICT` (default off) hard-queues images whose OCR yields little/no text — built into the item, not a follow-up.
4. **Battlecard after wave 2** (item 8): it claims shipped capabilities and cites real benchmark numbers; no early concession version.
