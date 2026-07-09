# Plan: Make RedactWall the go-to AI-compliance tool for credit unions

## Goal & context

**Outcome.** A credit union (CU) compliance officer can sit across from an NCUA
examiner and credibly say: *"Yes, we have an AI compliance tool. It stops member
NPI from leaking into third-party AI, it inventories where we use AI, and here is
the tamper-evident evidence that we tested the controls."* The pilot deliverable
**is** the exam artifact.

**Scope — sharp and deliberate.** RedactWall **owns** the GLBA Safeguards Rule
(12 CFR 748 App A) + shadow-AI data-leakage slice of NCUA AI compliance:

- Stop member NPI (SSN, member ID, loan/account/routing, cards, DOB, TIN) from
  leaking into ChatGPT / Copilot / Claude / Gemini.
- Catalog where AI is used (embedded vendor AI **and** shadow AI).
- Produce examiner-ready, tamper-evident evidence that controls were tested.

RedactWall **deliberately does NOT** do model-risk management / fair-lending /
SR 11-7. Those apply to **lending models a CU builds or buys** and are out of lane.
Overclaiming into model risk is a liability a compliance officer and their examiner
will see through. The honest play: **own the data-protection slice completely,
produce examiner-ready evidence, hand off the rest.** Board AI policy, the AUP prose,
board minutes, and 5300/863 filings remain CU-owned handoffs.

## Invariants (non-negotiable for the whole run)

Every code proposal below must respect these. They are load-bearing, not aspirational.

- **Detector logic lives ONLY in `detection-engine/detect.js`.** After any detector
  change run `npm run sync-engine`; `npm run sync-check` must stay green. Never
  hand-edit `sensors/browser-extension/lib/detect.js` (it is generated).
- **Semantic model changes go through `npm run train-semantic`** (deterministic; CI
  diffs on drift).
- **No `alwaysBlock` type weakened.** No raw PII / prompt text / secrets in logs or
  audit entry bodies. `verifyAuditChain()` must stay `ok:true`.
- **Keep the `detection-engine/` public API stable** (all sensors depend on it).
  Keep the hot path allocation-light (runs on every keystroke and paste). Functions
  ~<30 lines; extract helpers; don't duplicate detector boilerplate.
- **Acceptance evidence for code changes** = `npm test` + a new `test/*.test.js`
  case + `npm run simulate`/`npm run eval` where detection changes + `npm run review:ci`
  green.
- **Evidence exports** use hashes and omit prompt bodies
  (`scope.rawPromptBodiesIncluded=false`).
- **Do not name RedactWall competitors on any shipped/rendered surface** (console,
  served API/OpenAPI, evidence-pack JSON). Naming the CU's **own** core-banking
  vendors is fine and helpful; naming rivals in `docs/`/`PLANS/` collateral is also
  allowed. The ban targets rendered product surfaces only.

## Reality check: the wedge is ~70% built

Trust code + CHANGELOG over ROADMAP/STATUS TODO lists. Most of the CU wedge already
exists under CHANGELOG `[Unreleased]` — the work is **finish, prove, label honestly,
and ship**, not rebuild.

| CU capability | State | Grounding |
| --- | --- | --- |
| NCUA Readiness score + console view | ✅ built | `server/ncua-readiness.js`, `console/src/views/NcuaReadiness.tsx` |
| Examiner-profile evidence pack (schemaVersion 3) | ✅ built | `server/evidence.js:919`, `scripts/export-evidence-pack.js --examiner-profile federal_credit_union` |
| AI use-case inventory + 72h incident workflow | ✅ built | migrations v5 / v6 (12 CFR 748.1(c)) |
| Coded control mappings → NCUA 748 App A / GLBA 501(b) / NIST AI RMF | ✅ built | `server/control-map.js:14-152` (+ in-code "evidence pointers, not certification" caveat at `:5-7`) |
| `ncua_glba` policy template (SSN, member ID, loan#, acct/routing, cards, DOB, TIN) | ✅ built | `server/templates.js` |
| Core-banking EDM hard-block (salted one-way fingerprints, plaintext discarded) | ✅ built | `scripts/edm-fingerprint.js`, `detect.js:582 detectExactMatch`, `VIRTUAL_DETECTOR_IDS:355` (EXACT_MATCH sev 4) |
| Tamper-evident hash-chained audit + signed safe-to-send receipts | ✅ built | `server/db.js verifyAuditChain`, HMAC receipts |
| Debit/ATM PAN coverage (Visa/MC/Amex/Discover/Diners/JCB + Luhn, ctx incl. "debit") | ✅ built | `detect.js:157-168 cardNetwork()` / `CARD_CTX` |
| ~44 detector types incl. ROUTING (ABA mod-10), MEMBER_ID, LOAN_NUMBER, US_TIN_EIN, US_NPI | ✅ built | `detection-engine/detect.js` |
| Security Trust Package (self-attested SOC 2 map + CycloneDX SBOM) | ✅ built | `server/security-package.js`, `docs/security/SECURITY_TRUST_PACKAGE.md` |
| Published detection benchmarks + CI floors (semantic P≥0.95 / R≥0.80, structured R≥0.95, benign FP=0) | ✅ built | `docs/product/DETECTION_BENCHMARKS.md` |
| **Gap:** CU core-banking custom-detector pack (Symitar/Episys, Corelation, Fiserv, Finastra) | ❌ empty stub | `config/custom-detectors.json` = `{"detectors":[]}` |
| **Gap:** MICR-line / share-draft detector | ❌ absent | no MICR/transit/share-draft in `detect.js` |
| **Gap:** FFIEC control-family labels | ❌ roadmap language only | absent from `control-map.js`; only in `ROADMAP.md:23,41` |
| **Gap:** AUP artifact + clause→control crosswalk | ❌ absent | no `acceptable_use` control; `templates.js` has none |
| **Gap:** "evidence pointers, not certification" disclaimer as an emitted field | ❌ absent | caveat is a source comment only (`control-map.js:5`) |
| **Gap:** rendered (human-readable) quarterly examiner report | ❌ JSON only | `scripts/export-evidence-pack.js` writes `JSON.stringify` only |
| **Gap:** reconciled "Where are we using AI?" (shadow-AI ⋈ declared use-cases by host) | ❌ not joined | `reviewRollup()` drops host; `publicCatalog()` has it |
| **Gap:** structured knownLimitations/bypassPaths + per-control assurance level | ❌ absent | `security-package.js:464` generic strings; no assurance field |
| **Gap:** GLBA flow-down / DPA / BAA templates; CU-mapped DDQ pack | ❌ absent | `docs/legal/` does not exist; `questionnaire()` 5 generic Q&A |
| **Gap:** independent pentest report + real SOC 2 audit | ❌ external (money/time) | only self-attested `soc2Readiness()` map |
| **Gap:** first tagged release | ❌ none | `git tag` empty; `package.json` 0.3.0; Ed25519 key is placeholder |

## Strategic options

### Option A — Finish, prove, label, ship the existing wedge; land 1 design-partner CU *(RECOMMENDED)*
Close the small honest gaps on top of the ~70%-built wedge: ship the disclaimer field,
the rendered examiner report, the controlTests rollup, the CU detector pack (opt-in,
context-gated), roster EDM `--column`, procurement artifacts (assurance labels, GLBA
flow-down, DDQ pack), then tag a labeled release and run one direct AWS-customer-silo
pilot tied to a known 2026 exam date.

- **Pros:** Lowest risk; nearly everything already exists; every gap is closeable in
  days-to-weeks; produces the exact examiner artifact that wins the deal; matches
  `DECISIONS.md` (compete on simple regulated deployment + examiner-grade evidence,
  not connector breadth). Directly reduces the two live liabilities (implied
  certification; self-attested-SOC2 overclaim).
- **Cons:** Detection coverage of checksumless core IDs stays best-effort; independent
  assurance (pentest/SOC 2) is a money/time gate code cannot close.

### Option B — Broaden the compliance surface first (FFIEC / AUP prose / 5300–863 forms)
Add FFIEC control families, author an adoptable AUP, and auto-populate NCUA forms
before shipping.

- **Pros:** Wider on-paper coverage; more checkboxes in a bake-off.
- **Cons:** FFIEC as label-only is cheap (keep it), but **authoring AUP prose and form
  filing pushes into governance-document + model-adjacent territory that is out of lane
  and a liability.** Delays the wedge for surface area that examiners treat as CU-owned.
  Reject as the *primary* thrust.

### Option C — Platform / multi-tenant SaaS scale first
Build the shared-SaaS / managed-Postgres cutover before the first sale.

- **Pros:** Better long-run unit economics; channel-ready.
- **Cons:** Contradicts `DECISIONS.md` (first paid deploy = AWS customer-silo, not
  shared SaaS) and dilutes the single most valuable thing — one quantified reference.
  A shared data plane also complicates the per-CU 748 App A oversight story. Defer.

**DECIDED: Option A** (maintainer, 2026-07-09). The wedge is ~70% built; the remaining work
is finishing, proving, and labeling honestly, plus one design-partner CU. Keep FFIEC *labels*
(cheap, honest) from B; defer B's AUP-prose/forms and all of C.

## Workstreams

Legend: **Status** = built / partial / new. ✅ = ship/tighten, don't rebuild.
Proposals ordered P0 → P2 within each workstream.

### WS1 — Tune detection for credit-union data specifically

> None of these weaken `alwaysBlock`. **Critical CI caveat:** `scripts/eval-detect.js`
> calls `D.analyze(text)` with **no opts**, so it never loads `config/custom-detectors.json`
> or `config/exact-match.json` — the benign-FP=0 / adversarial-FP=0 floors do **not**
> exercise a shipped pack or roster EDM. A dedicated pack-loading benign test is
> **mandatory**, not optional.

| Proposal | Status | Priority | Effort | Why the examiner cares | Grounding file |
| --- | --- | --- | --- | --- | --- |
| Ship curated CU core-banking custom-detector pack (Symitar/Episys, Corelation KeyStone, Fiserv DNA/Portico/Premier, Jack Henry, Finastra), **labels name the core vendor, disabled-by-default, every pattern context-gated** (Decision 1) | new | **P0** | M | "Do you detect member data in *our* core system?" — coverage-map/evidence-pointer, not certified detection | `config/custom-detectors.json` (empty stub); `detect.js:465 normalizeCustomDetector` + `regexLooksSafe`; `server/custom-detectors.js loadRaw` |
| CU roster → EDM importer (add CSV `--column` flag) to hard-block **real** member numbers and cut false positives — ✅ capability already built, `--column` is the only net-new piece | partial | P1 | S | "Do you protect *our* members' actual numbers?" — strongest honest control; local operator script, no server plaintext upload | `scripts/edm-fingerprint.js`, `detect.js:582 detectExactMatch`, `VIRTUAL_DETECTOR_IDS:355` (sev 4); CSV parser reuse from `scripts/import-ai-discovery.js` |
| Built-in MICR-line / share-draft detector — emit the account span as existing `BANK_ACCOUNT` type (already in `alwaysBlock`); do **not** mint a new type | new | P1 | M | Share drafts are the CU checking product; a pasted MICR string is member NPI | `detect.js:37 abaValid()` (reuse), `:299 ROUTING ctx`, `:303-304 BANK_ACCOUNT` |
| Tighten MEMBER_ID / BANK_ACCOUNT with CU charter vocabulary — anchor on **multi-word** tokens ("share account", "share draft", "sub-share", "account suffix"), never bare "share" | new | P1 | S | Recall gain on CU-native terms without breaking benign-FP=0 | `detect.js:304 BANK_ACCOUNT ctx`, `:313 MEMBER_ID labels` |
| ✅ Verify debit-card BIN coverage — do **not** build; add one eval regression fixture proving a share-draft debit PAN is caught | built | P2 | S | Debit/ATM PANs already ride existing networks | `detect.js:157-168 cardNetwork()` / `CARD_CTX` incl. "debit" |

**WS1 guardrails.** The engine does **not** enforce a context clause
(`normalizeCustomDetector` treats `raw.context` as optional) — a contextless numeric
pattern **will** fire on bare numerics and break benign-FP=0. This is author discipline
backed by the new pack-loading benign test, not an engine guarantee. Most core IDs have
**no checksum**, so lean on roster-seeded EDM for hard-block confidence and keep the
regex pack context-gated/warn-tier. If a true hard-block guarantee is wanted for roster
values, add `EXACT_MATCH` to the `ncua_glba` `alwaysBlock` list (today it blocks only via
the severity-2 threshold).

### WS2 — The examiner artifact a CU can literally hand over

> None of these touch `detect.js` / the semantic model / `alwaysBlock`; sync-check and
> train-semantic determinism are unaffected (state this in the PR). All stay
> counts/enums/ISO-dates/pass-fail only, honoring `rawPromptBodiesIncluded=false`.

| Proposal | Status | Priority | Effort | Why the examiner cares | Grounding file |
| --- | --- | --- | --- | --- | --- |
| Add a "regularly test key controls" (748 App A) **controlTests** evidence section — assemble the scattered signals into one tested-controls rollup; stamp an **honest `lastTestedAt`** (export/verification time, not a periodic program) | partial | **P0** | M | 748 App A requires "regularly test key controls" + audit trails — this is the section that proves it | audit verify `ncua-readiness.js:239`; detection floors `evidence.js:708 safePostureDetectionQuality` (only in posture, not in `summarize()`); enforcement counts `ncua-readiness.js:56`; `evidence.js:213,286 restoreDrill` |
| Render the quarterly examiner report pack (N2) as a human-readable Markdown/HTML document over the existing schemaVersion-3 data — assert no free-text (owner/notes/minutes) leaks in | new | **P0** | M | A document a compliance officer hands across the table, not a JSON blob | `scripts/export-evidence-pack.js` (JSON-only: `parseArgs:17`, `writeEvidencePack:168`); data from `ncuaReadiness.summarize` + `boardPacket` |
| Add FFIEC handbook control-family **labels** to the control map (label-only string additions; existing caveat governs them) | new | P1 | S | FFIEC booklets are the framework examiners actually work from | `control-map.js:14-152 controlFamilies`; `buildControlMappings:360` passes through unchanged |
| Reconcile discovered shadow-AI with declared use-cases into one "Where are we using AI?" answer — plumb host-bearing `publicCatalog()` into `summarize()`, add an `aiInventory` panel | partial | P1 | M | The #1 examiner question; drives `ai_use_inventory` toward provable completeness | `db.js:732 listAiUseCases` (canonicalHost); `app-catalog.js:160 publicCatalog` (destination=canonicalHost) — NOT joined; `reviewRollup():152` drops host |
| Board cybersecurity-training + oversight evidence hook for `board_reporting` — self-attested enum/date/reference fields only (approval date, training-completion date, minutes reference id) | new | P1 | L | Board cyber training is a **named** 2026 NCUA priority; board minutes show AI governance | `control-map.js:252-258 stateFromBoardReporting` (grades cadence only); pattern from `db.js:708,805` migrations/routes |

**WS2 honesty guardrail.** Framing `verifyAuditChain` + CI floors as "testing key
controls" is defensible **only** as an evidence pointer with an honest export/verification
timestamp and the retained "evidence pointers, not certification" caveat — otherwise an
examiner reads more assurance than exists. Do **not** author an AUP or imply certification;
capture AUP as an attestation date + reference only (see Decision 4).

### WS3 — Close the loop between the CU's paper AI policy and enforcement

> **Sequencing:** P0 (clause ids) must land first — P2/P3 hard-depend on it. Order
> P0 → P1 → (P2, P3).

| Proposal | Status | Priority | Effort | Why the examiner cares | Grounding file |
| --- | --- | --- | --- | --- | --- |
| Ship an AUP clause→control **crosswalk** (machine-readable), as a new AUP-**specific** control — the CU supplies its own prose (Decision 4 → crosswalk + attestation only; RedactWall ships no board-adoptable AUP text) | new | **P0** | M | Proves the paper policy is actually enforced by the tool | no `acceptable_use` control today; `control-map.js:80` "acceptable-use" is a controlFamily under the **already-enforced** `ai_usage_governance` (`:83`); `templates.js` ships none |
| Promote the 7-department CU `policyScope` pack from docs-only JSON to a one-click **tighten-only APPEND** preset (must route through `normalizePolicyScopes`, never clobber base) | new | P1 | M | Department-scoped enforcement (Lending/Collections/…) shows granular control | inert JSON in `docs/security/NCUA_READINESS.md`; **confirmed clobber risk** `app.js:2825` shallow `{...before, ...t.policy}`; eval already tighten-only `policy.js:754-761` |
| Expose personal-vs-corporate account enforcement (N4) as an AUP-clause-backed control — **render the CU's actual configured action**, not an asserted block | partial | P2 | S | GLBA-relevant; shows personal-AI-account handling | N4 built: `app.js:1165`, `policy.js:447-449,734`, `evidence.js:855`; **default is `allow`** `policy.js:66` (dormant OOTB) |
| Coaching-acknowledgment audit trail keyed to acknowledged clause id (N3) — entry stays enum/id-shaped (`acknowledgedClauseId` is a code, never free text) | partial | P2 | S | "Employees were warned and acknowledged the policy" — training evidence | statuses `app.js:1334-1342`; counters `posture.js:646-647`; **`coachingCompleted` = justified+blockedByUser** (`posture.js:554`) — warned-then-proceeded not counted, needs a defined rule |

### WS4 — Survive CU vendor due diligence and procurement

> **File-bundling correction:** `docs()` (`security-package.js:452`) returns **pointers
> only**; `packageFiles()` (`:551`) bundles exactly four in-memory bodies and reads no
> doc bytes. To actually ship a file in the ZIP you must extend `packageFiles()` to
> `fs.readFileSync` it (as `scripts/export-security-package.js:37` already does). There is
> **no docs-drift gate** — `review:ci` runs `docs:demo-guide:check` only; drop any claim
> that new docs are auto-verified.

| Proposal | Status | Priority | Effort | Why the examiner cares | Grounding file |
| --- | --- | --- | --- | --- | --- |
| Per-control **assurance level** (self-attested \| ci-verified \| third-party-verified) — label `audit_chain` ci-verified, **nothing** third-party-verified until a real audit exists | new | **P0** | S | Cheapest de-risk of the self-attested-SOC2 overclaim that WILL surface in the review call | `security-package.js:180 control()` (no assurance field); `soc2Readiness note :347` |
| GLBA flow-down / DPA / BAA contract-language templates as real artifacts (labeled **draft/sample pending counsel**, gated on Decision 5) | new | **P0** | M | 748 App A service-provider clause is a named examiner checklist item; absence stalls the deal | `security-package.js:373-386 dpaBaaPosture()` asserts executed but ships zero text; `docs/legal/` does not exist |
| CU-mapped due-diligence questionnaire response pack (NCUA 07-CU-13 / 01-CU-20 dimensions) — every answer cites a control id or repo command | partial | **P0** | M | The artifact the CU files in its vendor folder | `security-package.js:420-450 questionnaire()` (5 generic Q&A, no NCUA mapping) |
| Structured `knownLimitations` / `bypassPaths` block in `trustPackage()` — 5 named bypass paths each paired with its compensating control | new | P1 | S | Reduces overclaim; honest residual-risk disclosure examiners respect | `security-package.js:464 limitations()` (4 generic strings); prose in `SECURITY_WHITEPAPER.md:141-160` |
| Independent pentest + SOC 2 readiness/scoping (`ASSURANCE_ROADMAP.md` + interim self-assessment labeled "internal self-assessment, not a third-party attestation") | partial | P1 | L | The two gaps code cannot close; the honest ceiling of WS4 | only `.claude/skills` tooling + self-attested `soc2Readiness():323-350` |
| Reviewable on-device NPI data-flow diagram (SVG) bundled in the trust package — show air-gapped default + connected-mode's two relaxations, not "nothing ever leaves" | partial | P1 | M | Shows exactly where member data does/doesn't go | ASCII already in `SECURITY_WHITEPAPER.md:49-78`; bundle via `packageFiles():551` |
| ✅ Formalize sub-processor register as a dated standalone file — do **not** change `subProcessors:[]` (breaks `security-package.test.js:171`) | partial | P2 | S | Vendor-management completeness | `security-package.js:382-383`; `SECURITY_WHITEPAPER.md:175-184` |
| CUSO / MSP / league channel enablement kit — GTM, **off the critical path** for the first direct AWS-silo sale | new | P2 | M | Positioning, not a first-sale procurement unblock | `ACCESS_ROLES.md:15` (MSP Engineer title only); no channel doc |

### WS5 — Deployment fit + go-to-market

> `docs/gtm/` is **not** a shipped surface — competitor names (Nightfall/Purview) are
> allowed there, as the existing battlecard already does. The seat model is **default
> warn-and-true-up, hard cap opt-in** (`REDACTWALL_ENFORCE_SEAT_LIMIT`) — never write
> "never blocks".

| Proposal | Status | Priority | Effort | Why the examiner cares | Grounding file |
| --- | --- | --- | --- | --- | --- |
| CU 30-day pilot playbook + examiner-tied success scorecard — frame output as tamper-evident **evidence pointers**, not certification; scope to the data-protection slice | new | **P0** | M | The pilot output IS the exam artifact; sets honest expectations | `infra/aws/customer-silo.yml`, `docs/deployment/AWS_SAAS_DEPLOYMENT.md`, `scripts/export-evidence-pack.js:204`, `docs/product/DETECTION_BENCHMARKS.md` |
| AWS customer-silo first-paid-deploy acceptance smoke (`scripts/aws-silo-smoke.js`) — the **one genuine code task**; asserts already-shipped behavior + ships a `test/*.test.js` case | partial | **P0** | M | Internal gate that the silo is examiner-ready before handover | `server/preflight.js:55 cloudSyncedPathReason()`, `db.verifyAuditChain()` (`app.js:714+`), examiner-profile export; pattern from `smoke-ai-gateway-ha.js` |
| Microsoft-shop deployment-fit brief (Purview-without-E5 wedge) — state plainly native Copilot/M365 coverage is **not** built (roadmap X3); fix command to `npm run identity:setup -- --provider entra` | new | P1 | M | Most CUs are Microsoft shops; honesty on Copilot scope preserves credibility | `docs/identity/IDENTITY_IDP_SETUP.md`, `/scim/v2`, `/auth/oidc/callback`, `docs/connectors/MCP_MICROSOFT365_CONNECTOR.md`; `ROADMAP.md:54 X3` future |
| Transparent CU pricing + packaging one-pager — "default warn-and-true-up, hard cap opt-in"; published number gated on Decision 6 | new | P1 | S | CUs buy on transparent, board-approvable pricing | `server/license.js`, `docs/process/CUSTOMER_LICENSING.md`; prior art `BATTLECARD_NIGHTFALL.md:27` |
| Reference-story + CUSO/state-league channel brief — de-identified case study honoring the evidence-export rule (no member data, no raw prompts) | new | P2 | S | Downstream of a landed reference; channel is deferred (Decision 7) | `docs/demo/SALES_DEMO_GUIDE.md`, `DECISIONS.md` |

### WS6 — Credibility / consistency fixes for the wedge

| Proposal | Status | Priority | Effort | Why the examiner cares | Grounding file |
| --- | --- | --- | --- | --- | --- |
| Emit the "evidence pointers, not certification" **disclaimer as a data field** in the schemaVersion-3 examiner pack + NcuaReadiness console — source from ONE exported constant in `control-map.js` so pack and console can't drift; v2 packs stay byte-unchanged | new | **P0** | S | **Single most important fix:** closes the implied-certification liability in the artifact an examiner actually receives | caveat is source-comment only `control-map.js:5`; pack ships `controlMappings` (`evidence.js:901,937`) with no disclaimer; console renders none |
| Move N2 from Now/pending → Shipped in `ROADMAP.md`/`STATUS.md` — mark shipped **only** the coded NCUA/GLBA/NIST slices; keep FFIEC + AUP explicitly listed as open tails | partial | **P0** | S | Kills doc-drift that a due-diligence reviewer would catch | drift at `ROADMAP.md:41`, `STATUS.md:107-109`; feature built (`evidence.js:919` schemaVersion 3); FFIEC absent from `control-map.js` |
| Cut first tagged release **v0.4.0** — labeled **pre-commercial/internal-demo** unless the placeholder Ed25519 key is replaced and the ≥1-week soak is done; sequence AFTER the two P0s above (Decision 8) | new | P1 | M | A regulated buyer inspects the release/licensing/SBOM chain; a placeholder signing key undercuts provenance | `git tag` empty; `package.json` 0.3.0; `license.js:36` placeholder key; `RELEASE_PROCESS.md:34` soak |
| Purge competitor names from **served artifacts only** (genericize `openapi.js:67` "zscaler" carefully — it's a real import source; genericize the one Nightfall line in customer-facing `DETECTION_BENCHMARKS.md`, keep named version in `PLANS/`) — guard targets **served output, not the docs tree** | partial | P2 | S | Consistency of the shipped/rendered product surface | `posture.js` already clean (`posture.test.js:244-245`); remaining: `openapi.js:67` (served at `app.js:1762`), `DETECTION_BENCHMARKS.md:18` |

## Decisions for the human (flagged)

These are product-changing. **Status as of 2026-07-09: Decisions 1–4 are RESOLVED**
(strategy = Option A; core-banking pack = name vendors + disabled-by-default; AUP = crosswalk +
attestation only; detection aggressiveness & roster handling = the defaults recorded below).
**Decisions 5–9 remain OPEN** and still gate their P1/P2 items — the agent must **not** silently
choose them.

1. **RESOLVED → name the vendors, ship disabled-by-default.** Pack labels/ids name the actual
   core processors (Symitar/Episys, Corelation KeyStone, Fiserv DNA/Portico/Premier, Jack Henry,
   Finastra) — the `DECISIONS.md` ban targets *competitors*, not the customer's own vendors — and
   every pattern ships disabled-by-default and context-gated; the CU enables its own core.

2. **RESOLVED (default) → roster EDM hard-block + regex warn-tier.** Roster-seeded EDM is the
   high-confidence hard-block for real member numbers; the regex pack stays context-gated and
   warn-tier (most core IDs have no checksum). The dedicated pack-loading benign test is
   **mandatory** (the default `npm run eval` loads no packs). *Flag if you want shape-only firing.*

3. **RESOLVED (default) → operator-run LOCAL script only.** Extend `scripts/edm-fingerprint.js`
   with a CSV `--column` flag; fingerprinting runs on the operator's machine and only salted
   one-way fingerprints reach the silo ("plaintext vault never ships"). No server-side
   roster-upload path. *Flag if you'd rather defer roster EDM past the first deploy.*

4. **RESOLVED → crosswalk + attestation only (CU supplies prose).** Ship the machine-readable
   clause→control crosswalk unconditionally (P0), and capture AUP adoption as an **attestation
   field (date + reference)** in the board-oversight hook. RedactWall does **not** author or ship
   board-adoptable AUP prose — that stays CU-owned, keeping RedactWall firmly in the
   data-protection lane.

5. **[OPEN — needs your input]** **Ship counsel-reviewed DPA/BAA/GLBA flow-down templates, or bespoke per-customer?**
   Options: (a) counsel-reviewed baseline templates (redlines allowed); (b) bespoke, no
   template; (c) "sample, non-binding" without counsel.
   **Recommendation:** (a). Drafting is doc work now; the gate is legal sign-off.
   **Reject (c)** — contract text that reads as binding without counsel is a
   regulated-finance liability.

6. **[OPEN — needs your input]** **Published per-seat annual price for the CU air-gapped SKU (+ connected delta)?**
   **Recommendation:** publish a transparent per-seat number clearly below the ~$25–60K
   competitor band and "far below an E5 uplift", with **default warn-and-true-up renewal
   reconciliation (hard cap opt-in only)** to match `server/license.js` +
   `CUSTOMER_LICENSING.md`. A dollar figure is a business commitment no engineer sets.

7. **[OPEN — needs your input]** **Default `personalAccountAction` in the shipped `credit_union` preset, and
   direct-vs-channel GTM timing?** Options for action: allow (current default) / coach /
   block. **Recommendation:** default **coach** (GLBA resonance, low friction), block as a
   per-department opt-in; the examiner-facing control must render the **actual configured
   action**. **GTM:** direct-first (AWS customer-silo) to own the first testimonial, open
   one CUSO/league channel only after the reference is quantified (keeps the channel kit P2).

8. **[OPEN — needs your input]** **First-tag version/timing + is the placeholder Ed25519 license key replaced first?**
   Options: (a) tag v0.4.0 now as pre-commercial/internal, placeholder key kept, labeled
   non-commercial; (b) replace the key, run the ≥1-week staging soak, then tag v0.4.0 as
   first commercial-ready; (c) hold for N1/N3 coaching UX.
   **Recommendation:** (b) — a regulated buyer inspects the release/licensing/SBOM chain;
   sequence the tag **after** WS6 P0s so it doesn't immortalize the doc drift or the
   missing disclaimer.

9. **[OPEN — needs your input]** **Competitor-name ban scope: shipped product only, or the whole `docs/product/` tree
   (does the Nightfall line in `DETECTION_BENCHMARKS.md` stay)?**
   **Recommendation:** scope the ban to the **shipped/rendered product** (console / API /
   evidence). Genericize the served OpenAPI example and the one customer-facing benchmark
   line (keep named versions in `PLANS/`); keep the sanctioned battlecard/competitive docs
   where the team already placed them. The "grep `docs/product/` returns zero" guard is
   self-contradictory and must not be an acceptance criterion.

## Sequenced roadmap

Respects dependencies: WS3 clause ids (P0) gate WS3 P2/P3; WS6 disclaimer + doc-drift (P0)
gate the release tag; the CU detector pack requires its own benign test before it can ship.

### P0 — next 30 days (finish, prove, label; land the artifact)
1. **WS6:** emit the "evidence pointers, not certification" disclaimer field (one exported
   constant, v2 packs byte-unchanged) + a new test — *the single highest-leverage fix.*
2. **WS6:** correct N2 status in `ROADMAP.md`/`STATUS.md` (coded slices shipped; FFIEC+AUP
   open).
3. **WS2:** controlTests (748 App A) rollup with honest `lastTestedAt`.
4. **WS2:** rendered human-readable quarterly examiner report over existing schemaVersion-3
   data.
5. **WS1:** CU core-banking custom-detector pack (opt-in, context-gated) **+ the mandatory
   pack-loading benign test** (Decisions 1–2).
6. **WS3:** AUP clause→control crosswalk + AUP-specific control (unblocks WS3 P2/P3).
7. **WS4:** per-control assurance labels; GLBA flow-down/DPA/BAA draft templates (Decision 5);
   CU-mapped DDQ pack.
8. **WS5:** CU pilot playbook + `scripts/aws-silo-smoke.js` (with `test/*.test.js` case).

### P1 — next quarter (deepen detection + procurement; tag a release)
- **WS1:** roster EDM `--column` (Decision 3); MICR/share-draft detector
  (emit `BANK_ACCOUNT`); CU charter-vocabulary anchors — re-run `npm run eval` (benign FP=0).
- **WS2:** FFIEC control-family labels (Decision 9); shadow-AI ⋈ use-case reconciliation
  panel; board cyber-training/oversight hook (migration + Security-Admin route).
- **WS3:** tighten-only dept `policyScope` preset (append via `normalizePolicyScopes`).
- **WS4:** structured knownLimitations/bypassPaths; data-flow SVG in the ZIP
  (`packageFiles()`); `ASSURANCE_ROADMAP.md` + procure pentest/SOC 2 (Decision 5's sibling).
- **WS5:** Microsoft-shop fit brief; transparent CU pricing one-pager (Decision 6).
- **WS6:** replace the Ed25519 key, run the soak, tag **v0.4.0** (Decision 8).

### P2 — later (dormant-feature exposure, hygiene, channel)
- **WS3:** personal-vs-corporate control (render actual action, Decision 7); coaching-ack
  audit keyed to clause id (define the counting rule).
- **WS1:** debit-BIN regression fixture.
- **WS4:** dated sub-processor register file; CUSO/MSP/league channel kit.
- **WS5:** de-identified reference story + channel brief.
- **WS6:** genericize served competitor names (OpenAPI example, one benchmark line).

## Acceptance evidence

Each phase is "done" only when these commands pass. Feed this into goal-contract-loop.

**Every code change (baseline gate):**
```
npm test
npm run sync-check          # engine parity green (browser copy generated, not hand-edited)
npm run review:ci           # includes docs:demo-guide:check
```

**Detection changes (WS1):**
```
npm run sync-engine         # after any detect.js edit
npm run eval                # benign-FP=0, adversarial-FP=0, semantic P>=0.95/R>=0.80, structured R>=0.95
npm run simulate            # end-to-end sensor behavior
# MANDATORY new test proving the shipped pack + roster EDM hold benign-FP=0
node -e "require('./scripts/verify-audit')" # or: assert verifyAuditChain() ok:true
# New test/*.test.js: pack loads config/custom-detectors.json AND config/exact-match.json
#   and the benign corpus still yields 0 false positives (default eval loads neither).
# MICR fixture: a pasted MICR/share-draft string emits BANK_ACCOUNT (alwaysBlock intact).
# Debit fixture: a share-draft debit PAN is caught by cardNetwork().
```

**Semantic model changes (if any):**
```
npm run train-semantic      # deterministic; CI diffs on drift
```

**Evidence artifact (WS2 / WS6):**
```
node scripts/export-evidence-pack.js --examiner-profile federal_credit_union
# Assert: schemaVersion 3; disclaimer field present; controlTests section present with
#   honest lastTestedAt; scope.rawPromptBodiesIncluded === false; no free-text
#   (owner/notes/minutes) in the rendered report; schemaVersion-2 default pack byte-unchanged.
node scripts/export-evidence-pack.js --examiner-profile federal_credit_union --format md   # rendered report exists (P0 #4)
```

**Trust package (WS4):**
```
node scripts/export-security-package.js
# Assert: per-control assurance field present (nothing 'third-party-verified'); DPA/BAA and
#   data-flow SVG bytes actually bundled by packageFiles() (not just listed in docs());
#   knownLimitations/bypassPaths structured; questionnaire maps NCUA 07-CU-13/01-CU-20;
#   subProcessors still [] (security-package.test.js:171 green).
```

**Deployment gate (WS5):**
```
node scripts/aws-silo-smoke.js   # asserts cloud-synced path rejected, tenant context required,
                                 # verifyAuditChain ok:true, examiner-profile export succeeds
npm run setup:check
```

**Release gate (WS6, before tagging v0.4.0):**
```
npm run suite                # full gate per RELEASE_PROCESS.md
npm run sync-check
# verifyAuditChain() ok:true; Ed25519 placeholder key replaced; >=1-week staging soak done;
# tag labeled pre-commercial UNLESS all release gates pass.
```

**Audit integrity (every phase, always):** `verifyAuditChain()` must return `ok:true`;
`grep` confirms no prompt text / PII / clause free-text / secrets in any audit entry body
or log line.
