# NCUA Readiness Center — Refined Integration Plan

Refined 2026-07-07 from an externally drafted plan, validated line-by-line
against the current codebase and aligned with the SaaS direction in
`PLANS/aws-saas-deployment.md` (customer-silo AWS stacks, tenant identity,
seat accounting, offline licensing).

## Goal And Context

Build the credit-union niche as a dedicated **NCUA Readiness Center**: a
Govern-area console view plus examiner-facing exports that turn existing
evidence, policy, catalog, EDM, audit, and posture data into NCUA/GLBA/
Part 748-facing workflows. First slice is **Examiner Proof**.

This is ROADMAP item **N2** ("Examiner report pack") — the row the roadmap
marks as the wedge, in a market where, per `ROADMAP.md`, nobody owns the
credit-union/community-bank vertical. Seeds of **X5** (core-banking EDM)
ride along, and the 72-hour workflow is a manual precursor to **X6**: it
ships the incident timelines that X6's AI-assisted triage would later
auto-summarize. It is composition over existing
seams, not a parallel product: the only net-new persistence is the AI
use-case inventory and incident records.

## Non-Negotiable Invariants

- Prompt-free exports: `scope.rawPromptBodiesIncluded: false` and
  `auditDetailsIncluded: false` stay hardcoded constants in
  `server/evidence.js`; every new export section carries only hashes, labels,
  masked findings, counts, and bounded metadata.
- New export surfaces sanitize at the **export boundary**, not only at
  input: every free-text field (use-case owner/approved-use, incident
  title/notes, any catalog-derived text) passes a `safeThreatText`-style
  filter (bounded length + SSN/card/secret pattern redaction — the
  `server/evidence.js` house pattern) when it enters the readiness report
  or any pack. The derived incident timeline consumes only `safeQuery`-/
  `safeAuditEntry`-shaped fields (action, actor, `detailHash` — never raw
  `audit.detail`, because approval/deny notes are free text that can carry
  member PII).
- `verifyAuditChain()` stays `ok: true`; all new mutations append sanitized
  audit entries (no raw prompt text, PII, or secrets in `detail`).
- No detector changes are required. If any become necessary they go in
  `detection-engine/detect.js` + `npm run sync-engine`, never hand-edited
  into sensors. The `detection-engine/` public API stays stable.
- Existing `CONTROL_MAPPINGS` ids, the evidence-pack consumers, and the
  `/api/export/evidence` contract stay backward compatible (additive only).
- Keep the hot detection path untouched — everything here is cold-path
  console/reporting code.
- SaaS-mode tenant and seat enforcement fail closed (`server/tenant.js`);
  new tables are tenant-ready from day one.

## What The Codebase Already Provides (Corrections To The Draft Plan)

The draft assumed more greenfield than exists. Build on these instead:

1. **Readiness scoring engine exists.** `server/control-readiness.js` already
   models `score`/`state` (`ready`/`attention`/`blocked`), `areas`, proof
   ledgers, and remediation playbooks, consumed via `server/posture.js` and
   `GET /api/posture`. The NCUA readiness report is a new composition in this
   module's style — not a new scoring system.
2. **NCUA control families exist.** `server/control-map.js` already emits
   NCUA/GLBA/HIPAA/PCI + NIST AI RMF/ISO 42001/EU AI Act/OWASP LLM mappings
   with `covered`/`attention`/`not_provided` states, consumed by
   `GET /api/compliance` (`server/app.js:2795`), the evidence pack, and
   `console/src/views/Compliance.tsx`. We append new controls; we do not
   restructure.
3. **The `ncua_glba` policy template exists** (`server/templates.js`), as do
   `MEMBER_ID`, `LOAN_NUMBER`, `ROUTING_NUMBER`, `BANK_ACCOUNT` detectors and
   hard-stop defaults. No new baseline template is needed.
4. **Department policy is `policyScopes`, not more templates.**
   `PUT /api/policy/apply-template` shallow-merges one global policy per
   silo, so the draft's eight department templates would overwrite each
   other. Department differentiation ships as a **tighten-only scoped-policy
   pack** (`policyScopes` matched on SCIM group names — Lending, Member
   Services, Collections, Marketing, IT, Compliance, Executives) layered on
   the `ncua_glba` base. `policyExceptions` already carry owner/reviewer/
   review-window lifecycle (`active`/`expiring_soon`/`review_due`/`expired`)
   surfaced in evidence as `policyExceptionReview` — the "exception review
   gaps" panel is a read of existing data.
5. **The app catalog is richer than assumed.** `server/app-catalog.js` +
   the `ai_apps` table already track owner, notes, `sanctionedStatus`
   (`under_review`/`sanctioned`/`tolerated`/`unsanctioned`/`blocked`),
   transparent risk scores with analyst override, per-source sighting
   counters, and a review workflow that writes policy destination lists
   atomically. The use-case inventory is a thin layer keyed to
   `canonicalHost` on top of it.
6. **EDM exists end-to-end; only status surfacing is missing.**
   `scripts/edm-fingerprint.js` (salted one-way fingerprints, plaintext
   discarded, salt-mismatch refusal) → `config/exact-match.json` →
   `server/exact-match.js` → engine `EXACT_MATCH` via
   `policy.analyzeOpts`. Gap found during recon:
   `exactMatch.publicSummary()` has **no caller** — EDM status appears in no
   API, posture, or evidence output. Closing that gap is a slice-1 item.
7. **Roles and middleware are fixed.** `security_admin`, `approver`,
   `operator`, `auditor` (`server/roles.js`), composed as `adminWrite`
   (auth + CSRF + Security Admin + `license.requireWritable`), `auditRead`,
   `operatorRead/Write`, `decisionWrite` at `server/app.js:1747-1760`.
   Mutating NCUA endpoints get `adminWrite`, which already enforces CSRF
   **and** the license read-only state — SaaS billing enforcement comes free.
8. **Evidence pack is options-driven, schemaVersion 2.**
   `buildEvidencePack(input)` (`server/evidence.js`) + CLI
   `scripts/export-evidence-pack.js` (schedule config, `--zip`,
   `--scheduled`, retention) + `GET /api/export/evidence` (`auditRead`).
   The examiner pack is a **profile of this pack**, not a parallel exporter.
9. **Console patterns are established.** React 19 + Vite hash-router console
   with a **Govern** nav group (`console/src/App.tsx` `GROUPS`), page
   patterns in `Coverage.tsx` (score ring + posture list), `Compliance.tsx`
   (framework rows + evidence link), `Catalog.tsx` (sortable tables,
   mutations), client CSV via `console/src/lib/csv.ts`, CSRF via
   `lib/api.ts`, SSE refresh via `lib/sse.ts`, route tests in
   `e2e/console-parity.spec.js` (`ROUTES`) and screenshots in
   `e2e/console-design.spec.js` (`VIEWS`).
10. **Incidents are net-new** (docs/alerting only today), and **board-packet
    ingredients exist**: `Insights.tsx` already exports an executive-summary
    CSV, `server/tenant.js` `seatReport()` gives adoption/seat stats,
    `license.publicStatus()` gives plan/expiry, `server/subscriptions.js`
    gives prompt-free scheduled delivery for later automation.
11. **Storage migrations are dual-dialect.** New tables append
    `{ version, name, sqlite, postgres }` entries to
    `server/storage/migrations.js` `MIGRATIONS` (currently at v4), with
    accessors in `server/db.js`. Tenant scoping is narrower than it looks:
    migration v3 scoped **only** the `queries` table, and v4 had to repair
    its orgId normalization — new tables use the v4-corrected `orgColumn`
    semantics (trim + lowercase, empty → NULL). The Postgres battery lives
    in `test/storage-postgres.test.js` (asserts the applied version list
    `[1, 2, 3, 4]`, via `test/support/pg-battery.js`) and
    `test/storage-postgres-rls.test.js` (pins
    `TENANT_SCOPED_TABLES = ['queries']`); both get extended —
    `suite/contract` holds route contracts only.
12. **OpenAPI is sensor-surface only** (`server/openapi.js` covers
    `/api/v1`); new console routes need `docs/reference/API_REFERENCE.md` updates, not
    OpenAPI changes.

## Architecture

One new domain module, additive extensions elsewhere:

- **`server/ncua-readiness.js`** — pure, privacy-preserving composition
  (mirrors the `control-readiness.js` contract: never emits prompt bodies,
  token vaults, secrets, or raw finding values; bounded `safeText`
  everywhere). Builds the readiness report from: `buildControlMappings`
  input, `control-readiness` summaries, `coverage.summarize`, posture
  aggregates, `policyExceptionReview`, `db.verifyAuditChain()`, backup/
  restore-drill evidence, `exactMatch.publicSummary()`, evidence-export
  schedule health (schedule-config presence + last-export recency from the
  scheduled task), catalog rollups, and the new use-case/incident tables.
  Catalog-derived content is limited to counts, canonical hosts,
  `sanctionedStatus`/vendor enums, and numeric risk scores — including a
  shadow-AI rollup (unsanctioned/tolerated sighting counts) — never catalog
  `notes`/`owner` free text. Functions stay under ~30 lines; no N+1
  over `better-sqlite3` (reuse the existing single-query summarizers; batch
  incident timeline reads by id set).
- **Profile-parameterized builders.** Internals take
  `examinerProfile: 'federal_credit_union'` (first profile) so future
  community-bank/FFIEC or healthcare variants reuse the module. The console
  label and routes stay wedge-specific ("NCUA Readiness").
- **Control-map additions (additive).** Append five controls to
  `CONTROL_MAPPINGS` with `stateFor`/`summaryFor` cases in the existing
  pattern: `member_information_safeguards` (EDM enabled + member-identifier
  hard-stops intact), `ai_use_inventory` (use-case records exist, reviews
  current), `vendor_service_provider_oversight` (catalog review coverage +
  vendor status), `incident_readiness` (drill/openness of the 72-hour
  workflow), `board_reporting` (packet generated within cadence). Existing
  nine control ids untouched. The draft's sixth family — exception review
  and employee coaching evidence — lands as follows: exception review is
  live data already (the `policyExceptionReview` evidence section and
  console panel; the existing `approval_workflow` control claims NCUA
  exception-review evidence), while employee coaching evidence is
  **deferred to ROADMAP N3** (coaching acknowledgment audit trail) and
  becomes a control state here once N3 ships.
- **Evidence pack profile.** `buildEvidencePack` accepts
  `examinerProfile`; when set, `scope.examinerProfile` is stamped and the
  pack adds `ncuaReadiness`, `useCases` (sanitized records), `incidents`
  (summary + prompt-free timelines), and `edm` (count/enabled/severity — no
  salt, no fingerprints) sections. Version semantics are explicit: default
  packs stay `schemaVersion` 2 byte-compatible (`test/evidence.test.js`
  pins it); only packs built with `examinerProfile` stamp `schemaVersion`
  3, and the privacy regression asserts both shapes.
  `rawPromptBodiesIncluded`/`auditDetailsIncluded` remain hardcoded `false`.
  CLI gains `--examiner-profile federal_credit_union` so the existing
  scheduled-export task produces it.

## API Surface

Follow the inline-registration convention in `server/app.js` with the
existing middleware arrays:

| Route | Method | Middleware | Purpose |
|---|---|---|---|
| `/api/ncua/readiness` | GET | `auth.requireAuth` | Readiness report (matches `/api/compliance` access) |
| `/api/ncua/use-cases` | GET | `auth.requireAuth` | Inventory list |
| `/api/ncua/use-cases` | POST | `...adminWrite` + zod | Create/update record |
| `/api/ncua/use-cases/:id/review` | POST | `...adminWrite` + zod | Review decision + next review date |
| `/api/ncua/incidents` | GET | `auth.requireAuth` | Incident list + deadline state |
| `/api/ncua/incidents` | POST | `...adminWrite` + zod | Open incident from query ids |
| `/api/ncua/incidents/:id/status` | POST | `...adminWrite` + zod | Advance status / mark reported |
| `/api/ncua/board-packet` | POST | `auth.requireAuth` + CSRF + Security Admin/Auditor + entitlement | Board packet JSON; appends prompt-free export evidence |
| `/api/export/evidence?examinerProfile=federal_credit_union` | GET | `auditRead` (existing) | Examiner pack |

Refinement vs the draft: **no separate `/api/ncua/examiner-pack`** — the
examiner pack reuses the one existing export route and CLI so there is a
single privacy gate and a single scheduled path to maintain. Auditor role
covers examiner read access (per the 2026-06-26 decision that examiner
review uses the read-only `auditor` account); mutations are Security Admin
+ CSRF and are blocked in license read-only state.

Validation lives in `server/validation.js` (zod, `validateBody` pattern):
bounded lengths on every text field, reject URLs with paths, reject
prompt-shaped free text (length caps + newline limits), `allowedDataClasses`
validated against engine detector ids + semantic categories, `queryIds`
validated as existing query ids, dates as ISO strings.

## Data Model (Migrations v5 + v6, Dual-Dialect, Tenant-Ready)

Only two new tables — `ai_use_cases` is migration v5 (slice 2),
`ai_incidents` is migration v6 (slice 3); everything else composes
existing facts.

- **`ai_use_cases`**: `seq`, `id`, `orgId`, `canonicalHost` (catalog key),
  `department` (SCIM group display name; soft-validated against
  `scim_groups` when SCIM is enabled), `owner`, `approvedUse` (bounded),
  `allowedDataClasses` (JSON, validated), `reviewStatus`
  (`approved`/`under_review`/`restricted`/`retired`), `vendorStatus`
  (`reviewed`/`pending`/`not_reviewed`), `nextReviewAt`, `policyScopeId`
  (links the enforcing scope), `createdAt`, `updatedAt`, `data` (JSON).
  Distinct records per host+department make "ChatGPT in Lending" ≠
  "ChatGPT in Marketing".
- **`ai_incidents`**: `seq`, `id`, `orgId`, `title` (bounded, validated),
  `status` (`open`/`under_review`/`reported`/`closed`), `detectedAt`,
  `deadlineAt` (= detectedAt + 72h per the NCUA cyber-incident reporting
  rule, 12 CFR §748.1(c)), `reportedAt`, `queryIds` (JSON), `dataClasses`
  (JSON, detector ids only), `destinations` (JSON, hosts only), `notes`
  (bounded, prompt-free validated), `createdAt`, `updatedAt`.
  The incident **timeline is derived on read** from the referenced queries
  and audit entries (who, destination, data types, control outcome, blocked
  vs exposed, review actions) — no duplicated event storage, reading only
  `safeQuery`-/`safeAuditEntry`-shaped fields (action, actor, `detailHash`),
  never raw `audit.detail`.

Both tables ship tenant-ready: an `orgId` column with a Postgres RLS
policy, using the **v4-corrected** normalization (`db.js` `orgColumn`
semantics: trim + lowercase, empty → NULL — not the raw v3 pattern, whose
backfill shipped defective), stamped from `tenant.config()` on write and
filtered on read in both dialects; both tables join `TENANT_SCOPED_TABLES`
in `test/storage-postgres-rls.test.js`. Readiness inputs `ai_apps` and
`audit` remain unscoped today, so the shared-plane migration
(`PLANS/stack-upgrade-plan.md` WS4; `PLANS/aws-saas-deployment.md`) still
has its own tenancy work — the new tables just don't add to it. Every
mutation appends a sanitized audit entry (`USE_CASE_UPDATED`,
`USE_CASE_REVIEWED` — actor, `reviewStatus` enum, next review date —
`INCIDENT_OPENED`, `INCIDENT_STATUS_CHANGED`; counts, enums, and dates
only, no free text).

## Console

New Govern item in `console/src/App.tsx` `GROUPS`
(`{ path: '/ncua', label: 'NCUA Readiness', view: lazy(...) }`) + icon in
`components/navIcons.tsx`. The view (`console/src/views/NcuaReadiness.tsx`)
follows the established page shape (route-contract doc comment, typed
`apiJson` fetchers, loader hook + `useEventStream` refresh,
`.console-frame-header`, KPI strip, `.panel` blocks, `EmptyState`):

- Readiness score card (`.score-ring`, Coverage pattern) + control-family
  rows (`ControlBar`/Compliance `FrameworkRow` pattern).
- Use-case inventory table (Catalog sortable-table pattern) with review
  actions (Security Admin only, role-gated via `useSession`).
- Member-data outcomes and exception-review panels (reads of readiness
  report sections).
- Shadow-AI and evidence-export health rollups (unsanctioned/tolerated
  sighting counts deep-linking to `/catalog`; scheduled-export recency).
- Core-banking EDM panel: status when configured; when absent, setup
  guidance quoting the `edm:fingerprint` flow and "plaintext is discarded".
- Incident readiness panel with 72-hour deadline countdowns.
- Exports: examiner pack via `<a href="/api/export/evidence?examinerProfile=federal_credit_union">`
  (Compliance pattern), board packet via JSON blob download (Audit pattern),
  use-case CSV via `lib/csv.ts` (formula-injection-safe).
- Empty states deep-link to `/catalog`, `/policy`, `/compliance`, `/audit`,
  `/queue` via `routeHref`.

## SaaS Integration

- **Deployment model.** Fits the customer-silo path (Option A in
  `PLANS/aws-saas-deployment.md`) with zero infra change: per-silo module,
  no cross-tenant aggregation in v1, no egress (consistent with the
  zero-egress licensing guarantee — works air-gapped).
- **Packaging/entitlement.** First consumer of the license payload
  `features[]` (currently surfaced by `license.publicStatus()` but consumed
  nowhere). A naive `features.includes(...)` would hide the module exactly
  in demo mode (unlicensed → `features: []`), so define the predicate
  explicitly: `license.entitled('ncua_readiness')` =
  `state === 'unlicensed' || features.includes('ncua_readiness') ||
  plan === 'enterprise'` — the payload persists through `grace` and
  `readonly`, so entitlement correctly survives expiry. Recommended
  packaging: included in `enterprise`, orderable add-on for `standard`
  (grant to an existing customer by re-issuing `redactwall.lic` with
  `scripts/license-issue.js --features` and installing via the existing
  `POST /api/billing/license`; update `docs/process/CUSTOMER_LICENSING.md` to
  define add-on flags alongside plan tiers). Per-surface behavior: the nav
  item stays visible with an upsell empty state when not entitled, and
  `GET /api/ncua/readiness` returns an explicit `entitled: false` body —
  the billing routes are Security-Admin read, so non-admin console sessions
  take the entitlement signal from the readiness response. Honor the
  license philosophy ("the license never disables the security function"):
  evidence/examiner exports work in **every** license state, and the
  read-only state already blocks NCUA mutations via `requireWritable`.
- **Tenancy and seats.** New tables are `orgId`-scoped with RLS from day
  one (v4-corrected normalization; see Data Model). The board packet embeds
  only the scalar `tenant.seatReport()` aggregates (tenantId, saasMode,
  seatLimit, seatsUsed, seatsRemaining, overLimit) — the per-user `users[]`
  roster is explicitly dropped, because an employee-level usage list must
  not enter a document built to leave the security team — plus a `trueUp`
  block comparing licensed seats (`license.publicStatus().seats`) against
  the configured `REDACTWALL_SEAT_LIMIT` and `seatsUsed`. Nothing wires the
  license seat count to the env limit today, so the packet is where a
  mismatch becomes visible, which is what makes it a true-up artifact.
- **Scheduled delivery.** The examiner pack rides the existing scheduled
  evidence-pack task (`scripts/run-evidence-pack.sh|ps1`, systemd/Task
  Scheduler installers) via the new CLI flag. Board-packet delivery is a
  later automation step, not v1 — and not free: `subscriptions.js` is an
  event pipeline (`siem-formats.toEvent`, dedupe, min-risk filters), so a
  periodic report needs a new digest-style payload type plus a scheduler
  hook.
- **Identity.** Department names validate against SCIM groups when
  provisioned (Entra/Okta per `docs/identity/SCIM_PROVISIONING.md`), matching how
  `policyScopes.groups` already match.

## Implementation Slices

**Slice 1 — Examiner Proof** (ROADMAP N2):
1. `server/ncua-readiness.js` + unit tests (fixture-driven, like
   `control-readiness` tests).
2. Surface EDM status: wire `exactMatch.publicSummary()` into posture and
   the evidence pack (closes the existing gap; feeds the readiness score).
3. Control-map additions (5 controls, additive) + `/api/ncua/readiness`.
4. Evidence-pack `examinerProfile` (schemaVersion 3) + CLI flag + scheduled
   task docs.
5. Console view (score, control rows, EDM panel, examiner-pack export) +
   parity/design/e2e test entries.
6. `license.entitled()` predicate + entitlement wiring (nav upsell state,
   readiness `entitled` flag, `docs/process/CUSTOMER_LICENSING.md` add-on note).
7. Docs: `docs/security/NCUA_READINESS.md` (operator setup + "what to hand an NCUA
   examiner" + EDM import guide with "plaintext is discarded" language);
   update `docs/reference/API_REFERENCE.md`, `PLANS/README.md`, `ROADMAP.md` N2 note.

**Slice 2 — Member-Data Inventory And Department Pack**:
1. Migration v5 (`ai_use_cases`) + `db.js` accessors + contract-battery
   version bump.
2. Use-case endpoints + validation + audit actions.
3. Console inventory table + review flow.
4. Credit-union scoped-policy pack: documented `policyScopes` preset
   (tighten-only, per-department SCIM groups) + default-deny unapproved AI
   destinations + required-sensors guidance + a member-data routing recipe
   (route member-data detector events to the compliance group via the
   existing `approvalRoutingRules` and notifier/subscription seams); ships
   as documented config, not as competing templates.
5. `ai_use_inventory` + `vendor_service_provider_oversight` control states
   flip from `not_provided` to live.

**Slice 3 — 72-Hour Incident Readiness And Board Packet**:
1. Migration v6 (`ai_incidents`) + accessors + endpoints + validation.
2. Derived prompt-free incident timeline + deadline tracking; console panel.
3. `/api/ncua/board-packet` (AI adoption, member-data attempts prevented,
   unapproved AI usage, open exceptions, overdue reviews, readiness score,
   seat aggregates + true-up, license status) + console export button.
4. `incident_readiness` + `board_reporting` control states go live; both
   summaries join the examiner pack.
5. Later (not v1): PDF packaging, subscriptions-based scheduled board
   delivery, ticket-sync escalation for incidents.

## Test Plan

- **Unit (`npm test`, `test/*.test.js`)**: readiness report composition from
  fixtures; new control states (`covered`/`attention`/`not_provided`) per
  input shape; examiner pack asserts **no** prompt bodies, raw findings,
  token vaults, local file paths, secrets, EDM salt/fingerprints (extend the
  existing evidence privacy regression tests); use-case validation rejects
  prompt text, URLs with paths, secrets, invalid data classes; incident
  timeline exports blocked-vs-exposed without raw content; EDM summary
  surfacing; board packet carries seat aggregates only (no `users[]`
  roster); default packs stay `schemaVersion` 2 while examiner-profile
  packs assert 3.
- **API/security (`suite/security`, `test/`)**: role matrix over all four
  roles (Security Admin mutates; auditor reads/exports but cannot mutate;
  operator and approver read but cannot mutate; CSRF required on all
  mutations; license read-only blocks mutations but not exports); tenant
  `orgId` stamping in SaaS mode.
- **Storage**: migrations v5/v6 in both dialects; extend the expected
  version list in `test/storage-postgres.test.js` (`[1, 2, 3, 4]` → append
  5, then 6) and add both tables to `TENANT_SCOPED_TABLES` in
  `test/storage-postgres-rls.test.js`; mixed-case tenant ids must
  round-trip through the new tables' RLS filters.
- **Console (`e2e/`)**: `console-parity.spec.js` `ROUTES` entry
  `{ hash: '/ncua', heading: 'NCUA Readiness' }` under `govern`;
  `console-design.spec.js` `VIEWS` entry; export buttons hit the right
  endpoints; empty states navigate to Catalog/Policy/Evidence; no console
  route renders raw prompt content (existing invariant-test pattern).
- **Gates**: `npm run review:ci` (build, tests, browser tests, `sync-check`,
  `eval` — both trivially unaffected: no detector changes), plus
  `node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"`.

## Regulation Watch (Assessed — Not Built)

Request considered: automatically change the product's regulation mappings /
enforcement policy when NCUA law changes. **Verdict: the fully automatic form
is a bad idea and is deliberately not built**, for reasons that go to the
product's spine:

1. **It inverts the trust model.** The product's examiner story is
   hash-chained audit + named human approval for every policy change. "A
   scraper rewrote the policy" is the answer no examiner accepts, and
   `control-map.js` explicitly disclaims inventing legal conclusions —
   auto-mapping legal text to enforcement *is* a legal conclusion.
2. **It adds an egress + remote-influence channel.** Zero egress is a sold
   guarantee (offline licensing, no phone-home; active-key verification was
   rejected for the same reason). A regulatory feed is remote content that
   steers enforcement — the exact class of influence the product exists to
   block — and it cannot work in air-gapped silos at all.
3. **The liability is the vendor's.** A misparsed rule that loosens
   enforcement is a compliance breach at a federally regulated institution.
4. **The cadence doesn't justify it.** NCUA rulemaking moves through
   months-long comment periods; material changes land ~1–2×/year.

**The defensible version, if demand appears:** vendor-curated *regulatory
mapping packs* — reviewed updates to `CONTROL_MAPPINGS` families/citations —
shipped through the existing signed release train, plus an optional console
"regulation watch" notice (data-only: "NCUA published X, review your
mapping", HTTPS-only, default off, nothing automated into policy). Every
actual change stays a human `POLICY_UPDATED` with an audit trail.

## Decisions For The Human

1. **Packaging**: `ncua_readiness` feature flag sold as add-on for
   `standard` and included in `enterprise` (recommended), vs
   enterprise-only, vs included everywhere as the wedge.
2. **Nav naming**: "NCUA Readiness" (wedge-specific, recommended) vs
   "Examiner Readiness" (general; profiles make renaming cheap later).
3. **Board packet timing**: slice 3 (recommended — after inventory/incident
   data exists to report on) vs pulled into slice 1 for sales demos.
4. **Department pack shape**: documented `policyScopes` preset applied by
   operators (recommended) vs a one-click "apply scoped pack" endpoint.

## Acceptance Evidence

```bash
npm run review:ci
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
npm run test:console-app
node scripts/export-evidence-pack.js --examiner-profile federal_credit_union   # slice 1+
```

Plus the focused checks per slice: new-route Playwright spec entries, the
evidence privacy regression, and the contract battery on both dialects.

## Assumptions Changed From The Draft Plan

- Readiness scoring composes the existing `control-readiness`/`control-map`
  machinery; no new scoring framework.
- The examiner pack is a profile of the existing evidence pack and export
  route/CLI — no parallel `/api/ncua/examiner-pack` exporter.
- Eight department templates are replaced by one existing base template
  (`ncua_glba`) plus a tighten-only `policyScopes` pack, because
  apply-template merges a single global policy per silo.
- The EDM work is status surfacing + guidance + docs; fingerprinting,
  salting, and enforcement already ship.
- Only use-case and incident records add persistence (dual-dialect,
  `orgId`-scoped, RLS-ready); everything else is derived on read.
- SaaS integration is explicit: license `features[]` entitlement (first
  consumer), seat/plan data in the board packet, tenant-ready tables,
  customer-silo deployment with zero egress, scheduled exports via the
  existing task infrastructure.
- v1 exports JSON (+ client CSV where the console already has the pattern);
  PDF stays deferred.
