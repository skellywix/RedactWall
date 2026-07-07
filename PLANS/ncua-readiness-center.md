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

This is ROADMAP item **N2** ("Examiner report pack — the wedge; nobody owns
the credit-union vertical"), with seeds of **X5** (core-banking EDM) and
**X6** (incident triage) phased behind it. It is composition over existing
seams, not a parallel product: the only net-new persistence is the AI
use-case inventory and incident records.

## Non-Negotiable Invariants

- Prompt-free exports: `scope.rawPromptBodiesIncluded: false` and
  `auditDetailsIncluded: false` stay hardcoded constants in
  `server/evidence.js`; every new export section carries only hashes, labels,
  masked findings, counts, and bounded metadata.
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
    `{ version: 5, name, sqlite, postgres }` to
    `server/storage/migrations.js` `MIGRATIONS`, with accessors in
    `server/db.js`. Migration v3 added `orgId` tenant scoping + Postgres RLS;
    new tables must ship tenant-ready the same way. The Postgres contract
    battery (`suite/contract`) asserts the current migration version and
    must be updated.
12. **OpenAPI is sensor-surface only** (`server/openapi.js` covers
    `/api/v1`); new console routes need `docs/API_REFERENCE.md` updates, not
    OpenAPI changes.

## Architecture

One new domain module, additive extensions elsewhere:

- **`server/ncua-readiness.js`** — pure, privacy-preserving composition
  (mirrors the `control-readiness.js` contract: never emits prompt bodies,
  token vaults, secrets, or raw finding values; bounded `safeText`
  everywhere). Builds the readiness report from: `buildControlMappings`
  input, `control-readiness` summaries, `coverage.summarize`, posture
  aggregates, `policyExceptionReview`, `db.verifyAuditChain()`, backup/
  restore-drill evidence, `exactMatch.publicSummary()`, catalog rollups, and
  the new use-case/incident tables. Functions stay under ~30 lines; no N+1
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
  nine control ids untouched.
- **Evidence pack profile.** `buildEvidencePack` accepts
  `examinerProfile`; when set, `scope.examinerProfile` is stamped and the
  pack adds `ncuaReadiness`, `useCases` (sanitized records), `incidents`
  (summary + prompt-free timelines), and `edm` (count/enabled/severity — no
  salt, no fingerprints) sections. `schemaVersion` bumps 2 → 3 additively;
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
| `/api/ncua/board-packet` | GET | `auditRead` | Board packet JSON |
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

## Data Model (Migration v5, Dual-Dialect, Tenant-Ready)

Only two new tables; everything else composes existing facts.

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
  vs exposed, review actions) — no duplicated event storage.

Both tables: `orgId` column + Postgres RLS policy in the v3 pattern, so the
future shared-plane migration (`STATUS.md` WS4) needs no retrofit. Writes
stamp `orgId` from `tenant.config()`. Every mutation appends a sanitized
audit entry (`USE_CASE_UPDATED`, `INCIDENT_OPENED`, `INCIDENT_STATUS_CHANGED`,
counts and enum values only).

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
  nowhere): add `license.hasFeature('ncua_readiness')`. Recommended
  packaging: included in `enterprise`, orderable add-on for `standard`.
  Honor the license philosophy ("the license never disables the security
  function"): unlicensed demo mode shows the module fully (it is the sales
  demo), evidence/examiner exports work in **every** license state, and the
  read-only state already blocks NCUA mutations via `requireWritable`.
  Ungated fallback if the flag is absent from older licenses: treat
  `enterprise` plan as entitled.
- **Tenancy and seats.** New tables are `orgId`-scoped with RLS from day
  one. The board packet embeds `tenant.seatReport()` (adoption, seats used/
  remaining) and `license.publicStatus()` (plan, expiry), so it doubles as
  a seat true-up artifact for billing conversations.
- **Scheduled delivery.** The examiner pack rides the existing scheduled
  evidence-pack task (`scripts/run-evidence-pack.sh|ps1`, systemd/Task
  Scheduler installers) via the new CLI flag. Board-packet delivery through
  the `subscriptions.js` pipeline (prompt-free, HTTPS-only) is a later
  automation step, not v1.
- **Identity.** Department names validate against SCIM groups when
  provisioned (Entra/Okta per `docs/SCIM_PROVISIONING.md`), matching how
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
6. `license.hasFeature()` + entitlement wiring.
7. Docs: `docs/NCUA_READINESS.md` (operator setup + "what to hand an NCUA
   examiner" + EDM import guide with "plaintext is discarded" language);
   update `docs/API_REFERENCE.md`, `PLANS/README.md`, `ROADMAP.md` N2 note.

**Slice 2 — Member-Data Inventory And Department Pack**:
1. Migration v5 (`ai_use_cases`) + `db.js` accessors + contract-battery
   version bump.
2. Use-case endpoints + validation + audit actions.
3. Console inventory table + review flow.
4. Credit-union scoped-policy pack: documented `policyScopes` preset
   (tighten-only, per-department SCIM groups) + default-deny unapproved AI
   destinations + required-sensors guidance; ships as documented config, not
   as competing templates.
5. `ai_use_inventory` + `vendor_service_provider_oversight` control states
   flip from `not_provided` to live.

**Slice 3 — 72-Hour Incident Readiness And Board Packet**:
1. Migration v6 (`ai_incidents`) + accessors + endpoints + validation.
2. Derived prompt-free incident timeline + deadline tracking; console panel.
3. `/api/ncua/board-packet` (AI adoption, member-data attempts prevented,
   unapproved AI usage, open exceptions, overdue reviews, readiness score,
   seat report, license status) + console export button.
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
  surfacing.
- **API/security (`suite/security`, `test/`)**: role matrix (Security Admin
  mutates; auditor reads/exports but cannot mutate; operator reads; CSRF
  required on all mutations; license read-only blocks mutations but not
  exports); tenant `orgId` stamping in SaaS mode.
- **Storage (`suite/contract`)**: migration v5/v6 in both dialects; update
  the Postgres contract battery's expected migration version; RLS policies
  on new tables.
- **Console (`e2e/`)**: `console-parity.spec.js` `ROUTES` entry
  `{ hash: '/ncua', heading: 'NCUA Readiness' }` under `govern`;
  `console-design.spec.js` `VIEWS` entry; export buttons hit the right
  endpoints; empty states navigate to Catalog/Policy/Evidence; no console
  route renders raw prompt content (existing invariant-test pattern).
- **Gates**: `npm run review:ci` (build, tests, browser tests, `sync-check`,
  `eval` — both trivially unaffected: no detector changes), plus
  `node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"`.

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
