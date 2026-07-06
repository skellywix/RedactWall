# Stack Upgrade Plan: Console, Parsing Isolation, Node 24, Postgres Hardening

> **Status (July 2026):** WS1 is complete — the React `/app` console reached
> full parity with the legacy console (all 16 views + shell chrome, verified by
> `e2e/console-parity.spec.js` and `e2e/console-design.spec.js`), and A4 cutover
> is done: `/` redirects to `/app/` and the legacy static console
> (`server/public/index.html`, `dashboard.js`, and the feature-renderer JS) was
> deleted, keeping the shared design system and login page. A line-by-line audit
> also fixed 131 verified defects, including the remaining stack-upgrade backend
> loose ends (Postgres RLS tenant context now wired, pg-driver quoting/desync
> bugs, parse-pool isolation for the endpoint agent, gateway response-choice
> redaction). What remains are the calendar-/SaaS-gated items (WS3.2 Node 24
> base flip, WS4.4 tenant lifecycle). See `../CHANGELOG.md` and `../STATUS.md`.

Action plan for the five concerns raised in the June 2026 architecture review
(`../STACK_REVIEW.md`), fact-checked against the codebase and against where
tech and fintech stacks are converging as of July 2026. Treat this as the
sequencing source of truth for stack work; per-pass state lives in
`../STATUS.md`.

Two review assumptions were corrected during planning:

- **Postgres support already exists and is CI-tested.** `server/storage/`
  selects a driver via `REDACTWALL_DB_DRIVER` (`sqlite` default, `postgres` +
  `REDACTWALL_DATABASE_URL`), `server/storage/pg-driver.js` mirrors the
  better-sqlite3 synchronous surface over a worker-thread bridge, migrations in
  `server/storage/migrations.js` ship dual sqlite/postgres SQL including tenant
  `orgId` + row-level security (migration 3), and CI runs the suite against a
  live `postgres:16-alpine` service. The Postgres workstream below is
  "harden what exists", not "build".
- **The current parsing timeout cannot preempt.** `withTimeout()` in
  `server/processors.js` is a `Promise.race`, but adm-zip and pdf-parse do
  synchronous CPU work on the main thread — the race cannot fire until the
  work finishes. A crafted docx/pdf stalls the whole control plane (auth,
  approvals, SSE) despite the upload size cap. Parsing isolation is therefore
  genuinely security-critical, not just hygiene.

## Workstreams at a glance

| ID | Workstream | Size | Depends on |
|----|-----------|------|-----------|
| WS1 | Console: Vite + React 19 + TypeScript | L | WS3 phase 1 recommended first |
| WS2 | File-parsing isolation | M | — (do before real production) |
| WS3 | Node 24 LTS validation | S + S | — |
| WS4 | Postgres hardening | M | SaaS timeline (except RLS tests: now) |
| WS5 | node:sqlite decision record | S | — |

Guiding constraints inherited from the repo:

- Preserve the install-in-an-afternoon path (`node scripts/setup.js`,
  `npm start`, Docker).
- Every phase lands green on the existing full gate (`npm run review:ci`):
  native binding smoke, tests, Playwright, `sync-check`, detection eval,
  audit-chain verify, semantic determinism, `test/frontend-csp.test.js`,
  `test/asset-budget.test.js`.
- CLAUDE.md rules apply throughout: detector logic only in
  `detection-engine/detect.js`, never log raw prompt text or PII, keep shared
  public APIs stable (`server/processors.js` is imported by
  `sensors/endpoint-agent/`).

## WS1 — Console migration to Vite + React 19 + TypeScript

### Framework decision: React 19 (not Preact, not Next.js)

React 19 + Vite + TypeScript is where enterprise and fintech frontends have
converged: React remains the dominant framework (~42% share) and the anchor of
enterprise frontend strategy, Vite is the standard build tool, and TypeScript
is table stakes. React buys the ecosystem an admin console grows into
(TanStack Query/Table for the queries and audit views, shadcn/ui or Ant Design
for accessible enterprise components) and the hiring pool a fintech-facing
product needs.

- The console is auth-gated and self-hosted, so React's ~45 KB gzip runtime is
  immaterial next to future-proofing. Per-route code splitting keeps the
  initial bundle inside a new `test/asset-budget.test.js` entry (~200 KB gzip
  initial route to start; ratchet down as views stabilize).
- Preact via `preact/compat` stays documented as a size fallback only if a
  customer constraint ever demands it — not the default.
- Next.js is rejected: it adds an SSR server the product does not need; the
  console stays static assets served by Express behind the existing auth gate.
- This supersedes the 2026-06-26 decision to keep the admin frontend static:
  `dashboard.js` is 5,133 lines plus 14 satellite feature modules and
  `index.html` is 3,409 lines — dashboard complexity now justifies a build
  chain, which was that decision's stated trigger.

### Project layout and build wiring

- New top-level `console/` directory with its own `package.json` +
  `package-lock.json`. Do not convert the root to npm workspaces (that would
  ripple through `Dockerfile`, `scripts/setup.js`, and
  `scripts/ensure-native-bindings.js` for no benefit). Root `package.json`
  gains orchestration scripts only: `console:install`, `console:dev`,
  `console:build`, `console:check`.
- Vite `base: '/app/'`, build output `server/public/app/` (**gitignored**).
  Never build into `server/public/` root: legacy files keep serving unchanged
  during the transition, and cutover/rollback is a directory-level operation.
  Committing minified `dist/` output is rejected — bundle diffs are
  unauditable and merge-hostile (the `sync-engine` idiom works for readable
  source, not minified bundles).
- Because `server/public/app/` is gitignored, wire the build into every
  consumption path: `scripts/setup.js` (skippable flag), the Dockerfile
  builder stage (console `npm ci` + build before the server copy), CI before
  `npm test`/Playwright, and `scripts/run-playwright.js`.
- Trade-off accepted: the "no build step" property is lost for the console
  only, and only for source installs — Docker users see no difference.

### Serving, auth, CSP

- Mirror the existing gate (`server/app.js`, `/index.html` route): serve
  `/app` index via `auth.requireAuth` + `sendFile` before `express.static`.
  Hashed assets under `/app/assets/*` stay public static — they contain no
  data; all data flows through auth-gated `/api/*` (same trust model as
  today's `dashboard.js`).
- CSP needs no relaxation: Vite production builds emit
  `<script type="module" src=...>` with no inline scripts, satisfying
  `script-src 'self'` and `test/frontend-csp.test.js`.
- Hash-based client routing (no Express catch-all needed; deep links work).

### Dev workflow, API layer, typing

- `console/vite.config.ts` dev server proxies `/api` (including SSE) and
  `/login.html` to Express. Cookies stay same-origin through the proxy, so the
  HMAC session cookie and the CSRF double-submit (`GET /api/csrf` →
  `x-csrf-token`) work unmodified in dev.
- `console/src/lib/api.ts` is a faithful TS port of the `api()` wrapper in
  `dashboard.js` (~lines 1860–1871): CSRF header on mutating methods,
  401 → redirect to `/login.html`, 403 → toast. `console/src/lib/sse.ts`
  wraps `EventSource('/api/stream')` with reconnect.
- Typing strategy: hand-written TS interfaces per endpoint family
  (`console/src/api/{stats,queries,policy,posture,...}.ts`), added
  incrementally as each view migrates. No upfront codegen — there is no
  OpenAPI source of truth and building a generator would stall the migration.
  Client-side zod only at high-risk round-trip boundaries (policy editor,
  detector test results); server-side zod schemas stay where they are.

### Strangler migration phases (full gate green at every step)

- **A0 — Scaffold (S).** `console/` project, empty authenticated shell (port
  `console-theme.css`), `/app` route in `server/app.js`, build wiring, new
  asset-budget entry, e2e smoke (login → `/app` renders → 401 redirect).
- **A1 — Platform layer (M).** `api.ts`, `sse.ts`, session hook (`/api/me`),
  toasts, shared table/badge/card components. Pilot view: `decision-quality`
  or `detector-feedback` (self-contained, one endpoint family each).
- **A2 — Core operator views (L).** In value order: stats + SSE live updates;
  **approval queue** (list, detail, approve/deny/bulk — best existing e2e
  coverage); policy editor (folds in `policy-impact-preview.js` and
  `policy-guides.js`); audit view + evidence export. After A2 add a "Try the
  new console" link in the legacy header and `REDACTWALL_CONSOLE_DEFAULT=app|legacy`.
- **A3 — Long tail (L, parallelizable).** Port the remaining feature modules
  one PR each (`siem-package.js`, `security-package.js`, `agentic-mcp.js`,
  `operator-flow.js`, `behavior-baselines.js`, `control-graph.js`,
  `coverage-file-flow.js`, `ai-threat-guardrails.js`, and the
  posture/catalog/compliance/lineage/identity views). Each is already a
  self-contained `<script defer>` unit over one endpoint family — they map
  ~1:1 to lazy-loaded routes.
- **A4 — Cutover (M).** `/` serves the new console; legacy reachable at
  `/legacy/` for one release; then delete `server/public/dashboard.js`,
  `index.html`, and the feature modules, and remove their budget entries.
- **A5 — Optional (S).** Vitest component tests for the policy editor; visual
  regression via Playwright screenshots.

`login.html`/`login.js` stay vanilla — small, pre-auth, security-critical.

E2E during transition: keep `e2e/admin-console.spec.js` green against legacy
until A4; grow a parallel `e2e/admin-console-app.spec.js` per migrated view;
at cutover the app spec replaces the legacy spec.

### WS1 risks

| Risk | Mitigation |
|---|---|
| Parity drift during dual maintenance | Feature-freeze each legacy view once its `/app` port lands; parity checklist per PR; time-box A2–A4 |
| Bundle growth | Per-route dynamic imports + budget test entry from day one |
| CSRF/session breakage | `api.ts` is a line-for-line port; login/approve/policy-save e2e from A1 |
| SSE flaky behind Vite proxy | Configure proxy for event streams; dev fallback: run against built assets |
| Empty `/app` in image from build-order mistakes | Image smoke asserts `server/public/app/index.html` exists |

## WS2 — File-parsing isolation (before real production)

### Mechanism: `child_process.fork()` pool

A small pool (1–2 recycled children) is preferred over `worker_threads`
despite the existing worker idiom in `server/storage/pg-worker.js`:

- SIGKILL from the parent always preempts a spinning child.
- Fault isolation is total: a child OOM, segfault, or pathological zlib case
  can never take down auth, approvals, or SSE. For attacker-controlled input
  feeding native-adjacent parsers, process isolation is the right default for
  a security product, and it is the established industry norm for handling
  untrusted documents.
- OS-level limits compose with processes: per-child
  `execArgv: ['--max-old-space-size=256']` now; container/seccomp-constrained
  parsing service later at SaaS scale (that escalation path composes with
  processes, not threads).
- Throughput is irrelevant here: uploads are low-rate and a warm pool
  amortizes fork cost.

### Design (public API stays stable)

- **`server/processors.js` is not modified.** Its `extractText(name, buf,
  opts)` contract, error codes (`unsupported`, `ocr_required`, `timeout`,
  `extract_failed`), and result shape stay byte-compatible.
  `sensors/endpoint-agent/agent.js` and `ocr.js` keep importing it in-process
  (scanning the user's own files is a different threat model).
- New `server/parse-pool.js` (parent): same `extractText` signature; sends
  `{id, name, buf, opts}` over IPC; parent-side hard timeout =
  `FILE_EXTRACT_TIMEOUT_MS` + grace → `child.kill('SIGKILL')` → respawn →
  return `{extractionOk: false, error: 'timeout'}`. Child crash mid-task →
  `extract_failed`. No new error codes leak into API responses. Recycle
  children after N tasks. `REDACTWALL_PARSE_ISOLATION=off` falls back to direct
  in-process extraction (dev/debug, low-resource demo boxes).
- New `server/parse-child.js` (child): receive task → call
  `processors.extractText` → post result. Truncation
  (`FILE_EXTRACT_MAX_CHARS`) happens in the child so oversized text never
  crosses IPC.
- One call-site change: the file-upload handler in `server/app.js` (~line
  1413) swaps `processors.extractText(...)` → `parsePool.extractText(...)`.
- Child stderr is captured but only sizes/error codes are logged — never
  filename-derived or content-derived text (CLAUDE.md PII rule).

### Verification

- `test/processors.test.js` untouched (proves API stability).
- New `test/parse-pool.test.js`: parity with direct extraction; CPU-spin
  preemption (request returns `timeout` within timeout+grace while a
  concurrent API call stays responsive); OOM kill → server healthy →
  `extract_failed`; crash recovery; off-switch path.

### Tika: criteria, not calendar

Apache Tika is justified only when (a) customers demand formats beyond
OOXML/PDF/text (legacy `.doc`/`.xls`, `.msg`/`.eml`, archives) **and** (b) the
deployment already tolerates a JVM sidecar — i.e. the shared SaaS plane, not
the install-in-an-afternoon silo. Until both hold, adm-zip + pdf-parse inside
a killable child covers the threat model at zero added footprint.

## WS3 — Node 24 LTS validation pass

Node 24 has been the **active LTS** line since October 2025 (22 is maintenance
LTS), and the ecosystem has seen better-sqlite3 prebuilt-binary/ABI issues on
Node 24 — exactly the risk `scripts/ensure-native-bindings.js` exists to
catch, so a matrix-then-flip approach is right.

- **Phase 1 (now, S):** `.github/workflows/ci.yml` test job becomes
  `strategy.matrix.node-version: ['22', '24']` running the **full** gate on
  both. `native:check:repair` is the better-sqlite3 ABI canary; the Docker
  toolchain (python3/make/g++) makes compile-from-source the fallback.
  `engines: ">=22"` stays unchanged. Optionally add `.nvmrc` = 22 now.
- **Phase 2 (criteria-gated, S):** flip both Dockerfile stages
  `node:22-bookworm-slim` → `node:24-bookworm-slim` only when all hold:
  (1) CI matrix green on 24 for ~2–3 weeks of normal merge traffic;
  (2) the Docker build job exercised on the 24 base; (3) no detection-eval
  perf regression; (4) better-sqlite3 builds cleanly. Keep the 22 CI lane
  after the flip until Node 22 support no longer matters, then consider
  raising `engines`. Rollback = revert the two Dockerfile lines.
- Coordinate Dockerfile churn with WS1's builder-stage change (same window or
  strictly after).

## WS4 — Postgres: harden what exists (SaaS-gated)

Industry alignment: shared-schema + `tenant_id` + Postgres row-level security
on managed Postgres is the 2026 default for B2B/fintech SaaS, with
defense-in-depth (app-layer tenant scoping + RLS + automated cross-tenant
tests) considered mandatory — CVE-2024-10976 showed RLS alone can leak across
mid-session context changes. The repo's existing design (migration 3:
`orgId` + RLS + `setTenantContext`) already matches this direction; the work
below hardens it. Postgres also gives future headroom (JSONB, pgvector for AI
features) without adding engines. SQLite remains the default for
single-customer silos per the 2026-06-26 customer-silo decision.

Priority order:

1. **RLS verification tests — do now (S, security-critical, cheap).** New
   `test/storage-postgres-rls.test.js` under the existing
   `REDACTWALL_TEST_PG_URL` CI service: for every tenant-scoped table, tenant-A
   context cannot read/update/delete tenant-B rows; missing or blank tenant
   context **fails closed**; the runtime role is not the table owner and lacks
   `BYPASSRLS` (owner silently bypasses RLS — the classic hole).
2. **Bound the sync bridge (S/M).** `server/storage/pg-worker.js` holds a
   single connection behind an `Atomics.wait` bridge. Do not rebuild it; add
   `statement_timeout` and connect retry/backoff in the worker, surface DB
   health in `/readyz`, and document the single-connection throughput
   ceiling. An async driver path for hot read endpoints is future work
   triggered by measured latency, not speculation.
3. **Backups (M).** `scripts/backup-store.js` / `backup-drill.js` are
   SQLite-only. Add a PG mode (`pg_dump`/restore for self-managed); for
   managed PG document snapshots + PITR and make `backup:drill` verify a
   restore into a scratch database.
4. **Tenant lifecycle (M).** Org create, suspend, offboard-with-export
   (dovetails with evidence-pack tooling), deletion with audit-chain
   preservation rules.
5. **Deployment docs (S).** New `docs/MANAGED_POSTGRES.md`:
   `REDACTWALL_DB_DRIVER=postgres` + `REDACTWALL_DATABASE_URL` with
   `sslmode=require`, non-owner app role setup, migration runbook, monitoring,
   sizing. Cross-link from `docs/AWS_SAAS_DEPLOYMENT.md` and
   `docs/DEPLOYMENT.md`.
6. **CI (S, optional).** Add `postgres:17` alongside 16.

Everything except item 1 is triggered by a signed shared-SaaS customer, not by
calendar.

## WS5 — node:sqlite: keep better-sqlite3 (decision record)

Recorded in `../DECISIONS.md`. Verified July 2026: `node:sqlite` in Node 24.x
is a **release candidate** (stability 1.2), still not stable — the review's
caution holds. Revisit only when ALL of:

1. `node:sqlite` marked stable (non-experimental) in both shipped LTS lines.
2. Feature parity audited against actual usage in `server/db.js` and
   `scripts/backup-store.js` (WAL pragma, transactions, `.backup()`/function
   APIs).
3. Benchmark within ~20% of better-sqlite3 on the real access pattern
   (audit-chain append + queue reads).
4. Adopted as a third driver behind `REDACTWALL_DB_DRIVER` — the
   `server/storage/` abstraction makes this a bounded, trialable swap.

Payoff at adoption: drop python3/make/g++ from the Docker builder and delete
`scripts/ensure-native-bindings.js` (the last native dependency).

## Sequencing

```
Now            WS3.1 CI Node-24 matrix (S)
               WS5 decision record (S)              independent — land immediately
               WS4.1 RLS verification tests (S)

Weeks 1–3      WS2 parse isolation (M)              security-critical, before real production
               WS1 A0–A1 scaffold + pilot (S+M)     validated on the 22/24 matrix from day one

Weeks 3–8+     WS1 A2 core views → A3 long tail → A4 cutover
               WS3.2 Docker base flip (S)           after matrix soak; align with WS1 Dockerfile change

SaaS-gated     WS4.2–4.6 Postgres ops hardening (M) triggered by a signed shared-SaaS customer
```

WS2 and WS1 touch different regions of `server/app.js` (upload handler ~1413
vs static serving ~2648) — no conflict.

## Future-proofing summary (industry direction check, verified July 2026)

| Choice | Where the industry is | Verdict |
|---|---|---|
| React 19 + Vite + TS | Enterprise/fintech frontend default; Vite replaced webpack; TS table stakes | Aligned |
| No Next.js | SSR server buys nothing for a static, auth-gated console | Right call |
| SQLite silo → managed Postgres + RLS for shared SaaS | Shared-schema + tenant_id + RLS is the B2B SaaS default; defense-in-depth required | Aligned — storage layer already matches |
| Process-isolated parsing | Sandboxed handling of untrusted documents is the security norm | Aligned — child pool now, service escalation path documented |
| Node 24 | Active LTS since Oct 2025 | Aligned — matrix then flip |
| better-sqlite3 over node:sqlite | node:sqlite still release-candidate in Node 24 | Aligned — keep, stable-in-LTS revisit trigger |

Re-check this table before starting each workstream rather than inheriting it
as a stale assumption.

## Verification map

| Phase | Existing gates that cover it | New tests required |
|---|---|---|
| WS1 A0–A4 | Playwright e2e, `frontend-csp.test.js`, `asset-budget.test.js`, Docker smoke | `admin-console-app.spec.js` (grows per view), `/app` budget entry, image-contains-console check |
| WS2 | `test/processors.test.js` (API stability), file-upload e2e | `test/parse-pool.test.js` (preemption, OOM, crash recovery, off-switch) |
| WS3 | Entire full gate × matrix, `native:check:repair`, Docker build job | none beyond matrix wiring |
| WS4 | CI postgres service, `storage-postgres.test.js`, `db-migration.test.js` | `storage-postgres-rls.test.js`, PG mode in `backup:drill` |
| WS5 | n/a (document) | none |

## Coordination with the production loop

The production loop reads `../STATUS.md` Open items each pass; the immediate
pickups (WS2, WS3.1, WS4.1) and the WS1 coordination rule are filed there.
The critical rule while WS1 is in flight: **new console work goes in
`console/` only; keep patching `server/public/` legacy views until a view's
`/app` port lands, then feature-freeze that view on legacy.** This lets
feature passes keep stepping the asset budget on legacy views without
creating parity drift against the migration.
