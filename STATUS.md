# PromptWall Status

Live working state for the production loop. Durable goals live in `PLAN.md`,
decision rationale in `DECISIONS.md`, the product roadmap in `ROADMAP.md`, and
release history in `CHANGELOG.md` and `ITERATIONS.md`. Older per-pass evidence
logs were pruned on 2026-07-04; they are preserved in git history
(`git log --follow STATUS.md`).

## Open (the TODO list, ordered)

Roadmap references (N*/X*) point at `ROADMAP.md`.

**Active engineering thread — stack upgrade** (`PLANS/stack-upgrade-plan.md`):

- WS1 A3: port the long-tail legacy feature modules to `/app` routes, one PR
  each (`siem-package.js`, `security-package.js`, `agentic-mcp.js`,
  `operator-flow.js`, `behavior-baselines.js`, `control-graph.js`,
  `coverage-file-flow.js`, `ai-threat-guardrails.js`, plus posture/catalog/
  compliance/lineage/identity views). Follow the conventions in
  `console/src/views/` (typed api module + view + co-located CSS; `Queue.tsx`
  is the richest example).
- WS1 A4 (after A3): cutover — flip `SENTINEL_CONSOLE_DEFAULT=app` as deploy
  default, serve legacy at `/legacy/` for one release, port remaining
  Playwright specs, then delete `server/public/dashboard.js`, `index.html`,
  and the feature-module files plus their asset-budget entries.
- WS3.2: flip the Dockerfile base to `node:24-bookworm-slim` once the Node
  22/24 CI matrix has soaked green ~2–3 weeks with no detection-eval perf
  regression and clean better-sqlite3 builds; keep the 22 CI lane after.
- WS4.4 (SaaS-gated): tenant lifecycle tooling (org create, suspend,
  offboard-with-export, deletion with audit-chain preservation) — triggered by
  a signed shared-SaaS customer, not calendar.

**Product roadmap:**

1. **Inline redaction + coaching UX in the browser sensor** (N1) — replace
   sensitive spans in the composer with typed tokens, explain why, allow
   proceed-with-redacted. Detector spans and tokenization already exist.
2. **Examiner report pack** (N2) — quarterly generated report mapping usage,
   enforcement, and evidence to NCUA 2026 exam priorities / FFIEC / GLBA /
   NIST AI RMF. Extends `server/evidence.js`.
3. **Coaching acknowledgment audit trail** (N3) — record warn/acknowledge/
   proceed/cancel into the hash-chained audit.
4. **Personal vs. corporate AI account detection** (N4) — detect the logged-in
   account identity on AI sites; policy to flag/block personal logins.
5. **GenAI browser-extension inventory** (N5) — surface installed GenAI
   extensions in Coverage/posture.
6. **Published detection benchmarks + red-team harness** (N6) — publish
   held-out eval numbers; ship a self-service detector test kit. Builds on
   `npm run eval` and `suite/`.
7. **Customer licensing implementation** (N7) — offline Ed25519-signed license
   file, seat counting with renewal true-up, 30-day grace, never block
   detection for billing reasons. Design in `docs/CUSTOMER_LICENSING.md`.
8. **First tagged release on the new process** (N7) — cut `v0.4.0` per
   `docs/RELEASE_PROCESS.md`: CHANGELOG cut, signed artifacts, SBOM.
9. **Desktop app file-open/drag-drop interception** (X7) — move beyond the
   protected-upload shell action, clipboard guard, and browser-local upload
   path (app-specific native collectors or native-messaging handoff). The
   longest-standing product gap: the endpoint package is not yet universal
   file-open interception for every desktop AI app.
10. **MCP server catalog + per-tool RBAC** (X1), **gateway prompt-injection
    benchmark** (X2), **Copilot ingestion** (X3) — next-quarter items; see
    `ROADMAP.md` for acceptance sketches.

## Ongoing invariants (every pass)

- `npm run review:ci` green before commit; audit chain `ok:true`.
- `suite/` regression tiers green before release (`npm run suite:smoke` on
  every PR-sized change, `npm run suite` before a tag).
- Detector changes keep `npm run eval` floors: zero benign false positives.
- **Console coordination rule:** new console work goes in `console/` only.
  Overview/queue/policy/audit/decision-quality are ported — feature-freeze
  those views on the legacy dashboard (new UI surfaces for them go in `/app`
  routes). Other legacy views can still be patched in `server/public/` until
  their port lands.

## Done (recent highlights)

- 2026-07-04: Documentation/process overhaul + full-codebase security/perf
  hardening — removed stale QA logs (`.codex/`), superseded `REVIEW.md`, dead
  `server/index.js`; added `ROADMAP.md`, `CHANGELOG.md`, `SECURITY.md`, and
  process docs (release, testing, licensing, support, documentation
  standards); added the standalone black-box regression suite in `suite/`
  (contract, security, detector, UI-flow tiers). A line-by-line review then
  fixed three `alwaysBlock` hard-stop bypasses, an Atlassian connector
  credential leak, outbound SSRF, and hot-path perf (overlap resolution
  O(k²)→O(k log k)); detail in `docs/SECURITY_REVIEW_2026-07.md`.
- 2026-07-04: Stack-upgrade plan WS1–WS5 (`PLANS/stack-upgrade-plan.md`) —
  killable child-process parse pool for attacker-controlled file extraction
  (`server/parse-pool.js`); Node 22/24 CI matrix + node24/postgres17 lane;
  Postgres RLS tenant-isolation tests + pg-worker statement_timeout/retry +
  pg_dump backup mode; new `console/` Vite + React 19 + TypeScript app served
  auth-gated at `/app` with Overview/Queue/Policy/Audit/Decision-Quality
  views ported.
- 2026-07-02: Safe-to-send receipts shipped (signed, prompt-free,
  `POST /api/receipts/verify`); console simplified to one navigation and one
  title per screen; PromptWall logo/favicon.
- 2026-06-29: Destination-scoped browser download blocking; managed browser
  text-upload inspection moved into the extension; per-user Clipboard Guard
  install path.
- 2026-06-28: Windows protected-upload desktop collector; inline employee
  coaching in the block/warn/justify banner.
- Full pass-by-pass history: `ITERATIONS.md` and git history of this file.
