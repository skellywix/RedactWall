# RedactWall Status

Live working state for the production loop. Durable goals live in `PLAN.md`,
decision rationale in `DECISIONS.md`, the product roadmap in `ROADMAP.md`, and
release history in `CHANGELOG.md` and `ITERATIONS.md`. Older per-pass evidence
logs were pruned on 2026-07-04; they are preserved in git history
(`git log --follow STATUS.md`).

## Open (the TODO list, ordered)

Roadmap references (N*/X*) point at `ROADMAP.md`.

### Frontend redesign branch 2026-07-10 (`codex/frontend-ui-redesign`, worktree `RedactWall-ui-redesign`)

The redesign is implemented on the audit-hardened `main` base but is not yet
delivery-complete. A continuation audit
closed additional response-bounding, auth recovery-code, logout, role-parity,
truthful-state, approval-audit, reversible policy-mutation, accessibility,
table-workflow, and map-performance gaps. Focused TypeScript/build/static tests
pass, and the complete serial Chromium run passes 169/169 tests across 19
specs, including the 21 live extension flows. Full detail is in
`PLANS/frontend-ui-ux-redesign.md` under the resume and continuation logs.

Remaining release gates are explicit: close the final fresh-review findings,
commit and merge this redesign plus the owner platform, run the responsive
screenshot review and `npm run review:ci` from the final integrated tree, then
push and verify GitHub CI. The prior audit-checkpoint/private-path blockers are
already integrated into `main`; no completion claim is made until the final
merged proof runs.

### Adversarial review 2026-07-08 — fix ledger (`claude/adversarial-codebase-review-xpfuyj`)

Full report + repro: the review artifact. Each fix below ships with a
failing-first regression guard (`test/adversarial-review-fixes.test.js`,
`test/adversarial-review-a1.test.js`) and the full node suite stays green.

**Fixed (18):** D1 unicode-digit detector bypass · D3 ENCRYPTED/DSA private
keys · D4 lowercase IBAN · N1 custom-detector ReDoS guard · N9 empty-extraction
OCR hold · N10 Word comments/footnotes scanned · N4 shadow-AI/self-block SIEM
alerts · C3 deleted-evidence detection · G1 gateway tool-definition scan/redact
· G4 response tool-call scan/redact · N6 backup manifest required · A1 SCIM
demote revokes sessions · R1 SSRF alt-encoding block · E1 re-validate sensor
`masked` · N11 corrupt Office entries fail the complete extraction closed · C5
held-status polling requires the per-item release token · A2 unassigned SCIM
identities cannot sign in · A3 logout persistently revokes the specific session
`jti`.

**FP-risk — deliberately not auto-fixed (review-standards caution):**
- D2 (bare card fires only with separator/context) and D5 (bare 9-digit SSN):
  broadening recall risks benign false positives; needs careful counter-tests.

**Decision-blocked — need a human call (safest mitigation noted):**
- C1 — audit chain is unkeyed with no external anchor. A real fix HMAC-keys the
  chain, which requires a one-time rekey MIGRATION of existing logs (their
  stored hashes change) + a key held outside the DB. Not shippable unilaterally.
- N2 — EDM fingerprints are fast/reversible. A slow keyed KDF changes the
  fingerprint format (existing `config/exact-match.json` must be regenerated)
  and can't fully protect an on-device salt; genuine architecture tradeoff.
- G2/G3/G5 — kill-switch: reject env key-override + placeholder in connected
  mode (G2), monotonic high-water-mark vs clock rollback (G3), refuse a wiped
  install anchor (G5). Code-doable and fail-closed, but the real vendor private
  key issuance is a release task, so these want a coordinated call.
- N8 — HA gateway ships plaintext HTTP. Config + docs are code; real TLS certs
  are supplied at deploy.

**Active engineering thread — stack upgrade** (`PLANS/stack-upgrade-plan.md`):

- WS1 A3: **DONE.** All 18 operator views are ported to the React `/app`
  console: Overview, Approval Queue, AI Command Center, All Activity,
  Insights, Sensor Coverage, Data Lineage, Decision Quality, App Catalog,
  Compliance, NCUA Readiness, Identity, Policy Configuration, Licensing,
  Deploy, Integrations, Audit Log, and Updates. The shell chrome includes a grouped Operate/Analyze/Govern/System rail
  with icons and a live pending badge, Ctrl/Cmd-K command palette, LIVE + last-
  updated indicators, sign out, system-status footer). The instrument design
  system (fonts, tokens, leak-map animation, selectors) lives in
  `server/public/console-base.css` so the console renders as designed in
  light/dark (dark default).
  Queue assignee editor, per-query audit trail, billing/seats, and the Command
  Center decision pivots all carried over. Coverage definitions now span all
  18 routes in `e2e/console-parity.spec.js` and 36 dark/light captures in
  `e2e/console-design.spec.js`; final regenerated proof remains gated above.
- WS1 A4 (cutover) — **DONE.** The legacy static console is retired: `/`
  redirects to `/app/`, and `server/public/{index.html,dashboard.js}` plus the
  15 feature-renderer JS files were deleted (the shared `console-base.css`,
  `console-theme.css`, `login.html`, `login.js`, and `favicon.svg` are kept —
  the React console uses them). Legacy-only tests were removed; the privacy and
  evidence-export invariants they guarded were migrated to assert against the
  React console source.
- **Repo-wide hardening pass — DONE.** A line-by-line audit (verified) fixed
  131 defects across server, storage, engine, gateway, sensors, console, and
  tooling, including several backend loose ends from the stack upgrade:
  Postgres RLS tenant context is now actually wired (`db.wireTenantContext`),
  the pg-driver literal-quoting and reply-desync bugs are fixed, the endpoint
  agent parses untrusted files through the killable parse pool, unsupported
  files fail closed (`file_blocked_unscanned`), and the AI Gateway redacts
  every response choice / array input with full policy+EDM coverage. See the
  `## Recently completed` note below and `CHANGELOG.md`.
- WS3.2: flip the Dockerfile base to `node:24-bookworm-slim` once the Node
  22/24 CI matrix has soaked green ~2–3 weeks with no detection-eval perf
  regression and clean better-sqlite3 builds; keep the 22 CI lane after.
- WS4.4 (SaaS-gated): tenant lifecycle tooling (org create, suspend,
  offboard-with-export, deletion with audit-chain preservation) — triggered by
  a signed shared-SaaS customer, not calendar.

**Next pass — browser→endpoint file-intent:** extend the new file-intent
handoff loop end to end in a pilot — add the file-intent host to
`scripts/check-endpoint-install.js` (a `--require-file-intent-host` check
mirroring `--require-desktop-collector`) and surface intent-resolved scans
distinctly in lineage so an examiner can see browser-intent-triggered endpoint
scans. Remaining product gap: desktop coverage is protected-upload, clipboard
guard, git-push guard, per-app guarded drop folders, browser text-upload
inspection, and browser→endpoint file-intent handoff — but still not universal
drag/drop or file-open interception inside every desktop AI app.

**Product roadmap:**

1. **Inline redaction + coaching UX in the browser sensor** (N1) — replace
   sensitive spans in the composer with typed tokens, explain why, allow
   proceed-with-redacted. Detector spans and tokenization already exist.
2. **Examiner report pack** (N2) — DONE (core slices). The schemaVersion-3
   examiner-profile pack maps usage, enforcement, and evidence to NCUA Part 748
   Appendix A / GLBA 501(b) / NIST AI RMF (`server/evidence.js`,
   `server/control-map.js`, `scripts/export-evidence-pack.js
   --examiner-profile federal_credit_union`). Open tails: FFIEC handbook labels
   (not yet coded) and a rendered human-readable report (JSON today).
3. **Coaching acknowledgment audit trail** (N3) — record warn/acknowledge/
   proceed/cancel into the hash-chained audit.
4. **Personal vs. corporate AI account detection** (N4) — detect the logged-in
   account identity on AI sites; policy to flag/block personal logins.
5. **GenAI browser-extension inventory** (N5) — surface installed GenAI
   extensions in Coverage/posture.
6. **Published detection benchmarks + red-team harness** (N6) — publish
   held-out eval numbers; ship a self-service detector test kit. Builds on
   `npm run eval` and `suite/`.
7. **Customer licensing implementation** (N7) — DONE. Offline Ed25519-signed
   license verified at boot + daily (`server/license.js`), issued with
   `npm run license:issue`, installed via `POST /api/billing/license`; 30-day
   grace, admin console goes read-only past grace but detection/enforcement/
   approvals/audit never stop. Replace the placeholder public key before the
   first commercial release. Docs in `docs/process/CUSTOMER_LICENSING.md`.
8. **First tagged release on the new process** (N7) — cut `v0.4.0` per
   `docs/process/RELEASE_PROCESS.md`: CHANGELOG cut, signed artifacts, SBOM.
9. **Desktop app file-open/drag-drop interception** (X7) — see the browser→
   endpoint file-intent next pass above; the endpoint package is not yet
   universal file-open interception for every desktop AI app.
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
  O(k²)→O(k log k)); detail in `docs/security/SECURITY_REVIEW_2026-07.md`.
- 2026-07-04: Browser→endpoint file-intent handoff — when the extension blocks
  an upload it cannot inspect (too large / OCR-required / unsupported), it
  sends name+size (never bytes) through a `com.redactwall.file_intent` native
  messaging host that resolves the file in local staging roots and writes the
  signed metadata-only handoff so the endpoint agent scans it locally.
- 2026-07-04: Console-parity checklist closed — inline queue reassignment
  (`POST /api/queries/:id/assign`, audited `APPROVAL_REASSIGNED`), hourly
  `SENSOR_STALE` sweep, and Command Center decision-pivot chips.
- 2026-07-04: Stack-upgrade plan WS1–WS5 (`PLANS/stack-upgrade-plan.md`) —
  killable child-process parse pool for attacker-controlled file extraction
  (`server/parse-pool.js`); Node 22/24 CI matrix + node24/postgres17 lane;
  Postgres RLS tenant-isolation tests + pg-worker statement_timeout/retry +
  pg_dump backup mode; new `console/` Vite + React 19 + TypeScript app served
  auth-gated at `/app` with Overview/Queue/Policy/Audit/Decision-Quality
  views ported.
- 2026-07-02: Safe-to-send receipts shipped (signed, prompt-free,
  `POST /api/receipts/verify`); console simplified to one navigation and one
  title per screen; RedactWall logo/favicon.
- 2026-06-29: Destination-scoped browser download blocking; managed browser
  text-upload inspection moved into the extension; per-user Clipboard Guard
  install path.
- 2026-06-28: Windows protected-upload desktop collector; inline employee
  coaching in the block/warn/justify banner.
- Full pass-by-pass history: `ITERATIONS.md` and git history of this file.
