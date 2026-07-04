# PromptWall Status

Live working state for the production loop. Durable goals live in `PLAN.md`,
decision rationale in `DECISIONS.md`, the product roadmap in `ROADMAP.md`, and
release history in `CHANGELOG.md` and `ITERATIONS.md`. Older per-pass evidence
logs were pruned on 2026-07-04; they are preserved in git history
(`git log --follow STATUS.md`).

## Open (the TODO list, ordered)

Roadmap references (N*/X*) point at `ROADMAP.md`.

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

## Done (recent highlights)

- 2026-07-04: Documentation/process overhaul — removed stale QA logs
  (`.codex/`), superseded `REVIEW.md`, dead `server/index.js`; added
  `ROADMAP.md`, `CHANGELOG.md`, `SECURITY.md`, engineering process docs
  (release, testing, licensing, support, documentation standards); added the
  standalone black-box regression suite in `suite/` with contract, security,
  detector, and UI-flow tiers.
- 2026-07-02: Safe-to-send receipts shipped (signed, prompt-free,
  `POST /api/receipts/verify`); console simplified to one navigation and one
  title per screen; PromptWall logo/favicon.
- 2026-06-29: Destination-scoped browser download blocking; managed browser
  text-upload inspection moved into the extension; per-user Clipboard Guard
  install path.
- 2026-06-28: Windows protected-upload desktop collector; inline employee
  coaching in the block/warn/justify banner.
- Full pass-by-pass history: `ITERATIONS.md` and git history of this file.
