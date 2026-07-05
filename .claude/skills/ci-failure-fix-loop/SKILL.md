---
name: ci-failure-fix-loop
description: Turns a red CI run into a merged fix. Reproduces the failure locally, fixes one root cause on a branch in an isolated worktree, verifies against the full RedactWall gate (tests, engine sync, semantic determinism, audit chain), and opens a PR. Invoke with /ci-failure-fix-loop after daily-triage-loop flags a failure.
---

# CI Failure → Fix Loop

Consumes a failure from `STATUS.md` and drives it to a reviewable PR. One root cause per pass.

## Loop
1. **Pick one failure** from `STATUS.md` (`gh run list --status failure --limit 5` to confirm it's still red).
2. **Reproduce locally** in a fresh worktree: `git worktree add ../ps-ci-<slug> -b fix/<slug>` then `npm ci && npm test`. If it passes locally, the failure is environmental (Node version is `22`, see `.github/workflows/ci.yml`) — note that and stop.
3. **Isolate** the smallest failing unit. Read the specific `test/*.test.js` and the module under it.
4. **Write the fix.** One root cause. If the cause is detector logic, edit `detection-engine/detect.js` and run `npm run sync-engine` so `sensors/browser-extension/lib/detect.js` stays identical — never hand-edit the copy.
5. **Verify the full gate** (mirror CI exactly):
   - `npm test`
   - `npm run sync-check`
   - `npm run train-semantic && npm run sync-check && git diff --exit-code -- detection-engine/detect.js sensors/browser-extension/lib/detect.js`
   - `docker build -t redactwall:loop .` (CI builds the image too)
6. **Open the PR:** `gh pr create --fill`. Link the failing run. Update `STATUS.md`.

## Stop condition (contract)
- Evidence: green local run of all gate commands; PR URL printed.
- Constraints: one root cause only; no skipped/`.only` tests left behind; no `alwaysBlock` type weakened.

## Escalate
If the same failure resists two passes, stop, write what you tried to `STATUS.md` + `DECISIONS.md`, and hand to a human. Don't thrash.
