---
name: daily-triage-loop
description: Scheduled discovery + triage loop. Each run scans CI failures, open issues, recent commits, and RedactWall health (tests, engine sync, audit-chain) and writes a prioritized findings list to STATUS.md. Read-only on code. This is the heartbeat the other loops react to. Invoke with /daily-triage-loop or schedule with /loop.
---

# Daily Triage Loop

The recurring trigger that surfaces work without you asking. It NEVER edits application code — it only looks, groups, and writes findings to a state file that the fix loops consume.

## When to run
- Every weekday morning, or on demand before you sit down.
- Schedule (Claude Code): `/loop "Run the daily-triage-loop skill" --schedule "0 8 * * 1-5"`
- In Cowork, schedule the same prompt as a recurring task at 8am on weekdays.

## The loop
1. **Read state first.** Open `PLAN.md` (goals) and `STATUS.md` (what's open/done). If they don't exist, create them (see `durable-memory-loop`).
2. **Gather signals** (read-only):
   - CI: `gh run list --status failure --limit 20` and read failing logs.
   - Issues: `gh issue list --label bug` and `gh issue list --label quick-win`.
   - Recent change: `git log --since="yesterday" --oneline`.
   - RedactWall health checks:
     - `npm test` — note any failing files (`test/*.test.js`).
     - `npm run sync-check` — confirms `detection-engine/detect.js` matches `sensors/browser-extension/lib/detect.js`. A mismatch is a release blocker.
     - Audit integrity: `node -e "const db=require('./server/db'); console.log(db.verifyAuditChain())"` — the hash-chain must report `ok:true`.
3. **Group by root cause, not by symptom.** Five failing tests from one regression are one finding.
4. **Write findings to `STATUS.md`** under `## Open`, newest first. Tag anything fixable in a single file as `quick-win`. For each, name the likely owning loop (`ci-failure-fix-loop`, `bug-repro-fix-loop`, `security-scan-loop`).
5. **Stop. Do not fix anything here.** Print a 5-line summary and exit.

## Stop condition (contract)
- Evidence: `STATUS.md` updated with today's date heading; summary printed listing counts of CI failures, open bugs, sync/audit status.
- Constraint: zero changes to files outside `STATUS.md` / `PLAN.md`.

## Memory
`STATUS.md` is the spine every other loop reads. Keep it terse and current — see `durable-memory-loop`. Preserve resolved items under `## Done` so the loop learns instead of re-reporting.
