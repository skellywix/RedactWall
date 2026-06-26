---
name: weekly-review-loop
description: Periodic review loop that fights comprehension debt. Once a week it summarizes what the loops shipped, reads the diffs you didn't write, prunes stale STATUS.md items, re-runs full verification (tests, engine sync, audit chain, semantic determinism), and flags anything merged but not understood. Invoke with /weekly-review-loop or schedule with /loop.
---

# Weekly Review Loop

A smooth loop ships code faster than you can understand it. This is the deliberate pass that keeps you the engineer, not just the person who pressed go.

## When to run
- End of week. Schedule: `/loop "Run the weekly-review-loop skill" --schedule "0 16 * * 5"`.

## The loop
1. **What shipped:** `git log --since="1 week ago" --oneline` and `gh pr list --state merged`. Write a plain-language digest of each change.
2. **Read what you didn't write.** For each agent-authored merge touching `shared/detect.js`, `src/policy.js`, `src/db.js`, or `src/crypto.js`, summarize WHAT changed and WHY in one line. Anything you can't explain → add to `STATUS.md` as `comprehension-debt` to review with a human.
3. **Full verification sweep:**
   - `npm test`
   - `npm run sync-check` (engine parity across the three sensors)
   - `npm run train-semantic && npm run sync-check` then `git diff --exit-code` (semantic model is deterministic)
   - `node -e "require('./src/db').verifyAuditChain()"` (tamper-evident log intact)
   - `npm run simulate` (end-to-end detection sanity over the sample corpus)
4. **Prune memory:** move resolved `STATUS.md` items to `## Done`, archive anything older than ~30 days into `ITERATIONS.md`, delete dead entries.
5. **Report:** a short weekly note — shipped, verification status, open risks, comprehension-debt items, and recommended focus for next week.

## Stop condition (contract)
- Evidence: weekly note produced; all five verification commands run with results recorded; `STATUS.md` pruned.
- Constraint: no code changes during review — findings become `STATUS.md` items for the fix loops, not fixes made here.

## The three habits this enforces
Preserve mistakes (so the loop learns), build verification into the loop (not bolted on), and treat the red test / broken chain as the signal that keeps the agent honest.
