---
name: goal-contract-loop
description: Run-until-verifiably-done loop. Turns a fuzzy objective into a contract the agent cannot fake — explicit end state, evidence command, constraints, and a turn/budget ceiling — then iterates until the evidence passes. Use for any multi-step task you want to walk away from. Invoke with /goal-contract-loop or pair with Claude Code /goal.
---

# Goal Contract Loop

A goal is only as good as the evidence that proves it. This skill forces every autonomous objective into a contract before work starts, so "done" means a command exited 0, not "it looks finished."

## Write the contract first
Fill in all four fields. Refuse to start if any is vague.

| Field | Weak | Verifiable (RedactWall example) |
|-------|------|-------------------------------------|
| End state | "Improve detection" | "`detect.js` flags `ROUTING_NUMBER` only with banking context AND valid ABA checksum" |
| Evidence | "It works" | "`npm test` exits 0 and `test/detect.test.js` has a new passing case for the false-positive" |
| Constraints | (unstated) | "Do not change `detection-engine/`'s public `api`; do not weaken any `alwaysBlock` type; keep `npm run sync-check` green" |
| Budget | (unbounded) | "Stop after 20 turns or when blocked twice on the same error" |

## The loop
1. State the contract back to the user and get the evidence command exactly right.
2. Do one unit of work toward the end state.
3. Run the **evidence command**. If it fails, read the failure, fix, repeat.
4. Re-check **every constraint** (here: `npm run sync-check` for engine parity; `node -e "require('./server/db').verifyAuditChain()"` if audit code changed; `npm run train-semantic && npm run sync-check` if you touched the semantic model — CI fails on drift).
5. Stop when evidence passes AND constraints hold, OR the budget is spent (then report exactly where you stopped and why).

## Pair with /goal
In Claude Code: `/goal "npm test passes, test/detect.test.js covers the ROUTING_NUMBER false-positive, and npm run sync-check is clean"`. A separate model grades the condition each turn, so the agent that wrote the code is not the one declaring victory. Hand the failing case to `maker-checker-loop` for an adversarial second opinion before merge.

## Never
Never edit the evidence command to make it pass. Never mark done with a red test, a failing `sync-check`, or a broken audit chain.
