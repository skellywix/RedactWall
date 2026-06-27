---
name: maker-checker-loop
description: Splits the agent that writes from the agent that checks. A maker drafts the change in an isolated worktree; an adversarial checker (different instructions, ideally a stronger model) runs the tests, audits the diff against project rules, and gates it before a human sees it. Use for any change you intend to merge. Invoke with /maker-checker-loop.
---

# Maker / Checker Loop

The model that wrote the code is far too generous grading its own homework. Separate the roles. For a regulated DLP product, the checker is also your compliance gate.

## Roles
- **Maker** — implements one finding from `STATUS.md` on a feature branch in an isolated worktree (`git worktree add ../ps-<branch> -b fix/<slug>`). Stays focused on the contract from `goal-contract-loop`.
- **Checker** — fresh context, adversarial stance, ideally a stronger model. Trusts tests over its own read of the diff.

## Checker pass (PromptSentinel gate)
The checker runs and must get a clean result on all of these before PASS:
1. `npm test` exits 0.
2. `npm run sync-check` — the shared engine and `sensors/browser-extension/lib/` copy are identical. Any detector change must go through `npm run sync-engine`, never hand-edited in one place.
3. If `detection-engine/detect.js` semantic weights changed: `npm run train-semantic` then `git diff --exit-code` on the model block — retraining must be deterministic (CI enforces this).
4. If audit/db code changed: `node -e "require('./server/db').verifyAuditChain()"` reports `ok:true`.
5. Diff review against project rules: no weakening of `alwaysBlock` types (SSN, cards, bank/routing, IBAN, passport, secret/private keys), no raw sensitive values written to logs or audit `entry`, no new dependency without reason, functions doing one thing.

## Output
Checker reports a short **PASS / FAIL list with evidence per line**. FAIL bounces back to the maker with the specific failing command. Only PASS reaches the human reviewer.

## Why it matters here
`/goal` already uses a maker/checker split on the stop condition itself. Make it explicit for code: in a product an examiner will inspect, the second opinion is the difference between "tests pass" and "we can prove this change didn't widen a leak."
