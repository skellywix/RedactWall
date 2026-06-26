---
name: no-mistakes-review
description: The validation pipeline for agent-written changes — the real bottleneck. Eyeball the diff for wrong-direction work, then run an autonomous pass in a FRESH context that peer-reviews, self-corrects, rebases, tests end-to-end with evidence, closes doc/lint gaps, opens a structured PR, and babysits CI — escalating only ambiguous, product-changing decisions to you. Invoke with /no-mistakes-review on a branch or diff.
---

# No-Mistakes Review

You're the manager; agents review agents. Most managers don't read every line — they make the team review each other and demand evidence it works. ~68% of agent changes carry a bug a fresh review catches, so this pipeline is not optional.

## Step 0 — sanity glance (human, ~10s)
Scan the diff (`git diff main...HEAD` or neogit). If the agent went in a completely wrong direction, it's obvious — stop and re-plan (`plan-first-spec`). Otherwise proceed.

## The pipeline (autonomous, with escalation)
1. **Fresh-context peer review.** Run the reviewer as a NEW agent/session — never the one that wrote the code (it's biased toward its own work). Use `maker-checker-loop` mechanics + the `pr-review-loop` checklist.
2. **Self-correct obvious bugs** found in review.
3. **Rebase** onto latest `main`, resolve conflicts.
4. **End-to-end evidence** — not just unit tests. Run `agent-self-validation` to prove the feature actually works (unit-green-but-product-broken is common).
5. **Close gaps:** update docs, fix lint.
6. **Package:** conventional commit on a descriptively named branch, push, open a well-structured PR with a **Testing** section containing the E2E evidence (screenshots / `npm run simulate` output). Babysit CI until green.

## Escalate to the human (don't auto-fix everything)
Ambiguous or **product-changing** decisions stay with you — e.g. changing an enforcement default, relaxing a detector threshold, altering what counts as `alwaysBlock`. Auto-fixing those lets the agent drift from intent. Log every auto-fix on the PR so you can audit.

## PromptSentinel gate (must pass before the PR is "green")
`npm test` · `npm run sync-check` · semantic determinism (`npm run train-semantic && git diff --exit-code`) · `verifyAuditChain()` = ok · no raw PII in logs/audit. For the security-sensitive surface, hand to `security-scan-loop`.
