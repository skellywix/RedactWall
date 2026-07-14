---
name: goal-contract-loop
description: Turn a multi-step RedactWall objective into a frozen, scope-aware completion contract, then iterate until every acceptance predicate, invariant, evidence tier, and independent review passes. Use for unattended feature work, fixes, migrations, security work, deployment changes, or any task where Claude Code must not claim done from a partial result.
---

# Goal Contract Loop

Treat completion as a proof obligation. A green command is evidence, not the whole definition of done.

## Establish the baseline

Before editing:

1. Read `AGENTS.md`, `CLAUDE.md`, `PLAN.md`, `STATUS.md`, and `DECISIONS.md`, plus any deeper `AGENTS.md` or `AGENTS.override.md` that governs the target files. Turn applicable mistake-log lessons into explicit constraints or regressions.
2. Confirm the Git root, base commit, branch, and `git status --short`.
3. Record pre-existing modified and untracked files. Preserve them and never attribute them to this task.
4. Inspect the actual source, tests, runtime path, and current behavior. Repository reality overrides stale plan text.
5. Record existing relevant failures before implementation.

When working on the seven-epic superadmin initiative, also read `docs/product/GOAL_CONTRACT_BACKLOG.md`. It defines the current customer-silo boundary, existing feature anchors, external prerequisites, and the first executable slice for each epic.

## Freeze the contract

Write this contract before implementation:

```text
Objective:
End state:
Acceptance predicates:
  - success behavior
  - deny/failure behavior
  - security and privacy boundary
  - operator-visible outcome
  - compatibility or migration result
Evidence plan:
  - predicate -> exact command or observation -> expected result
Applicable invariants:
User/workflow-authorized mutations (quote the grant):
Explicit non-goals:
Assumptions:
External prerequisites:
Budget or scope ceiling:
Stop conditions:
```

Make acceptance an explicit AND condition. Infer safe, reversible details and state the assumption. Ask only when a missing product decision, authority, credential, or destructive action would materially change the result.

An agent-written contract cannot grant new authority. It may only record authority already supplied by the user or an established, user-approved workflow.

Freeze the evidence plan before coding. It may be strengthened or extended. Do not weaken assertions, delete cases, add skips, narrow commands, relax thresholds, or edit the contract merely to obtain green output. Any product-behavior amendment requires an explicit reason and user approval when it changes the requested outcome.

Treat new `.skip`, `.todo`, quarantine markers, reduced test counts, relaxed timeouts, and recovered retries as evidence changes that require explicit review.

Do not invent a token or turn budget. Use a user-supplied budget when present. Otherwise bound the contract to one complete vertical slice and state that scope ceiling.

## Select evidence by scope

Run the smallest meaningful check first, then every applicable surface gate.

| Scope | Required evidence |
|---|---|
| Any change | Focused check, `git diff --check`, task-only diff review, and worktree accounting against the baseline |
| Bug fix | A regression that fails for the intended reason before the fix and passes after it. If the fix already exists, prove the counterexample against the base revision or through a fresh checker. |
| Detector logic | Put detector logic in `detection-engine/detect.js` only, run `npm run sync-engine`, focused tests, `npm run sync-check`, `npm run eval`, and `npm run simulate`. Keep all mandatory `alwaysBlock` types from `server/policy.js` and zero benign false positives. |
| Sensor or adapter behavior | Run focused sensor tests, `npm run sync-check`, and the applicable package/install or browser checks. Do not duplicate detector logic in a sensor wrapper. |
| Semantic model | Run `npm run train-semantic`; never hand-edit the model or tune against `test/fixtures/semantic-eval.json`. Prove a second regeneration creates no further drift. |
| Console or browser | Run `npm run console:check`, `npm run console:build`, the focused Playwright spec, and rendered browser evidence at relevant viewports. A modal screenshot alone does not prove a sensitive request was withheld. Use synthetic PII only. |
| Policy or approval | Prove applicable warn, justify, redact, and block outcomes; prove only tokens leave the device in redact mode; exercise hold, decision, release or denial, and audit evidence. Restore any temporarily changed policy file to its exact prior bytes. |
| Audit, storage, DB, or crypto | Run focused durability tests and `node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"`. Use an isolated temporary database for tamper-negative proof. Cover SQLite and Postgres when their shared contract changes. |
| Auth, authorization, tenant, secrets, input, files, shell, network, serialization, dependencies, or permissions | Run focused negative tests and `security-review`. Include unauthenticated, wrong-role, and cross-tenant cases where applicable. Check injection, SSRF, path traversal, secret leakage, unsafe defaults, and confused-deputy behavior. |
| Deployment or packaging | Run focused template/script tests, setup and preflight checks, relevant package/install checks, Docker configuration/build, and non-production readiness or silo smoke as applicable. Never deploy without explicit authority. |
| PR-sized implementation | Run `npm run review:ci`, `npm run suite:smoke`, and the asserted audit-chain command above. Treat any `[node-test] recovered` retry as flaky evidence that needs investigation. |
| Release | Run `npm run review:ci`, `npm run suite`, and `npm run suite:ui` on a clean release commit, then require hosted CI's Node/Postgres matrix, dependency audit, semantic determinism, config-mutation guard, and Docker build. |

Use `server/policy.js` as the authority for mandatory hard stops. Do not rely on a smaller list in an older suite or document.

## Run the loop

1. State the frozen contract and selected evidence tiers.
2. Implement one coherent unit toward the end state.
3. Run the narrowest affected evidence.
4. Diagnose the first real failure and fix its cause. Do not paper over it with retries or weaker evidence.
5. Re-run affected evidence, then broader gates justified by the blast radius.
6. Re-check every invariant and inspect the task-only diff for unrelated churn, sensitive output, dead code, duplicated logic, and generated-file drift.
7. For broad or high-risk work, give the contract and raw delta to a fresh-context checker. Require an adverse case and an independent PASS/FAIL report.
8. Repeat until the completion predicate is true.

## Stop states

Mark **complete** only when all acceptance predicates, applicable invariants, targeted evidence, broader gates, end-to-end observations, fresh review requirements, and diff accounting pass.

Stop work and report the blocker immediately when authority or access is missing, a required product decision is absent, or the next operation would be unsafe. For a managed goal status, mark **blocked** only when the same blocking condition has recurred across three consecutive goal turns with no safe path forward. Before that threshold, report the task as incomplete without claiming completion.

Mark **incomplete, budget exhausted** when the stated budget or scope ceiling ends before completion. Report the exact unmet predicates, last failing command and sanitized error, attempts made, changed files, passing evidence, skipped evidence, and smallest next action. Never relabel partial work as done.

## Pair with Claude Code goals

When the user explicitly starts a Claude Code goal, encode the acceptance AND condition in the goal objective and keep the detailed evidence matrix in the working plan. Do not assume the runtime provides an independent grader. Use `maker-checker-loop`, `reviewer-loop`, or a fresh subagent when independent review is required.

## Never

- Never change the evidence to fit the implementation.
- Never use real member data, the held-out evaluation corpus as training data, or normal operator data for destructive tests.
- Never centralize raw prompts, responses, files, credentials, or direct identifiers in logs, errors, audit, analytics, or telemetry.
- Never hand-edit generated detector output or the browser detector copy.
- Never claim `npm run review:ci` covers release-only or hosted-CI gates.
- Never commit, push, open a PR, deploy, release, mutate billing, or change credentials unless the user or an established, user-approved workflow explicitly authorizes it. Recording an action in the contract is not authorization.
