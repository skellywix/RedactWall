---
name: plan-first-spec
description: Spend most of your effort planning. Turn a rough idea into an AI-ready spec before any code — because plan quality determines how long an agent runs unattended (a one-line prompt buys minutes; a solid plan buys hours). Produces a reviewable plan artifact with goal, context, options+recommendation, flagged decisions, and acceptance evidence. Invoke with /plan-first-spec before big features/refactors.
---

# Plan-First Spec

The centerpiece of the manager-of-agents workflow: you stay at "what to build and whether it's good," and the plan is how you delegate hours of autonomous work safely. Weak plan in → drift and babysitting. Strong plan in → the agent runs to a clean PR.

## Three planning levels (climb to delegate more)
1. **Rough idea** — a sentence. Fine for trivial edits, but the agent stops in seconds and you're the bottleneck.
2. **AI-ready spec** — goal + context + constraints + acceptance evidence. Enough for the agent to run a feature unattended.
3. **Detailed plan** — the spec plus a step-by-step approach, file-level touch points, and decision points. Buys hours of unattended work.

## Write the plan as an artifact (not a chat wall)
Have the agent draft `PLANS/<feature>.md` (or an interactive HTML page if you use a visual planner). A good plan opens with:
- **Goal & context** — what and why.
- **Options** — 2-3 approaches, each with pros/cons and the agent's **recommendation**.
- **Decisions for the human** — explicitly flagged; don't let the agent silently choose product-changing behavior.
- **Acceptance evidence** — the exact commands that prove done (feeds `goal-contract-loop`).
Iterate on the artifact until you're confident, THEN hand off for autonomous implementation.

## RedactWall: every plan must name the invariants up front
A plan that touches detection, policy, or audit states these as non-negotiable constraints so the agent respects them for the whole run:
- Detector logic lives in `detection-engine/detect.js` only → `npm run sync-engine`; `npm run sync-check` must stay green.
- Semantic model changes go through `npm run train-semantic` (deterministic; CI diffs).
- No `alwaysBlock` type weakened; no raw PII in logs/audit `entry`; `verifyAuditChain()` stays `ok:true`.
- Acceptance evidence = `npm test` + the new `test/*.test.js` case + `npm run simulate` where detection changes.

## Hand-off
When the plan is confident: implement directly, or for a massive plan hand to `long-running-orchestrator`; spin the work into its own worktree via `parallel-agents-worktrees`.
