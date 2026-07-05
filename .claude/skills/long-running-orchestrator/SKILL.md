---
name: long-running-orchestrator
description: For tasks too big for one context window. Breaks the objective into small steps, each run in a fresh context seeded with a common base plus learnings from prior steps; rolls back failed attempts; respects a token budget; and ends with a branch of organized commits plus a notes.md summary. Use to implement a massive plan, improve a measurable metric, or run scored experiments overnight. Invoke with /long-running-orchestrator with an objective.
---

# Long-Running Orchestrator (gnhf-style)

"Good night, have fun." If you let one agent grind a huge task, it fills context, compacts, and loses important state. Instead, orchestrate many fresh-context steps against durable state — the Ralph loop, productized.

## How it runs
1. Decompose the objective into small, verifiable steps.
2. Each step = a **fresh context** seeded with a common base context + `notes.md` learnings from previous steps.
3. Run the step; verify; **commit on success**. On failure, **roll back** and let the next attempt take the failure into account.
4. Enforce a **token/turn budget** so you don't wake up bankrupt.
5. Finish with a branch of well-organized commits and a `notes.md` summarizing what was done and what's open.

## Three good use cases
- **Implement a massive plan:** "fully implement `PLANS/<feature>.md`" (pair with `plan-first-spec`).
- **Improve a measurable metric** while keeping functionality unchanged:
  - detection quality: raise precision/recall measured by `npm run simulate` (don't regress `alwaysBlock` recall — a false negative is a leak).
  - test coverage (`node --test --experimental-test-coverage`), startup/latency, or extension bundle size.
- **Scored experiments:** when you have an evaluator, run dozens of attempts and keep the best (e.g. tuning semantic thresholds against a labeled corpus, scored automatically).

## Invariants every step must hold (RedactWall)
`npm test` green · `npm run sync-check` green · semantic model regenerated via `npm run train-semantic` only (deterministic) · `verifyAuditChain()` ok. A step that breaks any of these rolls back.

## Pairs with
`goal-contract-loop` (each step has a verifiable stop condition), `durable-memory-loop` (notes.md is the spine), `parallel-agents-worktrees` (run it in its own worktree).
