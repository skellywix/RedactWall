---
name: parallel-agents-worktrees
description: Run 5-10+ agents at once without them stepping on each other. One git worktree per task from a managed pool (reuse an idle one with deps/build/env ready, synced to main), and keep each agent's status visible in its tab/window title so you can see what's running, done, or waiting. Invoke with /parallel-agents-worktrees when fanning out independent tasks.
---

# Parallel Agents over Worktrees

A fully autonomous implement-and-validate pipeline means a single task takes a while — which is good, because it frees you to run more at once. The two problems to solve are collisions and visibility.

## Isolation: a worktree per task
Agents sharing one directory clobber each other. Give each task its own `git worktree`:
```
git worktree add ../ps-<slug> -b <type>/<slug>
cd ../ps-<slug> && npm ci    # fresh deps for this checkout
```
Treat worktrees as a **pool**: reuse an idle one (deps/build/env already there), make sure it's synced to latest `main` before starting, and remove it after merge (`git worktree remove`). The point is to think about the work, not where to do it.

## Visibility: status in the title
Run each agent in its own tmux window / terminal tab and surface its status (running / done / needs-input) in the **tab title**. That one detail is what lets you run many sessions without losing track — a glance shows which agents need you. Claude Code/Codex do this by default.

## When to parallelize
Independent tasks: separate features, a bug fix + a dep bump + a doc pass. Most go straight to a clean PR via `no-mistakes-review`; you only engage when one escalates a decision.

## PromptWall caution: serialize engine edits
Two agents both editing `detection-engine/detect.js` in parallel worktrees will collide on `npm run sync-check` / `npm run train-semantic` at merge. Keep detector/semantic-model changes to ONE worktree at a time; parallelize the independent surfaces (extension UI, server endpoints, docs, tests) freely.

## Pairs with
`no-mistakes-review` (each worktree's exit path), `long-running-orchestrator` (give a big job its own worktree).
