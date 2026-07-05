---
name: durable-memory-loop
description: The on-disk memory discipline that lets a loop run longer than one conversation. Maintains PLAN.md (goals), STATUS.md (changing state), and DECISIONS.md (why), and runs each work pass Ralph-style — fresh context that reads state from disk, does one task, commits, updates state. Invoke with /durable-memory-loop.
---

# Durable Memory Loop

The model forgets everything between runs; the repo does not. State must live on disk, not in the context window. This skill owns the files every other loop reads and writes.

## The three files (keep them in the repo root)
- **PLAN.md** — durable goals and acceptance criteria. Changes rarely.
- **STATUS.md** — changing state: `## Open` (newest first) and `## Done`. The spine `daily-triage-loop` writes and the fix loops consume.
- **DECISIONS.md** — short dated entries for non-obvious choices ("bare 9-digit numbers need banking context before ROUTING_NUMBER fires — too many false positives otherwise"). This is how the loop stops re-litigating settled questions.

> PromptWall already keeps long-form history in `ITERATIONS.md` and `CHANGELOG.md`. Treat those as the archive; PLAN/STATUS/DECISIONS are the live working set. Don't duplicate — link.

## The Ralph-style pass
Each unit of work is a fresh agent with a clean context:
1. Read `PLAN.md` + `STATUS.md`.
2. Pick the single highest-priority open item.
3. Do exactly that one task; run its evidence command (`npm test`, etc.).
4. On success: commit, move the item to `## Done` with the commit hash, append a `DECISIONS.md` line if anything non-obvious came up.
5. Exit. The next pass starts clean and reads the updated state.

## Rules
- One task per pass. Granular beats heroic.
- Never store secrets or raw sensitive sample data in these files (this is a DLP product — practice what it preaches; use synthetic/tokenized examples only).
- If STATUS.md and reality disagree, reality wins — reconcile before working.

## Stop condition
State files reflect the true repo state; the worked item is in `## Done` with evidence; context is clean for the next pass.
