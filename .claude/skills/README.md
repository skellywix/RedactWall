# PromptWall Agent Skills

Project skills in the universal `SKILL.md` format. Claude Code (and Cursor / Codex / Gemini CLI) auto-discover them here. Each is either invoked as a slash command (`/skill-name`) or triggers automatically when its `description` matches the task.

Two groups:
1. **Loops** — must-have agent loops derived from loop engineering (designing the system that prompts the agent, not prompting by hand). Self-contained, tuned to this repo.
2. **The 10 "must-have skills" (2026 article)** — self-contained where the skill is a pure playbook; a tailored wrapper + upstream install command where it's an external tool.

> Loops vs skills: a *skill* is a reusable playbook; a *loop* is a skill meant to run on a schedule / until a verifiable goal, reading and writing on-disk state. The loops below lean on five building blocks + memory: **automations** (`/loop`), **worktrees**, **skills**, **MCP connectors**, **sub-agents** (maker/checker), and **memory** (`PLAN.md` / `STATUS.md` / `DECISIONS.md`).

## Memory convention (read this first)
Loops share three repo-root files, owned by `durable-memory-loop`:
- `PLAN.md` — durable goals. `STATUS.md` — live `## Open` / `## Done`. `DECISIONS.md` — why, dated.
Long-form history stays in the existing `ITERATIONS.md` / `REVIEW.md`.

## General loops
| Skill | What it does |
|-------|--------------|
| `daily-triage-loop` | Morning heartbeat: scan CI/issues/commits + tests, engine sync, audit chain → prioritized `STATUS.md`. Read-only on code. |
| `goal-contract-loop` | Turn a fuzzy objective into a contract (end state, evidence cmd, constraints, budget); iterate until evidence passes. Pairs with `/goal`. |
| `maker-checker-loop` | Maker drafts in a worktree; adversarial checker runs the full gate and compliance review before a human sees it. |
| `durable-memory-loop` | The on-disk state discipline; Ralph-style fresh-context passes that do one task and update state. |
| `weekly-review-loop` | Anti-comprehension-debt pass: digest what shipped, read diffs you didn't write, full verification sweep, prune memory. |

## Coding loops
| Skill | What it does |
|-------|--------------|
| `ci-failure-fix-loop` | Red CI → reproduce in a worktree → fix one root cause → full gate → PR. |
| `test-coverage-loop` | Raise coverage on detection/policy/crypto/audit; one real test per pass; never weaken assertions. |
| `pr-review-loop` | Adversarial pre-human review: quality + PromptWall invariants (no PII in logs, engine parity, `alwaysBlock` intact). |
| `dependency-upkeep-loop` | Scheduled `npm audit`/outdated; auto-merge low-risk green bumps; route majors & parser/native deps to a human. |
| `bug-repro-fix-loop` | No fix without a failing test first; turn each bug into a permanent regression guard. |
| `security-scan-loop` | Scheduled adversarial pass on local/staging: Shannon + product abuse cases (IDOR, detector bypass, PII leakage). Never prod. |

## The 10 article skills
| Skill | Type | Upstream install (run it yourself) |
|-------|------|-----------------------------------|
| `frontend-design` | self-contained (+ optional upstream) | `npx skills add anthropics/claude-code --skill frontend-design` |
| `browser-use` | wrapper | `npx skills add https://github.com/browser-use/browser-use --skill browser-use` (in Cowork, prefer built-in Claude-in-Chrome) |
| `code-reviewer` | self-contained (+ optional `simplify`) | `npx skills add anthropics/claude-code --skill simplify` |
| `remotion` | wrapper | `npx skills add remotion/agent-skills` |
| `google-workspace` | wrapper | `npm i -g @googleworkspace/cli` → `gws mcp -s drive,gmail,sheets,docs` |
| `valyu` | wrapper (needs API key) | `npx skills add valyuAI/skills` |
| `antigravity-awesome-skills` | wrapper (curate!) | `npx antigravity-awesome-skills --claude` |
| `planetscale-db` | wrapper | `brew install planetscale/tap/pscale` → `npx skills add planetscale/agent-skill` |
| `shannon-pentest` | wrapper (Docker + key) | `npx skills add unicodeveloper/shannon` |
| `excalidraw-diagram` | wrapper | `npx skills add https://github.com/coleam00/excalidraw-diagram-skill --skill excalidraw-diagram` |

Installers were intentionally NOT run. The wrapper SKILL.md files document *when to use* each tool and a PromptWall-tuned playbook; run the install command yourself, and provide any API keys / OAuth consent directly (never share secrets in chat).

## How they fit together (a real loop)
`daily-triage-loop` (scheduled) writes findings → `ci-failure-fix-loop` / `bug-repro-fix-loop` pick one up in a worktree → `goal-contract-loop` frames the stop condition → `maker-checker-loop` / `pr-review-loop` gate it → PR. Weekly, `security-scan-loop` and `weekly-review-loop` run. `dependency-upkeep-loop` runs Mondays. State lives in `PLAN/STATUS/DECISIONS.md`.

## Adoption ladder (don't jump to auto-merge)
0 manual → 1 triage (findings only) → 2 draft PRs → 3 verifier-gated PRs → 4 auto-merge low-risk classes. Climb only when the current rung is producing work you'd have done by hand. `dependency-upkeep-loop` is the safe place to try level 4.

## Agentic engineering workflow (L8 / Kun Chen)
Added from the "L8 Principal's Agentic Engineering Workflow" talk. The throughline: act as the **manager of an always-on agent team** — Plan → Implement → Validate — and stay at "what to build and whether it's good." These complement the loops above; they don't replace them.

| Skill | Phase | What it does |
|-------|-------|--------------|
| `plan-first-spec` | Plan | Turn a rough idea into an AI-ready spec/plan artifact; plan quality = how long agents run unattended. |
| `delegate-like-a-manager` | Plan | Prompt for outcomes not actions, always give the why, never take back control; fix the system (AGENTS.md) not the symptom. |
| `long-running-orchestrator` | Implement | gnhf-style overnight runner: fresh-context steps + durable notes.md, rollback on failure, token budget. For massive plans, metric improvement, scored experiments. |
| `parallel-agents-worktrees` | Implement | Run 5-10+ agents without collisions via a worktree pool, with status in each tab title. |
| `agent-self-validation` | Validate | Force end-to-end evidence (not just unit tests); the repo's AGENTS.md says how to exercise the app. |
| `no-mistakes-review` | Validate | Fresh-context review → self-correct → rebase → E2E evidence → docs/lint → structured PR → CI green; escalate product-changing decisions. |

Companion file: **`AGENTS.md`** (repo root) — the agent operating contract: commands, hard invariants, how to exercise PromptWall E2E, review standards, and a mistake log. `agent-self-validation` and `delegate-like-a-manager` depend on it.

A normal day: voice/describe the work → `plan-first-spec` until the plan is confident → implement directly or hand a big job to `long-running-orchestrator`, each in its own `parallel-agents-worktrees` checkout → `no-mistakes-review` (which runs `agent-self-validation`) opens a clean PR while you start the next task. Findings/mistakes flow back into `AGENTS.md` and `STATUS.md`.
