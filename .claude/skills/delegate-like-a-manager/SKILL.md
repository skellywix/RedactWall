---
name: delegate-like-a-manager
description: Prompt agents the way a good manager delegates — ask for outcomes not actions, always explain the why and give context, and never take back control. When the agent errs, give feedback and update the agent-memory file (AGENTS.md) instead of doing it yourself. Invoke with /delegate-like-a-manager or apply to every prompt.
---

# Delegate Like a Manager

Working with agents is delegation. The same failure modes that sink new tech leads sink agent users: asking for actions instead of outcomes, omitting the why, and taking back control at the first mistake.

## Three rules
1. **Outcome, not action.** "Rename this variable" finishes in seconds and leaves you the bottleneck. Instead: "Audit `server/policy.js` and make naming follow our convention (link), so the next reader understands intent." The agent runs longer, aligned to a goal.
2. **Always give the why + context.** Rationale lets the agent suggest something better and do it right next time. No why → it guesses.
3. **Never take back control.** When the agent does something wrong, the instinct is to do it yourself — and you stop scaling. Give feedback and help it improve instead.

## When it errs, fix the system not the symptom
Write the correction into the agent-memory file (`AGENTS.md` / `CLAUDE.md`), or ask the agent to reflect on the mistake and update that file, so it never repeats. (See `AGENTS.md` mistake log.) This is how the team gets better over time instead of you re-explaining.

## RedactWall examples
- Weak: "add a routing-number regex." → Strong: "Reduce false negatives on bank routing numbers without adding false positives; keep the banking-context guard; prove it with a new `test/detect.test.js` case and `npm run simulate`."
- Weak: silently fixing a bad diff yourself. → Strong: tell the agent what was wrong and add a line to `AGENTS.md` so the next session avoids it.

## Pairs with
`plan-first-spec` (the outcome lives in the plan) and `no-mistakes-review` (feedback loop on the produced change).
