---
name: code-reviewer
description: Runs a structured quality pass over code the agent just wrote — extracts duplication, splits oversized functions, kills dead code, fixes weak typing/naming — and fixes what it finds before you see it. The per-change quality pass; pairs with pr-review-loop (the gate). Invoke with /code-reviewer or run after each implementation.
---

# Code Reviewer

Makes the code you receive the second draft, not the first. This is quality/simplification; the security + compliance gate lives in `pr-review-loop`.

## Optional upstream skill
Official Anthropic `simplify`: `npx skills add anthropics/claude-code --skill simplify`. (Install yourself.) This file is self-contained.

## Review standards (PromptSentinel)
After completing any implementation, review changed code for:
- Functions longer than ~30 lines (likely doing too much) → extract.
- Logic duplicated more than twice → pull into a shared helper. (E.g. detector boilerplate belongs in `shared/detect.js`, not copied per sensor.)
- Inconsistent patterns vs the surrounding module.
- Performance: avoid `N+1` over the `better-sqlite3` layer; keep the hot detection path allocation-light (it runs on every keystroke/paste).
- Dead code, unused imports/exports.
- Naming that doesn't communicate intent.

## Project-specific musts
- Detector changes live in `shared/detect.js` only, then `npm run sync-engine` — never duplicate logic into `extension/lib/detect.js` by hand.
- No raw prompt text / PII in log lines or thrown errors.
- Keep the `shared/` public `api` surface stable; sensors depend on it.

## Loop
1. Diff the change. 2. Flag against the list above. 3. **Fix** the mechanical issues (don't just report). 4. Re-run `npm test` and, if `shared/` changed, `npm run sync-check`. 5. Summarize what you changed and why.

## Add to CLAUDE.md
Copy the "Review standards" list into the repo `CLAUDE.md` so it shapes default behavior, not just explicit invocations.
