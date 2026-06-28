# Contributing to PromptWall

This repository uses a single source-of-truth and review-gated workflow.

## Local source and hooks

- Work only inside the active app repo folder (`promptsentinel/` in this checkout
  until the physical folder migration is completed).
- Run:

```bash
npm run hooks:install
```

to activate the local hooks.

## Review gate

- Run `npm run review:ci` before each commit in the local cycle.
- `pre-commit` runs `npm run review:agent` automatically and blocks bad commits.
- `post-commit` reruns `npm run review:ci` and only pushes when checks pass.

`review:ci` runs:

- `git diff --check`
- `npm test`
- `npm run sync-check`
- `npm run eval`

If push fails, the commit stays local and you can retry `git push` after the issue is fixed.

## Required evidence

For any change you can reference:
- `ITERATIONS.md` for what was done and when.
- `STATUS.md` for current execution and evidence.
- `DECISIONS.md` for strategic guardrails.

Keep all outputs synthetic and avoid real member/personal data.
