# Contributing to RedactWall

This repository uses a single source-of-truth and review-gated workflow.

## Local source and hooks

- Work only inside the active app repo folder (`redactwall/` in this checkout).
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
- `npm run docs:demo-guide:check`
- `npm run ai-domains:check`
- `npm test`
- `npm run test:browser`
- `npm run sync-check`
- `npm run eval`

`npm run docs:demo-guide` refreshes the generated current-state sections in the
demo guide hub, sales demo guide, and technician setup guide from the current
package, policy, sensor, detector, and supporting-doc state.

If push fails, the commit stays local and you can retry `git push` after the issue is fixed.

## Required evidence

For any change you can reference:
- `CHANGELOG.md` for customer-visible history (add an `[Unreleased]` entry
  for any change with user impact).
- `ITERATIONS.md` for what was done and when.
- `STATUS.md` for the live TODO list and current execution state.
- `DECISIONS.md` for strategic guardrails.

## Process references

- Documentation rules: `docs/DOCUMENTATION_STANDARDS.md` — docs change in the
  same commit as the code they describe.
- Testing rules and where a new test belongs: `docs/TESTING_STRATEGY.md`.
  The standalone regression suite in `suite/` runs with `npm run suite:smoke`
  (every change) and `npm run suite` (before release).
- Releases: `docs/RELEASE_PROCESS.md`. Security reports: `SECURITY.md`.

Keep all outputs synthetic and avoid real member/personal data.
