# UI/UX QA Log

## 2026-06-30

### Iteration 1 - Dashboard shortcut controls

- Files: `server/public/index.html`, `server/public/dashboard.js`, `e2e/admin-console.spec.js`
- Issue: Dashboard navigation relied on visual active classes without exposing the current tab state to assistive technology. The global search also relied on placeholder text instead of an explicit accessible name.
- Fix: Added `aria-current="page"` to active dashboard tabs, kept it in sync through the tab activation path, added `aria-label` to the global search field, and kept the Evidence/Configure shortcut controls on the existing tab-jump behavior.
- Baseline command: `npm run test:admin-console`
- Baseline result: Passed, 6 Playwright tests.
- Validation command: `npm run test:admin-console`
- Validation result: Passed, 6 Playwright tests. First rerun found a Playwright locator targeting the hidden hero shortcut region. Second rerun found a loose role-name match against "not configured" chips. Test was corrected to the visible queue shortcuts with exact role names.
- Broad validation command: `npm run review:ci`
- Broad validation result: Passed. Includes `git diff --check`, demo-guide drift check, AI-domain coverage check, 76 Node test files, admin-console Playwright, detector sync, and held-out eval.
- Dependency validation command: `npm audit --omit=dev`
- Dependency validation result: Passed, 0 production vulnerabilities.
- Docker validation command: `docker build -t promptwall:ui-ux-qa .`
- Docker validation result: Passed.
- Full browser validation command: `npm run test:browser`
- Full browser validation result: Passed, 14 Playwright tests.
- GitHub CI result: Push and pull_request `docker` and `test` checks passed on PR #53. The pull_request browser-extension job initially flaked in existing smoke coverage, then passed on rerun without code changes.
- Artifacts: Playwright console output in current run.
- Risks: Low. Change is limited to existing dashboard markup and existing tab routing behavior.
