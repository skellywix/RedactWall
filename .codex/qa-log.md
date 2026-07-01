# QA Log

Branch: `codex/full-app-qa`
Base: `origin/main`
Local timestamp: `2026-06-30T22:35:08-05:00`

## Required Setup Evidence

- Active repo: `C:\Users\Eric\Desktop\Coding_Projects\promptsentinel-app\promptwall`
- Wrapper note: the workspace root is routing only; source, npm, Git, and GitHub work are in `promptwall/`.
- Base branch: `origin/main`
- Work branch: `codex/full-app-qa`
- Package manager: npm with `package-lock.json`
- Runtime discovered: Node `v22.22.3`, npm `11.17.0`
- Installed dependency surface: Express 5, better-sqlite3, helmet, cookie-parser, zod, adm-zip, pdf-parse, Playwright.
- Lint/typecheck/build scripts: no dedicated `lint`, `typecheck`, or `build` scripts are defined in `package.json`.
- Primary local gate: `npm run review:ci`
- GitHub workflows read: `.github/workflows/ci.yml`, `.github/workflows/ai-domain-refresh.yml`
- Docs read: `AGENTS.md`, `README.md`, `CONTRIBUTING.md`, `test/README.md`, `scripts/README.md`, `server/README.md`, `docs/README.md`, `.env.example`

## Section 1 - Baseline Install, Tooling, And Test Discovery

Status: Passed

### Inspection

- Confirmed the active repo is the nested `promptwall/` checkout.
- Confirmed `origin` is `https://github.com/skellywix/promptwall.git`.
- Confirmed `origin/HEAD` resolves to `origin/main`.
- Confirmed only npm lockfile present is `package-lock.json`.
- Confirmed the current branch is `codex/full-app-qa`.
- Ran `npm run` to enumerate available scripts.

### Commands Run

- `git fetch --prune origin` - passed.
- `git switch -c codex/full-app-qa origin/main` - passed in the baseline setup pass.
- `git pull --ff-only` - passed, already up to date.
- `node -v` - `v22.22.3`.
- `npm -v` - `11.17.0`.
- `npm ls --depth=0 --omit=optional` - passed.
- `npm ci` - passed; 114 packages installed and 0 vulnerabilities reported by npm install audit.
- `npm run` - passed; discovered the scripts listed in `package.json`.
- `npm run review:ci` - passed.
- `node --test --test-concurrency=1 test\oidc-login.test.js` - passed after one later transient local full-suite native binding load failure.
- `npm run review:ci` - passed again after the transient local failure.
- `git commit -m "test(qa): align full-app audit artifacts"` - passed; pre-commit and post-commit hooks both ran `npm run review:ci`, and the post-commit hook pushed `codex/full-app-qa`.
- `gh pr view 54 --json number,title,url,state,baseRefName,headRefName,mergeStateStatus,isDraft,commits,statusCheckRollup` - verified PR #54 exists for `codex/full-app-qa` into `main`.
- `gh pr status` - verified PR #54 is the current branch PR and checks were pending at the time checked.

### Baseline Gate Result

`npm run review:ci` passed and covered:

- `git diff --check`
- `npm run docs:demo-guide:check` - demo guides current.
- `npm run ai-domains:check` - 75 domains; Cloudflare Radar enrichment skipped because no `CLOUDFLARE_API_TOKEN` is configured.
- `npm test` - 76 Node test files run sequentially.
- `npm run test:admin-console` - 6 Chromium Playwright tests passed.
- `npm run sync-check` - engine copies identical.
- `npm run eval` - all held-out detector floors met; semantic micro precision 100.0%, recall 94.4%, F1 97.1%; structured PII micro precision/recall/F1 100.0%; benign category false positives 0; ordinary-id PII false positives 0.

### Notes

- `npm ci` printed npm's `allow-scripts` warning for `better-sqlite3@12.11.1`, which uses a native install path. The package installed and the Node test suite passed against the installed binding.
- There is no separate project lint/typecheck/build command to run in this repo.
- One later local `npm run review:ci` attempt failed when `better-sqlite3` could not resolve its native binding during `test/oidc-login.test.js`; the focused OIDC test and a subsequent full `review:ci` rerun passed without code changes.

## Carried-Forward Evidence From Prior Merged UI/UX Slice

PR #53, `test(ui): verify UI/UX implementation`, is already merged into `main` at `98449e788bfdaf46ebb2f0f2582daddec56a2a53`.

Tracked artifacts already present on `main`:

- `.codex/ui-ux-qa-log.md`
- `.codex/ui-ux-pr.md`

That slice covered dashboard shortcut controls, active tab accessibility state, global search accessible naming, admin-console Playwright coverage, full browser Playwright coverage, npm audit, Docker build, and GitHub CI. This evidence is useful for the navigation/accessibility sections, but the full application QA objective remains open.

## GitHub Delivery

- Branch: `codex/full-app-qa`
- PR: `https://github.com/skellywix/promptwall/pull/54`
- Latest observed CI status: pending for GitHub `test` and `docker` on the latest pushed head.
- Merge status: not merged. The full application QA objective remains open and the next section is forms and validation.

## Section 2 - Navigation And Routing

Status: Passed

### Inspection

- Reviewed `server/app.js` route registration for public health/readiness, SCIM, sensor APIs, admin APIs, OIDC, dashboard, and root redirect behavior.
- Reviewed `server/auth.js` unauthenticated behavior, including browser-page redirects and API JSON 401 responses.
- Reviewed `e2e/admin-console.spec.js` coverage for login navigation, content tabs, rail tabs, shortcut controls, logout, and mobile tab behavior.
- Reviewed `test/dashboard-linkage.test.js`, `test/routing.test.js`, and `test/server-integration.test.js`.

### Issue Found

The server HTTP smoke tests covered `/healthz` and `/readyz`, but did not directly lock the route contract for root redirect, unauthenticated dashboard redirect, public login-page availability, and unauthenticated API JSON errors.

### Fix Made

Added `test/server-integration.test.js` coverage for:

- `GET /` returning a `302` redirect to `/index.html`.
- `GET /index.html` without a session returning a `302` redirect to `/login.html`.
- `GET /login.html` remaining publicly reachable as HTML.
- `GET /api/me` without a session returning `401` with `{ error: 'unauthenticated' }`.

### Commands Run

- `node --test --test-concurrency=1 test\server-integration.test.js test\dashboard-linkage.test.js test\routing.test.js` - passed before edit, 11 tests.
- `npm run test:admin-console` - first focused rerun failed before tests because the Playwright health URL on port `4211` was already in use during the parallel run.
- `netstat -ano | Select-String ':4211'` - showed no active listener after the failure, only `TIME_WAIT` sockets.
- `Invoke-WebRequest http://127.0.0.1:4211/healthz` - timed out after the failure, confirming no stale responding Playwright server.
- `npm run test:admin-console` - passed on serial rerun, 6 Chromium tests.
- `node --test --test-concurrency=1 test\server-integration.test.js` - passed after edit, 3 tests.
- `node --test --test-concurrency=1 test\dashboard-linkage.test.js test\routing.test.js` - passed after edit, 9 tests.

### Notes

- The transient Playwright failure was local harness timing, not an application routing regression. The serial rerun passed without code changes.
- Runtime server routing/auth code was not changed in this section.

## Section 3 - Authentication And Authorization

Status: Passed

### Inspection

- Reviewed `server/auth.js` session cookie signing, verification, MFA/TOTP helpers, OIDC state handling, API-vs-page unauthenticated behavior, and audit logging hooks.
- Reviewed `server/roles.js` role constants and admin capability helpers.
- Reviewed auth and authorization coverage across `test/auth.test.js`, `test/admin-mfa.test.js`, `test/admin-csrf.test.js`, `test/approver-role.test.js`, `test/auditor-role.test.js`, `test/approval-stepup.test.js`, `test/reveal-stepup.test.js`, `test/oidc-login.test.js`, `test/scim.test.js`, and `test/security-headers.test.js`.
- Checked coverage for security-admin, approver, auditor, SCIM bearer, CSRF, step-up, MFA, OIDC callback, and session-protected API behavior.

### Issue Found

The MFA login test verified status codes and response bodies for bad credentials, missing MFA, and wrong MFA, but did not explicitly lock the session-cookie contract for failed login attempts.

### Fix Made

Updated `test/admin-mfa.test.js` to assert:

- Bad password responses do not set `promptwall_session`.
- Missing security-admin MFA responses do not set `promptwall_session`.
- Wrong security-admin MFA responses do not set `promptwall_session`.
- Successful security-admin and auditor logins do set `promptwall_session`.

### Commands Run

- `node scripts/run-node-tests.js test\auth.test.js test\admin-mfa.test.js test\admin-csrf.test.js test\approver-role.test.js test\auditor-role.test.js test\approval-stepup.test.js test\reveal-stepup.test.js test\oidc-login.test.js test\scim.test.js test\security-headers.test.js` - passed before edit, 36 tests.
- `node --test --test-concurrency=1 test\admin-mfa.test.js` - passed after edit, 1 test.
- `node scripts/run-node-tests.js test\auth.test.js test\admin-mfa.test.js test\admin-csrf.test.js test\approver-role.test.js test\auditor-role.test.js test\approval-stepup.test.js test\reveal-stepup.test.js test\oidc-login.test.js test\scim.test.js test\security-headers.test.js` - passed after edit, 36 tests.

### Security Review Notes

- No runtime auth, session, RBAC, CSRF, OIDC, MFA, SCIM, or audit behavior changed in this section.
- The added regression coverage reduces auth bypass risk by proving failed login and failed MFA paths do not issue a reusable session cookie.
- Residual auth/security work remains for later full-application sections, including broader manual cross-session checks, API abuse/rate-limit review, and final security/privacy review.

## Section Queue

1. Baseline install/lint/typecheck/build/test discovery - passed.
2. Navigation and routing - passed.
3. Authentication and authorization - passed.
4. Forms and validation - pending.
5. Buttons, controls, overlays, and interactive states - pending.
6. Loading, empty, error, and success states - pending.
7. API integration and data fetching - pending.
8. Backend API behavior - pending.
9. Database/persistence/migrations if present - pending.
10. State management and cache - pending.
11. Tables, search, filters, and pagination - pending.
12. File/media flows if present - pending.
13. Payments/billing if present - not yet assessed.
14. Admin/RBAC if present - pending.
15. Accessibility - pending.
16. Responsive/cross-browser behavior - pending.
17. Motion/effects/reduced-motion behavior - pending.
18. Performance and bundle health - pending.
19. Security and privacy - pending.
20. Analytics/observability if present - pending.
21. CI/CD and release readiness - pending.
22. Final e2e regression - pending.
