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
- Latest observed CI status: GitHub `test` and `docker` checks are watched after each pushed QA slice.
- Merge status: not merged. The full application QA objective remains open and the next section is Responsive/cross-browser behavior.

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

## Section 4 - Forms And Validation

Status: Passed

### Inspection

- Reviewed `server/validation.js` Zod request-body schemas, strict unknown-field handling, length limits, detector-id validation, policy rule validation, and sanitized validation field reporting.
- Reviewed `server/public/dashboard.js` policy form parsers, guided scope/exception builders, step-up password dialogs, destination review reason dialog, decision note handling, and policy save flow.
- Reviewed `test/validation.test.js`, `test/dashboard-linkage.test.js`, and `e2e/admin-console.spec.js` coverage for server-side validation, dashboard payload construction, browser form wiring, JSON-array errors, and dialog required fields.

### Issue Found

The dashboard policy save flow returned silently when `/api/policy` rejected a form payload with a server-side `400` validation error. Because the save button is a button handler rather than a native form submit, an operator could enter an out-of-range numeric value and see no field-level feedback after the server rejected it.

### Fix Made

- Added `apiErrorSummary()` in `server/public/dashboard.js` to extract sanitized server error fields from a cloned response body.
- Updated policy save handling to show `Could not save: <field>` in `#polSaved` when the server returns a validation error.
- Added Playwright coverage that enters `3651` for raw-retention days, verifies `rawRetentionDays` appears in the dashboard save status, and verifies the invalid value does not mutate policy.

### Commands Run

- `node --test --test-concurrency=1 test\validation.test.js test\dashboard-linkage.test.js` - passed after edit, 48 tests.
- `npm run test:admin-console` - failed first after the UI change because the expected `/api/policy` validation `400` was still counted as an unexpected UI problem by the shared Playwright collector.
- `npm run test:admin-console` - passed after scoping that expected validation `400`, 6 Chromium tests.
- `git diff --check` - passed with the repo's usual CRLF working-copy warnings.

### Security Review Notes

- The server remains the authority for policy validation and policy mutation.
- The new dashboard feedback displays only sanitized server field names from `server/validation.js`; it does not echo rejected form values, prompt text, secrets, or policy payload contents.

## Section 5 - Buttons, Controls, Overlays, And Interactive States

Status: Passed

### Inspection

- Reviewed dashboard tab controls, rail/content navigation, queue filters, queue density toggle, theme toggle, status popovers/tooltips, monitor chips, inspector controls, step-up dialogs, destination review dialog, and policy template/control buttons in `server/public/dashboard.js`.
- Reviewed Playwright coverage in `e2e/admin-console.spec.js` for theme persistence, popovers, tab controls, queue controls, reveal/approve dialogs, cancel paths, destination review actions, policy buttons, monitor controls, and mobile tabs.
- Reviewed static/linkage assertions in `test/admin-csrf.test.js` and `test/dashboard-linkage.test.js`.

### Issue Found

The browser suite covered successful destination review actions and cancel paths for reveal/approve dialogs, but did not lock the destination review overlay's required reason and cancel/Escape behavior before policy mutation.

### Fix Made

Updated `e2e/admin-console.spec.js` to verify:

- Blank destination review reason keeps the overlay open.
- Escape closes the destination review overlay without saving.
- Canceled destination review does not add the destination to governed, allowed, or blocked policy lists.

### Commands Run

- `npm run test:admin-console` - passed after edit, 6 Chromium tests.
- `node --test --test-concurrency=1 test\admin-csrf.test.js test\dashboard-linkage.test.js` - passed after edit, 13 tests.
- `git diff --check` - passed with the repo's usual CRLF working-copy warnings.

### Security Review Notes

- No runtime code changed in this section.
- The added browser regression proves an overlay cancel path does not mutate governed destination policy before an explicit reasoned save.

## Section 6 - Loading, Empty, Error, And Success States

Status: Passed

### Inspection

- Reviewed dashboard loading states driven by `setBusy()`, including stats, queue, activity, coverage, identity, audit, and policy panels.
- Reviewed empty states for queue clear, no queue matches, no selected incident, no activity matches, no detections, no coverage/fleet data, no shadow AI, and lineage empty tables.
- Reviewed success/error states for policy save, policy validation failure, retention purge, evidence export, monitor refresh, monitor search validation, and identity setup unavailable.
- Reviewed `e2e/admin-console.spec.js` and `test/evidence-export-ui.test.js` coverage for empty, processing, success, failure, and sanitized export behavior.

### Issue Found

The browser suite covered successful evidence export downloads, but did not lock the visible failure path for export processing, failure status, and button re-enable behavior when `/api/export/evidence` fails.

### Fix Made

Updated `e2e/admin-console.spec.js` to route `/api/export/evidence` to a delayed synthetic `500` response and verify:

- `#exportStatus` shows `PROCESSING` while the export request is in flight.
- `#exportEvidence` is disabled during the in-flight export.
- `#exportStatus` shows `Export failed` on failure.
- `#exportEvidence` is re-enabled after failure.

### Commands Run

- `npm run test:admin-console` - failed first after the section 6 test addition because the test stayed on the audit tab before clicking the policy tab's `View coverage` button.
- `npm run test:admin-console` - passed after returning to the policy tab before the existing `View coverage` assertion, 6 Chromium tests.
- `node --test --test-concurrency=1 test\evidence-export-ui.test.js` - passed after edit, 2 tests.
- `git diff --check` - passed with the repo's usual CRLF working-copy warnings.

### Security Review Notes

- No runtime code changed in this section.
- The added static export check confirms dashboard evidence export does not call reveal or raw-prompt APIs.
- The new browser failure route uses a synthetic error body and does not introduce or log sensitive prompt content.

## GitHub CI Follow-Up - Browser Extension Policy Sync

Status: Passed locally and on GitHub

### Failure Captured

- GitHub PR #54 `test` failed on heads `a638063` and `1d85101` in `npm run test:browser`.
- The blocking failure was `e2e/browser-extension.spec.js` file-drop policy coverage timing out while waiting for the content script to observe the configured `drop` browser-action rule.
- The same CI run also showed flaky extension tests where page behavior briefly reflected a different policy than the fixture policy.

### Root Cause

The browser-extension background worker refreshes `/api/v1/policy` during startup. The Playwright fixture seeded `chrome.storage.local.policy`, but the test server policy could differ from that fixture after earlier E2E policy mutations, so the startup refresh could overwrite the fixture policy before or after the content-script handshake.

The local full-browser suite also showed that admin-console and browser-extension specs can interfere when Playwright uses multiple workers, because both files share the same temp server policy and database.

### Fix Made

- Updated `e2e/browser-extension.spec.js` to sync the Playwright server's admin policy to the same fixture policy before launching each extension context.
- Added a `/api/v1/policy` verification step so the sensor policy endpoint must match the fixture before the content script is exercised.
- Compared browser-action contract fields only, because the server normalizes configured rules with `enabled: true`.
- Reset merge-persistent policy fields in the test setup so scoped rules, routing rules, response scanning, and sensor requirements cannot leak from earlier browser specs.
- Set Playwright `workers: 1` so browser E2E specs that mutate shared temp policy/database state run serially in local and CI environments.

### Commands Run

- `npm run test:browser-extension` - failed first after the policy sync addition because the assertion did not account for server-normalized `enabled: true`.
- `$env:PLAYWRIGHT_PORT='4241'; npm run test:browser-extension` - passed after comparing normalized browser-action contract fields and clearing merge-persistent policy fields, 8 Chromium tests.
- `npm run test:browser` - failed locally with admin-console setup prompts returning `destination_blocked` while extension policy sync ran in a parallel worker against the same temp server.
- `npm run test:browser` - failed once after serialization when a local Windows Playwright worker crashed and left a stale Playwright server on port `4211`; exact stale `playwright-server` and `promptwall-extension-e2e` Chromium processes were stopped.
- `$env:PLAYWRIGHT_PORT='4241'; npm run test:browser` - passed after stale harness cleanup and the fuller policy reset, 14 Chromium tests.
- `npm run review:ci` - passed after browser-suite stabilization.
- `gh pr checks 54 --watch --interval 10` - passed on head `6fccc30`, two `test` checks and two `docker` checks.

### Security Review Notes

- No runtime extension or server code changed.
- The test now drives extension policy through the same authenticated admin policy path and ingest-key protected sensor policy endpoint used by production sensors.

## Section 7 - API Integration And Data Fetching

Status: Passed

### Inspection

- Reviewed the shared dashboard `api()` wrapper, CSRF header injection, auth redirect behavior, and forbidden-session handling.
- Reviewed timeout/fallback helpers for dashboard JSON reads, including queue fallback behavior from activity data.
- Reviewed dashboard loaders for stats/seats, queue, activity, coverage, identity setup, lineage, audit, and policy/templates.
- Reviewed existing browser coverage for successful dashboard data fetches, tab refreshes, and API-driven state updates.

### Issue Found

Several dashboard loaders parsed JSON from non-OK API responses and then treated the error body as normal data. A transient failed refresh could replace loaded state with an error object or throw a page error, for example activity rows calling `.filter()` on a 500 body or policy templates calling `.map()` on an error object.

### Fix Made

- Added guarded JSON helpers for response bodies, object payloads, and array payloads.
- Updated stats, activity, coverage, identity, lineage, audit, and policy loaders to ignore non-OK or malformed responses instead of overwriting loaded dashboard state.
- Preserved the previous good activity, coverage, and policy-template UI state when refresh endpoints fail.
- Preserved the identity setup route's existing sanitized `400` error display for operator input errors.
- Added a Playwright regression that loads real dashboard data, forces synthetic activity/coverage/policy-template `500` responses, and verifies the console keeps the prior good state without uncaught page errors.

### Commands Run

- `$env:PLAYWRIGHT_PORT='4241'; npx playwright test admin-console.spec.js --grep "preserves loaded API data" --reporter=line` - passed, 1 Chromium test.
- `$env:PLAYWRIGHT_PORT='4241'; npm run test:admin-console` - passed, 7 Chromium tests.
- `node --test --test-concurrency=1 test\dashboard-linkage.test.js test\admin-csrf.test.js` - passed, 13 tests.
- `npm run review:ci` - passed after section 7 edit.

### Security Review Notes

- Runtime changes are limited to dashboard response handling for existing authenticated routes.
- Generic dashboard loaders now discard failed response bodies instead of rendering them, while identity setup still shows its existing sanitized validation errors.
- The new browser failure routes use synthetic error bodies and do not introduce or log prompt content.

## Section 8 - Backend API Behavior

Status: Passed

### Inspection

- Reviewed sensor APIs for gate, heartbeat, rehydrate, policy, detectors, scan-file, scan-response, and status polling.
- Reviewed session APIs for login, CSRF, logout, current user, queue reads, reveal, approve, deny, stats, audit, policy, evidence export, coverage, lineage, and identity setup.
- Reviewed existing auth, RBAC, CSRF, validation, release-token, evidence-export, detector, and dashboard-linkage tests.
- Checked list-style backend API parameters for status-code stability, bounded work, and consistency between reported limits and storage queries.

### Issue Found

List and export endpoints accepted raw numeric query parameters for `limit`, `queryLimit`, and `auditLimit`. Negative values were clamped by storage but still reported as negative in evidence scope, while non-finite or oversized values could either fall back inconsistently or request more rows than an operator-facing API should allow.

### Fix Made

- Added `boundedApiLimit()` in `server/app.js` and applied it to query listing, lineage, audit, and evidence export limits.
- Added a defensive `boundedLimit()` in `server/db.js` for query and audit listing callers.
- Evidence exports now report the same clamped query/audit limits they use.
- Added `test/api-limits.test.js` to exercise blank, invalid, negative, non-finite, and oversized limits across `/api/queries`, `/api/lineage`, `/api/export/evidence`, and `/api/audit`.

### Commands Run

- `node --test --test-concurrency=1 test\api-limits.test.js` - passed, 1 test.
- `node --test --test-concurrency=1 test\api-limits.test.js test\db.test.js test\dashboard-linkage.test.js test\validation.test.js` - passed, 58 tests.
- `npm run review:ci` - passed after section 8 edit.
- `gh pr checks 54 --watch --interval 10` - passed on head `1fd658c`, two `test` checks and two `docker` checks.

### Security Review Notes

- Backend list APIs now reject unbounded work by clamping hostile query limits before storage access.
- No auth, CSRF, RBAC, release-token, raw reveal, detector, or tenant-access behavior changed.
- The new test uses synthetic SSNs and confirms export scope metadata is bounded consistently without exposing raw prompt bodies.

## Section 9 - Database/Persistence/Migrations

Status: Passed

### Inspection

- Reviewed the SQLite datastore initialization in `server/db.js`, including WAL setup, local-disk fallback, table/index creation, query writes, transactional query updates, audit appends, retention purges, SCIM tables, stats, and legacy JSON migration.
- Reviewed `server/audit-integrity.js` for canonical hashing, chain verification, and query content binding.
- Reviewed `scripts/backup-store.js` for backup, verify, restore, overwrite protection, manifest integrity, manifest contents, and audit-chain gating.
- Reviewed focused datastore, retention, backup, and evidence-pack tests.

### Coverage Gaps Found

- The one-time legacy JSON to SQLite migration had no regression test. That left the default auto-import path, `.migrated` file handoff, audit re-anchoring, and explicit `SENTINEL_DB_PATH` opt-out behavior unpinned.
- Backup verification covered valid manifests, but not adjacent manifest hash mismatches blocking restore.

### Fix Made

- Added `test/db-migration.test.js`.
- The new test copies the DB runtime into a temp mini-runtime so migration uses temp `data/` files and never touches the repo's real local `data/sentinel.db`.
- Covered default legacy query/audit import, audit-chain verification after re-anchoring, `.migrated` renames, and the explicit SQLite path opt-out.
- Updated `test/backup-store.test.js` to tamper the adjacent manifest hash, verify `manifestOk: false`, and assert restore refuses the mismatched evidence.

### Commands Run

- `node --test --test-concurrency=1 test\db.test.js test\backup-store.test.js test\retention.test.js test\evidence-pack.test.js test\evidence.test.js` - passed before backup-manifest edit, 29 tests.
- `node --test --test-concurrency=1 test\db-migration.test.js` - passed, 2 tests.
- `node --test --test-concurrency=1 test\db-migration.test.js test\db.test.js test\backup-store.test.js test\retention.test.js test\evidence-pack.test.js` - passed after backup-manifest edit, 24 tests.
- `node --test --test-concurrency=1 test\db.test.js test\db-migration.test.js test\backup-store.test.js test\retention.test.js test\evidence-pack.test.js test\evidence.test.js test\policy-history.test.js test\preflight.test.js test\env.test.js` - passed before backup-manifest edit, 74 tests.
- `node --test --test-concurrency=1 test\backup-store.test.js` - passed after backup-manifest edit, 6 tests.
- `node --test --test-concurrency=1 test\db.test.js test\db-migration.test.js test\backup-store.test.js test\retention.test.js test\evidence-pack.test.js test\evidence.test.js test\policy-history.test.js test\preflight.test.js test\env.test.js` - passed after backup-manifest edit, 75 tests.
- `npm run review:ci` - passed after section 9 edit.

### Security Review Notes

- Runtime persistence code was not changed in this section.
- The new migration test uses synthetic prompt data and verifies the migration path in a temp runtime rather than the ignored local runtime database.
- The backup-manifest tamper test uses temp SQLite backups and synthetic rows; no production data, real secrets, or repo `data/` files are touched.
- Backup, restore, retention, audit-chain, and evidence-pack tests continued to pass with the migration coverage included.

## Section 10 - State Management And Cache

Status: Passed

### Inspection

- Reviewed dashboard in-memory state for selected queue item, activity cache, coverage cache, lineage cache, identity setup cache, queue filters, queue density, theme persistence, revealed prompt pruning, SSE refresh handlers, and failed-refresh fallbacks.
- Reviewed browser-extension cached policy and enabled state in background, content, popup, storage-change listeners, policy refresh, popup toggle persistence, shadow-AI throttle state, and clean-upload bypass cache.
- Reviewed existing admin-console and browser-extension Playwright coverage for theme persistence, queue density, API refresh failures, popup toggle storage, and content-script policy sync.

### Issue Found

`pendingQueueRows()` used stale `currentActivity` as the first fallback when `/api/queries?status=pending` failed. After an approval or denial, a transient pending-queue refresh failure could repopulate the approval queue from the old activity cache before trying a fresh activity query.

### Fix Made

- Reordered `pendingQueueRows()` so it tries the direct pending query, then a fresh bounded activity query, and only then falls back to the in-memory activity cache.
- Added Playwright coverage that approves a held prompt while the pending refresh endpoint returns a synthetic `500`, then verifies the decided row stays out of the queue and the activity row shows the approved state.
- Added extension unit coverage proving policy refresh preserves cached policy when protection is disabled or the control plane fails, and merges server policy with defaults on success.

### Commands Run

- `node --test --test-concurrency=1 test\extension.test.js` - failed first because the new VM-backed assertion compared cross-realm arrays.
- `node --test --test-concurrency=1 test\extension.test.js` - passed after normalizing cross-realm arrays, 31 tests.
- `node --test --test-concurrency=1 test\extension.test.js test\dashboard-linkage.test.js test\policy-scope.test.js test\policy-history.test.js` - passed after section 10 edit, 49 tests.
- `$env:PLAYWRIGHT_PORT='4241'; npx playwright test admin-console.spec.js --grep "avoids stale queue cache" --reporter=line` - failed before tests because a stale local Playwright harness still held the port.
- `$env:PLAYWRIGHT_PORT='4257'; npx playwright test admin-console.spec.js --grep "avoids stale queue cache" --reporter=line` - passed, 1 Chromium test.
- `node --test --test-concurrency=1 test\dashboard-linkage.test.js test\admin-csrf.test.js` - passed after section 10 dashboard edit, 13 tests.
- `$env:PLAYWRIGHT_PORT='4257'; npm run test:admin-console` - failed while tightening the new regression selector and target-specific queue assertion.
- `$env:PLAYWRIGHT_PORT='4257'; npm run test:admin-console` - passed after the selector/assertion fixes, 8 Chromium tests.
- `$env:PLAYWRIGHT_PORT='4258'; npm run test:browser-extension` - passed after section 10 edit, 8 Chromium tests.
- `npm run review:ci` - failed first after section 10 edit at the admin-console step because the default local Playwright health URL on port `4211` was still in use; listener inspection showed only `TIME_WAIT` sockets afterward.
- `npm run review:ci` - passed on rerun after the port cleared, including 78 node test files, 8 admin-console Chromium tests, `sync-check`, and `eval`.

### Security Review Notes

- Dashboard fallback behavior now avoids resurrecting stale approval-queue state after a decision.
- Extension cache tests use synthetic policy data and do not send secrets or prompt bodies.
- No auth, CSRF, raw reveal, evidence export, detector, or persistence behavior changed in this section.

## Section 11 - Tables, Search, Filters, And Pagination

Status: Passed

### Inspection

- Reviewed approval queue metadata filters, global search, activity rows, lineage aggregate tables, audit log rows, monitor search, table pagination, and backend list/audit/evidence limit handling.
- Existing backend API coverage already clamps hostile list limits before storage access, and queue, activity, lineage, and monitor surfaces already had search or metadata filtering.
- Found that the audit log table loaded `/api/audit` entries but did not apply the dashboard global search term.
- Found that long activity, lineage, and audit tables did not expose operator paging controls even though their APIs return bounded recent rows.

### Issue Found

Global search rerendered the approval queue, activity table, and lineage tables, but not audit rows. On the Audit Log tab, searching for a query ID or actor left unrelated audit entries visible. Long activity, lineage, and audit result sets also rendered as one uninterrupted table.

### Fix Made

- Added cached audit entry state plus `auditText`, `matchesAudit`, and `renderAuditRows`.
- Updated `updateSearch()` to rerender audit rows from cache and show a clear empty state when no audit entry matches.
- Added shared client-side paging helpers for activity, lineage, and audit tables, with page reset when global search changes.
- Added pager containers and table-linkage coverage for activity, lineage, and audit surfaces.
- Added static and Playwright coverage proving global search filters one audit query ID while hiding another and that searchable tables page correctly.

### Commands Run

- `node --check server\public\dashboard.js` - passed after section 11 edit.
- `node --test --test-concurrency=1 test\dashboard-linkage.test.js test\coverage.test.js` - passed after section 11 edit, 12 tests.
- `$env:PLAYWRIGHT_PORT='4261'; npx playwright test admin-console.spec.js --grep "paginates searchable activity" --reporter=line` - passed after section 11 edit, 1 Chromium test.
- `$env:PLAYWRIGHT_PORT='4262'; npm run test:admin-console` - passed after section 11 edit, 10 Chromium tests.
- `node --test --test-concurrency=1 test\admin-csrf.test.js test\dashboard-linkage.test.js` - passed after section 11 edit, 15 tests.
- `git diff --check` - passed with the repo's usual CRLF working-copy warnings.
- `npm run review:ci` - passed after section 11 edit, including 78 node test files, 10 admin-console Chromium tests, `sync-check`, and `eval`.

### Security Review Notes

- Audit filtering is client-side over already-loaded sanitized audit rows visible to the authenticated dashboard session.
- Table pagination is client-side over already-loaded sanitized dashboard rows.
- The change does not call reveal/raw-prompt APIs and does not change auth, CSRF, RBAC, evidence export, detector, or persistence behavior.

## Section 12 - File/Media Flows If Present

Status: Passed

### Inspection

- Reviewed browser-extension file drop and file selection interception, local text-readable upload scanning, OCR-required handling, unsupported/oversized file blocks, clean-upload bypass, and file-upload destination policy blocks.
- Reviewed direct `/api/v1/scan-file` extraction paths for text, Office, PDF, image/OCR-needed, unsupported, unreadable, redact, pending, and allow outcomes.
- Reviewed endpoint-agent watched-file, endpoint-local OCR, signed native handoff, protected-upload, and redacted companion flows.
- Reviewed MCP guard and Microsoft 365 connector file-content sanitization, bounded content fetching, timeout, and least-privileged scope coverage.

### Issue Found

The direct `/api/v1/scan-file` route sanitized prompt/file content, and browser/endpoint sensors avoided raw filenames, but direct API filenames were still copied into response bodies, stored query fields, redacted previews, raw-retained prefixes, and audit details after file inspection started. A filename containing an SSN or other regulated identifier could therefore appear in dashboard/audit evidence even when file bytes were otherwise sanitized or redacted.

### Fix Made

- Added server-side `safeFileLabel()` handling for direct scan-file requests.
- Kept the original submitted filename only for processor selection, while using the sanitized label in response `filename`, stored query `filename`, redacted previews, raw-retained file prefixes, tokenized prompts, and audit details.
- Added validation coverage for a sensitive Windows-path text filename and a sensitive OCR-needed image filename, proving response bodies, stored query rows, and audit entries omit both the raw filename and embedded SSN.

### Commands Run

- `node --check server\app.js` - passed after section 12 edit.
- `node --test --test-concurrency=1 test\processors.test.js` - passed after section 12 edit, 9 tests.
- `node --test --test-concurrency=1 test\validation.test.js test\endpoint-agent.test.js test\endpoint-ocr.test.js test\native-handoff.test.js test\native-handoff-writer.test.js test\mcp-guard.test.js test\mcp-connector-sdk.test.js test\mcp-microsoft365-connector.test.js` - passed after section 12 edit, 106 tests.
- `node --test --test-concurrency=1 test\extension.test.js` - passed after section 12 edit, 31 tests.
- `$env:PLAYWRIGHT_PORT='4264'; npm run test:browser-extension` - passed after section 12 edit, 8 Chromium tests.
- `git diff --check` - passed after section 12 edit with the repo's usual CRLF working-copy warnings.
- `node --test --test-concurrency=1 test\processors.test.js test\validation.test.js` - passed after duplicate-test cleanup, 56 tests.
- `npm run review:ci` - passed after section 12 edit, including 78 node test files, 10 admin-console Chromium tests, `sync-check`, and `eval`.
- `$env:PLAYWRIGHT_PORT='4265'; npm run review:ci` - passed after section 12 edit, including docs demo guide check, AI domain coverage check, 78 node test files, 10 admin-console Chromium tests, `sync-check`, and `eval`.

### Security Review Notes

- Direct scan-file requests still decode uploaded file content only after ingest auth, tenant enforcement, destination policy checks, and size checks.
- The fix reduces data retained in response, dashboard, and audit evidence by replacing sensitive filenames with `[sensitive filename]`.
- Original filenames are still used transiently inside the request handler to select the extraction processor; they are not intentionally stored or broadcast after this change.
- Browser, endpoint, native handoff, MCP, and OCR flows continue to avoid sending file bytes or raw local filenames through sanitized evidence paths covered by the focused tests.

## Section 13 - Payments/Billing If Present

Status: Passed

### Inspection

- Searched source, docs, config, and tests for payment-provider, checkout, invoice, subscription, pricing, license, quota, and seat-limit surfaces.
- Confirmed there is no Stripe, checkout, card-payment, invoice, webhook, or subscription-provider integration in this codebase.
- Reviewed the billing-adjacent paid customer surface: SaaS/customer-silo tenant config, `SENTINEL_SEAT_LIMIT` / `PROMPTWALL_SEAT_LIMIT`, `/api/billing/seats`, dashboard seat KPI rendering, preflight checks, deployment docs, and seat-limit enforcement on sensor ingest routes.
- Reviewed `test/tenant.test.js`, `test/saas-tenancy.test.js`, `test/preflight.test.js`, `test/db.test.js`, `test/dashboard-linkage.test.js`, and deployment coverage for seat reporting and paid-seat blocking.
- Browser-checked the admin stats card state for malformed SaaS seat-limit configuration.

### Issue Found

Production preflight already rejects missing or invalid SaaS seat limits, but runtime tenant parsing converted missing, non-numeric, fractional, zero, and negative `SENTINEL_SEAT_LIMIT` values to `0`. If a paid customer stack started despite failed preflight, sensor ingest could silently run without paid-seat enforcement.

### Fix Made

- Added explicit seat-limit presence and validity tracking in `server/tenant.js`.
- Aligned runtime validity with preflight: SaaS mode now requires a positive integer paid-seat limit.
- Updated sensor access validation to fail closed with `seat_limit_not_configured` and `503` when SaaS billing configuration is missing or invalid.
- Updated the dashboard seat stat to show `Seat config / Invalid` when `/api/billing/seats` reports malformed paid-seat configuration.
- Added tenant, dashboard linkage, and browser coverage for missing, zero, negative, fractional, and non-numeric seat limits, plus seat-report validity state.
- Stabilized the full browser secondary-controls export-failure path by restoring policy mode after template checks and holding the mocked export response until the disabled state is asserted.

### Commands Run

- `node --check server\tenant.js` - passed after section 13 edit.
- `node --check server\public\dashboard.js` - passed after section 13 edit.
- `node --test --test-concurrency=1 test\tenant.test.js test\saas-tenancy.test.js test\preflight.test.js test\setup.test.js test\dashboard-linkage.test.js test\db.test.js` - passed after section 13 edit, 52 tests.
- `$env:PLAYWRIGHT_PORT='4267'; npx playwright test admin-console.spec.js --grep "invalid SaaS seat-limit" --reporter=line` - passed after section 13 edit, 1 Chromium test.
- `$env:PLAYWRIGHT_PORT='4268'; npm run review:ci` - passed after section 13 edit, including docs demo guide check, AI domain coverage check, 78 node test files, 11 admin-console Chromium tests, `sync-check`, and `eval`.
- `node --check e2e\admin-console.spec.js` - passed after GitHub browser-test failure reproduction fix.
- `$env:PLAYWRIGHT_PORT='4268'; npx playwright test admin-console.spec.js --grep "secondary controls" --reporter=line` - passed after GitHub browser-test failure reproduction fix, 1 Chromium test.
- `$env:PLAYWRIGHT_PORT='4269'; $env:CI='1'; npx playwright test admin-console.spec.js --grep "secondary controls" --reporter=line` - passed after GitHub browser-test failure reproduction fix, 1 Chromium test with retry behavior enabled.
- `$env:PLAYWRIGHT_PORT='4271'; npm run test:browser` - passed after GitHub browser-test failure reproduction fix, 19 Chromium tests.
- `npm run review:ci` - passed after GitHub browser-test failure reproduction fix, including docs demo guide check, AI domain coverage check, 78 node test files, 11 admin-console Chromium tests, `sync-check`, and `eval`.

### Security Review Notes

- This section adds no payment provider, card data, billing webhook, checkout, or external billing network path.
- Runtime paid-seat enforcement now fails closed when billing configuration is malformed instead of silently disabling seat limits.
- Invalid seat-limit dashboard rendering uses aggregate billing config state only and does not expose billable user lists in the stat card.
- No auth, CSRF, RBAC, raw reveal, evidence export, detector, or persistence schema behavior changed in this section.

## Section 14 - Admin/RBAC If Present

Status: Passed

### Inspection

- Reviewed the Security Admin, approver, auditor, and operator role surfaces in `server/auth.js`, `server/roles.js`, `server/app.js`, `server/oidc.js`, `server/scim.js`, and `server/public/dashboard.js`.
- Rechecked dashboard role gating for decision controls, raw reveal, policy edits, retention purge, destination review, read-only policy rendering, queue filters, and billing stats.
- Reviewed SCIM/OIDC username mapping and approval-routing docs for `assignedUser` ownership semantics.
- Reviewed existing role coverage in `test/auth.test.js`, `test/admin-mfa.test.js`, `test/admin-csrf.test.js`, `test/approver-role.test.js`, `test/auditor-role.test.js`, `test/approval-stepup.test.js`, `test/reveal-stepup.test.js`, `test/oidc-login.test.js`, and `test/scim.test.js`.

### Issues Found

1. `/api/billing/seats` returned the paid-seat report, including billable user identities, to any authenticated dashboard role. Approver and auditor sessions need sanitized evidence review, not tenant billing rosters.
2. Approval ownership compared `assignedUser` with the session user by exact string. SCIM lookup and OIDC login already treat provisioned usernames case-insensitively, so a casing or whitespace mismatch could block a legitimate approver from deciding an item explicitly assigned to them.

### Fix Made

- Added an `adminRead` middleware and restricted `/api/billing/seats` to Security Admin sessions.
- Updated the dashboard stats loader to fetch billing-seat data only when the current role can perform admin writes, avoiding a guaranteed 403 for read-only sessions.
- Normalized assigned-user principal comparison in `roles.canDecideQuery()` and the dashboard `canDecide()` / `mine` queue filter.
- Added `test/roles.test.js` for normalized approver ownership and non-decider role checks.
- Extended approver and auditor role tests to prove `/api/billing/seats` is forbidden to non-admin roles, still available to Security Admins, and that mixed-case assigned-user ownership can still be approved.
- Extended static dashboard checks to keep the normalized principal gate and admin-only billing fetch wired.

### Commands Run

- `node --check server\roles.js` - passed after section 14 edit.
- `node --check server\app.js` - passed after section 14 edit.
- `node --check server\public\dashboard.js` - passed after section 14 edit.
- `node --test --test-concurrency=1 test\roles.test.js test\approver-role.test.js test\auditor-role.test.js test\auth.test.js test\admin-mfa.test.js test\approval-stepup.test.js test\reveal-stepup.test.js test\oidc-login.test.js test\scim.test.js test\admin-csrf.test.js` - passed after section 14 edit, 38 tests.
- `$env:PLAYWRIGHT_PORT='4272'; npm run test:admin-console` - passed after section 14 edit, 11 Chromium tests.
- `npm run review:ci` - passed after section 14 edit, including docs demo guide check, AI domain coverage check, 79 node test files, 11 admin-console Chromium tests, `sync-check`, and `eval`.

### Security Review Notes

- Seat reports include billable user identities and SaaS capacity state, so they are now Security Admin-only.
- The assigned-user normalization does not broaden role access: the request still requires an authenticated approver, `assignedRole: "approver"`, and matching normalized principal, or a Security Admin.
- Approvers and auditors continue to read sanitized evidence and remain blocked from raw reveal, retention purge, policy mutation, destination review, and unassigned security-admin decisions.

## Section 15 - Accessibility

Status: Passed

### Inspection

- Reviewed login, dashboard alert, step-up dialog, destination review dialog, browser-extension banner, queue filter, approval queue, selected incident, activity row, status-chip, and Signal Monitor keyboard/accessibility semantics.
- Confirmed existing coverage already exercised active content-tab `aria-current`, reduced-motion pulse behavior, status-chip keyboard activation, activity-row keyboard expansion, Signal Monitor listbox rows, invalid monitor-search `aria-invalid`, and modal Escape/cancel paths.
- Focused on approval queue and authentication feedback surfaces because they are high-frequency operator workflows and carry state that must be announced without relying on visual styling.

### Issues Found

1. Login and dashboard error feedback rendered visually but did not consistently expose an alert/live-region contract or mark the invalid login fields.
2. Step-up and destination-review `<dialog>` elements had visible headings/descriptions but no explicit `aria-labelledby` / `aria-describedby` wiring.
3. Queue filter buttons used visual active state without synchronized `aria-pressed`.
4. Approval queue rows were keyboard-selectable but exposed only as generic focusable articles, so the selected row and controlled incident-detail region were not announced clearly.
5. Browser-extension block/warn/justify banners interrupted page sends but did not expose an alertdialog contract, initial focus, or invalid state on the required business-reason textbox.

### Fix Made

- Added live alert semantics to login errors and the dashboard banner.
- Added `aria-describedby` on login inputs and `aria-invalid` updates for invalid credential, MFA-required, and cleared-error states.
- Added generated dialog heading/description ids and explicit ARIA wiring for password step-up and destination review dialogs.
- Synchronized approval queue filter `aria-pressed` with the active filter state.
- Exposed approval queue rows as list items with accessible row labels, `aria-current` on the selected row, and `aria-controls="incidentDetail"`.
- Exposed the selected incident detail pane as a polite live region.
- Added browser-extension banner `alertdialog` semantics, title/detail relationships, initial focus, an accessible business-reason textbox, and `aria-invalid` feedback for short justifications.
- Added browser coverage for login error announcements, keyboard selection of approval queue rows, and extension banner accessibility.

### Commands Run

- `node --check server\public\login.js` - passed after section 15 edit.
- `node --check server\public\dashboard.js` - passed after section 15 edit.
- `node --check sensors\browser-extension\content.js` - passed after section 15 edit.
- `node --check e2e\admin-console.spec.js` - passed after section 15 edit.
- `node --check e2e\browser-extension.spec.js` - passed after section 15 edit.
- `node --test --test-concurrency=1 test\admin-csrf.test.js test\dashboard-linkage.test.js` - passed after section 15 edit, 18 tests.
- `node --test --test-concurrency=1 test\extension.test.js` - passed after section 15 edit, 31 tests.
- `$env:PLAYWRIGHT_PORT='4274'; npx playwright test admin-console.spec.js --grep "login form announces|controls and forms" --reporter=line` - passed after section 15 edit, 2 Chromium tests.
- `$env:PLAYWRIGHT_PORT='4277'; npm run test:browser-extension` - passed after section 15 edit, 8 Chromium tests.
- `$env:PLAYWRIGHT_PORT='4278'; npm run review:ci` - passed after section 15 edit, including docs demo guide check, AI domain coverage check, 79 node test files, 12 admin-console Chromium tests, `sync-check`, and `eval`.

### Security Review Notes

- Section 15 changes UI accessibility semantics and client-side invalid-field state only.
- Login error text remains generic and does not reveal whether a username, password, or MFA secret exists.
- Dialog ARIA wiring does not change step-up auth, CSRF, RBAC, raw reveal, destination review, detector, evidence export, or persistence behavior.
- Approval queue accessibility labels are built from already-rendered sanitized row metadata and do not expose raw prompts or hidden billing/user rosters.
- Extension banner labels and descriptions are built from already-sanitized detector labels and coaching guidance, not raw prompt text.

## Section Queue

1. Baseline install/lint/typecheck/build/test discovery - passed.
2. Navigation and routing - passed.
3. Authentication and authorization - passed.
4. Forms and validation - passed.
5. Buttons, controls, overlays, and interactive states - passed.
6. Loading, empty, error, and success states - passed.
7. API integration and data fetching - passed.
8. Backend API behavior - passed.
9. Database/persistence/migrations if present - passed.
10. State management and cache - passed.
11. Tables, search, filters, and pagination - passed.
12. File/media flows if present - passed.
13. Payments/billing if present - passed.
14. Admin/RBAC if present - passed.
15. Accessibility - passed.
16. Responsive/cross-browser behavior - pending.
17. Motion/effects/reduced-motion behavior - pending.
18. Performance and bundle health - pending.
19. Security and privacy - pending.
20. Analytics/observability if present - pending.
21. CI/CD and release readiness - pending.
22. Final e2e regression - pending.
