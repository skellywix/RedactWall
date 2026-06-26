# PromptSentinel Production Loop Status

## Open

- None selected. Next pass should pick the highest-impact production-readiness gap.

## Done

- 2026-06-26: Scoped approval-status polling with per-query release tokens: held prompt and file responses now return a release token, the server stores only its hash, `/api/v1/status/:id` requires the matching token for held rows, and the reference proxy bridge forwards it while polling.
  Evidence: `node --test test/release-token.test.js test/squid-icap-bridge.test.js test/approval-stepup.test.js test/validation.test.js`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added a production preflight blocker for unsafe SQLite evidence-store paths: missing, cloud-synced, or UNC/network `SENTINEL_DB_PATH` values now fail production readiness while local demo mode keeps running with warnings.
  Evidence: `node --test test/preflight.test.js test/setup.test.js test/server-integration.test.js`, `npm test`, `npm run test:browser`, `npm run setup:check`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added sanitized SIEM alerts for sensor version posture gaps: mixed or missing browser/endpoint/MCP sensor versions now emit forced `SENSOR_VERSION_GAP` webhook events with bounded source/version/platform metadata, while API/proxy traffic is excluded.
  Evidence: `node --test test/validation.test.js test/alerts.test.js test/coverage.test.js`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added sensor version posture across the control plane: browser extension, endpoint agent, and MCP guard now send bounded name/version/platform metadata; ingest validation stores it safely; the Coverage tab summarizes latest and mixed sensor versions without prompt bodies.
  Evidence: `node --test test/coverage.test.js test/validation.test.js test/extension.test.js test/endpoint-agent.test.js test/mcp-guard.test.js test/alerts.test.js test/evidence.test.js`, `npm test`, `npm run test:browser`, `npm run package:extension -- <temp>`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added repeatable Chrome extension packaging for managed pilots: `npm run package:extension` writes a zip plus SHA-256 manifest, verifies Manifest V3 wiring, synced engine copies, managed-storage schema coverage, and refuses packaged development ingest keys. The extension now fails closed until local or managed storage supplies the ingest key.
  Evidence: `npm run package:extension -- <temp>`, `node --test test/extension-package.test.js test/extension.test.js test/managed-extension-docs.test.js`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Tightened the dashboard blocked-today metric so it counts only held or blocked statuses, not audit-only paste warnings, shadow-AI sightings, warnings, justifications, or successful redactions.
  Evidence: `node --test test/db.test.js`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Closed the browser paste-audit gap: `paste_flagged` reports from the extension now pass API validation, create audit-only `PASTE_FLAGGED` evidence with masked findings, avoid raw prompt retention, and show as warning activity in the admin dashboard instead of disappearing as rejected sensor traffic.
  Evidence: focused syntax checks, `node --test test/validation.test.js test/extension.test.js test/alerts.test.js`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added sanitized SIEM/webhook alerts for failed and locked admin step-up confirmations: reveal and approval failures now force best-effort admin security alerts with actor/scope metadata while omitting prompt bodies, raw retained prompts, token vaults, and raw finding values.
  Evidence: `node --test test/alerts.test.js test/approval-stepup.test.js test/reveal-stepup.test.js test/admin-csrf.test.js`, `npm test`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added password step-up for approval release: approving a held prompt now requires admin password confirmation in the dashboard and API, failed confirmations are audit-logged without releasing content, repeated failures lock out the release path, and browser E2E covers the approval dialog.
  Evidence: `node --test test/approval-stepup.test.js test/reveal-stepup.test.js test/retention.test.js test/admin-csrf.test.js test/validation.test.js`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added password step-up for raw prompt reveal: the dashboard now collects a masked admin password before reveal, the API validates it with lockout-backed auth, failed confirmations are audit-logged without prompt leakage, and successful raw reveals remain explicit audit events.
  Evidence: `node --test test/reveal-stepup.test.js test/retention.test.js test/admin-csrf.test.js test/auth.test.js test/validation.test.js`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added verifier-first backup/restore tooling for the SQLite evidence store: `npm run backup`, `npm run backup:verify`, and `npm run backup:restore` create prompt-free manifests, verify audit-chain integrity on backup files, and refuse unsafe overwrites unless explicitly forced.
  Evidence: `node --test test/backup-store.test.js test/db.test.js`, `npm test`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `npm run backup -- <temp>`, `npm run backup:verify -- <backup.db>`, `npm run backup:restore -- <backup.db> <temp/restored.db>`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added policy-backed retained-data disposal for finalized approval/redact records: `rawRetentionDays` now drives audited purging of sealed raw prompts and token vaults, reveal falls back to safe redacted text after purge, evidence exports show purge metadata without prompt bodies, and the admin policy form exposes the retention window.
  Evidence: `node --test test/db.test.js test/retention.test.js test/policy-history.test.js test/admin-csrf.test.js test/validation.test.js`, `node --test test/evidence.test.js`, `npm test`, `PLAYWRIGHT_PORT=4310 npm run test:browser`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Sanitized semantic-category previews so held prompts, scanned files, and flagged AI responses store whole-chunk `[REDACTED: ...]` evidence instead of retaining confidential business context with only structured values masked.
  Evidence: `node --test test/redact-policy.test.js test/processors.test.js test/evidence.test.js`, `npm test`, `PLAYWRIGHT_PORT=4310 npm run test:browser`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added a Windows endpoint-agent scheduled-task install path for pilots: per-user logon task, restart-on-failure settings, least-privilege interactive principal, restricted local config, `SENTINEL_ENV_PATH` loading, uninstall support, and client-demo docs.
  Evidence: `node --test test/env.test.js test/endpoint-agent.test.js test/endpoint-agent-install.test.js`, PowerShell parser checks for endpoint install/run/uninstall scripts, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm run setup:check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Closed the mixed-content redact-mode leak path: prompt and file flows now tokenize only structured-only findings, hold semantic or mixed semantic+structured content for Security Admin review, and preserve MCP whole-chunk redaction telemetry as redacted.
  Evidence: `node --test test/redact-policy.test.js test/processors.test.js test/extension.test.js test/mcp-guard.test.js`, `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Aligned `/api/v1/scan-file` with redact-mode policy for structured file findings: supported file uploads now return a tokenized safe prompt plus sealed rehydrate vault, while category-only file hits remain held for Security Admin review.
  Evidence: `node --test test/processors.test.js`, `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Hardened sensor/admin validation so client-reported redaction evidence and policy detector lists can only reference detector IDs published by the shared engine, preventing invented labels from polluting policy decisions or examiner evidence.
  Evidence: `node --test test/validation.test.js`, `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added repeatable deployment setup tooling: `.env` loading, generated setup/preflight scripts, Docker Compose path, deployment docs, and tests that keep copied example credentials flagged as unsafe.
  Evidence: `node --test test/env.test.js test/setup.test.js test/auth.test.js test/preflight.test.js`, `npm run setup:check`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Bounded MCP guard control-plane requests so policy refresh and best-effort audit logging cannot stall redacted tool output delivery when the control plane is slow or unavailable.
  Evidence: `node --test test/mcp-guard.test.js`, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Published full sensor policy from `/api/v1/policy` and made browser local analysis honor centralized detector `ignore` and `disabledDetectors` settings, aligning browser, endpoint, MCP, and server policy behavior.
  Evidence: `node --test test/extension.test.js`, `node --test test/validation.test.js`, live temp-server sensor-policy smoke through endpoint and MCP refresh, `npm test`, `npm run test:browser`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Hardened the browser extension control-plane path with bounded background-worker requests, fail-closed gate/file-scan outage verdicts, and warn/justify resend logic that waits for a recorded server decision before allowing a sensitive prompt to proceed.
  Evidence: `node --test test/extension.test.js`, live temp-server extension background smoke, `npm run test:browser`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added an AI coverage posture dashboard and protected `/api/coverage` summary so admins can see governed AI destinations, sensor mix, shadow-AI sightings, and coverage score without exposing prompt bodies.
  Evidence: `node --test test/coverage.test.js`, `npm run test:browser`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Hardened the reference Squid/ICAP bridge with bounded control-plane requests, explicit fail-closed gate verdicts, and fail-closed release polling for API/proxy enforcement.
  Evidence: `node --test test/squid-icap-bridge.test.js`, live temp-DB proxy bridge smoke through `/api/v1/gate`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Updated GitHub Actions workflow dependencies to maintained current major lines for checkout, setup-node, and artifact upload after CI reported Node 20 action deprecation warnings.
  Evidence: upstream release tags verified through GitHub API; `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Hardened the endpoint agent to fail closed when supported-file scans or policy refreshes stall or return unusable control-plane responses. Scan outages now block locally and can be recorded as sanitized `scan_unavailable` unscanned-file events.
  Evidence: `node --test test/endpoint-agent.test.js`, `node --test test/validation.test.js`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added permanent Playwright coverage for the mobile admin console layout so CI verifies collapsed rail tabs, usable content tabs, and no page-level horizontal overflow.
  Evidence: `npm run test:browser`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Made the MCP guard detection path policy-aware so tool-output redaction honors centralized `ignore` and `disabledDetectors` settings before reporting sanitized evidence.
  Evidence: `node --test test/mcp-guard.test.js`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Improved mobile admin-console layout by hiding duplicated side-rail tabs under narrow viewports while keeping content tabs reachable and preventing horizontal page overflow.
  Evidence: `npm run test:browser`, mobile Playwright smoke at 390x844 viewport; earlier same-worktree gate passed `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, and `verifyAuditChain()`.
- 2026-06-26: Synced the endpoint agent with centralized scanner policy from `/api/v1/policy`, including managed ignore directories, filenames, extensions, and max file size enforcement.
  Evidence: `node --test test/endpoint-agent.test.js`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Polished the redesigned admin console tab rails by hiding native scrollbars while preserving horizontal scrolling for dense operations layouts.
  Evidence: `npm run test:browser`; earlier same-worktree gate for this UI delta also passed `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, and `verifyAuditChain()`.
- 2026-06-26: Hardened MCP guard telemetry so locally redacted tool output reports masked client findings/categories to the control plane while keeping raw tool content out of the logged prompt body.
  Evidence: `node --test test/mcp-guard.test.js`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, live temp-DB client-redacted ingest smoke, `verifyAuditChain()`.
- 2026-06-26: Verified and adopted the redesigned admin console UI: denser operations layout, redesigned login surface, selected-incident detail panel, icon command buttons, and functional global search across queue/activity data.
  Evidence: `npm run test:browser`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Upgraded GitHub Actions CI so branch pushes under `codex/**` run the production gate: dependency audit, sync-check, Node tests, Playwright browser E2E, audit-chain verification, detection eval, semantic determinism, config drift check, and Docker build.
  Evidence: local non-Docker CI-equivalent commands passed; Docker build remains enforced in GitHub Actions because the local Docker daemon was unavailable.
- 2026-06-26: Added Playwright browser E2E coverage for the admin console login, pending prompt approval, policy save, audit integrity display, and sanitized evidence export. The E2E server uses temp DB and policy files so tests do not mutate demo config.
  Evidence: `npm run test:browser`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Hardened sensor ingest authentication with constant-time API-key comparison and a bounded invalid-key throttle that still lets a correct key through from the same client.
  Evidence: `node --test test/ingest-auth.test.js`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, live HTTP ingest auth smoke, `verifyAuditChain()`.
- 2026-06-26: Added fail-closed file extraction guardrails: corrupt supported files and extraction timeouts are recorded as blocked unscanned files, extracted text is bounded before detection, and browser/endpoint clients surface unreadable files as blocked.
  Evidence: `node --test test/processors.test.js`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, live HTTP file extraction smoke, `verifyAuditChain()`.
- 2026-06-26: Added Zod request-body validation for sensor ingest, file scanning, response scanning, login, approval notes, template application, and policy updates. Validation responses name fields only, malformed JSON returns sanitized JSON, bad base64 is rejected before decoding, and unknown policy keys fail closed.
  Evidence: `node --test test/validation.test.js`, `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, live HTTP validation smoke, `verifyAuditChain()`.
- 2026-06-26: Reviewed the app stack, upgraded Express 4 to Express 5, added Helmet-managed security headers, externalized admin/login JavaScript for stricter CSP, added frontend CSP regression tests, and documented stack decisions in `STACK_REVIEW.md`.
  Evidence: `npm test`, `npm run sync-check`, `npm audit --omit=dev`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added a `npm run fire-drill` canary-control script that sends a synthetic tripwire prompt through the gate API and fails if `CANARY_TOKEN` is missed or the raw canary leaks in the response.
  Evidence: `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added deployment preflight checks for default admin credentials, dev ingest key, session secret source, raw-prompt encryption readiness, and secure cookies; wired checks into production startup, `/readyz`, and `/api/preflight`.
  Evidence: `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Refactored server startup behind a `require.main` guard and added real HTTP integration tests for health, readiness, and security headers on an ephemeral port.
  Evidence: `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added structured policy-change diffs for manual and template policy updates, and exposed parsed allowlisted policy changes in evidence exports while keeping general audit detail text hashed.
  Evidence: `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added an admin dashboard evidence export button that downloads the sanitized examiner pack from `/api/export/evidence`, plus static UI tests to keep it away from raw-prompt APIs.
  Evidence: `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added managed Chrome extension deployment guide, force-install policy example, managed storage policy example, and schema-alignment tests for pilot deployment docs.
  Evidence: `npm test`, `npm run sync-check`, `git diff --check`, `verifyAuditChain()`.
- 2026-06-26: Added planted canary token detector, policy/template hard-stop defaults, extension default policy support, full masking, docs, and false-positive counterexamples.
  Evidence: `npm test`, `npm run sync-check`, `npm run eval`, `verifyAuditChain()`.
- 2026-06-26: Added session-protected examiner evidence export with policy, stats, audit integrity, detector inventory, query metadata, masked findings, prompt hashes, and audit hashes. Prompt bodies and audit detail text are omitted.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Added optional sanitized SIEM/webhook alerts for high-risk events; payloads omit raw prompt text, redacted prompt body, token vaults, and raw finding values.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Added baseline production HTTP security headers, disabled Express fingerprinting, and tightened admin session cookie attributes.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Added signed CSRF tokens for admin unsafe actions; dashboard fetch wrapper sends `x-csrf-token`; tests cover token binding and route wiring.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Created durable production loop plan and status files.
