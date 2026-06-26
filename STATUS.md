# PromptSentinel Production Loop Status

## Open

- None selected. Next pass should pick the highest-impact production-readiness gap.

## Done

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
