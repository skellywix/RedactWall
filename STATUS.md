# PromptSentinel Production Loop Status

## Open

- None selected. Next pass should pick the highest-impact production-readiness gap.

## Done

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
