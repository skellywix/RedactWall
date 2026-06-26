# PromptSentinel Production Loop Status

## Open

- None selected. Next pass should pick the highest-impact production-readiness gap.

## Done

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
