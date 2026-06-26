# PromptSentinel Production Loop Status

## Open

- [P1] Add honeytoken/canary detector and policy event.
  Evidence: detector tests with counter-examples.
- [P1] Add managed extension deployment guide and policy JSON examples.
  Evidence: docs lint/static review.

## Done

- 2026-06-26: Added session-protected examiner evidence export with policy, stats, audit integrity, detector inventory, query metadata, masked findings, prompt hashes, and audit hashes. Prompt bodies and audit detail text are omitted.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Added optional sanitized SIEM/webhook alerts for high-risk events; payloads omit raw prompt text, redacted prompt body, token vaults, and raw finding values.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Added baseline production HTTP security headers, disabled Express fingerprinting, and tightened admin session cookie attributes.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Added signed CSRF tokens for admin unsafe actions; dashboard fetch wrapper sends `x-csrf-token`; tests cover token binding and route wiring.
  Evidence: `npm test`, `npm run sync-check`, `verifyAuditChain()`.
- 2026-06-26: Created durable production loop plan and status files.
