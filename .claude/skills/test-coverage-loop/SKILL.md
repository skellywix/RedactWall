---
name: test-coverage-loop
description: Drives test coverage up to a target on the modules that matter most (detection, policy, crypto, audit). Each pass adds real tests for one uncovered branch, proves the number moved, and never weakens an assertion to go green. Invoke with /test-coverage-loop.
---

# Test Coverage Loop

Coverage is a means, not the goal: the goal is that a regression in a security-critical path fails a test. Prioritize the modules where a silent bug = a data leak.

## Priority order (PromptSentinel)
1. `detection-engine/detect.js` — every detector + the semantic categories (`SOURCE_CODE`, `CONFIDENTIAL_BUSINESS`, `CREDENTIALS`, `LEGAL_CONTRACT`). Cover both true positives AND the false-positive guards (e.g. bare 9-digit number is NOT a routing number without context).
2. `server/policy.js` — `evaluate()` decisions across all modes (warn / justify / redact / block) and the `alwaysBlock` hard stops.
3. `server/crypto.js` — `seal`/`open` round-trip and the disabled-key path.
4. `server/db.js` — `appendAudit` + `verifyAuditChain` detects tampering (mutate an entry, expect `ok:false`).

## Loop
1. Measure: `node --test --experimental-test-coverage` and read the per-file summary.
2. Pick the single lowest-covered priority module.
3. Add a test in the matching `test/*.test.js` for one uncovered branch. Use **synthetic** PII only (this is a DLP product — never commit real sensitive data).
4. Prove it: the new test passes, and re-running coverage shows the number rose for that file.
5. `npm run sync-check` if you touched anything under `detection-engine/`. Commit. Update `STATUS.md`.

## Stop condition (contract)
- End state: target module reaches the agreed line/branch threshold (set it explicitly before starting, e.g. 90% for `detect.js`).
- Evidence: coverage report before/after; `npm test` green.
- Never: lower a threshold or delete an assertion to hit the number.
