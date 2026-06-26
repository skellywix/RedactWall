---
name: bug-repro-fix-loop
description: Reproduce → red test → isolate → fix → regression-guard loop for an incoming bug (especially detection false-positives/negatives). The fix is not done until a previously failing test now passes and stays in the suite. Invoke with /bug-repro-fix-loop with a bug description.
---

# Bug Repro → Fix Loop

No fix without a failing test first. This is how a one-off bug becomes a permanent regression guard — critical for a detector whose mistakes are either a leak (false negative) or user friction (false positive).

## Loop
1. **Reproduce.** Turn the report into the smallest input that shows the bug. For detection bugs, capture the exact prompt text (use **synthetic** PII) and expected vs actual verdict.
2. **Write the red test** in the matching `test/*.test.js` (e.g. `test/detect.test.js` for a missed `IBAN`, `test/auth.test.js` for a session bug). Run `npm test` — it MUST fail for the right reason.
3. **Isolate** the cause in the module (`shared/detect.js`, `src/policy.js`, …). Form a one-line hypothesis before editing.
4. **Fix** minimally. If in `shared/`, run `npm run sync-engine` to keep `extension/lib/` identical.
5. **Go green + guard:** `npm test` passes; the new test stays. Add a `DECISIONS.md` line if the cause was non-obvious (e.g. a regex edge case).
6. Verify the wider gate: `npm run sync-check`; if detector weights moved, `npm run train-semantic && git diff --exit-code`.

## Stop condition (contract)
- Evidence: the new test failed before the fix and passes after; full `npm test` green.
- Constraints: minimal change; no unrelated refactor; false-negative fixes must not silently broaden a detector into new false positives (add a counter-example test).

## Classes to watch
False negatives on `alwaysBlock` types are sev-1 (a leak). False positives on `CONFIDENTIAL_BUSINESS`/`PERSON_NAME` are friction — tune thresholds, don't disable.
