---
name: pr-review-loop
description: Adversarial automated review pass over a PR or diff before a human looks. Checks correctness, security, performance, and PromptWall-specific invariants (no PII in logs, engine parity, audit integrity, alwaysBlock intact), and posts a PASS/FAIL review with evidence. Invoke with /pr-review-loop on a PR number or diff.
---

# PR Review Loop

The second draft before the human draft. Runs on a diff, trusts commands over vibes, and is deliberately hard to satisfy.

## Inputs
A PR number (`gh pr diff <n>`) or local diff (`git diff main...HEAD`).

## Review checklist
**Correctness & quality**
- Functions doing one thing; no logic duplicated more than twice; no dead code or unused imports; names communicate intent.
- Async paths handle errors; no `N+1` over the SQLite layer.

**PromptWall invariants (block-level)**
- `npm run sync-check` is green — detector edits propagated via `npm run sync-engine`, not hand-copied.
- No raw sensitive value (prompt text, detected PII) written to logs, errors, or the audit `entry`. Audit stores redacted detections + hashes only.
- No `alwaysBlock` type (SSN, cards, bank/routing, IBAN, passport, secret/private keys) removed or down-graded.
- Semantic model block in `detection-engine/detect.js` only changes via `npm run train-semantic` (deterministic) — no hand-edited weights.
- If `server/db.js`/`server/crypto.js` touched: `verifyAuditChain()` still `ok:true`.

**Security** — delegate the deep pass to `shannon-pentest` for auth/IDOR/injection on the server endpoints (approval queue, login, reveal).

## Output
Post a review: `PASS` or `CHANGES REQUESTED` with a bulleted, evidence-backed list (the command and its result for each finding). Fixable nits → suggest the diff. Architectural concerns → flag, don't silently rewrite.

## Stop condition
Every checklist item has an explicit pass/fail with evidence; review posted via `gh pr review`.
