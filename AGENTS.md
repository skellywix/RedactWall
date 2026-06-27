# AGENTS.md — operating contract for agents working in PromptSentinel

Read this before changing anything. It is the agent-memory file: how we work, how to prove a change works, the invariants you may not break, and the mistakes not to repeat. Update it when you learn something (see "Mistake log"). `CLAUDE.md`, if present, may extend this.

## What this project is
PromptSentinel is a compliance-grade DLP layer that inspects prompts/files headed to AI tools and **warns / requires justification / redacts / blocks** by policy, with a tamper-evident audit log. Three sensors (browser `extension/`, `endpoint-agent/`, `mcp-guard/`) all run the SAME local engine and report to one server. Sold to regulated shops (credit unions; NCUA/GLBA/PCI/HIPAA) — an examiner will inspect this.

## How we work (manager-of-agents)
Plan → Implement → Validate. Spend most effort planning. See `.claude/skills/`:
- Plan: `plan-first-spec`, `delegate-like-a-manager`
- Implement: `long-running-orchestrator`, `parallel-agents-worktrees`, the fix loops
- Validate: `agent-self-validation`, `no-mistakes-review`, `maker-checker-loop`, `security-scan-loop`

## Commands
- `npm test` (= `node --test`) — unit/integration.
- `npm run sync-check` — verifies `shared/detect.js` == `extension/lib/detect.js`. MUST stay green.
- `npm run sync-engine` — propagate the shared engine to the copy (the ONLY way to update the copy).
- `npm run train-semantic` — regenerate the on-device semantic model in `shared/detect.js`. Deterministic; CI fails on drift.
- `npm run hooks:install` — install local review hooks into `.githooks`.
- `npm run review:agent` — run the pre-commit review alias locally.
- `npm run review:ci` — full local gate (`git diff --check`, `npm test`, `npm run sync-check`, `npm run eval`).
- `npm run eval` — precision/recall/F1 on the HELD-OUT labeled corpus (`test/fixtures/semantic-eval.json`). Floors enforced by `test/eval.test.js`; **zero benign false positives** is the hard gate.
- `npm run simulate` — end-to-end detection over the sample corpus.
- `npm start` — run the server. `docker build -t promptsentinel .` — CI also builds the image.

## Change-control process
- Run `npm run hooks:install` after cloning or reinstalling the repo.
- `pre-commit` runs `npm run review:agent` and aborts the commit if checks fail.
- `post-commit` runs `npm run review:ci` and only pushes to `origin` when checks pass.
- If review or push fails, the commit remains local and you can run `git push` after resolving the issue.

## Hard invariants (do not break)
1. Detector logic lives in `shared/detect.js` ONLY. After editing, run `npm run sync-engine`; never hand-edit `extension/lib/detect.js`.
2. Never hand-edit the semantic model block — regenerate via `npm run train-semantic` (deterministic).
3. `alwaysBlock` types (US_SSN, CREDIT_CARD, BANK_ACCOUNT, ROUTING_NUMBER, IBAN, US_PASSPORT, SECRET_KEY, PRIVATE_KEY) always block/tokenize regardless of mode. Do not weaken.
4. No raw PII / prompt text in logs, errors, or the audit `entry` — redacted detections + hashes only.
5. The audit log is append-only and hash-chained: after any `src/db.js` / `src/crypto.js` change, `node -e "require('./src/db').verifyAuditChain()"` must report `ok:true`.
6. Detection changes must keep `npm run eval` floors green — held-out precision/recall AND **zero false positives on benign prompts**. Don't tune the model against `test/fixtures/semantic-eval.json`; it's the held-out test, not training data.

## How to exercise PromptSentinel end-to-end (required evidence before handing back)
Don't trust green unit tests alone. For the surface you changed, produce a **Testing** section with this evidence (synthetic PII only — never real member data):
- **Detection:** `npm run simulate`; show before/after verdicts for the affected prompts; prove `alwaysBlock` types still block.
- **Browser sensor:** load unpacked `extension/` in a test Chrome profile, paste `123-45-6789` into a chat box → screenshot the block modal and confirm nothing was sent.
- **Policy modes:** flip `config/policy.json`; show warn / require-justification / redact / block behaving correctly; in redact mode confirm only tokens leave the device.
- **Approval flow:** block → held in queue → admin approve → released; capture the audit entries.
- **Audit integrity:** `verifyAuditChain()` → `ok:true`; a tampered row → `ok:false`.

## Review standards (apply before presenting code)
Functions under ~30 lines; no logic duplicated >2x; no dead code/unused imports; names communicate intent; async paths handle errors; keep the hot detection path allocation-light (it runs on every keystroke/paste); no `SELECT *` on hot SQLite paths. Review in a FRESH context, not the session that wrote the code.

## Mistake log (append when you learn something; don't repeat these)
- 2026-06-24: Detector edits must go through `shared/detect.js` + `npm run sync-engine`. Editing `extension/lib/detect.js` directly breaks `npm run sync-check` (a release blocker).
- 2026-06-24: The semantic model weights are generated, not hand-written. Hand-editing them fails the CI determinism check — retrain with `npm run train-semantic` and commit the regenerated block.
- 2026-06-24: Measure detection on a HELD-OUT set, not the trainer's own negatives. Calibrating the threshold on training negatives hid a 34%% CONFIDENTIAL precision (12/18 benign prompts flagged). `npm run eval` is the guard.
- 2026-06-24: Low-variation positive templates (legal/credentials) must NOT be de-duplicated before training — `uniq()` collapsed them to ~15 examples vs ~1000 negatives and the model learned to predict ~0 (recall 0). Keep repeats so they carry training weight.
- (add new lessons here, newest first)

