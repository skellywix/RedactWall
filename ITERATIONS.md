# PromptSentinel — Iteration Log

A record of the self-improvement passes taken to move the project from "skeleton
that proves the loop" toward production-ready, benchmarked against commercial AI
DLP (Strac, Nightfall, Harmonic, Prompt Security) and pushed with a few eccentric
ideas of our own. Every iteration shipped working code **plus tests**; the suite
grew from 11 passing / 3 known-failing to **42 passing / 0 failing / 0 todo**.

## Competitive read (what the market ships, and our response)
- **Reversible tokenization / pseudonymization** (Strac, Nightfall) → built it, on-device, with a sealed vault (Iteration 2).
- **On-endpoint small models for intent** (Harmonic) → a zero-dependency hashing-LR classifier embedded in the engine (Iteration 3).
- **Output/response scanning** (Prompt Security) → `/api/v1/scan-response` (Iteration 5).
- **"Man-in-the-Prompt" defense** (Prompt Security) → invisible-character injection guard (Iteration 4).
- **Shadow-AI discovery** (Harmonic, Nightfall) → background discovery of ungoverned AI hosts (Iteration 4).
- **Regulation posture presets** → one-click NCUA/GLBA, PCI, HIPAA templates (Iteration 5).

---

## Iteration 1 — Audit integrity + a real datastore (REVIEW #5, #6)
- Replaced the unlocked JSON read-modify-write store (which could drop entries and
  break the hash chain under concurrent writes) with **SQLite/better-sqlite3**:
  WAL, ACID transactions, indices. Auto-migrates the legacy JSON store and
  re-anchors the chain. Falls back to local disk with a loud log if the configured
  path can't host SQLite (e.g. a cloud-synced folder).
- **Tamper-evidence now covers the evidence**, not just the event header: each
  audit entry hashes a *canonical serialization of the full entry* plus a
  `contentHash` binding the referenced query's current state. Editing a finding,
  decision note, or detail after the fact now fails verification.
- Tests: `test/db.test.js` — 1,000-entry chain, audit-detail tamper, query-evidence
  tamper, legitimate-transition integrity.

## Iteration 2 — Reversible redaction vault + "Redact & Send" mode
- New on-device primitive: `tokenize()` / `detokenize()` replace each finding with
  a stable typed placeholder (`[[US_SSN_1]]`); identical values share a token so the
  model can still reason about "the same person".
- New enforcement mode **`redact`**: the prompt goes to the AI with **no real PII**,
  the token→value map is sealed at rest (AES-256-GCM), and `/api/v1/rehydrate`
  restores the real values in the model's response. In the browser the map never
  leaves the page — the reply is re-hydrated locally via a MutationObserver.
- Tests: `test/tokenize.test.js` — exact round-trip, no-PII-in-tokenized-text,
  token stability, `_1` vs `_11` disambiguation.

## Iteration 3 — Compact on-device semantic model
- Replaced brittle keyword-only semantics with a **hashing-trick logistic-regression
  classifier** (1,032 features: L2-normalized word uni/bigrams + 8 structural
  signals) embedded in the engine (~10 KB). It *augments* the heuristic (max-combine),
  so literal markers still fire and paraphrases get caught.
- Deterministic, seeded trainer (`scripts/train-semantic.js`) picks thresholds for
  **zero false positives on a benign holdout**. Closed all three prior semantic gaps
  (vendor-switch euphemism, layoff-before-merger, keyword-less code) and they now
  generalize to unseen phrasings — while "help me write a Python function…" stays clean.

## Iteration 4 — Identity, reliable send, and two new defenses (REVIEW #7, #8)
- **End-user identity** from MDM-injected `chrome.storage.managed` (email/user/orgId),
  with a `schema.json` managed policy and an explicit `unattributed@unmanaged` marker
  so gaps are visible, never mislabeled.
- **Reliable send**: replaced the synthetic-Enter resend (which React ignores) with
  per-site **send-button adapters** that click the real control after approval.
- **Man-in-the-Prompt guard**: strips zero-width payloads and hard-blocks bidi-override
  / Unicode-tag injection a malicious extension could smuggle into a prompt.
- **Shadow-AI discovery**: the background worker flags visits to AI tools policy
  doesn't govern. Pure helpers live in `shared/adapters.js` with `test/adapters.test.js`.

## Iteration 5 — Security & ops hardening (REVIEW P2)
- **Auth**: brute-force lockout (per user+IP), and a **stable signing secret** —
  env `SENTINEL_SECRET`, else generated-and-persisted so sessions survive restarts;
  startup warns when ephemeral. Tests in `test/auth.test.js`.
- **Output scanning**: `/api/v1/scan-response` flags PII/secret leakage in AI replies.
- **Per-user risk**: `/api/risk` aggregates events/avg-risk/top-entities per user —
  the examiner's "did employee X expose member data?" view.
- **Regulation templates**: `src/templates.js` + dashboard one-click apply
  (Baseline, NCUA/GLBA, PCI-DSS, HIPAA, Redact-first). Tests in `test/templates.test.js`.
- **Ops**: `/healthz`, `/readyz`, `/api/metrics`; multi-stage **Dockerfile** (non-root,
  healthcheck, `/data` volume); **GitHub Actions CI** running tests, engine-drift check,
  and a model-determinism check.

## Iteration 6 — Verification + docs
- End-to-end verification across every sensor (extension syntax, API gate, file
  processors, MCP guard redaction, endpoint agent) with audit integrity green
  throughout. Updated README + REVIEW, added this log, initialized git.

## Iteration 7 — Detection quality made measurable (the "real model" step)
- **Held-out eval harness.** New `test/fixtures/semantic-eval.json` (hand-labeled, phrased
  differently from any training data) + `scripts/eval-detect.js` report precision/recall/F1
  per detector and per semantic category, with benign "bait" as the false-positive gate.
  `npm run eval`; floors enforced in CI via `test/eval.test.js`.
- **Baseline it exposed.** The old semantic model fired on 12/18 benign prompts (even
  "What's the capital of Australia") — CONFIDENTIAL precision **34%** — because the trainer
  calibrated its threshold on the *same* negatives it trained on, and `CREDENTIALS`/
  `LEGAL_CONTRACT` had no trained model at all (recall 17% / via keywords only).
- **Fixes.** (1) Trained models for **all four** categories. (2) **Subword char n-gram**
  features in `_featurize` for paraphrase generalization. (3) **Honest calibration** —
  thresholds picked on a held-out benign split the model never trained on, plus a large,
  diverse benign pool incl. "about-X-but-not-X" hard negatives. (4) A precision-first
  `CONFIDENTIAL_BUSINESS` rule: explicit marker **or** (secrecy cue **and** sensitive
  business topic) **or** model.
- **Result (held-out):** semantic **P 50.9%→100%, R 75%→94%**; CONFIDENTIAL precision
  **34%→100%**; CREDENTIALS recall **17%→83%**; benign false positives **12→0**;
  structured PII 100/100. Model stays deterministic (CI re-trains and diffs) and a few KB.

---

## Iteration 8 — Source-of-truth and review-gated change control

- Added a review-gated local git workflow in-process:
  - `.githooks` for `pre-commit` and `post-commit`
  - `npm run hooks:install` to pin hook path to repository hooks
  - `npm run review:ci` as the required local gate (`git diff --check`, `npm test`, `npm run sync-check`, `npm run eval`)
- Updated operational docs (`README.md`, `PLAN.md`, `AGENTS.md`, `REVIEW.md`, `STATUS.md`) and process decisions (`DECISIONS.md`) so all references now describe this same flow.

This iteration keeps local change quality and GitHub sync aligned to a single repository path:
`promptsentinel/`.

### Test growth
| Pass | Iteration |
|----:|-----------|
| 11 (+3 todo) | baseline |
| 16 | +db |
| 22 | +tokenize |
| 28 | +semantic model (todos closed) |
| 31 | +adapters |
| 39 | +auth +templates |
| **42** | +held-out detection eval |
| 42 | +workflow/process coherency (documentation + hooks) |
