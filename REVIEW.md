# PromptWall — Project Review

Reviewed against the stated end goal: *a compliance-grade safety layer that lets a regulated company adopt AI without leaking customer data, and that an examiner will trust.*

## Update — June 27, 2026: Review workflow and Git process

The development flow is now enforced as review-first in git itself:

- Pre-commit gate: `npm run review:agent` before commit.
- Post-commit gate and sync: `npm run review:ci` then automatic push only on pass.
- New hook path is `.githooks`, with `npm run hooks:install` for bootstrap.

The technical review model itself remains the same, but the process now ensures
that each local change is validated before it can leave the machine.

The skeleton genuinely proves the whole loop end to end, and the architecture is the right one (shared detection engine, plugin-registry detectors, three sensors into one control plane, hash-chained audit, redaction/masking, MV3 extension, Office/PDF processors). The clean module separation is a real asset. The issues below are about making it *true* and *trustworthy*, not about restructuring.

Everything marked "evidence" was reproduced by running the actual code, not inferred.

---

## Update — June 23, 2026: both P0 blocks addressed

The detection false positives and the raw-prompt privacy gap have been fixed and tested. What changed:

- **Detection FPs (#1–#3):** SSN split into a separator-required hard-block detector plus a bare-9-digit detector that now requires context; credit cards require a valid issuer (BIN) prefix plus separators-or-context; routing numbers require banking context. Measured false-positive rate on random ids dropped from ~88% (SSN) and ~10% (card) to **0%**, with true positives still caught.
- **Raw-prompt privacy (#4):** new `server/crypto.js` (AES-256-GCM). The server now retains the raw prompt only for items *held for approval*, encrypted at rest, decrypted only on an audit-logged reveal; with no key configured it stores no raw at all. Added a `storeRawForApproval` policy toggle and `SENTINEL_DATA_KEY`. README privacy claim corrected to match.
- **Tests:** `test/detect.test.js` + `test/crypto.test.js` (run with `npm test`). 11 pass, 0 fail; the 3 semantic-paraphrase gaps below are tracked as `todo`. Also fixed the broken `npm run seed` reference and added `npm run sync-engine` to keep the two engine copies identical.

Everything from **#5 onward is still open** (audit-chain coverage, datastore concurrency, reliable re-send, user identity, network backstop, and the semantic model).

---

## Update — June 24, 2026: P1/P2 closed + competitive features added

All previously-open items are addressed and tested (suite now **39 pass / 0 fail / 0 todo**). See `ITERATIONS.md` for the full log.

- **#5 Audit chain now covers the evidence.** Each entry hashes a *canonical serialization of the full entry* plus a `contentHash` binding the referenced query's live state. Editing a finding, `decisionNote`, or `detail` after the fact fails `verifyAuditChain()` (`reason: 'evidence'`/`'chain'`). Tests in `test/db.test.js`.
- **#6 Concurrency-safe datastore.** Swapped the unlocked JSON read-modify-write for **SQLite/better-sqlite3** (WAL + ACID transactions), with auto-migration and chain re-anchoring. No more last-write-wins drops.
- **#7 Reliable send.** The browser sensor no longer re-dispatches a synthetic Enter (which React ignores); it clicks the site's **real send button** via per-site adapters after approval, with a one-shot trusted bypass.
- **#8 End-user identity.** Identity comes from MDM-injected `chrome.storage.managed` (email/user/orgId, `schema.json`); unattributed events are explicitly marked, never mislabeled. `orgId` is stored per event for multi-tenant audit.
- **#9 Honest, layered enforcement.** Client-side enforcement is paired with an ICAP network backstop (existing) and now a **shadow-AI discovery** signal for ungoverned tools; the narrative is "managed + network backstop," not "stops a determined insider."
- **P2 — all addressed.** Labeled detector fixture (`test/detect.test.js`), real **on-device semantic model** closing the three paraphrase gaps with zero benign false positives, engine-drift **CI guard** (`npm run sync-check`), login **rate-limit/lockout**, and a **stable session secret** (env or persisted) so logins survive restarts. The `scripting` permission was dropped.

New capabilities beyond the original review (competitive parity + differentiation): **reversible tokenization / Redact-&-Send** with a sealed vault and response re-hydration, **AI output/response scanning**, **Man-in-the-Prompt** invisible-injection defense, **per-user risk** aggregation, **one-click regulation templates**, and **/healthz · /readyz · /api/metrics** + Docker + CI for operations.

---

## P0 — These break the core promise. Fix before any demo to a regulated buyer.

### 1. The SSN detector fires on essentially every 9-digit number — as a *critical hard-block*
**Evidence:** `analyze("Your order number is 122105155 and ships Tuesday")` returns `US_SSN`, severity **critical**, hard-block. The regex `\d{3}[- .]?\d{2}[- .]?\d{4}` makes separators optional, and `ssnPlausible()` only rejects a few number ranges, so the large majority of bare 9-digit strings qualify.

**Why it matters for the goal:** credit unions are saturated with 9-digit values — account numbers, member numbers, transaction IDs, reference numbers. Under the default `block` mode, every one becomes an un-overridable critical block routed to the Security Admin queue. The admin drowns in false alarms, stops trusting the tool, and either rubber-stamps approvals or disables it. A DLP control that gets switched off is itself the examiner finding you're selling against.

**Fix:** split SSN into two detectors, mirroring what you already do for EIN/passport:
- *High-confidence:* separated form `\d{3}[- ]\d{2}[- ]\d{4}` → keep as critical hard-block.
- *Bare 9 digits:* require a context keyword nearby (`ssn`, `social security`, `ss#`, `taxpayer`) before flagging. No context → don't flag.

This one change removes the single worst false-positive source.

### 2. Credit-card detector flags ~10% of all 16-digit numbers; no card-network or context check
**Evidence:** 20,117 of 200,000 random 16-digit strings pass `luhnValid()` → `CREDIT_CARD`, critical. Luhn alone is a 1-in-10 filter, and there is no BIN/context gate.

**Fix:** require a valid issuer prefix (Visa `4`; Mastercard `51–55`/`2221–2720`; Amex `34`/`37`; Discover `6011`/`65`…) and/or nearby context (`card`, `visa`, `exp`, `cvv`). Expect roughly an order-of-magnitude drop in false positives.

### 3. Routing-number detector hard-blocks ~1.2% of random 9-digit numbers
**Evidence:** 2,382 of 200,000 random 9-digit numbers pass the ABA checksum → `ROUTING_NUMBER` (in `alwaysBlock`). Same class of problem as #1; gate it behind context (`routing`, `aba`, `account`) too.

### 4. Raw prompts — full SSNs, card numbers, AWS keys, passwords — are stored in cleartext on the server
**Evidence:** `server/app.js` persists `_rawPrompt: prompt` for every blocked/flagged event. `data/queries.json` currently contains, in plaintext: `SSN 524-71-9043`, `card 4111 1111 1111 1111`, `AKIA…`, `Pass=Summer2026!`. A `grep` for any encryption (`encrypt`/`cipher`/`aes-`) across `server/` and `server/app.js` returns nothing. The README claims "detection runs locally so most prompt text never leaves the device" and "redacted/masked data is what gets stored."

**Why it matters for the goal:** this is the examiner's first question, and right now the honest answer contradicts the marketing. The product aggregates every employee's most sensitive prompts into one unencrypted file — a brand-new, concentrated breach target. As written, the privacy claim is false for exactly the data that matters most.

**Fix (in order of preference):**
1. Don't transmit raw at all. Hold the raw prompt client-side; send only the redacted text, masked findings, and hashes. Release locally once the admin approves.
2. If an admin must read the raw text to make an approval decision, encrypt `_rawPrompt` at rest with a per-tenant key, gate the existing `/reveal` endpoint behind re-auth/MFA, and add retention + auto-purge.
3. At absolute minimum, change the README so the claim matches the implementation.

Recommend (1) + (2).

---

## P1 — These weaken the compliance story or make enforcement unreliable.

### 5. The audit hash-chain doesn't cover the fields an examiner cares about
**Evidence:** `appendAudit()` hashes only `prevHash + ts + action + queryId + actor`. The `detail` field, the findings, the decision notes, and the *entire* `queries` table (mutable through `updateQuery`) sit outside the chain. Someone can rewrite `detail`, a query's findings, or a `decisionNote` and `verifyAuditChain()` still returns `ok: true`.

**Fix:** hash a canonical serialization of the full entry, and record query state transitions as chained audit events (you already do this for approve/deny — extend it so the evidence itself is tamper-evident, not just the thin event header).

### 6. The JSON store does unlocked read-modify-write — concurrent writes corrupt the audit log
**Evidence:** every `appendAudit`/`createQuery` reloads the whole array, mutates, and rewrites. Two near-simultaneous calls last-write-win the entire file, silently dropping an entry and breaking `prevHash` linkage. With three sensors plus SSE plus client polling, concurrency is real even at tiny scale.

**Why it matters:** this isn't a "scale later" item — it's correctness of the audit log, which is the thing you sell. Move to SQLite/Postgres with real transactions. It's on your roadmap; raise its priority and frame it as audit integrity, not performance.

### 7. "Send anyway" / "Submit & send" likely doesn't actually send on ChatGPT/Claude
**Evidence:** after `preventDefault()`, `resend()` re-dispatches a synthetic `KeyboardEvent`. Modern React composers generally ignore non-trusted (`isTrusted: false`) events, so warn/justify can fail silently after the user complies — the prompt just sits there.

**Fix:** verify per-site; prefer letting the original user gesture through after approval (a one-shot bypass flag checked at the top of the handler) over re-dispatching a fake event. Add a smoke test per supported site.

### 8. The browser sensor has no end-user identity — everything is "browser-user"
**Evidence:** `background.js` sends `user: c.user || 'browser-user'`, and `c.user` is never set anywhere. The endpoint agent at least uses the OS username; the extension attributes every event to a single placeholder.

**Why it matters:** the entire pitch is "prove employee X didn't paste member data last quarter." Without per-user attribution, the audit log can't answer the examiner's question for the flagship sensor. Wire identity from managed install / SSO / MDM before anything else user-facing.

### 9. Enforcement is client-side and bypassable — say so honestly, and make the network backstop first-class
The extension guards listed sites in one browser. A user can disable it, switch browser/profile, use an unlisted AI site, hit the API directly, or go to mobile. That's genuinely fine for *accidental and casual* leakage, which is most of the real risk — but the compliance narrative should be "managed, force-installed, with a network-layer backstop for unmanaged paths," not an implication that it stops a determined insider. You already have `scripts/squid-icap-bridge.js`; promote it to a first-class, documented deployment rather than a script.

---

## P2 — Hygiene and smaller items.

- **`npm run seed` is broken.** `package.json` and the README reference `scripts/seed.js`, which doesn't exist. Add it or remove the reference.
- **No tests.** A security product needs a labeled precision/recall fixture for the detector (true positives, evasions, false-positive bait) wired into CI, plus unit tests on `policy.evaluate`. I can scaffold this directly from the probe I ran for this review.
- **Semantic detection is brittle keyword matching** and empirically misses realistic paraphrases: `"we're thinking about switching away from Acme… keep this internal"`, `"reduce headcount by 15% before the merger closes"`, and ordinary code without keyword tokens all scored **0**. Your README's own example (`"considering leaving our vendor, do not share"`) lands at exactly 0.34 against a 0.34 threshold — one word away from missing. This is the known roadmap item (real on-device model); the misses above make the case concrete and are worth keeping as the eval set for whatever model replaces it.
- **Two copies of the engine drift by hand.** `detection-engine/detect.js` and `sensors/browser-extension/lib/detect.js` are byte-identical today but kept in sync manually. Add a build/copy step or a CI check that fails if they differ.
- **Minor:** the manifest requests the `scripting` permission but uses static content scripts (drop it unless needed); the admin login has no rate-limit/lockout; the session secret and password salt regenerate per process (fine now, but logins won't survive a multi-instance deployment).

---

## Suggested order of work
1. Detection false positives (#1, #2, #3) — fastest path to a tool people trust, and the cheapest.
2. Raw-prompt handling + encryption (#4) — closes the contradiction at the heart of the pitch.
3. Audit integrity + real datastore (#5, #6) — makes "tamper-evident" survive scrutiny.
4. Identity + reliable send (#7, #8) — makes the flagship sensor's evidence real.
5. Test fixture for detection — locks in 1–3 and de-risks the future model swap.

