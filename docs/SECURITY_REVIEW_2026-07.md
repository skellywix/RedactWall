# Codebase Hardening Review — July 2026

A full line-by-line review of the server, detection engine, sensors, gateway,
admin frontend, and scripts. This document records what was fixed and the
residual items deliberately deferred (with precise remediation) rather than
changed under automation because they carry data-migration or FP/FN risk.

## Fixed in this pass

### Critical / High — hard-stop (alwaysBlock) bypasses
- **Policy `ignore` list defeated `alwaysBlock`.** `evaluate()` filtered
  findings by the admin ignore list before the hard-stop check, so an ignored
  US_SSN produced `decision: allow` and a safe-to-send receipt for the raw
  prompt. Hard-stop types are now exempt from the ignore filter.
  (`server/policy.js`, test/alwaysblock-invariant.test.js)
- **`clientOutcome` override defeated `alwaysBlock`.** A sensor-declared
  `sent_after_warning`/`justified` set the recorded status before `hardStop`
  was consulted, recording a raw SSN as cleared and minting a receipt. A
  hard-stop finding now forces `pending` regardless of clientOutcome.
  (`server/app.js`)
- **Gateway forwarded raw PII to upstream on redact.** Only string message
  content was tokenized; OpenAI content-parts and tool-call arguments were
  scanned but forwarded raw. Redaction now covers array text parts and
  tool/function-call arguments; unscannable content (image parts) fails closed.
  (`gateway/server.js`, `gateway/canonical.js`)

### High — credential exfiltration / SSRF
- **Atlassian connector honored a model-controlled `siteUrl`.** A poisoned tool
  call could send the Atlassian credential to an attacker host. The site is now
  derived only from operator config/env. (`sensors/mcp-guard/connectors/atlassian.js`)
- **Outbound webhook SSRF.** `outboundHttpsUrl` validated scheme but not host.
  It now blocks loopback, link-local (incl. the cloud-metadata endpoint
  `169.254.169.254`), and unspecified IP literals plus `localhost`, while still
  allowing RFC1918 ranges (on-prem SIEM). (`server/url-policy.js`)

### Medium — robustness / availability
- **OOXML decompression-bomb DoS.** `docx/xlsx/pptx` extraction now bounds
  cumulative uncompressed bytes and fails closed past a budget. (`server/processors.js`)
- **Hung webhook could stall approvals.** Every outbound SIEM/notifier/
  subscription fetch now has an abort timeout. (`server/{alerts,notifiers,subscriptions}.js`)
- **Policy bundle fail-open on bad expiry.** `verifyBundle` now fails closed on
  a missing/unparseable `expiresAt`. (`server/policy-bundle.js`)
- **Gateway response gate** now also honors `scan.decision === 'block'`.
- **Browser redact fail-open.** The redact path now resends only after the
  control plane records the send (mirrors warn/justify). (`sensors/browser-extension/content.js`)
- **MCP telemetry leak.** Structured-only redaction logged the fetched document
  prose (PII masked) to the control plane; it now logs a label-only summary.
  (`sensors/mcp-guard/guard.js`)
- **Trust-proxy / fleet lockout.** `TRUST_PROXY` env now configures Express
  `trust proxy` so per-client ingest throttling isn't collapsed behind an LB.
  (`server/app.js`)
- **Postgres audit-chain fork.** Audit appends take a transaction-scoped
  advisory lock so concurrent instances can't fork the hash chain.
  (`server/storage/pg-driver.js`, `server/db.js`)

### Medium — performance (hot paths)
- Detection overlap resolution: O(k²) → O(k log k) neighbour check (200K paste
  ~1.7s → ~0.18s), proven equivalent over randomized trials. (`detection-engine/detect.js`)
- `knownDetectorIds` memoized on config mtime (was hundreds of disk reads per
  gate request). (`server/validation.js`)
- Gateway agent-token store cached on file mtime (was re-read per request).
  (`gateway/tokens.js`)
- Gateway rate-limit buckets evicted when expired. (`gateway/server.js`)
- `stats()` top-entities full-row scan cached for a short window (was scanned
  per ingest). (`server/db.js`)

### Low — correctness / hygiene
- Evidence/SIEM `categories`/`reasons` bounded and scrubbed (defense-in-depth).
- Frontend: `riskOverride` escaped in its quoted HTML attribute.
- Dead ternary removed in `server/workflow.js`.

## Deferred (tracked) — remediation planned, not changed under automation

These are real hardening items, but each risks breaking the audit chain, a
not-yet-deployed path, or the detector's zero-false-positive gate, so they need
a dedicated, separately-reviewed change rather than an inline edit.

1. **Keyed audit-chain hash (High).** Audit entry hashes are unkeyed
   `sha256(canonical(body))`. An insider with direct DB write access could edit
   a finalized `queries` row and append a covering audit entry (recomputing the
   contentHash themselves) to re-anchor, and `verifyAuditChain()` would still
   pass. Remediation: HMAC the chain with a server-held key (e.g. derived from
   `REDACTWALL_SECRET`) so a covering entry can't be forged. This changes the
   hash of every existing row, so it needs a versioned migration that re-seals
   the chain once on upgrade — done deliberately, not inline, because a botched
   change would break the product's core tamper-evidence guarantee. Mitigated
   today by the DB-level append-only triggers on the `audit` table.
2. **Postgres row-level tenant isolation wiring (Medium).** Migration v3
   installs RLS keyed on `current_setting('redactwall.org_id')`, but
   `setTenantContext` is not called per request, and the shared single worker
   connection means session-level `set_config` would bleed context across
   tenants. Remediation: call `setTenantContext` inside a per-request
   transaction with `set_config(..., true)` (transaction-local). Only affects
   the shared-multi-tenant Postgres path, which is not the shipped deployment
   shape (customer-silo single-node SQLite is).
3. **EDM fingerprint preimage resistance (Medium).** Exact-Data-Match uses fast
   non-cryptographic hashes (FNV-1a/djb2) with a salt that must ship to sensors,
   so low-entropy watchlist values (SSNs, account numbers) are brute-forceable
   on any endpoint holding the extension. Remediation: use a slow keyed KDF with
   a server-held pepper and do membership checks server-side, or document the
   on-device EDM confidentiality limit honestly. Needs a design decision on the
   on-device vs server-side detection tradeoff.
4. **Bare-PAN / compact-SSN detection (High, detection tuning).** A compact
   16-digit Luhn-valid card or 9-digit SSN with no separator or context word is
   not flagged (a deliberate false-positive-avoidance tradeoff). Flagging bare
   Luhn+known-BIN PANs would improve recall but risks the zero-false-positive
   eval floor on an `alwaysBlock` type (a false block is highly disruptive).
   Remediation: add a "possible"-tier signal and validate it against the eval
   corpus in a dedicated detector change with the corpus extended for hard
   negatives.
5. **`itinPlausible` tautological branch (trivial).** Ends with
   `return ssnPlausible(d) === false`, which is always true given the `9xx`
   precondition. Harmless; fold into the next detector change so the generated
   engine copy is re-synced with other detector work rather than for a cosmetic
   edit alone.
