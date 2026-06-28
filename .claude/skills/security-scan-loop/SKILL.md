---
name: security-scan-loop
description: Scheduled adversarial security pass against a local/staging PromptWall instance. Runs the shannon-pentest skill plus product-specific abuse cases (auth/IDOR on the approval queue, detector bypass, PII leakage in logs/audit) and files confirmed findings only. Invoke with /security-scan-loop or schedule with /loop. Never run against production.
---

# Security Scan Loop

PromptWall IS a security product, so the adversarial pass is not optional — it's dogfooding. Runs on a system you own (local `npm start` or staging), never production.

## When to run
- Before each release and weekly: `/loop "Run the security-scan-loop skill against http://localhost:3000" --schedule "0 3 * * 6"`.

## Loop
1. **Authorization gate.** Confirm the target is local/staging and you own it. Abort on any production host.
2. **Automated pass:** invoke `shannon-pentest` against the running server (injection, XSS, SSRF, broken auth, broken authorization). Docker required; ~$50/run.
3. **Product-specific abuse cases** (what a generic scanner misses):
   - **Approval-queue IDOR:** can a non-admin session approve/reveal another tenant's held prompt? (`server/auth.js` session + the reveal endpoint.)
   - **Detector bypass:** can crafted spacing/unicode/encoding slip an `alwaysBlock` value past `detection-engine/detect.js`? Feed mutations through `npm run simulate`.
   - **PII leakage:** grep server logs and the audit `entry` after a blocked prompt — raw sensitive values must never appear (redacted + hashed only).
   - **Audit tamper-evidence:** mutate a row in `data/sentinel.db`, expect `verifyAuditChain()` → `ok:false`.
   - **Redact mode integrity:** in redact mode, confirm no raw PII leaves the device — only tokens (`server/crypto.js` `seal`).
4. **Report confirmed only.** No exploit, no report — zero false-positive noise. Each finding gets a reproducible PoC and a `STATUS.md` entry tagged by severity.

## Stop condition (contract)
- Evidence: Shannon report + results of all five product abuse cases; confirmed findings in `STATUS.md` with PoCs.
- Constraints: authorized non-prod target only; attack tooling stays in Docker; no destructive actions against real data.
