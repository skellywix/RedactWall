# Incident Response Runbook

This runbook is for the operator of a RedactWall deployment responding to a
suspected or confirmed security incident: sensitive data reaching an AI
destination, a compromised sensor or gateway token, tampering with evidence, or
compromise of the control plane itself.

Rules that apply to every step:

- Never paste prompt text, member data, or secrets into tickets, chat, or SIEM
  notes. Reference events by query id, receipt id, prompt hash, or audit entry
  id. Every RedactWall export is already prompt-free; keep your notes the same.
- Record who did what and when. Admin actions land in the tamper-evident audit
  chain automatically; record out-of-band actions (network blocks, HR steps)
  in your ticket system.

## 1. Detection Sources

An incident usually surfaces through one of these channels:

| Source | Where | What it tells you |
|--------|-------|-------------------|
| SIEM subscriptions | `config/subscriptions.json` destinations, delivery history in the dashboard | Sanitized posture and security events routed to Splunk, Sentinel, Chronicle, ServiceNow, or an OpenTelemetry collector (`otlp` type, OTLP/HTTP JSON logs) |
| SIEM webhook | `SIEM_WEBHOOK_URL` alerts | Best-effort sanitized alert stream for blocked and held events |
| Approval queue | Dashboard, approval routing notifications | A held prompt that a human flagged during review |
| Audit chain verification | `node -e "console.log(require('./server/db').verifyAuditChain())"` | Evidence tampering: a broken chain means stored records were altered |
| Posture and coverage dashboards | Coverage tab, posture alerts | A required sensor went dark, a machine lost enforcement, gateway proof stopped |
| Detection eval / CI | `npm run review:ci` | Detector regression that could have allowed leakage |

## 2. Triage Severity

Classify within 30 minutes of first report. When in doubt, pick the higher
severity.

| Severity | Definition | Examples | Response target |
|----------|------------|----------|-----------------|
| SEV-1 | Confirmed regulated data reached an external AI destination, or evidence integrity is broken | Verified `allowed` receipt for text later confirmed to contain member PII; `verifyAuditChain()` returns not-ok | Immediate, all hands |
| SEV-2 | Credential or token compromise with enforcement still intact | Leaked gateway agent token, exposed admin session, stolen `INGEST_API_KEY` | Same business day |
| SEV-3 | Enforcement gap without confirmed leakage | Required sensor offline on a subset of machines, default-deny disabled by mistake, detector false negative found in eval | 72 hours |
| SEV-4 | Hardening or process finding | Preflight check regression, stale dependency with no known exploit path | Next release cycle |

## 3. Containment

Apply the steps that match the compromise. All policy changes are audited.

1. **Block destinations.** Add the destination to `blockedDestinations` in
   policy, or enable `blockUnapprovedAiDestinations` to default-deny anything
   unreviewed. Sensors pick the change up on their next signed policy-bundle
   refresh and fail closed if they cannot verify a bundle.
2. **Revoke gateway agent tokens.** Remove the compromised entry from the
   gateway token store (`gateway-agent-tokens.json` under the data dir). Only
   salted hashes are stored; removal takes effect on the next request. Re-mint
   with `gateway/mint-token.js` for legitimate callers.
3. **Rotate `REDACTWALL_SECRET`.** This invalidates all admin sessions, HMAC
   receipts keys, and derived keys. If `REDACTWALL_DATA_KEY` is not set
   separately, the data key is derived from `REDACTWALL_SECRET`, so also perform
   the data-key rotation in the next step (with the old `REDACTWALL_SECRET`
   value as the previous key) and set a dedicated `REDACTWALL_DATA_KEY` going
   forward.
4. **Rotate the data key without losing sealed evidence.** Set
   `REDACTWALL_DATA_KEY` to the new key and `REDACTWALL_DATA_KEY_PREVIOUS` to the
   key being retired, then run `node scripts/rotate-data-key.js` (use
   `--dry-run` first to preview). The tool re-encrypts retained raw prompts
   and token vaults under the new key and prints counts only — never prompt
   text or key material. When a run reports `unreadable: 0`, unset
   `REDACTWALL_DATA_KEY_PREVIOUS` and restart the server. A non-zero exit means
   some sealed values opened with neither key; keep the old key available and
   investigate before retiring it.
5. **Rotate ingest and API keys.** Replace `INGEST_API_KEY` on the server and
   every sensor, ICAP bridge, and gateway that uses it.
6. **Tighten enforcement.** Raise `enforcementMode` to `block`, set
   `responseScanMode` to `block`, and confirm `alwaysBlock` still covers the
   categories involved in the incident.
7. **Isolate a compromised control plane.** If the server itself is suspect,
   remove its network exposure; sensors and gateways fail closed when the
   control plane is unreachable, so containment does not open a bypass.

## 4. Evidence Preservation

Do this before any cleanup, and before the retention window purges data:

1. Export an examiner evidence pack: `npm run evidence:pack -- --zip`.
2. Export the trust package for the reviewer: `npm run security:package -- --zip`.
3. Verify and record audit-chain state:
   `node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"`.
4. Back up the database file from the data directory to controlled storage.
5. Mind retention: RedactWall has no automated legal-hold flag today. Purges
   run against `rawRetentionDays`. To preserve sealed approval prompts relevant
   to the incident, raise `rawRetentionDays` for the affected period and export
   evidence packs before the original purge window elapses.
6. Preserve receipts. Safe-to-send receipts are signed and prompt-free; they
   prove what was scanned and cleared under which policy version.

## 5. Notification Duties (Regulated Entities)

Coordinate with legal counsel; this section is operational guidance, not legal
advice.

- **NCUA-insured credit unions**: reportable cyber incidents must be reported
  to the NCUA within 72 hours of reasonably believing one occurred. The
  evidence pack plus audit-chain verification output is the artifact set to
  attach to examiner notes.
- **GLBA / FTC Safeguards Rule entities**: notification obligations may apply
  for security events involving customer information; the FTC rule sets a
  30-day window for qualifying events. Your incident ticket should record the
  determination either way.
- **Examiner notes**: describe the event using RedactWall's sanitized
  vocabulary — detector ids, categories, counts, destinations, and decisions —
  never the underlying values.

## 6. Post-Incident

1. **Feed the detector loop.** Record verdicts on the involved events in the
   dashboard (valid, false positive, too sensitive, missed) so detector
   feedback reporting reflects the incident.
2. **Close the detection gap.** For a missed pattern, add a custom detector or
   exact-match entry; for a policy gap, adjust severity thresholds or
   `alwaysBlock`. Detector changes go in `detection-engine/detect.js` followed
   by `npm run sync-engine`.
3. **Re-run the gate.** `npm run review:ci` must pass, including detection
   eval, before the fix ships.
4. **Verify posture recovered.** Coverage shows all required sensors active;
   preflight passes in production mode; audit chain verifies clean.
5. **Update this runbook** with anything the incident taught you, and schedule
   a fresh evidence pack so the post-incident state is captured.
