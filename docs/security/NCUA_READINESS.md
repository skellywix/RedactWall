# NCUA Readiness Center

Examiner-readiness for federal credit unions: one console view (Govern →
**NCUA Readiness**) plus an examiner-profile evidence pack, composed entirely
from evidence RedactWall already keeps. Prompt-free by construction — counts,
enums, hashes, masked findings, and bounded labels only.

Plan and phasing: `PLANS/ncua-readiness-center.md` (this is slice 1,
Examiner Proof). The AI use-case inventory, 72-hour incident workflow, and
Board Packet ship in later slices.

## Federal credit union setup (operator guide)

1. **Apply the baseline policy.** Configuration → templates → apply
   **NCUA / GLBA (credit unions, banks)** (`ncua_glba`). This hard-stops
   member nonpublic personal information: SSN, member ID, loan number,
   account and routing numbers, cards, DOB, TIN.
2. **Tune core-banking detectors.** Enable only the relevant disabled starter
   detector in `config/custom-detectors.json`, adapt it to the institution's
   identifier format, and validate representative hard negatives. Do not put
   enumerable member, account, or loan numbers in an offline EDM pack.
3. **Require the sensors you deploy.** Coverage → required sensors: browser
   extension, endpoint agent, and MCP guard for any AI-agent usage. The
   readiness score counts required-sensor health.
4. **Review AI destinations.** Govern → App Catalog: sanction the tools each
   department may use; leave `blockUnapprovedAiDestinations` on so
   unreviewed AI tools stay default-deny.
5. **Schedule the examiner pack** (below) and verify backups
   (`npm run backup`, `npm run backup:drill`) so evidence health stays green.

The NCUA Readiness view scores all of this continuously and lists the gaps
under "Close the gaps", each linking to the screen that fixes it.

## What to hand an NCUA examiner

Export from the NCUA Readiness header (**Export examiner pack**), the CLI, or
the scheduled task:

```bash
node scripts/export-evidence-pack.js --examiner-profile federal_credit_union
```

The pack is the standard evidence pack (schemaVersion 3 when the profile is
set) plus:

- `scope.examinerProfile: "federal_credit_union"`
- `ncuaReadiness` — the readiness report: score, control states, member-data
  outcomes (prevented / redacted / released), shadow-AI review rollup, EDM
  status, exception-review lifecycle, audit-chain verification.
- `edm` — watchlist status: enabled, fingerprint **count**, thresholds. The
  salt and the fingerprints themselves are never exported.
- `controlMappings` — includes the credit-union control families (NCUA
  Part 748 Appendix A member-information safeguards, 12 CFR 748.1(c)
  incident readiness, service-provider oversight, board reporting) alongside
  the existing GLBA/HIPAA/PCI and AI-framework mappings.

What is **never** in the pack: prompt bodies, raw findings, token vaults,
audit detail text, secrets, local file paths, EDM salts or fingerprints
(`scope.rawPromptBodiesIncluded` and `scope.auditDetailsIncluded` are
hardcoded `false`; regression-tested in `test/evidence.test.js`).

Talking points that map to NCUA 2026 exam priorities:

| Examiner question | Where it is answered |
|---|---|
| "What AI tools are in use, and who approved them?" | `ncuaReadiness.panels.shadowAi` + App Catalog review trail (audit actions `DESTINATION_REVIEWED`) |
| "How do you keep member data out of AI tools?" | `member_information_safeguards` control: mandatory structured-identifier hard stops plus institution-tuned custom detectors, with per-event outcomes in `queries[]` (masked) |
| "Show me your monitoring evidence." | Hash-chained audit (`auditIntegrity.ok`), coverage totals, safe-to-send receipts |
| "What happens when something gets through?" | Approval workflow, exception review lifecycle (`policyExceptionReview`), incident workflow (slice 3) |

## AI use-case inventory

NCUA's 2026 exam priorities put "what AI is in use, for what, approved by
whom" first. The inventory lives in the NCUA Readiness view: one record per
**(tool host, department)**, so "ChatGPT in Lending" and "ChatGPT in
Marketing" carry separate approvals, owners, allowed data classes, review
status, vendor-review status, and next-review dates.

- Records are Security-Admin mutations (CSRF-protected); every change appends
  a `USE_CASE_UPDATED` / `USE_CASE_REVIEWED` audit entry carrying enums,
  counts, and dates only — never the operator's free text.
- Input validation keeps records inventory-shaped: hostname-only
  destinations (no URLs or paths), single-line bounded text with sensitive
  codes rejected, `allowedDataClasses` validated against real detector ids.
- The `ai_use_inventory` control goes **covered** when records exist and no
  review is overdue; `vendor_service_provider_oversight` goes covered when
  every active use case has vendor review completed.
- Examiner packs embed the summary plus records with free-text fields passed
  through pattern redaction at the export boundary.

## Department scoped-policy pack

Department differentiation ships as **tighten-only `policyScopes`** on top of
the `ncua_glba` base template (`docs/identity/POLICY_SCOPES.md`) — never as competing
templates that would overwrite each other. A starting preset for a federal
credit union with SCIM groups provisioned:

```json
{
  "policyScopes": [
    { "id": "cu_lending", "groups": ["Lending"], "enforcementMode": "block",
      "blockMinSeverity": 2, "blockRiskScore": 15,
      "alwaysBlockAdd": ["DOB", "US_DRIVERS_LICENSE"], "reason": "member_loan_files" },
    { "id": "cu_member_services", "groups": ["Member Services", "Contact Center"],
      "enforcementMode": "block", "blockMinSeverity": 2, "blockRiskScore": 15,
      "reason": "member_contact_data" },
    { "id": "cu_collections", "groups": ["Collections"], "enforcementMode": "block",
      "blockMinSeverity": 2, "blockRiskScore": 10, "reason": "delinquency_data" },
    { "id": "cu_marketing", "groups": ["Marketing"], "enforcementMode": "block",
      "blockMinSeverity": 3, "blockRiskScore": 25, "reason": "member_lists" },
    { "id": "cu_it_developers", "groups": ["IT", "Developers"],
      "alwaysBlockAdd": ["SECRET_KEY", "PRIVATE_KEY"], "reason": "credentials_and_source" },
    { "id": "cu_compliance", "groups": ["Compliance"], "enforcementMode": "block",
      "blockMinSeverity": 2, "blockRiskScore": 10, "reason": "exam_and_bsa_material" },
    { "id": "cu_executives", "groups": ["Executives", "Board"], "enforcementMode": "block",
      "blockMinSeverity": 2, "blockRiskScore": 15, "reason": "board_material" }
  ]
}
```

Pair the pack with the safe defaults the readiness score already checks:
`blockUnapprovedAiDestinations: true` (default-deny unapproved AI tools),
required browser/endpoint/MCP sensors, and **member-data routing** — send
member-identifier events to the compliance group via `approvalRoutingRules`
(`docs/identity/APPROVAL_ROUTING.md`), e.g. route `detectors: ["MEMBER_ID",
"LOAN_NUMBER", "EXACT_MATCH"]` to `group: "compliance"`, so a member-data
hold always lands with the team that answers to the examiner.

## 72-hour incident readiness

NCUA's cyber-incident reporting rule (12 CFR §748.1(c)) requires reporting a
reportable cyber incident within **72 hours** of reasonably believing one
occurred. The NCUA Readiness view tracks that clock:

- A Security Admin opens an incident from the held/blocked event ids involved
  (single-line title only — validation rejects member-data shapes). The
  server stamps `detectedAt` and `deadlineAt = detectedAt + 72h`.
- The incident **timeline is derived** from the referenced events through the
  same sanitizer the evidence pack uses: who, destination, decision, data
  classes, blocked vs exposed — never prompt text, never audit note text.
- Status flow: `open → under_review → reported/closed`; marking `reported`
  stamps `reportedAt`. The `incident_readiness` control shows `attention`
  whenever any open incident is past its deadline.
- Examiner packs embed the summary and pattern-redacted incident records with
  their timelines. RedactWall tracks readiness and evidence — the actual
  report to the NCUA is filed by your team through official channels.

## Board packet

**Board packet** (NCUA Readiness header) downloads a prompt-free executive
JSON summary: readiness score, member-data outcomes, shadow-AI review state,
use-case and incident rollups, exception review, audit-chain status, and
**seat aggregates with a license true-up** (licensed seats vs configured
limit vs seats used — the per-user roster is never included). Each export is
recorded in the audit log, and the `board_reporting` control grades
`covered` while the latest packet is within the quarterly cadence.

## High-entropy exact-match import

`config/exact-match.json` is an offline sensor pack for random identifiers
with at least 96 bits of source entropy. Version 2 stores a public salt and
SHA-256 fingerprints and rejects enumerable identifiers such as SSNs, member
numbers, account numbers, loan numbers, names, and email addresses. The salt
and fingerprints ship to managed sensors, so hashing alone cannot protect a
low-entropy source value from offline guessing.

```bash
# One random identifier per line, for example UUIDv4 or a >=96-bit opaque token.
# Generate the source file locally, build the pack, then securely remove the source.
node scripts/edm-fingerprint.js --in random-identifiers.txt
```

- Legacy packs and ineligible values fail closed. Rebuild a legacy pack from
  the complete eligible source list before re-enabling it.
- Re-runs must use the same salt (the script refuses to merge mismatched
  salts); rebuild the full eligible list to rotate the salt.
- Status (enabled + fingerprint count) appears in the NCUA Readiness EDM
  panel and the `edm` section of evidence packs. Counts only — never the
  salt, never the fingerprints.
- Use mandatory built-in detectors and carefully tuned custom detectors for
  low-entropy member, account, and loan identifiers. A future protected
  server-side lookup is the appropriate design if exact roster matching is
  required for those enumerable values.

## Scheduled examiner packs

The existing evidence-pack schedule (`docs/deployment/EVIDENCE_PACK_TASK.md`) carries
the profile: add `"examinerProfile": "federal_credit_union"` to
`config/evidence-schedule.json`, or pass `--examiner-profile` on the CLI.
Everything else (retention, zip, backup evidence inputs) is unchanged. The
console's Evidence health panel and the pack's `exportHealth` section read
`config/evidence-schedule.json` — a schedule kept at a custom path shows as
"not scheduled" there even though the CLI honors it.

## Licensing

The console module is entitlement-gated (`license.entitled('ncua_readiness')`):

- **Demo mode (no license): fully visible** — the license never disables the
  security function, and this is the sales demo.
- **Licensed:** included with the `enterprise` plan; `standard` plans add the
  `ncua_readiness` feature flag (see `docs/process/CUSTOMER_LICENSING.md`).
- **Every license state exports evidence.** Read-only license state blocks
  configuration writes as usual; readiness reads and examiner packs always
  work.

## API

`GET /api/ncua/readiness` (any authenticated console role, prompt-free)
returns `{ entitled, report }`. `POST /api/ncua/board-packet` (Security Admin
or Auditor, CSRF-protected) returns the board packet JSON and records
`BOARD_PACKET_EXPORTED` evidence for the cadence control. The examiner pack is
`GET /api/export/evidence?examinerProfile=federal_credit_union`
(Security Admin or Auditor, like every evidence export).
