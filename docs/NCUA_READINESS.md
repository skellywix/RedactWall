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
2. **Fingerprint core-banking records** (see the EDM guide below) so *your*
   members' identifiers hard-stop even when their format is ambiguous.
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
| "How do you keep member data out of AI tools?" | `member_information_safeguards` control: hard-stop identifiers + core-banking EDM, with per-event outcomes in `queries[]` (masked) |
| "Show me your monitoring evidence." | Hash-chained audit (`auditIntegrity.ok`), coverage totals, safe-to-send receipts |
| "What happens when something gets through?" | Approval workflow, exception review lifecycle (`policyExceptionReview`), incident workflow (slice 3) |

## Core-banking EDM import

`config/exact-match.json` holds **only** a salt and one-way fingerprints.
The plaintext export is discarded — it never reaches disk in the config, the
database, the sensors, or any export.

```bash
# One value per line: member IDs, account numbers, loan numbers, core-system
# identifiers. Generate the file from the core system, run, then delete it.
node scripts/edm-fingerprint.js --in members.txt
```

- Digits-only forms are fingerprinted too, so `900-123-456` matches
  `900123456`.
- Re-runs must use the same salt (the script refuses to merge mismatched
  salts); re-fingerprint the full list to rotate the salt.
- Status (enabled + fingerprint count) appears in the NCUA Readiness EDM
  panel and the `edm` section of evidence packs. Counts only — never the
  salt, never the fingerprints.

## Scheduled examiner packs

The existing evidence-pack schedule (`docs/EVIDENCE_PACK_TASK.md`) carries
the profile: add `"examinerProfile": "federal_credit_union"` to
`config/evidence-schedule.json`, or pass `--examiner-profile` on the CLI.
Everything else (retention, zip, backup evidence inputs) is unchanged.

## Licensing

The console module is entitlement-gated (`license.entitled('ncua_readiness')`):

- **Demo mode (no license): fully visible** — the license never disables the
  security function, and this is the sales demo.
- **Licensed:** included with the `enterprise` plan; `standard` plans add the
  `ncua_readiness` feature flag (see `docs/CUSTOMER_LICENSING.md`).
- **Every license state exports evidence.** Read-only license state blocks
  configuration writes as usual; readiness reads and examiner packs always
  work.

## API

`GET /api/ncua/readiness` (any authenticated console role, prompt-free)
returns `{ entitled, report }`. The examiner pack is
`GET /api/export/evidence?examinerProfile=federal_credit_union`
(Security Admin or Auditor, like every evidence export).
