# Credit-Union 30-Day Pilot Playbook

A repeatable pilot that ends with the artifact that wins the deal: a
tamper-evident, NCUA/GLBA-mapped **examiner evidence pack** the credit union can
hand to an examiner. Scope is deliberately the **data-protection slice** —
stopping member NPI from leaking into AI tools and proving it — not model-risk
or fair-lending (those stay credit-union-owned).

> Everything RedactWall produces is an **evidence pointer, not certification**.
> The pilot proves the control works and generates the evidence; the credit
> union's compliance officer and examiner draw the conclusions.

## Deployment shape
- **Single-tenant AWS customer silo** (per `DECISIONS.md`), not shared SaaS.
- On-device detection: prompts are scanned locally; only masked evidence and
  hashes reach the control plane.
- Gate before handover with `npm run silo:smoke` (asserts a non-cloud evidence
  store, a verifying audit chain, and a schemaVersion-3 examiner export).

## Timeline

### Week 0 — Setup (0.5 day)
- Stand up the silo; run `npm run setup:check -- --production`.
- Apply the `ncua_glba` policy template (member-NPI hard stops).
- Optionally enable the relevant core-banking detector (Symitar/Episys,
  Corelation, Fiserv, Finastra) in `config/custom-detectors.json` and fingerprint
  a member-number sample with `npm run edm:fingerprint` (local only).
- Install the browser, endpoint, and MCP sensors on the pilot cohort.
- Record AUP adoption as an attestation (date + minutes reference).

### Weeks 1–2 — Observe
- Run in `warn`/`coach` mode; catalog where AI is actually used (shadow-AI + the
  declared AI use-case inventory).
- Confirm zero benign false positives on the cohort's real traffic.

### Week 3 — Enforce
- Move member-NPI hard stops to `block`; keep the approval queue + step-up.
- Exercise the 72-hour incident workflow once end-to-end (tabletop).

### Week 4 — Examiner dry run
- Export the pack: `node scripts/export-evidence-pack.js --examiner-profile federal_credit_union --format md`.
- Walk the compliance officer through the rendered report and control tests.
- Assemble the vendor-risk artifacts: `npm run security:package -- --zip` (per-control
  assurance levels, NCUA-mapped due-diligence, sample DPA/BAA/flow-down).

## Success scorecard (examiner-tied)

| Outcome | Evidence | Target |
| --- | --- | --- |
| Member NPI blocked before reaching AI | Enforcement counts in the examiner pack | Every hard-stop type blocking |
| "Where are we using AI?" answered | AI use-case inventory + shadow-AI review | Inventory complete, no overdue reviews |
| Controls tested (748 App A) | `controlTests` rollup with honest `lastTestedAt` | Audit chain verifies; backup/restore drilled |
| Tamper-evident audit | `verifyAuditChain()` -> `ok:true` | Green throughout |
| Zero false positives on real traffic | Detector eval floors + cohort review | benign-FP = 0 |
| Vendor due diligence satisfied | Security Trust Package + DDQ + sample agreements | Filed in the CU's vendor folder |
| Incident readiness | 72-hour workflow exercised once | Deadline tracked; CU files with NCUA |

## Explicitly out of scope (hand-off, not RedactWall)
- Board-adoptable AUP prose, board minutes, and 5300/863 filings.
- Model-risk management / fair-lending review of any lending model.
- The independent SOC 2 audit and penetration test (roadmap; the trust package
  is self-attested until then).
