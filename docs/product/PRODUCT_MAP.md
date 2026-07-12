# Financial Institution Product Map

Last updated: 2026-07-12 (supersedes the Texas FCU product map — positioning is
now institution-generic so RedactWall sells to credit unions and banks in any
state, not only Texas FCUs)

## Positioning

RedactWall is positioned for regulated financial institutions — credit unions
and banks of any charter and any state — that want employees to use AI tools
without exposing customer or member nonpublic personal information, loan files,
credentials, contracts, or confidential operating context.

The app should read like a financial-institution control plane, not a generic
DLP dashboard. Use institution, customer/member data, examiner evidence,
NCUA / GLBA / FFIEC, board readiness, AI vendor review, and branch/team language
wherever the user is making a compliance or operating decision.

The regulatory framing is examiner-first and framework-aware:

- Credit unions: NCUA member-information safeguards (Part 748 / Appendix A) and
  cyber-incident notification (12 CFR 748.1(c)).
- Banks: GLBA Safeguards, FFIEC IT handbook expectations, and the applicable
  federal/state supervisor's incident-notification rule.
- Keep regulator names only where they are factual (an NCUA control mapping is
  about the NCUA); never use a regulator name as product branding.

Do not imply RedactWall replaces legal counsel, regulator reporting, state
regulator communications, or the institution's own incident-response process.

## Naming Rules (the point of this revision)

- **Never** brand UI, docs, or copy with a specific customer, state, or segment
  ("Texas FCU", "Texas Federal Credit Union", bare "FCU" as a brand noun).
- Prefer `institution`, `financial institution`, or the tenant's own configured
  name where available.
- `member` language is reserved for credit-union regulatory surfaces (the NCUA
  readiness center, Part 748 control copy). Generic surfaces say
  `customer data` or `sensitive data`.

## Section Map

| Section | Tab | Institution job |
|---|---|---|
| Defense | Institution Overview | Show the daily data-protection posture, blocked releases, pending queue, and exposure map. |
| Defense | Approval Queue | Let reviewers approve or deny held AI prompts with exam-ready decision notes and redacted context. |
| Defense | AI Command Center | Give operators a live command view of sanitized data posture, AI vendor risk, objectives, and handoff actions. |
| Defense | Exam Activity | Let admins search and export recent gated events without exposing raw prompt bodies. |
| Risk & Proof | Risk Insights | Show AI use, sensitive categories, blocked or held activity, shadow-AI sightings, and exposure trends. |
| Risk & Proof | Institution Coverage | Prove branch browser, endpoint, MCP, discovery, and AI tool inventory coverage by team and control point. |
| Risk & Proof | Data Lineage | Summarize employees, AI destinations, sensors, channels, categories, and decisions from sanitized evidence. |
| Risk & Proof | Reviewer Decisions | Track approval quality, SLA posture, coaching signals, overrides, and decision hotspots. |
| Governance | AI Vendor Catalog | Review sanctioned, tolerated, blocked, and shadow AI vendors used by institution teams. |
| Governance | NCUA / GLBA Controls | Map live RedactWall controls to information safeguards, board oversight, incident readiness, and AI governance. |
| Governance | Examiner Readiness | Package examiner-ready evidence, use-case inventory, incident readiness, EDM state, and board packet posture. |
| Governance | Identity & Roles | Configure OIDC, SCIM, reviewer groups, and team routing without exposing secrets. |
| Governance | Policy Configuration | Tune institution policy mode, data thresholds, retention, AI vendor governance, hard stops, and sensor setup. |
| Platform | Sensor Rollout | Generate and track browser, endpoint, and MCP sensor packages for branch and remote users. |
| Platform | Evidence Delivery | Configure prompt-free delivery to email, board digest, SIEM, SOAR, and gateway integrations. |
| Platform | Examiner Audit Chain | Inspect the tamper-evident audit chain for policy, admin, and data-decision evidence. |
| Platform | Controlled Updates | Pull approved releases while preserving institution evidence data, logs, backups, and update auditability. |

## Copy Rules

Use these terms in user-facing app copy:

- Prefer `institution`, `customer data` / `sensitive data` (or `member data` on
  credit-union regulatory surfaces), `AI vendor`, `exam-ready`,
  `examiner evidence`, `board packet`, and `NCUA / GLBA / FFIEC`.
- Prefer `employee` or `team` over `user` or `department` when the context is
  visible to operators. Keep API/schema field names stable when they already
  use `user` or `department`.
- Prefer `masked text`, `redacted context`, or `prompt-free evidence` over
  `prompt log`.
- Prefer `AI vendor review` over generic app catalog review.

Avoid:

- Any state-, customer-, or segment-branded naming in UI or docs.
- Claiming jurisdiction-specific legal compliance that is not implemented or
  documented.
- Suggesting RedactWall files official regulator reports automatically.
- Exposing raw prompts, raw findings, local paths, URLs, token vault values, or
  freeform audit text in export or dashboard copy.
- Renaming runtime fields, database columns, or API payload keys just to match
  marketing language.

## Behavioral Boundaries

This product-map pass is a positioning and information-architecture change. It
must preserve existing behavior:

- No detector, policy, approval, audit, auth, storage, or sensor enforcement
  semantics change from copy-only UI work.
- Existing tests must continue to prove prompt-free posture, evidence export
  privacy, audit-chain behavior, and browser console routes.
- If a future pass changes enforcement or exports, update this document and run
  the broader security and evidence gates called out in `AGENTS.md`.
