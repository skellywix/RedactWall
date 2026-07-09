# Texas FCU Product Map

Last updated: 2026-07-09

## Positioning

RedactWall is positioned for Texas Federal Credit Unions that want employees to
use AI tools without exposing member nonpublic personal information, loan files,
credentials, contracts, or confidential operating context.

The app should read like a credit-union control plane, not a generic DLP
dashboard. Use Texas FCU, member data, examiner evidence, NCUA, GLBA, board
readiness, AI vendor review, and branch/team language wherever the user is
making a compliance or operating decision.

The regulatory framing is federal-credit-union first:

- NCUA and GLBA member-information safeguards: https://ncua.gov/regulation-supervision/manuals-guides/federal-consumer-financial-protection-guide/compliance-management/deposit-regulations/privacy-consumer-financial-information-regulation-p
- NCUA cyber incident notification readiness: https://ncua.gov/regulation-supervision/letters-credit-unions-other-guidance/cyber-incident-notification-requirements
- NCUA board cybersecurity oversight: https://ncua.gov/regulation-supervision/letters-credit-unions-other-guidance/board-director-engagement-cybersecurity-oversight

Texas is the market and operating focus. Do not imply RedactWall replaces legal
counsel, NCUA reporting, state regulator communications, or the credit union's
own incident-response process.

## Section Map

| Section | Tab | Texas FCU job |
|---|---|---|
| Member Defense | Texas FCU Overview | Show the daily member-data protection posture, blocked releases, pending queue, and exposure map. |
| Member Defense | Member Data Queue | Let reviewers approve or deny held AI prompts with exam-ready decision notes and redacted context. |
| Member Defense | FCU Command Center | Give operators a live command view of sanitized member-data posture, AI vendor risk, objectives, and handoff actions. |
| Member Defense | Exam Activity | Let admins search and export recent gated member-data events without exposing raw prompt bodies. |
| Risk & Proof | Member Risk Insights | Show AI use, sensitive categories, blocked or held activity, shadow-AI sightings, and member-data risk trends. |
| Risk & Proof | Texas FCU Coverage | Prove branch browser, endpoint, MCP, discovery, and AI tool inventory coverage by team and control point. |
| Risk & Proof | Member Data Lineage | Summarize employees, AI destinations, sensors, channels, categories, and decisions from sanitized evidence. |
| Risk & Proof | Reviewer Decisions | Track approval quality, SLA posture, coaching signals, overrides, and decision hotspots. |
| Governance | AI Vendor Catalog | Review sanctioned, tolerated, blocked, and shadow AI vendors used by Texas FCU teams. |
| Governance | NCUA / GLBA Controls | Map live RedactWall controls to member-information safeguards, board oversight, incident readiness, and AI governance. |
| Governance | Texas FCU Readiness | Package examiner-ready FCU evidence, use-case inventory, incident readiness, EDM state, and board packet posture. |
| Governance | Identity & Roles | Configure OIDC, SCIM, reviewer groups, and team routing without exposing secrets. |
| Governance | Policy Configuration | Tune Texas FCU policy mode, member-data thresholds, retention, AI vendor governance, hard stops, and sensor setup. |
| Platform | Sensor Rollout | Generate and track browser, endpoint, and MCP sensor packages for branch and remote users. |
| Platform | Evidence Delivery | Configure prompt-free delivery to email, board digest, SIEM, SOAR, and gateway integrations. |
| Platform | Examiner Audit Chain | Inspect the tamper-evident audit chain for policy, admin, and member-data decision evidence. |
| Platform | Controlled Updates | Pull approved releases while preserving FCU evidence data, logs, backups, and update auditability. |

## Copy Rules

Use these terms in user-facing app copy:

- Prefer `member data`, `member-information safeguards`, `AI vendor`, `Texas FCU team`, `exam-ready`, `examiner evidence`, `board packet`, and `NCUA / GLBA`.
- Prefer `employee` or `team` over `user` or `department` when the context is visible to operators. Keep API/schema field names stable when they already use `user` or `department`.
- Prefer `masked text`, `redacted context`, or `prompt-free evidence` over `prompt log`.
- Prefer `held member-data event` or `member-data incident` over generic `prompt`.
- Prefer `AI vendor review` over generic app catalog review.
- Use `Federal Credit Union` or `FCU` when describing the regulated buyer. Avoid broader bank language unless the surface is explicitly multi-industry.

Avoid:

- Claiming Texas-specific legal compliance that is not implemented or documented.
- Suggesting RedactWall files official NCUA reports automatically.
- Exposing raw prompts, raw findings, local paths, URLs, token vault values, or freeform audit text in export or dashboard copy.
- Renaming runtime fields, database columns, or API payload keys just to match marketing language.

## Behavioral Boundaries

This product-map pass is a positioning and information-architecture change. It
must preserve existing behavior:

- No detector, policy, approval, audit, auth, storage, or sensor enforcement
  semantics change from copy-only UI work.
- Existing tests must continue to prove prompt-free posture, evidence export
  privacy, audit-chain behavior, and browser console routes.
- If a future pass changes enforcement or exports, update this document and run
  the broader security and evidence gates called out in `AGENTS.md`.
