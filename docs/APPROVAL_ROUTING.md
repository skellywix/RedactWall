# Approval Routing

PromptWall assigns held decisions before they become a shared queue problem. The
first routing pass is deterministic and metadata-only: rules use detector ids,
semantic categories, source, channel, destination, severity, and risk score.
They do not read raw prompt bodies, extracted file text, token vaults, decision
notes, or uploaded file bytes.

## Stored Workflow Fields

Routeable blocked records carry:

- `assignedRole`: `security_admin` or `approver`.
- `assignedGroup`: `security`, `compliance`, `privacy`, or `legal`.
- `workflowReason`: the detector, category, source, or critical-risk reason.
- `slaDueAt`: the review deadline in ISO-8601 UTC.
- `escalatedAt`: reserved for later persisted escalation state.
- `notificationStatus`: currently `not_configured` until a customer notification
  channel is connected.

The dashboard exposes the owner and SLA in the approval queue, all-activity
table, selected incident detail, and queue filters. SIEM alerts and examiner
exports include only the sanitized workflow summary.

## Default Routing Rules

| Signal | Assigned group | Assigned role | SLA |
| --- | --- | --- | --- |
| `SECRET_KEY`, `PRIVATE_KEY`, `CREDENTIALS`, `PASSWORD`, `CANARY_TOKEN` | `security` | `security_admin` | 30 minutes |
| `SOURCE_CODE` | `security` | `security_admin` | 60 minutes |
| `MEMBER_ID`, `LOAN_NUMBER`, `US_SSN`, payment or banking entities | `compliance` | `approver` | 4 hours |
| `HEALTH_RECORD`, `MEDICAL_RECORD_NUMBER`, `HEALTH_INSURANCE_ID`, `US_NPI` | `privacy` | `approver` | 4 hours |
| `CONFIDENTIAL_BUSINESS` | `legal` | `approver` | 4 hours |
| `LEGAL_CONTRACT` | `legal` | `approver` | 8 hours |
| Endpoint file-flow events without a stronger detector match | `security` | `approver` | 2 hours |
| Critical severity or risk score at least 75 | `security` | `security_admin` | no more than 60 minutes |

## Operating Notes

- Treat the routing fields as the ownership contract for the current release.
- Do not use free-form prompt text or file names in routing reasons.
- Configure external notifications only after the destination is approved for
  sanitized security events.
- Future SSO and SCIM work should map IdP groups onto these stable route groups
  instead of replacing the stored evidence fields.

## Verification

Run:

```powershell
npm test -- test/routing.test.js test/approval-routing.test.js test/alerts.test.js test/evidence.test.js
```

For full release review, include:

```powershell
npm run review:ci
```

## Works Cited

National Institute of Standards and Technology. "Incident Response
Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0
Community Profile." *NIST Special Publication 800-61 Revision 3*, U.S.
Department of Commerce, 3 Apr. 2025,
https://doi.org/10.6028/NIST.SP.800-61r3. Accessed 28 June 2026.

National Institute of Standards and Technology. "The NIST Cybersecurity
Framework (CSF) 2.0." *NIST Cybersecurity White Paper 29*, U.S. Department of
Commerce, 26 Feb. 2024, https://doi.org/10.6028/NIST.CSWP.29. Accessed 28 June
2026.
