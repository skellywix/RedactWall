# Approval Routing

PromptWall assigns held decisions before they become a shared queue problem.
Routing is metadata-only: rules use provisioned SCIM user names, SCIM groups,
org ids, detector ids, semantic categories, source, channel, destination,
severity, and risk score. They do not read raw prompt bodies, extracted file
text, token vaults, decision notes, or uploaded file bytes.

## Stored Workflow Fields

Routeable blocked records carry:

- `assignedRole`: `security_admin` or `approver`.
- `assignedGroup`: `security`, `compliance`, `privacy`, or `legal`.
- `workflowReason`: the detector, category, source, or critical-risk reason.
- `slaDueAt`: the review deadline in ISO-8601 UTC.
- `escalatedAt`: when the SLA monitor escalated the record.
- `escalationReason`: currently `sla_due` for overdue approval items.
- `notificationStatus`: `not_configured`, `sent`, `partial`, or `failed`.
- `notificationLastAttemptAt`: when PromptWall last attempted workflow
  notification delivery.
- `notificationAttemptCount`: number of persisted notification attempts.
- `notificationChannels`: bounded channel names such as `webhook`, `slack`,
  `teams`, or `smtp`, never URLs, hosts, recipients, or tokens.

The dashboard exposes the owner and SLA in the approval queue, all-activity
table, selected incident detail, queue filters by workflow state, category, and
destination, notification state, and escalation state. SIEM alerts and examiner
exports include only the sanitized workflow summary.

## Customer Routing Rules

Security Admins can configure `approvalRoutingRules` from the Policy tab or via
`PUT /api/policy`. The rules are evaluated in array order. The first enabled
matching rule wins; if no rule matches, PromptWall uses the default routing table
below.

Each rule can match on:

- `users`: provisioned SCIM `userName` values such as
  `counsel@example.test`.
- `groups`: provisioned SCIM group display names such as
  `PromptWall Legal`.
- `orgIds`: managed deployment or customer-silo org ids.
- `detectors`: built-in detector ids such as `MEMBER_ID`, `SOURCE_CODE`, or
  `SECRET_KEY`.
- `categories`: semantic detector categories such as `LEGAL_CONTRACT` or
  `CONFIDENTIAL_BUSINESS`.
- `sources`: sensor ids such as `browser_extension`, `endpoint_agent`, or
  `mcp_guard`.
- `channels`: event channels such as `submit`, `file_upload`, `ai_response`, or
  `shadow_ai`.
- `destinations`: governed AI hosts or desktop labels. Wildcards follow the same
  destination matching rules as block lists.
- `minSeverity` and `minRiskScore`.

Example:

```json
[
  {
    "id": "member_services_chatgpt",
    "detectors": ["MEMBER_ID", "LOAN_NUMBER"],
    "destinations": ["chatgpt.com"],
    "assignedGroup": "member_services",
    "assignedRole": "approver",
    "slaMinutes": 120,
    "reason": "member_services"
  },
  {
    "id": "engineering_source_code",
    "groups": ["PromptWall Engineers"],
    "categories": ["SOURCE_CODE"],
    "sources": ["browser_extension"],
    "assignedGroup": "engineering",
    "assignedRole": "approver",
    "slaMinutes": 90,
    "reason": "engineering_review"
  }
]
```

Rule ids, group ids, and reason codes are bounded identifiers so workflow
metadata stays clean in the dashboard, SIEM alerts, audit history, and examiner
exports. Critical-risk items still keep the built-in safety floor:
`security_admin` ownership and no more than a 60-minute SLA unless the item is
already routed to legal.

The sensor policy endpoint, `/api/v1/policy`, does not expose
`approvalRoutingRules`; sensors only need enforcement and scanner controls.

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
- Security Admins can approve, deny, and reveal retained raw prompts for any
  held item after the required step-up. Optional local approver accounts can
  approve or deny only items assigned to `assignedRole: "approver"` and their
  `assignedUser`, when present. Approvers cannot reveal raw prompts, purge
  retention, edit policy, or review governed destinations.
- Do not use free-form prompt text or file names in routing reasons.
- Configure external notifications only after the destination is approved for
  sanitized security events. Notification payloads include query id, owner,
  source, destination, severity, detector labels, and SLA. They do not include
  prompt bodies, redacted previews, raw findings, token vaults, release tokens,
  decision notes, or uploaded file bytes.
- SCIM provisioning maps known PromptWall IdP groups onto these stable route
  roles. OIDC login consumes those active provisioned users and group-derived
  roles instead of replacing the stored evidence fields. Approval routing can
  also use the same SCIM group membership to assign held incidents to customer
  reviewer pools such as legal, lending, or engineering.

## Notification Channels

PromptWall can notify workflow systems without adding another sensitive data
sink. The app sends best-effort notifications and records the delivery outcome
on the query plus an audit event.

| Channel | Env var |
| --- | --- |
| Generic JSON webhook | `PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_URL` or `APPROVAL_NOTIFY_WEBHOOK_URL` |
| Generic webhook bearer token | `PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_TOKEN` or `APPROVAL_NOTIFY_WEBHOOK_TOKEN` |
| Slack incoming webhook | `PROMPTWALL_APPROVAL_SLACK_WEBHOOK_URL` or `APPROVAL_SLACK_WEBHOOK_URL` |
| Microsoft Teams webhook | `PROMPTWALL_APPROVAL_TEAMS_WEBHOOK_URL` or `APPROVAL_TEAMS_WEBHOOK_URL` |
| SMTP host | `PROMPTWALL_APPROVAL_SMTP_HOST` or `APPROVAL_SMTP_HOST` |
| SMTP port | `PROMPTWALL_APPROVAL_SMTP_PORT` or `APPROVAL_SMTP_PORT`; defaults to `587`, or `465` when implicit TLS is enabled |
| SMTP from address | `PROMPTWALL_APPROVAL_SMTP_FROM` or `APPROVAL_SMTP_FROM` |
| SMTP recipients | `PROMPTWALL_APPROVAL_SMTP_TO` or `APPROVAL_SMTP_TO`; separate addresses with commas or semicolons |
| SMTP username | `PROMPTWALL_APPROVAL_SMTP_USERNAME` or `APPROVAL_SMTP_USERNAME` |
| SMTP password | `PROMPTWALL_APPROVAL_SMTP_PASSWORD` or `APPROVAL_SMTP_PASSWORD` |
| SMTP implicit TLS | `PROMPTWALL_APPROVAL_SMTP_SECURE=true` or `APPROVAL_SMTP_SECURE=true` |
| SMTP insecure local relay opt-in | `PROMPTWALL_APPROVAL_SMTP_ALLOW_INSECURE=true` or `APPROVAL_SMTP_ALLOW_INSECURE=true` |

The generic webhook receives the canonical sanitized JSON payload. Slack and
Teams receive channel-native message shapes built from the same sanitized
payload. SMTP receives the same routing metadata as a plain-text email. Webhook
URLs and SMTP credentials are secrets; keep them in environment or
secret-manager configuration only. SMTP requires TLS by default and will only use
an insecure relay when the explicit insecure-local-relay opt-in is set.

## SLA Escalation

`startServer()` checks overdue routed approvals at startup and then every five
minutes. Items with `slaDueAt` in the past receive:

- `escalatedAt`: current UTC timestamp.
- `escalationReason`: `sla_due`.
- `assignedRole`: promoted to `security_admin` unless already assigned there.
- `APPROVAL_ESCALATED`: an audit entry bound into the hash chain.
- A second approval notification with action `APPROVAL_ESCALATED`, when a
  notification channel is configured.

## Verification

Run:

```powershell
npm test -- test/routing.test.js test/approval-routing.test.js test/alerts.test.js test/evidence.test.js
npm test -- test/notifiers.test.js test/workflow-notifications.test.js
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

Slack. "Sending Messages Using Incoming Webhooks." *Slack Developer Docs*,
Slack, https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/.
Accessed 28 June 2026.

Microsoft. "Create and Send Actionable Messages." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/connectors-using.
Accessed 28 June 2026.

Klensin, John. "Simple Mail Transfer Protocol." *RFC 5321*, Internet
Engineering Task Force, Oct. 2008, https://www.rfc-editor.org/rfc/rfc5321.
Accessed 28 June 2026.

Hoffman, Paul. "SMTP Service Extension for Secure SMTP over Transport Layer
Security." *RFC 3207*, Internet Engineering Task Force, Feb. 2002,
https://www.rfc-editor.org/rfc/rfc3207. Accessed 28 June 2026.
