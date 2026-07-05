# PromptWall Scoped Policy And Exceptions

PromptWall supports server-side scoped policy for customer-silo deployments that
need stricter rules for specific users, SCIM groups, orgs, sources, channels,
destinations, detectors, or semantic categories.

The feature is intentionally conservative:

- `policyScopes` can only tighten enforcement. They can raise the mode to a
  stricter mode, lower block thresholds, or add hard-stop detector ids.
- `policyExceptions` can temporarily allow matching non-hard-stop content.
- `alwaysBlock` entities cannot be downgraded by a scope or exception.
- Sensors do not receive scoped policy yet. The control plane applies scopes
  when it receives gate and file-scan events.
- Exception owner and review metadata is limited to safe group and role codes.
- Evidence records include matched scope ids, exception ids, and sanitized
  exception review state, not raw prompt bodies.

## Policy Scopes

Example:

```json
{
  "policyScopes": [
    {
      "id": "legal_contract_review",
      "groups": ["PromptWall Legal"],
      "destinations": ["claude.ai"],
      "categories": ["LEGAL_CONTRACT"],
      "enforcementMode": "block",
      "blockMinSeverity": 2,
      "blockRiskScore": 10,
      "alwaysBlockAdd": ["SECRET_KEY"],
      "reason": "legal_review"
    }
  ]
}
```

Supported matchers:

| Matcher | Purpose |
| --- | --- |
| `users` | Managed user id or email from the sensor event. |
| `groups` | SCIM group display names assigned to the user. |
| `orgIds` | Tenant or org id from the sensor event. |
| `sources` | Sensor source such as `browser_extension`, `endpoint_agent`, or `mcp_guard`. |
| `channels` | Event channel such as `submit` or `file_upload`. |
| `destinations` | Host or desktop label matched with the same destination matcher as block lists. |
| `detectors` | Structured detector ids such as `MEMBER_ID` or `US_SSN`. |
| `categories` | Semantic categories such as `LEGAL_CONTRACT` or `SOURCE_CODE`. |
| `accountTypes` | AI-site account identity: `personal`, `corporate`, or `unknown` (ROADMAP N4). Classified locally by the browser sensor from workspace badges and the logged-in account's email domain against `corporateAiAccounts.orgEmailDomains`. |

> **Trust boundary for `accountTypes`.** The account signal is asserted by the
> sensor (like `clientFindings`), and only ever an enum — the raw account email
> never reaches the control plane. Because scopes can only *tighten* policy
> (stricter-wins), a spoofed `corporate` claim can at most forfeit extra
> tightening; it can never weaken `alwaysBlock` or the base thresholds.

Supported scoped overrides:

| Override | Behavior |
| --- | --- |
| `enforcementMode` | Applies only if stricter than the global mode. |
| `blockMinSeverity` | Uses the lower value between global and scoped settings. |
| `blockRiskScore` | Uses the lower value between global and scoped settings. |
| `alwaysBlockAdd` | Adds detector ids to the global hard-stop list for the matched scope. |

## Time-Bound Exceptions

Example:

```json
{
  "policyExceptions": [
    {
      "id": "legal_vendor_24h",
      "users": ["counsel@example.test"],
      "destinations": ["claude.ai"],
      "categories": ["LEGAL_CONTRACT"],
      "expiresAt": "2030-01-01T00:00:00.000Z",
      "ownerGroup": "legal",
      "reviewerRole": "security_admin",
      "reviewAfter": "2029-12-15T00:00:00.000Z",
      "reason": "approved_vendor_review"
    }
  ]
}
```

Exceptions currently support `action: "allow"` only. If a matching event contains
an `alwaysBlock` entity such as `US_SSN`, `CREDIT_CARD`, `SECRET_KEY`, or
`PRIVATE_KEY`, the exception is ignored and the event still blocks.

Lifecycle fields are optional, but recommended:

| Field | Purpose |
| --- | --- |
| `ownerGroup` | Safe routing group responsible for reviewing the exception. |
| `reviewerRole` | Review role, either `security_admin` or `approver`. |
| `reviewAfter` | ISO timestamp when the exception should be reviewed before expiry. |

The examiner evidence pack includes an exception review summary with
`active`, `reviewDue`, `expiringSoon`, and `expired` counts plus per-exception
id, owner group, reviewer role, review timestamp, expiry timestamp, and status.
It does not include matched users, prompt text, or file content.

## Configure

Use the Policy tab's guided scoped-enforcement and time-bound exception builders
for common user, SCIM group, destination, detector, and category rules. The
builders append validated JSON into the `Scoped enforcement rules` and
`Time-bound exceptions` editors so Security Admins can review the exact policy
payload before saving.

Use the advanced JSON editors directly when a customer needs less common
matchers such as org, source, or channel. The fields accept JSON arrays and are
validated by the authenticated admin policy API.

The same fields can also be managed directly through the API:

```bash
curl -X PUT https://promptwall.customer.example/api/policy \
  -H "Content-Type: application/json" \
  -H "Cookie: promptwall_session=<session>" \
  -H "x-csrf-token: <csrf-token>" \
  -d @scoped-policy.json
```

The dashboard renders these fields read-only for auditor sessions and editable
only for Security Admin sessions. Validation rejects malformed matchers and does
not echo sensitive values back in error responses.

## Verify

Use synthetic events only:

```bash
npm test -- test/policy-scope.test.js test/policy-scope-api.test.js
npm run test:browser
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```
