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
- Evidence records include matched scope ids and exception ids, not raw prompt
  bodies.

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
      "reason": "approved_vendor_review"
    }
  ]
}
```

Exceptions currently support `action: "allow"` only. If a matching event contains
an `alwaysBlock` entity such as `US_SSN`, `CREDIT_CARD`, `SECRET_KEY`, or
`PRIVATE_KEY`, the exception is ignored and the event still blocks.

## Configure

Update the advanced policy fields through the authenticated admin policy API:

```bash
curl -X PUT https://promptwall.customer.example/api/policy \
  -H "Content-Type: application/json" \
  -H "Cookie: promptwall_session=<session>" \
  -H "x-csrf-token: <csrf-token>" \
  -d @scoped-policy.json
```

The dashboard policy editor preserves existing `policyScopes` and
`policyExceptions` when saving other policy fields, but it does not yet provide
dedicated form controls for them.

## Verify

Use synthetic events only:

```bash
npm test -- test/policy-scope.test.js test/policy-scope-api.test.js
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```
