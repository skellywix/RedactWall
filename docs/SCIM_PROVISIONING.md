# PromptWall SCIM Provisioning

PromptWall exposes a minimal SCIM 2.0 provisioning surface for customer-silo
deployments that need identity lifecycle evidence before full SSO login exists.
It stores users and groups, deactivates users, maps known PromptWall group names
to local roles, and writes sanitized audit entries into the hash chain.

This is not login yet. Local Security Admin, approver, and auditor accounts still
control console sessions until SSO/OIDC consumes the provisioned identities.

## Enablement

Set one strong bearer token in the customer secret store:

```text
SCIM_BEARER_TOKEN=<32-plus-random-characters>
```

`PROMPTWALL_SCIM_BEARER_TOKEN` is accepted as the product-prefixed alias. Leave
both unset or empty to disable `/scim/v2/*`; disabled endpoints return 404.
Production preflight blocks a configured token shorter than 32 characters.

Rotate the token by updating the customer IdP provisioning app and the PromptWall
secret in the same maintenance window. Do not put the token in policy files,
support tickets, screenshots, or handoff packets.

## Endpoints

Base URL:

```text
https://promptwall.customer.example/scim/v2
```

Supported resources:

| Method | Path | Behavior |
| --- | --- | --- |
| `GET` | `/ServiceProviderConfig` | Reports bearer auth, patch support, and simple filter support. |
| `GET` | `/Users` | Lists users. Supports `filter=userName eq "..."` and `filter=externalId eq "..."`. |
| `POST` | `/Users` | Creates a user. Duplicate `userName` returns SCIM 409 `uniqueness`. |
| `GET` | `/Users/:id` | Reads one user. |
| `PUT` | `/Users/:id` | Replaces supported user fields. |
| `PATCH` | `/Users/:id` | Supports `active`, `displayName`, and `roles` replacements. |
| `DELETE` | `/Users/:id` | Deactivates the user instead of deleting the row. |
| `GET` | `/Groups` | Lists groups. Supports `filter=displayName eq "..."` and `filter=externalId eq "..."`. |
| `POST` | `/Groups` | Creates a group. Duplicate `displayName` returns SCIM 409 `uniqueness`. |
| `GET` | `/Groups/:id` | Reads one group. |
| `PUT` | `/Groups/:id` | Replaces supported group fields. |
| `PATCH` | `/Groups/:id` | Adds, replaces, or removes group members. |
| `DELETE` | `/Groups/:id` | Deletes the provisioned group. |

Use `Authorization: Bearer <token>` and `Content-Type: application/scim+json`
for writes.

## Role Mapping

Group display names map onto the existing PromptWall route roles:

| PromptWall role | Matching group display names |
| --- | --- |
| `security_admin` | `PromptWall Security Admins`, `Security Admins`, `Admins` |
| `approver` | `PromptWall Approvers`, `PromptWall Reviewers`, `Approvers`, `Reviewers` |
| `auditor` | `PromptWall Auditors`, `PromptWall Read-only`, `Auditors`, `Read-only` |
| `operator` | `PromptWall Operators`, `PromptWall Ops`, `Operators`, `Ops` |

Direct SCIM `roles` values can also set one of the same normalized role names.
If no direct or group role matches, the user resource returns `auditor` as the
safe default. A provisioned role does not grant console login until SSO/OIDC is
implemented.

## Example Smoke Test

```bash
curl -sS \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  https://promptwall.customer.example/scim/v2/ServiceProviderConfig

curl -sS \
  -X POST \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"PromptWall Approvers"}' \
  https://promptwall.customer.example/scim/v2/Groups
```

After provisioning, verify the audit chain:

```bash
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

SCIM audit entries include bounded metadata such as user names, active state,
group names, and member counts. They do not include prompt bodies, raw findings,
tokens, MFA seeds, or IdP secrets.

## IdP Notes

For Microsoft Entra or Okta-style provisioning, configure:

- Tenant URL: `https://promptwall.customer.example/scim/v2`
- Secret token: the `SCIM_BEARER_TOKEN` value from the approved vault
- Provision users and groups
- Assign groups using the PromptWall display names above when role mapping is
  needed
- Keep local break-glass Security Admin credentials enabled until SSO/OIDC login
  is available and tested

## Works Cited

Internet Engineering Task Force. "System for Cross-Domain Identity Management:
Protocol." *RFC 7644*, RFC Editor, Sept. 2015,
https://www.rfc-editor.org/rfc/rfc7644. Accessed 28 June 2026.

Microsoft. "Tutorial: Develop and Plan Provisioning for a SCIM Endpoint in
Microsoft Entra ID." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups.
Accessed 28 June 2026.
