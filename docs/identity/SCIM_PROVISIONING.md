# RedactWall SCIM Provisioning And OIDC Login

RedactWall exposes a minimal SCIM 2.0 provisioning surface and a SCIM-backed
OpenID Connect login bridge for customer-silo deployments. SCIM stores users and
groups, deactivates users, maps known RedactWall group names to local roles, and
writes sanitized audit entries into the hash chain. OIDC then consumes those
active provisioned identities to issue console sessions with the same
`security_admin`, `approver`, `auditor`, and `operator` route roles.

Local Security Admin, approver, and auditor credentials remain the break-glass
path. OIDC login does not grant access to unprovisioned or inactive SCIM users.

## Enablement

Set one strong bearer token in the customer secret store:

```text
SCIM_BEARER_TOKEN=<32-plus-random-characters>
```

`REDACTWALL_SCIM_BEARER_TOKEN` is accepted as the product-prefixed alias. Leave
both unset or empty to disable `/scim/v2/*`; disabled endpoints return 404.
Production preflight blocks a configured token shorter than 32 characters.

Rotate the token by updating the customer IdP provisioning app and the RedactWall
secret in the same maintenance window. Do not put the token in policy files,
support tickets, screenshots, or handoff packets.

## Endpoints

Base URL:

```text
https://redactwall.customer.example/scim/v2
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

Group display names map onto the existing RedactWall route roles:

| RedactWall role | Matching group display names |
| --- | --- |
| `security_admin` | `RedactWall Security Admins`, `Security Admins`, `Admins` |
| `approver` | `RedactWall Approvers`, `RedactWall Reviewers`, `Approvers`, `Reviewers` |
| `auditor` | `RedactWall Auditors`, `RedactWall Read-only`, `Auditors`, `Read-only` |
| `operator` | `RedactWall Operators`, `RedactWall Ops`, `Operators`, `Ops` |

Direct SCIM `roles` values can also set one of the same normalized role names.
If no direct or group role matches, the user resource returns `auditor` as the
safe default. OIDC login uses this effective role after the ID token is validated
and the user is confirmed active in SCIM.

The same provisioned group membership can also drive `approvalRoutingRules`.
For example, a rule with `groups: ["RedactWall Legal"]` and
`categories: ["LEGAL_CONTRACT"]` can assign held contract prompts to the legal
review pool while storing only the sanitized workflow owner, reason, and SLA on
the evidence record.

## OIDC Login

Configure the IdP web application with this redirect URI:

```text
https://redactwall.customer.example/auth/oidc/callback
```

Set these server-side secrets:

```text
OIDC_ISSUER=https://login.customer.example/<tenant-or-org>
OIDC_CLIENT_ID=<registered-web-client-id>
OIDC_CLIENT_SECRET=<32-plus-random-characters>
OIDC_REDIRECT_URI=https://redactwall.customer.example/auth/oidc/callback
```

`REDACTWALL_OIDC_*` aliases are accepted for each value. RedactWall discovers
`authorization_endpoint`, `token_endpoint`, and `jwks_uri` from the issuer's
`.well-known/openid-configuration` document by default. If discovery is not
available, set all three explicit endpoint variables:

```text
OIDC_AUTHORIZATION_ENDPOINT=https://login.customer.example/oauth2/v2.0/authorize
OIDC_TOKEN_ENDPOINT=https://login.customer.example/oauth2/v2.0/token
OIDC_JWKS_URI=https://login.customer.example/discovery/v2.0/keys
```

The login bridge uses authorization-code flow with `openid email profile`,
stores state and nonce in a short-lived HttpOnly state cookie, validates RS256
ID-token signatures through JWKS, checks issuer, audience, expiry, nonce, and
subject claims, and maps `preferred_username`, `upn`, `unique_name`, and (only
when the IdP asserts `email_verified`) `email` to an active SCIM `userName`. Token values and client secrets are never written
to audit entries.

Fresh OIDC sessions include a short step-up window when the ID token contains a
recent `auth_time` claim. That lets routed approvers and Security Admins use the
existing approve/reveal gates immediately after IdP authentication while local
break-glass accounts still use password confirmation.

## Example Smoke Test

```bash
curl -sS \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  https://redactwall.customer.example/scim/v2/ServiceProviderConfig

curl -sS \
  -X POST \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"RedactWall Approvers"}' \
  https://redactwall.customer.example/scim/v2/Groups
```

After provisioning and first SSO login, verify the audit chain:

```bash
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

SCIM audit entries include bounded metadata such as user names, active state,
group names, and member counts. They do not include prompt bodies, raw findings,
tokens, MFA seeds, or IdP secrets.

## IdP Notes

For Microsoft Entra or Okta provisioning, use `docs/identity/IDENTITY_IDP_SETUP.md`, the
dashboard Identity tab, or the secret-free CLI handoff:

```bash
npm run identity:setup -- --provider entra --base-url https://redactwall.customer.example --tenant-id <tenant-id-or-domain>
npm run identity:setup -- --provider okta --base-url https://redactwall.customer.example --tenant-id <customer.okta.com>
```

At a minimum, configure:

- Tenant URL: `https://redactwall.customer.example/scim/v2`
- Secret token: the `SCIM_BEARER_TOKEN` value from the approved vault
- Provision users and groups
- Assign groups using the RedactWall display names above when role mapping is
  needed
- Register a web OIDC app with the callback URL above
- Use a tenant-specific issuer where possible instead of a broad common issuer
- Keep local break-glass Security Admin credentials enabled after SSO is tested

## Works Cited

Microsoft. "OpenID Connect on the Microsoft Identity Platform." *Microsoft
Learn*, Microsoft, https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc.
Accessed 28 June 2026.

OpenID Foundation. "OpenID Connect Core 1.0 Incorporating Errata Set 2."
*OpenID Foundation*, 15 Dec. 2023,
https://openid.net/specs/openid-connect-core-1_0.html. Accessed 28 June 2026.

Internet Engineering Task Force. "System for Cross-Domain Identity Management:
Protocol." *RFC 7644*, RFC Editor, Sept. 2015,
https://www.rfc-editor.org/rfc/rfc7644. Accessed 28 June 2026.

Microsoft. "Tutorial: Develop and Plan Provisioning for a SCIM Endpoint in
Microsoft Entra ID." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups.
Accessed 28 June 2026.
