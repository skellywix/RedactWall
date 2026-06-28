# PromptWall IdP Setup For Entra And Okta

Use this guide after the customer has a public PromptWall console URL and a
secret store for SCIM bearer tokens and OIDC client secrets. The dashboard
Identity tab and the CLI both render the same secret-free setup values:

```powershell
npm run identity:setup -- --provider entra --base-url https://promptwall.customer.example --tenant-id <tenant-id-or-domain>
npm run identity:setup -- --provider okta --base-url https://promptwall.customer.example --tenant-id <customer.okta.com>
```

The output intentionally uses placeholders for `SCIM_BEARER_TOKEN` and
`OIDC_CLIENT_SECRET`. Generate and store those values in the customer secret
manager, not in tickets, screenshots, policy files, or evidence packs.

## Microsoft Entra ID

SCIM provisioning:

- Create a non-gallery enterprise application for PromptWall.
- Set Provisioning mode to Automatic.
- Tenant URL: `https://promptwall.customer.example/scim/v2`.
- Secret token: the value stored in `SCIM_BEARER_TOKEN` or
  `PROMPTWALL_SCIM_BEARER_TOKEN`.
- Unique identifier: `userName`.
- Provision assigned users and groups.
- Include PromptWall role groups such as `PromptWall Security Admins`,
  `PromptWall Approvers`, `PromptWall Auditors`, and `PromptWall Operators`.

OIDC console login:

- Register a web app for the PromptWall console.
- Redirect URI: `https://promptwall.customer.example/auth/oidc/callback`.
- Issuer: `https://login.microsoftonline.com/<tenant-id-or-domain>/v2.0`.
- Scopes: `openid email profile`.
- Store the client id in `OIDC_CLIENT_ID`.
- Store the client secret in `OIDC_CLIENT_SECRET`.
- Store the callback URL in `OIDC_REDIRECT_URI`.

Use a tenant-specific issuer. Do not use broad `common` or consumer authorities
for production customer stacks because PromptWall maps the signed identity back
to active SCIM users.

## Okta

SCIM provisioning:

- Create or edit the PromptWall app integration.
- Enable API integration on the Provisioning tab.
- Base URL: `https://promptwall.customer.example/scim/v2`.
- Authentication mode: bearer token.
- Token value: the value stored in `SCIM_BEARER_TOKEN` or
  `PROMPTWALL_SCIM_BEARER_TOKEN`.
- Enable the create, update, deactivate, and group-push actions needed for the
  pilot.
- Push the PromptWall role groups when role mapping or approval routing depends
  on IdP group membership.

OIDC console login:

- Create an OIDC web application integration.
- Sign-in redirect URI:
  `https://promptwall.customer.example/auth/oidc/callback`.
- Issuer: `https://<customer.okta.com>/oauth2/default`, unless the customer uses
  a dedicated authorization server.
- Scopes: `openid email profile`.
- Store the client id in `OIDC_CLIENT_ID`.
- Store the client secret in `OIDC_CLIENT_SECRET`.
- Store the callback URL in `OIDC_REDIRECT_URI`.

## PromptWall Role Groups

| PromptWall role | Accepted group display names |
| --- | --- |
| `security_admin` | `PromptWall Security Admins`, `Security Admins`, `Admins` |
| `approver` | `PromptWall Approvers`, `PromptWall Reviewers`, `Approvers`, `Reviewers` |
| `auditor` | `PromptWall Auditors`, `PromptWall Read-only`, `Auditors`, `Read-only` |
| `operator` | `PromptWall Operators`, `PromptWall Ops`, `Operators`, `Ops` |

If no direct role or group role matches, the SCIM user defaults to `auditor`.
OIDC login succeeds only when the signed identity maps to an active SCIM
`userName`.

## Validation

Run production preflight after the secrets are present:

```powershell
npm run setup:check -- --skip-install
```

Smoke the SCIM endpoint with a non-secret placeholder in docs and the real token
only in the customer shell:

```bash
curl -sS \
  -H "Authorization: Bearer $SCIM_BEARER_TOKEN" \
  https://promptwall.customer.example/scim/v2/ServiceProviderConfig
```

Then sign in through SSO as one active SCIM-provisioned test user and confirm
`/api/me` returns the expected role. Finish with the audit-chain check:

```powershell
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

## Works Cited

Microsoft. "OpenID Connect on the Microsoft Identity Platform." *Microsoft
Learn*, Microsoft,
https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc.
Accessed 28 June 2026.

Microsoft. "Tutorial: Develop and Plan Provisioning for a SCIM Endpoint in
Microsoft Entra ID." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups.
Accessed 28 June 2026.

Okta. "Create SAML or SCIM App Integrations." *Okta Help Center*, Okta,
https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_scim.htm.
Accessed 28 June 2026.

Okta. "Create OIDC App Integrations." *Okta Help Center*, Okta,
https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm.
Accessed 28 June 2026.
