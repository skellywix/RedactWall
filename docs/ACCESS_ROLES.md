# Access Roles

PromptWall ships exactly four console roles. Every session carries one role;
there are no per-permission toggles to misconfigure, and the audit log records
which role took every action. The set is deliberately small: each role is a
distinct job, and together they cover separation-of-duties for a regulated
deployment without inventing hierarchy for its own sake.

## The four roles

| Role | Typical titles | One-line job |
| --- | --- | --- |
| `security_admin` | CISO, Security Officer, Head of IT Security | Owns the product: policy, configuration, identity, secrets, reveals. |
| `approver` | Compliance Officer, BSA Officer, Team Lead, Branch Manager | Decides held prompts assigned to them. Nothing else changes by their hand. |
| `operator` | IT Administrator, Systems Technician, MSP Engineer | Keeps the fleet healthy: updates, posture triage, delivery checks. Cannot touch policy or decisions. |
| `auditor` | Internal Auditor, Examiner Liaison, Compliance Analyst | Reads everything and exports evidence. Changes nothing. |

Every authenticated role can **view** the console (queue, command center,
insights, coverage, activity, audit log) — visibility is not a privilege here,
because nothing in the console shows raw prompt content. Power is what is
gated.

## What each role can do

| Capability | security_admin | approver | operator | auditor |
| --- | :-: | :-: | :-: | :-: |
| View console (all tabs, prompt-free) | yes | yes | yes | yes |
| Approve / deny held prompts | yes | assigned only | – | – |
| Reveal sealed raw prompt (step-up required) | yes | – | – | – |
| Edit policy, destinations, catalog, scopes | yes | – | – | – |
| Identity setup (OIDC, SCIM, seats) | yes | – | – | – |
| Manage subscriptions / SIEM destinations | yes | – | – | – |
| Run update check / apply / restart | yes | – | yes | – |
| Posture action triage (assign, snooze, resolve) | yes | – | yes | – |
| View delivery history, send test delivery | yes | – | yes | – |
| Export evidence pack | yes | – | – | yes |
| Export security trust package / SIEM package | yes | – | – | yes |
| Retention purge, ticket sync, billing | yes | – | – | – |

Notes:
- Approvers decide only items routed to the `approver` role and (when set)
  assigned to their username — `security_admin` can always decide.
- Sensitive actions (reveal, approve) additionally require password step-up or
  a fresh elevation window (`POST /api/auth/step-up`), regardless of role.

## How people get a role

1. **IdP groups (recommended).** SCIM-provisioned users inherit the role from
   their group's display name (`security_admin` / `approver` / `operator` /
   `auditor` — case-insensitive, spaces and dashes tolerated). Users with no
   role-mapped group default to `auditor` — the safe floor: they can look and
   export, never change. OIDC sign-ins resolve through the same SCIM record,
   so deactivating the user in the IdP revokes console access, live sessions,
   and the seat.
2. **Local accounts (small pilots, break-glass).** One local account per role
   via env: `ADMIN_USER`/`ADMIN_PASSWORD` (+ TOTP), `APPROVER_*`,
   `AUDITOR_*`, `OPERATOR_*`. Usernames must be distinct or the extra account
   is not enabled.

## What we deliberately did NOT add

- **No separate read-only "viewer" role** — `auditor` is the read-only role.
- **No custom permission builder** — four fixed roles are examiner-explainable
  and cannot drift into an unauditable matrix.
- **No super-admin above `security_admin`** — infrastructure access (AWS,
  database, secrets manager) is governed by your cloud IAM, not by the app.
