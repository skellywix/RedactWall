# Customer Licensing

How RedactWall licenses are structured, enforced, and priced. Modeled on the
offline license-file patterns used by GitLab (self-managed license + renewal
true-up) and Keygen (cryptographically signed offline licenses), adapted for
regulated buyers who often run air-gapped or egress-restricted environments.

Status: connected-first migration in progress. Production customer silos use
`server/connected-license-runtime.js` with the strict vendor-control heartbeat
and acknowledgement channels. The Ed25519 verifier in `server/license.js` has
no network client or mutable vendor overlay. Its deployment-bound license is a
bounded outage fallback for connected silos. Offline mode is retained only for
local development and explicit legacy compatibility, and cannot pass customer
production preflight. Absence = demo mode only when external management is not
enabled;
past the grace window only the admin console's config writes go read-only —
detection, enforcement, approvals, audit, and evidence export always run. The
embedded public key in `server/license.js` is a development placeholder.
Production uses the vendor's real public key from `--init-keypair`, configured
as SPKI DER base64 for AWS or embedded for an air-gapped distribution. The
step-by-step guide is `docs/deployment/LICENSE_KEY_SETUP.md`.

## Principles

1. **Connected first, bounded offline fallback.** Production authorization is
   the vendor's signed online registry verdict plus signed entitlement. A
   deployment-bound active offline artifact may preserve previously granted
   rights only during an eligible bounded transport outage. It never clears or
   outranks a newer pause or revoke.
2. **Never disable the security function for billing reasons.** Seat overage
   and license expiry degrade the *admin* experience, never detection or
   enforcement. Turning off a DLP control over an invoice is both a sales
   killer and a safety problem.
3. **Count honestly, reconcile at renewal.** Seat usage is measured and shown
   to the customer continuously; overage is a renewal conversation (GitLab-
   style true-up), not a hard block.

## Deployment modes

RedactWall customer production is **connected-only**. It uses the strict
protocol documented in `CONNECTED_DEPLOYMENT.md` and
`docs/reference/VENDOR_CONTROL_PROTOCOL.md`. Offline mode verifies its license
locally and starts no vendor heartbeat, but is limited to development and
explicit legacy compatibility. Everything below describes the offline artifact,
not the primary connected authority.

## Offline artifact formats

A `redactwall.lic` file is a base64-encoded JSON payload plus an Ed25519
signature. The customer verifies it against the separately provisioned offline
public root. The connected online-verdict and entitlement services use
different keys and signature domains.

The legacy offline-only format is retained for development and explicitly
supported legacy installations:

```json
{
  "customer": "Example Credit Union",
  "customerId": "cu-000123",
  "plan": "standard",
  "seats": 120,
  "features": ["gateway", "mcp-guard", "endpoint-agent"],
  "issued": "2026-08-01",
  "expires": "2027-08-01",
  "graceDays": 30
}
```

It is not a connected outage artifact. A connected fallback is issued through
the Owner provisioning workflow and also binds the exact deployment:

```json
{
  "customer": "Example Credit Union",
  "customerId": "cu-000123",
  "deploymentId": "dep_0123456789abcdef0123456789abcdef",
  "status": "active",
  "plan": "standard",
  "seats": 120,
  "features": ["gateway", "mcp-guard", "endpoint-agent"],
  "issued": "2026-08-01",
  "expires": "2027-08-01",
  "graceDays": 3
}
```

`customerId` is mandatory and uses the same bounded tenant-slug format as
`REDACTWALL_TENANT_ID`, and makes the signed file customer-bound.
Customer-silo deployments compare it with `REDACTWALL_TENANT_ID`; licensed
standalone deployments set `REDACTWALL_LICENSE_CUSTOMER_ID`. If both settings
exist they must match. Missing or mismatched customer binding is rejected both
when a license is installed and whenever the file is loaded at boot or during
the daily refresh. Connected production additionally requires signed
`status: "active"` and an exact deployment ID equal to
`REDACTWALL_CONNECTED_DEPLOYMENT_ID`. Missing, malformed, inactive, legacy, or
sibling-deployment artifacts cannot enter fallback.

- Generated with `node:crypto` Ed25519 keys; the private signing key lives
  offline with the vendor, never in the repo.
- Connected fallback is installed only by the managed Owner provisioning or
  renewal workflow. Customer-side license installation routes reject connected
  mode before verification or mutation.
- Console paste or direct file installation is limited to development and
  explicit legacy offline-only deployments and is recorded in the audit log
  with metadata only.
- Verification failure or absence can enter demo behavior only when production
  and external management are both disabled. Production fails closed.

## Seat model

- A **seat** is a distinct user identity observed by any sensor or the
  gateway in the trailing 30 days (`/api/billing/seats`). The window is
  enforced in `db.seatStats`; override with `REDACTWALL_SEAT_WINDOW_DAYS`
  (`all` = lifetime).
- The console shows seats used vs. licensed; warnings begin at 100%.
  Enforcement above the limit follows the existing `seat_limit_blocked`
  policy for *new* identities only where the customer has opted into hard
  enforcement; the default is warn-and-true-up.

## Legacy offline expiry behavior

| Phase | Behavior |
|-------|----------|
| Active | Full product. |
| Expired, within `graceDays` (default 30) | Full product + persistent renewal banner for admins. |
| Past grace | Admin console locks to read-only (evidence and audit stay exportable — an examiner must never be blocked); sensors, detection, enforcement, and the approval API keep working. |

## Pricing structure (guidance for order forms)

- **Per-seat, annual, with a site minimum** (e.g., 50-seat minimum).
  Credit unions budget per-employee for security tooling (EDR, email
  security); seats scale naturally with asset size.
- Plans: **Standard** (control plane + browser sensor) and **Enterprise**
  (adds endpoint agent, MCP guard, AI gateway, priority support). Feature
  flags in the license file gate plan differences.
- **Add-on feature flags** ride the same `features[]` array. First add-on:
  `ncua_readiness` (the NCUA Readiness Center console module) — included with
Enterprise, orderable on Standard. Entitlement is
  `license.entitled(flag)`: demo mode (no license) shows everything, and
  evidence export works in every license state — flags gate console modules,
  never the security function. In connected production, grant an add-on through
  the Owner entitlement projection and signed release lifecycle. The standalone
  issuance script remains only for an authorized legacy offline-only workflow
  and is excluded from the customer image.
- Pilots: 90-day, full-featured, seat-capped license file.

## Legal shape

- Keep the EULA short (~6 pages) and based on a familiar standard (e.g. the
  Common Paper Software License Agreement): internal-use grant scoped to
  licensed seats/sites, no service-bureau use, warranty disclaimer, liability
  cap at 12 months of fees, audit clause tied to the seat report the product
  already generates, and data-protection terms reflecting that RedactWall
  processes no member data on vendor infrastructure (self-hosted).
- The seat report doubles as the audit mechanism — no intrusive vendor audits.

## What we deliberately avoid

- Per-prompt licensing telemetry or any heartbeat containing prompts, findings,
  user rosters, secrets, or customer content.
- Shared credentials across heartbeat, acknowledgement, diagnostics, or Shadow
  AI candidate channels.
- Per-prompt or usage-metered pricing (unpredictable for the buyer, and it
  would require counting prompts — against the product's privacy posture).
- Disabling detection, blocking, or evidence export on any billing state.
