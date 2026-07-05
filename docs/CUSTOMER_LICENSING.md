# Customer Licensing

How PromptWall licenses are structured, enforced, and priced. Modeled on the
offline license-file patterns used by GitLab (self-managed license + renewal
true-up) and Keygen (cryptographically signed offline licenses), adapted for
regulated buyers who often run air-gapped or egress-restricted environments.

Status: SHIPPED. The offline Ed25519 verifier is `server/license.js`
(verified at boot and re-checked daily); licenses are issued offline with
`npm run license:issue` and installed via `POST /api/billing/license` or by
dropping `promptwall.lic` next to `.env`. Absence = demo mode (zero gating);
past the grace window only the admin console's config writes go read-only —
detection, enforcement, approvals, audit, and evidence export always run. The
embedded public key in `server/license.js` is a placeholder to be replaced with
the vendor's real public key (from `--init-keypair`) before the first
commercial release.

## Principles

1. **Offline first.** A license is a signed file, not a phone-home check.
   Credit unions and banks routinely block vendor callbacks; the product must
   be fully functional with zero egress.
2. **Never disable the security function for billing reasons.** Seat overage
   and license expiry degrade the *admin* experience, never detection or
   enforcement. Turning off a DLP control over an invoice is both a sales
   killer and a safety problem.
3. **Count honestly, reconcile at renewal.** Seat usage is measured and shown
   to the customer continuously; overage is a renewal conversation (GitLab-
   style true-up), not a hard block.

## License file format

A `promptwall.lic` file: base64-encoded JSON payload plus an Ed25519
signature, verified at boot and daily against a public key embedded in the
product.

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

- Generated with `node:crypto` Ed25519 keys; the private signing key lives
  offline with the vendor, never in the repo.
- Installed by pasting into the admin console (Configuration tab) or dropping
  the file next to `.env`; recorded in the audit log (metadata only).
- Verification failure or absence = demo mode (existing behavior), clearly
  labeled in the console.

## Seat model

- A **seat** is a distinct user identity observed by any sensor or the
  gateway in the trailing 30 days (the data already exists —
  `/api/billing/seats`).
- The console shows seats used vs. licensed; warnings begin at 100%.
  Enforcement above the limit follows the existing `seat_limit_blocked`
  policy for *new* identities only where the customer has opted into hard
  enforcement; the default is warn-and-true-up.

## Expiry behavior

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
- Pilots: 90-day, full-featured, seat-capped license file.

## Legal shape

- Keep the EULA short (~6 pages) and based on a familiar standard (e.g. the
  Common Paper Software License Agreement): internal-use grant scoped to
  licensed seats/sites, no service-bureau use, warranty disclaimer, liability
  cap at 12 months of fees, audit clause tied to the seat report the product
  already generates, and data-protection terms reflecting that PromptWall
  processes no member data on vendor infrastructure (self-hosted).
- The seat report doubles as the audit mechanism — no intrusive vendor audits.

## What we deliberately avoid

- License servers, activation callbacks, or telemetry-based enforcement.
- Per-prompt or usage-metered pricing (unpredictable for the buyer, and it
  would require counting prompts — against the product's privacy posture).
- Disabling detection, blocking, or evidence export on any billing state.
