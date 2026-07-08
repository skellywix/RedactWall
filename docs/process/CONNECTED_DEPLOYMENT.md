# Connected Deployment (Vendor-Managed SKU)

RedactWall ships in two deployment modes. This guide covers the **connected**
mode; the default remains fully air-gapped.

| | Air-gapped (default) | Connected (opt-in) |
|---|---|---|
| License check | Offline Ed25519 file, no network | Offline file **plus** a signed vendor heartbeat |
| Vendor egress | None (zero phone-home) | License heartbeat to your license server only |
| Kill-switch | None | Vendor can revoke → all AI use blocked |
| Seat reporting | Local only (`/api/billing/seats`) | Counts sent to the vendor on the heartbeat |
| Second-layer scan | On-device only | Optional vendor-side scanner (`REDACTWALL_SEMANTIC_REMOTE_URL`) |

Connected mode is **entirely opt-in**: with none of the env vars below set, a
deployment behaves exactly as the air-gapped SKU. Nothing in connected mode
ever fails open — a revoked or unreachable state blocks AI use (maximal data
protection); it never disables detection.

## License heartbeat + kill-switch

Set the license server URL to enable the daily heartbeat (`server/vendor-link.js`):

```
REDACTWALL_LICENSE_SERVER_URL=https://license.yourvendor.example/heartbeat
REDACTWALL_LICENSE_SERVER_TIMEOUT_MS=8000   # optional, default 8000, max 30000
```

- The URL must be **HTTPS** and public (loopback / link-local / cloud-metadata
  hosts are rejected). Private RFC1918 hosts are allowed for internal license
  servers.
- On boot and every 24h the control plane POSTs a **prompt-free** body:
  `{ customerId, plan, seatsUsed, seatLimit, version, sentAt }` — seat counts
  and license identifiers only, never prompts, findings, member data, or the
  per-user roster.
- The server replies with a signed verdict `base64(json).base64(ed25519sig)`
  over `{ status: "active" | "revoked", customerId }`, signed with the **same
  private key** that signs license files. The control plane verifies the
  signature against the embedded public key and checks `customerId` matches the
  installed license, so a verdict cannot be spoofed or replayed across tenants.

**Revoking a customer.** Have your license server return a signed
`{ status: "revoked" }` verdict for that `customerId`. On the next heartbeat
(or immediately, if you also disable their license reissue) the control plane
moves to the `revoked` state:

- Every sensor ingest path (`/api/v1/gate`, scan-file, scan-response,
  heartbeat, discovery) **fail-closed-blocks** with status `license_revoked` —
  browser extension, endpoint agent, MCP guard, and the AI gateway (which calls
  `/api/v1/gate`) all stop passing AI traffic.
- The admin console goes read-only (`license_revoked` on config writes); the
  license-install route stays open so a renewal can be applied.
- Evidence export, audit, and the approval workflow keep working — you are
  cutting off *use of AI through the product*, not the customer's data
  protection or their examiner evidence.
- Reinstalling a license does **not** self-clear a revocation; only a signed
  `active` verdict from your server lifts it.

Failure handling: an unreachable or unverifiable license server **never**
changes state on its own — the last verified verdict holds. Plan your server
for availability; a vendor outage should not silently revoke a customer.

> Sensor-side display: a revoked control plane returns a distinct
> `license_revoked` status in the response body and records it in the audit
> chain. Sensors currently render their generic fail-closed message on any
> block; surfacing the licensing reason in the sensor UI is a follow-up.

## Seat window

A seat is a distinct billable user seen in the **trailing 30 days** (matching
`docs/process/CUSTOMER_LICENSING.md`), so lapsed users roll off and both the local
`/api/billing/seats` view and the heartbeat report current usage. Override with
`REDACTWALL_SEAT_WINDOW_DAYS=<n>`; set it to `all` for lifetime counting.

## Vendor-side second-layer scanning

The on-device engine stays the source of truth. Point the optional remote
classifier at your scanner to add a second layer whose categories are
max-combined into the local verdict (it can only *raise* risk):

```
REDACTWALL_SEMANTIC_REMOTE_URL=https://scan.yourvendor.example/classify
REDACTWALL_SEMANTIC_REMOTE_KEY=<bearer token>       # optional
REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS=1500           # optional
```

This path ships prompt text to your scanner — the one place the connected SKU
sends content off the customer box. Routing member NPI to your infrastructure
makes you a GLBA service provider (SOC 2 posture, due-diligence packet, breach
obligations); price and contract accordingly. A scanner outage degrades to
local-only detection rather than blocking.

## Compliance note

The air-gapped SKU's "prompt data never leaves the institution" guarantee does
**not** hold in connected mode when the vendor scanner is enabled. Keep the two
SKUs' data-flow claims distinct in customer-facing material.
