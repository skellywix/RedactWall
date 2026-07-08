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
  over `{ status: "active" | "revoked", customerId, issuedAt }`, signed with
  the **same private key** that signs license files. The control plane verifies
  the signature against the embedded public key, checks `customerId` matches the
  installed license, and requires `issuedAt` to be **strictly newer** than the
  last applied verdict. Your server must therefore stamp a fresh `issuedAt`
  (e.g. current time) on **every** heartbeat response — only a fresh verdict
  counts as live contact. This makes verdicts non-replayable: a captured older
  `active` verdict can neither keep an install alive nor lift a revocation.

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
- Reinstalling a license does **not** self-clear a revocation; only a fresh
  signed `active` verdict from your server lifts it. The revocation is
  persisted (`redactwall.vendor`, next to the license) and restored at boot
  **before** the control plane accepts any ingest, so it survives a restart.

**Heartbeat-or-die.** Connected mode requires periodic fresh contact to keep
serving. If no fresh, verified verdict arrives within
`REDACTWALL_LICENSE_MAX_STALENESS_DAYS` (default 7), the install fails
**closed** (`vendor_unreachable`) — so a customer who firewalls the license
server or deletes local state cannot escape a revocation by simply going
offline; without your renewed `active` verdicts they stop passing AI traffic.
Set the tolerance to balance kill-switch responsiveness against surviving a
vendor-side outage. A short transient outage inside the window changes nothing.

> Sensor-side display: a revoked control plane returns a distinct
> `license_revoked` status in the response body and records it in the audit
> chain. Sensors currently render their generic fail-closed message on any
> block; surfacing the licensing reason in the sensor UI is a follow-up.
>
> The heartbeat POSTs to the operator-configured URL over HTTPS (loopback/
> metadata IP literals are rejected). Point it only at a license host you
> control; the body is non-sensitive (seat counts + license ids).

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
REDACTWALL_SEMANTIC_REMOTE_FAIL_MODE=degrade         # optional: degrade | hold
```

This path ships prompt text to your scanner — the one place the connected SKU
sends content off the customer box. It must be **HTTPS** for any remote host
(cleartext to a remote host is rejected — prompt text may not cross the network
in the clear); `http://` is accepted only to loopback for local testing, or
with an explicit `REDACTWALL_SEMANTIC_REMOTE_ALLOW_INSECURE=1`. Routing member
NPI to your infrastructure makes you a GLBA service provider (SOC 2 posture,
due-diligence packet, breach obligations); price and contract accordingly.

**Fail mode** when the scanner is unreachable:
- `degrade` (default): fall back to on-device detection — availability over the
  second layer.
- `hold`: withhold the prompt for Security Admin approval (a normal held item)
  rather than let it proceed un-vetted — the second layer over availability.

## Sensor transport

Sensors send the ingest key and prompt metadata to the control plane, so a
**remote** plane must be HTTPS or the key travels in cleartext. The browser
extension, endpoint agent, and MCP guard reject a non-HTTPS control-plane URL
for any non-loopback host; `http://localhost` stays fine for local installs.
The Node sensors accept `REDACTWALL_ALLOW_INSECURE_SERVER=1` as an explicit
escape hatch; the browser extension has none (a managed policy pointing at a
remote plane must use HTTPS). Terminate TLS at the plane's load balancer
(`infra/aws/customer-silo.yml`).

## Compliance note

The air-gapped SKU's "prompt data never leaves the institution" guarantee does
**not** hold in connected mode when the vendor scanner is enabled. Keep the two
SKUs' data-flow claims distinct in customer-facing material.
