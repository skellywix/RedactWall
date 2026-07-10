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
REDACTWALL_LICENSE_SERVER_TOKEN=<customer-specific-random-token>
REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
REDACTWALL_LICENSE_SERVER_TIMEOUT_MS=8000   # optional, default 8000, max 30000
```

### Migrating an existing connected deployment

The authenticated verdict protocol intentionally has no fallback to the former
license-root-signed format. For an existing connected customer:

1. Create the dedicated online verdict key, customer token registry, and a new
   license-service endpoint without copying the offline private root.
2. Upgrade the customer control plane to a build that supports the dedicated
   verdict key.
3. In one maintenance change, set the new URL, customer token, and verdict
   public key, then restart and verify a fresh `VENDOR_HEARTBEAT_OK` audit row.
4. Complete every customer migration inside the configured staleness window,
   then retire the legacy endpoint and remove any offline root material that
   was previously present on an online host.

Do not point an old control plane at the new service or configure the offline
license public key as the verdict key. Both combinations fail closed by design.

For the schema-9 shared verdict-state upgrade, drain **every** control-plane
replica before starting the new build, allow one upgraded replica to complete
the migration, then start the remaining upgraded replicas. Do not run pre-v9
and v9 replicas together: pre-v9 processes do not reconcile the shared verdict
row on authorization requests and therefore cannot safely participate in a
rolling connected-mode upgrade. Verify all replicas report the new version and
a fresh `VENDOR_HEARTBEAT_OK` entry before restoring load-balancer traffic.

Schema 10 has the same no-mixed-control-plane requirement for native handoff
idempotency. Drain every pre-v10 control-plane replica, let one upgraded
replica apply `native-handoff-ingest-idempotency`, then start only v10-capable
replicas before restoring traffic. Upgrade endpoint agents immediately after
the control plane. Pre-v10 agents do not send the opaque signed-event identity,
so their in-flight native handoffs retain the old at-least-once reporting risk;
the server cannot safely invent an identity for them from a free-text note.

- The URL must be **HTTPS** and public (loopback / link-local / cloud-metadata
  hosts are rejected), without credentials, query parameters, or fragments.
  Private RFC1918 hosts are allowed for internal license servers.
- On boot and every 24h the control plane authenticates with its
  customer-specific bearer token and POSTs a **prompt-free** body:
  `{ customerId, plan, seatsUsed, seatLimit, version, sentAt }` — seat counts
  and license identifiers only, never prompts, findings, member data, or the
  per-user roster.
- The server replies with a domain-separated signed verdict
  `base64(json).base64(ed25519sig)` over
  `{ kind, status: "active" | "revoked", customerId, issuedAt }`. It uses a
  dedicated online verdict key that is separate from the offline license root.
  The control plane verifies the signature against
  `REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY`, checks `customerId` matches the
  installed license, and requires `issuedAt` to be **strictly newer** than the
  last applied verdict. The server must therefore stamp a fresh `issuedAt`
  (e.g. current time) on **every** heartbeat response — only a fresh verdict
  counts as live contact. This makes verdicts non-replayable: a captured older
  `active` verdict can neither keep an install alive nor lift a revocation.
  Customer and vendor clocks must stay synchronized; verdicts more than five
  minutes from the control-plane clock are rejected without advancing replay
  high-water.
  The customer token is also bound to an explicit vendor-side customer and
  plan allowlist, so the endpoint is not an anonymous signing oracle.

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
  persisted in the shared datastore (with `redactwall.vendor` as a private
  signed-verdict cache) and restored at boot **before** the control plane
  accepts any ingest, so it survives a restart and is enforced by every
  upgraded replica on its next authorization request.

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
in the clear); `http://` is accepted to loopback for local testing. An explicit
`REDACTWALL_SEMANTIC_REMOTE_ALLOW_INSECURE=1` can enable other cleartext hosts
only outside production and is ignored when `NODE_ENV=production`. Routing member
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
The Node sensors accept `REDACTWALL_ALLOW_INSECURE_SERVER=1` only in a
non-production development process. `NODE_ENV=production` ignores the override,
and the browser extension has no override at all. A managed policy pointing at
a remote plane must use HTTPS. Terminate TLS at the plane's load balancer
(`infra/aws/customer-silo.yml`).

Sensor policy has a separate authenticity boundary from TLS and the ingest
credential. The browser extension receives `policyPublicKey` through managed
browser storage. Endpoint, MCP, and agent-hook runtimes use one of:

```
REDACTWALL_POLICY_PUBLIC_KEY_PATH=/etc/redactwall/policy-public-key.pem
# or an exact PEM value in REDACTWALL_POLICY_PUBLIC_KEY
REDACTWALL_POLICY_CACHE_PATH=/var/lib/redactwall/sensor-policy-bundle.json
```

Export the public key from the control-plane host after its durable `/data`
volume is mounted, then distribute that copy through MDM, configuration
management, or another authenticated operator channel. Sensors never bootstrap
trust by calling `/api/v1/policy/pubkey`. They fetch only
`/api/v1/policy/bundle`, verify Ed25519 locally, and atomically persist a bounded
last-known-good bundle. The cache also retains the highest verified `issuedAt`,
even after that bundle expires, so an older but still-valid signed replay cannot
roll policy back across a sensor restart. A fresh LKG permits a short
control-plane outage. No pin
or no fresh verified current/LKG policy fails closed before browser, endpoint,
MCP, or inherited agent-hook egress.

Treat signing-key rotation as a coordinated maintenance event. Stop the sensor,
replace its out-of-band pin, remove the old-key LKG at the configured cache path,
then restart and confirm a fresh bundle verifies. Never clear the LKG merely to
work around a replay or signature failure. For managed browsers, the LKG is the
extension's `chrome.storage.local` `policyBundle`, not a filesystem cache. Remove
the force-install assignment long enough for the browser to uninstall the
extension and clear its local storage, deploy the new `policyPublicKey`, then
force-install again and require a healthy `policy_cache` heartbeat before users
resume AI access. Updating the pin while the old-key browser LKG remains is
deliberately fail closed.

## Compliance note

The air-gapped SKU's "prompt data never leaves the institution" guarantee does
**not** hold in connected mode when the vendor scanner is enabled. Keep the two
SKUs' data-flow claims distinct in customer-facing material.
