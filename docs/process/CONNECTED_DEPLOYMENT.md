# Connected Deployment (Vendor-Managed SKU)

RedactWall production customer silos use the **connected** mode. An offline
artifact remains secondary, deployment-bound outage authority. Offline mode is
limited to local development and explicit legacy compatibility; it does not
pass customer production preflight.

| | Offline-only | Connected production |
|---|---|---|
| License check | Offline Ed25519 file, no network | Signed online registry verdict plus signed entitlement; offline artifact is bounded fallback only |
| Vendor egress | None | Strict `POST /v1/heartbeat` and `POST /v1/acknowledgements` channels |
| Vendor restriction | None | Pause/revoke blocks protected egress while local DLP, admin, and evidence stay online |
| Seat reporting | Local only (`/api/billing/seats`) | Prompt-free aggregate counts in the strict heartbeat |
| Second-layer scan | On-device only | Optional vendor-side scanner (`REDACTWALL_SEMANTIC_REMOTE_URL`) |

The customer protocol is implemented by `server/vendor-control-client.js`,
`server/vendor-control-connector.js`, and `server/connected-license-runtime.js`.
Its exact route, schema, key, replay, timeout, and ACK contract is frozen in
`docs/reference/VENDOR_CONTROL_PROTOCOL.md`. The customer-local sensor health
route `POST /api/v1/heartbeat` is separate and remains supported.

Nothing in connected mode fails open. Only a narrowly classified transport
outage may enter the bounded offline fallback. A signed pause/revoke, invalid
artifact, protocol rejection, replay, or integrity failure cannot use fallback.

## Removed legacy v1 heartbeat

The former daily `server/vendor-link.js` client, shared
`REDACTWALL_LICENSE_SERVER_TOKEN`, mutable license overlay, and unversioned
vendor `/heartbeat` route are removed. Do not configure or restore them.

Connected production uses an exact HTTPS origin in
`REDACTWALL_LICENSE_SERVER_URL`; the client appends the frozen
`/v1/heartbeat` or `/v1/acknowledgements` path for those channels. The current
customer connector reserves `/v1/diagnostics` and
`/v1/shadow-ai/candidates`, but those optional channels remain
integration-gated until the committed Owner service freezes matching ingestion
semantics. Connected production requires:

- the vendor-issued `REDACTWALL_TENANT_ID` and immutable
  `REDACTWALL_CONNECTED_DEPLOYMENT_ID` in the exact
  `dep_<32 lowercase hex>` form;
- distinct heartbeat and acknowledgement credentials, plus distinct optional
  diagnostics and Shadow AI candidate credentials;
- explicit diagnostics and Shadow AI consent booleans;
- current online-verdict and entitlement Ed25519 public pins, optional next
  pins, and full SPKI-fingerprint key IDs; and
- the bounded heartbeat interval and total request timeout described in
  `docs/reference/VENDOR_CONTROL_PROTOCOL.md`.

Do not put a bearer credential, query, fragment, or route path in the configured
origin. Do not reuse a credential or signing identity across purposes.

### Migrating an existing connected deployment

The v2 protocol intentionally has no alias or key-identity fallback to v1. A
legacy customer-only offline license is not a connected outage artifact. The
Owner provisioning flow must issue a replacement whose signed payload includes
the exact customer, exact active deployment, and `status: "active"`.

For an existing customer:

1. Create or recover the Owner enrollment for the exact customer and
   deployment. Generate purpose-separated channel credentials and signing
   identities. Never copy the offline private root into the online verdict or
   license service.
2. Drain every customer control-plane replica that predates the composite
   connected-state migrations. Mixed old and new replicas are not supported.
3. Install the exact connected origin, scope, channel credentials, consents,
   current and optional next public pins, and the new deployment-bound outage
   artifact through the managed deployment workflow.
4. Start one upgraded replica so it can migrate and reconcile durable state,
   then start only upgraded replicas. The silo remains unready until a signed
   nonzero registry generation and signed entitlement are atomically applied
   and their ordered acknowledgements are durably accepted.
5. Verify the prompt-free heartbeat, independent registry and entitlement
   high-waters, delivered-before-applied acknowledgements, customer audit
   evidence, and protected-egress enforcement before restoring normal traffic.
6. Revoke the v1 credential and remove every legacy endpoint and configuration
   value after all deployments have completed the migration.

A signed pause or revoke remains effective across restart and reinstall. It
blocks protected AI egress, but the local DLP engine, customer administration,
audit, approval, and evidence surfaces remain available. An online active
registry verdict cannot clear an entitlement pause or revoke.

#### AWS stacks created before `DeploymentId`

An AWS application stack that does not already publish `DeploymentId` is not an
updatable connected stack. `silo:deploy` refuses it, and `silo:maintenance`
cannot infer or add the missing identity. Do not rename a customer-only license,
invent a deployment id, or force the CloudFormation parameter into that stack.

Use this planned-outage migration:

The executable authority is `node scripts/aws-legacy-connected-migrate.js`.
Run its ordered `plan`, `freeze`, `cutover`, and `commit` commands exactly as
documented in `docs/deployment/AWS_SAAS_DEPLOYMENT.md`. `plan` publishes a
private HMAC-authenticated manifest, a separately keyed monotonic
witness/tombstone, and an independent external lease. The plan binds the exact
source customer, source secret ARN/version, live versioned template bytes,
complete private deploy-argument snapshot, retained volume, image, target
secret version, fallback digest, trust-pin fingerprints, and opaque channel
credential references. `freeze` works without
`/etc/redactwall/maintenance-context.json`, waits for ALB deregistration, stops
the exact legacy writer, and only then creates the final authenticated backup.
Its checkpoint also binds the verified audit head, count, and sequence. `abort`
is allowed only before source deletion and restores writer readiness plus ALB
service before releasing the lease. `rollback-check` is mandatory before any
legacy restoration and permanently fails after
`connected_authority_committed`.

1. In Owner, create the exact customer enrollment and one new immutable
   `dep_<32 lowercase hex>` deployment. Issue its distinct heartbeat and
   acknowledgement credentials, current trust pins and key IDs, and an active
   outage fallback signed for that exact customer and deployment.
2. Freeze legacy configuration changes. Record the exact stable complete stack
   id, template version, image digest, secret version, instance id, data-volume
   identity, and audit-chain head.
3. With the exact legacy image, create and verify an authenticated evidence
   backup. Copy the backup, manifest, and required sidecars to a root-owned
   retained location and take the approved encrypted retained-volume snapshot.
   A root-volume-only legacy stack must be restored into the separately retained
   data-volume design before connected cutover.
4. Begin the outage. Deregister the only writer from the ALB and wait for drain,
   stop that exact writer, create and verify the final backup from the stopped
   volume, and delete the legacy application stack so the volume is detached.
   Keep the captured legacy template and recovery evidence intact.
5. Create a fresh connected application stack with the Owner-issued customer and
   deployment identity, the exact connected secret version, and either the same
   retained volume or an approved snapshot-restored volume whose lineage names
   the prior volume. This is reprovisioning, not an in-place update.
6. If cutover is interrupted, run `reconcile` against the exact private
   manifest and independent witness before any retry. If fresh provisioning
   fails, run `rollback-check` and then
   `cleanup-failed-candidate`. The latter removes only an exact operation-owned
   failed StackId. Restore the captured legacy stack and verified backup only
   from the resulting `rollback_ready` state. Do not delete the retained
   recovery set or advance Owner enrollment from ambiguous evidence.
7. Before restoring traffic, prove `/readyz`, one authenticated prompt-free
   heartbeat with a nonzero monotonic registry generation, the signed entitlement
   version, and durable delivered then applied acknowledgement acceptance. Record
   the resulting Owner audit references and customer audit-chain verification.

The commit command accepts no scalar authority inputs. It requires raw Owner
durable-ACK and customer acknowledged-high-water receipts. Production verifiers
must authenticate each raw receipt and bind the exact customer, deployment,
operation, StackId, instance, container, registry generation/state digest,
entitlement version/artifact digest, delivered then applied acceptance, audit
heads/references, and authority fingerprints before a publication CAS can
advance the one-way tombstone. The current standalone CLI deliberately returns
`RELEASE-BLOCKED` until those Owner and customer verifier adapters are injected.
The production legacy recreate/restore adapter is likewise release-blocked
until it can attest exact candidate cleanup, a newly returned operation-owned
legacy StackId, stopped-writer recovery digests, writer readiness, and ALB
health before lease release. This supported-workflow fence is not a claim that
AWS can cryptographically disable a manually reconstructed obsolete image. The
release gate also requires the customer connected high-water to survive restart
and Owner to revoke the legacy license and channel credentials.

Downtime begins when the legacy writer is stopped and ends only after the fresh
connected target is healthy and the customer DNS alias reaches the new ALB.
Stacks that already publish the exact `DeploymentId` use the normal
`silo:maintenance` lock, latch, checkpoint, and rollback workflow instead.

Only a classified `transport_unavailable` result may enter offline fallback.
The fallback defaults to 72 hours, is capped at seven days, and can only reduce
authority to the signed fallback plan, seats, features, and deadline. Protocol,
authentication, signature, replay, schema, and integrity failures never enter
fallback. An exact verdict replay is not fresh vendor contact, and no offline
artifact can clear a newer connected restriction.

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
