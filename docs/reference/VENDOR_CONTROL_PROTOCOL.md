# Vendor Control Protocol v1

## Purpose

This protocol connects one RedactWall vendor control plane to many independent
customer data planes. It does not turn customer `security_admin` accounts into
vendor identities and does not grant the vendor direct access to a customer
database, evidence directory, prompt, held item, file, user identity, or
credential.

The executable contract is `server/vendor-control-protocol.js`. It uses strict
schemas, closed enums, canonical JSON, per-channel size ceilings, dedicated
signature domains, and monotonic versions. Unknown fields fail before outbound
serialization or inbound state mutation.

## Identity and scope

Every production customer deployment receives a unique `customerId`,
`deploymentId`, and connector credential during vendor-controlled enrollment.
The vendor derives the effective customer and deployment scope from that
authenticated credential. A body that names a different customer or deployment
is rejected. Body fields never select the tenant.

Credentials are per deployment, revocable, and independently rotatable. They
must not be reused as signing keys, offline-license roots, Stripe secrets,
session secrets, or audit keys. Heartbeat, acknowledgement, diagnostics, and
Shadow AI candidate calls use distinct scoped connector credentials. Reusing
one bearer value across two channel scopes fails connector configuration.

## Channels

| Kind | Direction | Purpose | Maximum bytes | Integrity |
|---|---|---|---:|---|
| `heartbeat.v1` | Customer to vendor | Prompt-free license and adoption state | 8 KiB | Authenticated connector |
| `entitlement.release.v1` | Vendor to customer | Plan, seats, features, pause, revoke, and restore | 16 KiB | Dedicated vendor signature |
| `acknowledgement.v1` | Customer to vendor | Delivery or durable-application evidence | 8 KiB | Authenticated connector |
| `diagnostic.event.v1` | Customer to vendor | Closed-taxonomy operational metadata | 8 KiB | Authenticated connector |
| `shadow-ai.candidate.v1` | Customer to vendor | Authorized candidate intelligence | 8 KiB | Authenticated connector |
| `shadow-ai.global-catalog-release.v1` | Vendor publication | Customer-neutral analyst-approved global catalog | 512 KiB | Dedicated global-catalog signature |
| `shadow-ai.catalog-distribution.v1` | Vendor to one customer deployment | Tenant rollout envelope binding one exact global artifact | 16 KiB | Separate distribution signature |
| `policy.desired-state.v1` | Vendor to customer | Signed policy bundle reference and mandatory-control digest | 16 KiB | Dedicated vendor signature |
| `audit-support.request.v1` | Vendor to customer | Expiring governed request | 16 KiB | Dedicated vendor signature |
| `audit-support.response.v1` | Customer to vendor | Customer-approved bounded summaries | 64 KiB | Authenticated connector |

Channels are separate endpoints, queues, rate limits, storage tables, and
permissions. Heartbeat success does not imply diagnostics consent. Diagnostics
failure does not alter licensing. Catalog or policy rejection does not grant
fallback licensing authority. Diagnostics and candidate intelligence remain
disabled until their separate customer-consent flags are explicitly enabled.

## Heartbeat

The default interval is 60 seconds. Configuration may select 30 through 300
seconds. Values outside that range fail configuration instead of being silently
clamped.

The heartbeat carries only:

- protocol and message identity
- customer and deployment binding
- a random heartbeat nonce
- plan, seats used, and seat limit
- product version and timestamp
- last applied online-registry generation, entitlement version, policy version,
  and catalog version

It never carries prompts, responses, held content, file names, URLs, user or
device identities, stack traces, arbitrary errors, notes, or diagnostics.

The connector sends immediately at startup, after applying a signed artifact,
and after reconnecting. Normal retries use bounded exponential backoff and
jitter. A new heartbeat nonce prevents a captured request from becoming a
fresh contact event.

`lastAppliedRegistryGeneration` is an independent monotonic high-water. It is
not an alias for entitlement, policy, or catalog version. A value of `0` means
that no signed online-registry verdict has been durably accepted, and an
activated production deployment must remain unready in that state. Lower
registry generations are rejected. A same-generation heartbeat may carry a
new signed issuance time, but it must bind the same stable registry-state
digest and status; a same-generation state conflict fails closed. The exact
latest verdict envelope digest and signing key remain audit evidence, but the
time-varying envelope digest is not used as the stable state identity.

An online-registry `active` verdict cannot clear an explicit entitlement pause
or revocation. Online registry generation and entitlement version advance
independently, and enforcement applies the most restrictive valid authority.
The vendor registry pair also requires its own non-rewindable witness boundary;
the customer acknowledgement field does not replace that vendor-side witness.

### Frozen heartbeat transport

The only licensing route is `POST /v1/heartbeat` on the configured exact HTTPS
origin. `/heartbeat` has no compatibility alias. Requests use
`application/json` or `application/json; charset=utf-8`, are limited to 8,192
bytes, and must complete server-side body reading within five seconds. The
customer total request deadline defaults to eight seconds and may be configured
only from 1 through 30 seconds. Redirects are rejected.

The request has these exact ordered required keys:

1. `schemaVersion`
2. `messageId`
3. `customerId`
4. `deploymentId`
5. `kind`
6. `heartbeatNonce`
7. `plan`
8. `seatsUsed`
9. `seatLimit`
10. `version`
11. `sentAt`
12. `lastAppliedEntitlementVersion`
13. `lastAppliedRegistryGeneration`
14. `lastAppliedPolicyVersion`
15. `lastAppliedCatalogVersion`

`schemaVersion` is `1`, `kind` is `heartbeat.v1`, and `deploymentId` matches
`dep_[a-f0-9]{32}`. `sentAt` is canonical millisecond UTC within five minutes.
Null and unknown fields are rejected. The authenticated heartbeat credential,
not request fields, selects the exact customer and deployment. The vendor
durably claims `messageId` plus nonce for 15 minutes. An exact duplicate returns
the exact cached response bytes without becoming fresh contact; conflicting
reuse returns HTTP 409.

A successful response is exactly `application/json; charset=utf-8`, no larger
than 24,576 bytes, and includes exact `Content-Length`, `Cache-Control:
no-store`, `Pragma: no-cache`, and `X-Content-Type-Options: nosniff`. Its exact
ordered keys are:

1. `schemaVersion`
2. `kind`
3. `requestMessageId`
4. `onlineRegistryVerdict`
5. `entitlementArtifact`

`schemaVersion` is `1`, `kind` is `heartbeat.response.v1`, and
`requestMessageId` exactly echoes the request. `onlineRegistryVerdict` is
always a non-null signed v2 text envelope. `entitlementArtifact` is either null
or the exact signed `{ keyId, payload, signature }` representation of
`entitlement.release.v1`. Null grants no entitlement, and an active registry
verdict plus null entitlement cannot enable protected egress. The vendor still
returns a signed revoked registry verdict when entitlement projection is
unavailable.

The customer parses and verifies both artifacts independently, then reverifies
their raw bytes inside one DB and audit transaction. That transaction applies
the distinct registry and optional entitlement high-waters and creates or
reuses immutable ordered delivery acknowledgements. Any verification, scope,
state, audit, or acknowledgement failure rolls back the complete response. An
exact registry-verdict replay is not fresh contact. Final enforcement uses the
most restrictive durable result.

HTTP 401 and 403 map to `authentication_rejected`; 409 maps to
`version_conflict`; 429 maps to `rate_limited`; 408, 502, 503, 504, and
allowlisted network timeouts or unreachable errors map to
`transport_unavailable`; 500 and unknown transport failures map to
`transport_ambiguous`; 400, 404, 405, 413, 415, and 422 map to
`protocol_rejected`. Invalid media, schema, or correlation maps to
`invalid_schema`, and response overflow maps to `response_too_large`. Only
`transport_unavailable` can authorize bounded outage fallback. A signed revoke
is a normal HTTP 200 response, never a transport failure.

The acknowledgement route is `POST /v1/acknowledgements`, uses the distinct
acknowledgement credential and strict `acknowledgement.v1` schema, and is capped
at 8,192 bytes. A delivered acknowledgement must be durably accepted before an
applied acknowledgement is sent. Exact replay returns 204, conflict returns
409, and incomplete final acceptance returns 503 so the exact retry can resume.
Publishing an entitlement to the delivery projection means only `issued`;
customer acknowledgements advance `delivered`, `applied`, and finally
`acknowledged`.

### Connected configuration names

Customer silos use these exact environment names:

- `REDACTWALL_LICENSE_SERVER_URL`
- `REDACTWALL_TENANT_ID`
- `REDACTWALL_CONNECTED_DEPLOYMENT_ID`
- `REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN`
- `REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN`
- `REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN`
- `REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN`
- `REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED`
- `REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED`
- `REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS`
- `REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS`
- `REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY` or `_B64`
- `REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY` or `_B64`
- `REDACTWALL_ENTITLEMENT_PUBLIC_KEY` or `_B64`
- `REDACTWALL_ENTITLEMENT_KEY_ID`
- `REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY` or `_B64`
- `REDACTWALL_ENTITLEMENT_NEXT_KEY_ID`

The vendor issues each deployment identity in the exact `dep_` plus 32
lowercase hexadecimal character form. Setup accepts it only via
`--deployment-id`; it never generates, normalizes, or rotates this value. An
empty configuration may be enrolled once. After enrollment, reruns preserve
the exact value, and both `--force` and a mismatched replacement fail before
the environment file is written. Connected preflight requires both the exact
deployment identity and `REDACTWALL_TENANT_ID`.
`REDACTWALL_LICENSE_CUSTOMER_ID` remains an offline-license binding and cannot
supply connected customer scope.

Connected production rejects the legacy
`REDACTWALL_LICENSE_SERVER_TOKEN`. Current and next keys are selected only by
the signed key ID, with at most two Ed25519 public identities per purpose. The
runtime does not trial-verify keys, invent default IDs, or permit any SPKI
identity to cross purposes.

The isolated license service receives only
`LICENSE_VERDICT_SIGNING_KEY_PATH`, `LICENSE_VERDICT_SIGNING_KEY_ID`,
`LICENSE_ENTITLEMENT_CURRENT_PUBLIC_KEY_PATH`,
`LICENSE_ENTITLEMENT_CURRENT_KEY_ID`,
`LICENSE_ENTITLEMENT_NEXT_PUBLIC_KEY_PATH`,
`LICENSE_ENTITLEMENT_NEXT_KEY_ID`, and `LICENSE_ENTITLEMENT_DELIVERY_DIR`.
Owner uses `OWNER_ENTITLEMENT_CURRENT_PRIVATE_KEY_PATH`,
`OWNER_ENTITLEMENT_CURRENT_KEY_ID`,
`OWNER_ENTITLEMENT_NEXT_PRIVATE_KEY_PATH`,
`OWNER_ENTITLEMENT_NEXT_KEY_ID`, and
`OWNER_CONNECTED_ENTITLEMENT_DELIVERY_DIR`. The license service sees the
read-only signed delivery projection and entitlement public pins only. It never
receives Owner database access, Stripe authority, private entitlement keys,
command keys, audit keys, lifecycle keys, or witness keys.

## Signed entitlements

An entitlement binds all enforcement authority to:

- exact customer and deployment
- `active`, `paused`, or `revoked` status
- plan, seats, and feature set
- monotonic entitlement version and previous version
- issued and expiry times
- an active-only fallback deadline
- a closed reason code

The customer commits the canonical digest, high-water version, entitlement,
trusted wall-time and monotonic boot anchors, audit evidence, signing key ID,
signature domain, and acknowledgement outbox entry in one transaction. The
durable boundary accepts only the complete signed artifact and verifies it
again against the configured current/next connected keyring inside that
transaction. A response is not considered applied before that commit.

An older version is rejected. An equal version with the same digest is an
idempotent redelivery and reuses the exact immutable acknowledgement event. An
equal version with different bytes is a conflict and fails closed. Every newer
release must name the exact current version as its predecessor, so delivery
cannot skip a withheld pause or revocation. A paused or revoked state can be
restored only by a newer signed active entitlement with `manual_restore`.

The signing input is the channel signature domain, key identifier, and
canonical payload separated by NUL bytes. This binds accepted state and audit
evidence to the exact rotation identity. Production accepts at most the current
and next online key. Keyrings are bound to one signed channel, key identifiers
must name that purpose, fingerprints cannot be registered under a second
purpose in the same customer runtime, and the offline license root is rejected
from every connected keyring.

An entitlement key identifier is exactly `rw-entitlement-` followed by the
full 64-character lowercase SHA-256 fingerprint of that Ed25519 public key's
SPKI DER bytes. Current and next lookup uses only the signed key identifier.
Aliases, truncated fingerprints, trial verification, and default-key fallback
are forbidden.

## Delivery lifecycle

The vendor ledger tracks these stages independently:

1. `requested`
2. `issued`
3. `delivered`
4. `applied`
5. `acknowledged`

Stages cannot be skipped or moved backward. Repeating the same stage is
idempotent. Portal status must not say complete when only issuance or delivery
is known. Customer messages may report only `delivered` or `applied`. The
vendor-owned ledger advances to `acknowledged` only after it accepts the exact,
tenant-bound applied ACK.

Publishing an artifact into the license-service projection leaves it at
`issued`. A customer `delivered` ACK advances `issued` to `delivered` and must
receive a durable `204` before the customer sends its `applied` ACK. The
`applied` ACK advances `delivered` through `applied` to `acknowledged` and
returns `204` only after final durable acceptance. If final acceptance is
pending, the Owner route returns `503`; an exact retry resumes the same
operation. Exact replay returns `204`, while reuse with different bytes returns
`409`. A vendor-side publication or delivery attempt cannot claim either
customer stage.

## Offline outage fallback

Offline licensing is not a second authority. It is an automatic, degraded
outage mode available only when all of these facts are proven:

- this deployment previously enrolled successfully
- the last accepted connected entitlement was active
- its durable high-water and canonical digest are intact
- the current failure is genuine transport unavailability
- the trusted-time anchor does not show clock rollback
- same-boot monotonic elapsed time has not exceeded the fallback allowance
- the signed fallback deadline has not passed
- the signed offline artifact is active and binds the exact customer and deployment

The default fallback window is 72 hours and the absolute maximum is seven days.
Fallback cannot increase plan, seats, or features above the last connected
entitlement. It is unavailable for never-connected deployments, pause, revoke,
invalid signatures, malformed responses, customer or deployment mismatch,
version conflicts, missing state, corrupt state, or clock rollback.

If a machine reboots during an outage, the prior boot's monotonic evidence is
not reusable. Linux uses the kernel boot UUID, Windows uses the operating
system boot timestamp, and macOS uses the kernel boot timestamp. If that
identity cannot be obtained, connected fallback fails closed. Protected egress
remains blocked until a fresh authenticated vendor contact establishes a new
wall-time and monotonic anchor.

After fallback expires, protected AI egress and ordinary licensed operations
fail closed. Detection, mandatory blocking, local inspection, audit integrity,
evidence export, administrator status, and recovery remain available.

## Diagnostics

Diagnostics use a closed component, code, severity, outcome, count bucket, size
bucket, timing bucket, retry state, version, and timestamp. The schema rejects
arbitrary error messages, stack traces, host names, subdomains, URLs, file
names, prompts, identities, and metadata bags.

Customer-side sanitization is authoritative. If sanitization or schema
validation fails, nothing is sent. Rejection is recorded locally using a fixed
reason code that does not include the rejected value. The durable customer
outbox uses transactional enqueue, bounded capacity, exact message/digest
idempotency, leased delivery, bounded retry, and fixed-schema local audit
descriptors.

Vendor ingestion derives customer and deployment scope from the authenticated
diagnostics credential and then requires an exact body match. It rechecks the
customer's current diagnostics consent, enforces a durable per-deployment
quota, and stores only the validated protocol snapshot. Each retained row and
replay tombstone is authenticated under the diagnostics-integrity domain and
bound to a vendor audit event. Portal searches are bounded and post-validated
against the trusted vendor identity's customer scope. Export additionally
requires a fresh step-up event. Retention compacts expired rows to bounded,
authenticated replay tombstones before final deletion, while the maximum
accepted event age prevents a deleted tombstone from reopening replay.

The included vendor diagnostic SQLite runtime is test/reference-only. Its
constructors inspect the actual process environment and reject production even
when a caller supplies a development environment, preopened store, wrapped
storage, or assurance label. Reference health always reports
`productionReady: false`. Managed Postgres plus an independently retained
exact-CAS witness remains a production blocker.

## Shadow AI

Customer-local observations and tenant overrides remain in the customer silo.
The outbound candidate channel may carry only an authorized registrable domain,
coarse first-seen day, count bucket, source class, confidence, local
classification, and local outcome.

Protocol v1 currently accepts only already-normalized two-label aggregate
domains and rejects long numeric or sensitive-looking labels, reserved or
private TLDs, and DNS-import candidates. It does not try to derive a
registrable domain from arbitrary host input. A future public suffix
implementation requires an approved production dependency and its own privacy
tests.

Vendor analysts approve or reject candidate records before publication. Global
catalog releases are customer-neutral, signed, monotonic, versioned, and
rollback-aware. Distribution is a second signed artifact with its own
per-deployment sequence. It binds the exact global release ID, global version,
complete global-artifact digest, records digest, tenant scope, and rollout. A
new customer can therefore receive current global version N as distribution
sequence 1 without pretending that global and tenant history are the same
counter. Both signed payloads also bind the reconciled authority-manifest
generation and the exact `current` or `next` signing slot. Incoming artifacts
are accepted only from the current manifest generation and an active slot.
The vendor captures one authority snapshot for each publication, rechecks it
before commit, and refuses to combine a global artifact from generation N with
a distribution signed at N+1. After manifest rotation, the global catalog must
be republished under the new generation before any new tenant distribution can
be created. The customer likewise rechecks the same authority snapshot inside
its application transaction, so a concurrent rotation cannot turn a
historical `verifyOnly` key into current delivery authority.
Persisted history is reverified through the exact purpose-and-key-ID resolver,
which may return a referenced `verifyOnly` key but never makes that key eligible
for new delivery. Applied or rejected acknowledgements target the distribution
sequence and repeat the exact global-artifact binding.

Customer acknowledgements are durable transitions, not freshly generated HTTP
responses. The exact target, lifecycle stage, and outcome identify one stored
canonical payload. Required delivery records `delivered` and then `applied`
once; a restart or lost response returns the exact same bytes. The vendor
deduplicates that transition independently of the random message ID. A rejected
transition is separately bound and cannot be multiplied into additional failure
evidence by changing only the message ID. Customer ACK transitions are created
inside the same catalog transaction as the applied distribution. Their
canonical chain count, head digest, and target-version high-water are included
in the catalog head committed through the non-rewindable witness. A database
snapshot from before ACK persistence therefore fails readiness instead of
minting a different acknowledgement.

Every versioned read supplies and verifies the expected release ID, global
version, artifact digest, and records digest. Current global state,
classification revisions, per-deployment distribution state, and adoption
revisions have authenticated monotonic heads bound to the complete audit-chain
count, sequence, and head. A pending witness freezes readiness until deterministic
reconciliation. Replaying an older valid row, deleting or reordering a middle
audit row, or swapping a valid artifact into a different lookup fails closed.
The vendor audit keeps a bounded active suffix and advances an authenticated
checkpoint plus a monotonic tail anchor in the same serializable transaction,
so compaction does not reopen valid-old replay or hide chain gaps.

Candidate consent is prospective after approved evidence has been de-linked
into the customer-neutral catalog. Revocation or deletion immediately blocks
new candidate ingestion, local-observation reads, and analyst review for that
scope, purges the remaining customer-local observations, and records a
prompt-free purge audit. It does not silently delete already approved global
intelligence. Every consent epoch binds the consent ID, revision, complete
consent digest, status, and epoch. If the consent authority advances through a
revoke and regrant without an intervening Shadow AI call, the first read under
the new grant purges prior-epoch observations and page snapshots before any
result is visible. A synchronous consent-transition hook performs the same purge
and records its witness for Owner outbox integration. Production construction
remains unavailable until that Owner transition adapter is wired. Tenant
overrides remain local and cannot mutate the global record or another tenant's
override.

Portal pagination uses short-lived HMAC-authenticated cursors over immutable,
authenticated page snapshots. The cursor binds channel, scope, page size,
snapshot identity, page index, and expiry. Inserts or classification updates
between pages cannot appear in the existing snapshot, and swapped or reordered
page rows fail their authenticated descriptor.

A catalog rollback is itself the next signed release. It names an earlier
locally known version and carries records with the exact digest of that
reverified signed history row. The customer never changes its high-water back
to the old version. A first-time customer may adopt the vendor's signed current
release even when that release is a rollback, because it has no prior local
history to reverify; an existing customer still requires the rollback target
inside its retained local window.

Customer catalog history retains a fixed rollback window of active distribution
states, then replaces older states with authenticated bounded tombstones.
Compaction occurs inside the same serializable, signed-release application and
audit transaction. Complete signed global artifacts have their own bounded
rollback window rather than inheriting the distribution-retention clock. This
preserves independently verifiable rollback proof when more than 32 tenant
distribution revisions reference only a few global releases. The most recent
32 global artifacts are retained, with one additional slot only when an older
active rollout must remain usable. The retained artifact count and canonical
head digest are part of the customer catalog's non-rewindable witnessed head,
so deletion or replay freezes readiness. Once the bounded distribution tombstone
archive is full, the oldest authenticated tombstone is exact-deleted in the
same transaction. An application acknowledgement is emitted only for the
committed state. Active states and retained tombstones contribute reference
counts for both global and distribution signing keys, so an archived key is
retireable only when its retained reference count is zero.

The executable Shadow AI SQLite adapter is a single-row, HMAC-authenticated JSON
reference implementation. It proves restart behavior, exact CAS, transaction
rollback, and the vendor-to-customer applied-ACK path, but it is not a production
vendor datastore or a scalability claim. `NODE_ENV=production` refuses the vendor
adapter. Managed Postgres remains a required production implementation blocker.
Reference constructors cannot be promoted by passing `NODE_ENV`, `production`,
`productionReady`, assurance labels, or wrapped copies. Production constructors
require privately branded managed storage, an independently retained witness, a
reconciled authority manifest, and the consent-transition adapter; no such
complete vendor production adapter is currently exported.

The SQLite monotonic-anchor store is also test/reference-only because a coherent
snapshot can rewind both the primary database and a witness on the same host.
Production must inject an independently retained, non-rewindable exact-CAS witness.
The witness provider owns and declares that assurance. A caller cannot upgrade a
reference provider by adding an assurance label. Customer catalog and override
witnesses are customer-local authorities and must be distinct from Owner catalog,
manifest, registry, audit, signing, and commercial authorities.

The customer Shadow AI package boundary includes only customer catalog state,
customer storage, its witness client, and public signature verification. It excludes
vendor intelligence, the authority manifest, signing private keys, vendor ledgers,
vendor compaction authority, Owner routes, and Owner secrets.

## Policy desired state

The desired-state message binds a policy bundle by version and digest and also
binds a mandatory-controls digest. The customer derives the mandatory set from
`server/policy.js`, normalizes the vendor bundle internally, and permits only a
narrow tenant override schema that mechanically adds restrictions or raises
enforcement strength. Caller callbacks cannot attest a weaker effective
policy. Licensing fail-closed and audit-required controls are forced on before
the effective digest is committed.

Policy rollback is explicit in `rollbackOfVersion`. It is accepted only in the
next linked release, must target a version older than the current release, and
must reproduce that known bundle digest. Matching an older digest without the
signed rollback field is an ordinary new release, not an inferred rollback.

## Governed audit and support

The vendor never opens a customer database or evidence volume. A privileged,
recently reauthenticated vendor operator may issue a signed, expiring,
tenant-bound request with a closed purpose, request type, field allowlist,
record ceiling, and time window of at most 24 hours.

The customer may approve, deny, let expire, or revoke the request. A response
contains only allowed coded summaries. Both planes append sanitized audit
evidence for request, decision, response, expiry, and revocation.

Customer responses are one-shot per request version. The sum of represented
records, not only the number of summary rows, is capped by `maxRecords`.
Duplicate summary fields are rejected, and clock rollback cannot extend an
approved request window.

## Key separation

At minimum, production uses independent keys and signature domains for:

- offline outage licenses
- connected entitlements
- Shadow AI catalog releases
- policy desired state
- governed audit/support requests
- diagnostic retention and replay-tombstone integrity
- vendor audit integrity
- Shadow AI catalog-state integrity
- command and acknowledgement idempotency
- pagination cursors and immutable page descriptors
- each customer connector identity

Rotating one key must not authorize another channel. Rollout supports current
and next public keys only for a bounded overlap, and accepted artifacts remain
bound to the exact key identifier and canonical digest.

Shadow AI routes platform audit records, command/acknowledgement claims,
pagination state, and all remaining catalog state through four distinct HMAC
authorities. The first three must match the manifest's `platform_audit`,
`command_idempotency`, and `pagination_cursor` current identities exactly. The
supplemental catalog-state integrity identity and each external witness remain
outside the 20 application purposes and must be distinct from every manifest
identity, signing key, commercial offline/online authority, and each other.

The signed authority manifest has exactly these 20 application purposes:

1. `offline_license`
2. `online_verdict`
3. `entitlement`
4. `platform_audit`
5. `recovery`
6. `diagnostic_integrity`
7. `audit_request`
8. `policy`
9. `lifecycle`
10. `catalog_global`
11. `catalog_distribution`
12. `owner_attestation`
13. `witness_integrity`
14. `heartbeat_credential`
15. `acknowledgement_credential`
16. `diagnostic_credential`
17. `shadow_candidate_credential`
18. `license_registry_integrity`
19. `command_idempotency`
20. `pagination_cursor`

The manifest carries cumulative authenticated tombstones for every retired key
ID and identity across all purposes and identity types. Generation one has no
retired history. Later generations must carry the exact prior tombstones plus
every identity removed by that transition. Dropping and later re-adding a key,
reusing its identity under another purpose, or promoting a retired key is
rejected. The bounded tombstone capacity fails closed instead of discarding
lifetime retirement history.

External monotonic witnesses are separate authorities and do not increase that
application-purpose count. The reserved Owner environment names for this slice are
`OWNER_AUTHORITY_MANIFEST_WITNESS_KEY`, `OWNER_CATALOG_WITNESS_KEY`,
`OWNER_LICENSE_REGISTRY_WITNESS_KEY`, `OWNER_COMMAND_IDEMPOTENCY_KEY`, and
`OWNER_PAGINATION_CURSOR_KEY`. HMAC secrets use
canonical Base64 for exactly 32 decoded bytes. The catalog witness cannot equal the
manifest or registry witness, command-idempotency key, pagination-cursor key,
platform audit key, commercial offline signing authority, or online-verdict signing
authority. The registry witness is independently retained outside the replaceable
registry pair and is pairwise distinct from every application, channel, integrity,
recovery, audit, signing, and other witness authority.

Vendor catalog history retains 32 active global releases and 32 active distributions
per deployment before authenticated compaction. Customer silos retain 32 active
distribution states plus an independent bounded set of complete signed global
artifacts for rollback verification. Rollback cannot target data outside the
retained and cryptographically reverified global-release window.

## Compatibility and rollout

Protocol v1 is introduced in shadow mode before it becomes an enforcement
authority. Existing customer silos keep their current enforcement during the
migration. A production deployment becomes connected-ready only after it has a
deployment identity, enrolled connector, first authenticated heartbeat, first
signed online-registry generation, first signed entitlement, durable application,
exact-generation and exact-version acknowledgement,
health and readiness proof, audit verification, tenant-isolation proof, and
customer administrator MFA.

Legacy v1 `active` and `revoked` verdicts cannot silently populate the strict
v2 online-registry high-water. Migration requires an explicitly issued v2
registry verdict, a separately signed v1 entitlement, and an acknowledged
cutover.
