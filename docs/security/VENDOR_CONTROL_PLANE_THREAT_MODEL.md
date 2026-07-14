# Vendor Control Plane Threat Model

## Scope

This model covers one separately authenticated RedactWall vendor control plane
managing many independent customer data planes. It covers provisioning,
connected licensing, Stripe projection, diagnostics, Shadow AI intelligence,
policy desired state, and governed audit/support requests.

It does not authorize production deployment, Stripe mutation, credential
rotation, or customer telemetry collection. Those actions require explicit
operator authorization and approved non-production proof first.

## Assets

- Customer prompt, response, file, held-item, identity, policy, and audit data
- Customer deployment identity and connector credentials
- Vendor staff identities, MFA factors, sessions, roles, and recovery material
- Stripe event ledger and entitlement projection
- Connected entitlement, catalog, policy, and audit-request signing keys
- Offline fallback signing root
- Vendor and customer audit chains
- Provisioning state, AWS resource identities, and recovery artifacts

## Trust boundaries

### Legacy AWS connected cutover boundary

A pre-`DeploymentId` AWS migration uses an HMAC-authenticated private operator
manifest, a purpose-separated monotonic witness/tombstone, and an independent
CloudFormation lease. Replaying an older valid manifest against the current
witness fails closed. The lease survives deletion of the replaceable application
stack and blocks supported competing recreation. ALB deregistration completes
before the exact writer stops, and the final backup is created only from that
stopped writer. The checkpoint binds the bounded recovery set plus its
authenticated audit head/count/sequence. Candidate cleanup authority is the
immutable operation ID plus exact StackId returned by CloudFormation, never a
reused stack name. A legacy restore must use a preallocated operation ID and
attest a newly returned exact StackId, source template/parameter identities,
stopped recovery set, writer readiness, and ALB health before lease release.

After durable delivered-before-applied ACK evidence, the manifest enters the
one-way `connected_authority_committed` phase and every supported legacy
restart/rollback command fails. This AWS control is an operational fence, not a
cryptographic kill switch for a manually reconstructed obsolete image. Release
therefore also requires the customer runtime's authenticated connected
high-water and Owner-side revocation of every legacy license and credential.
The standalone migration CLI is intentionally release-blocked until production
Owner raw-receipt verification, customer acknowledged-high-water verification,
publication CAS, applied-attestation verification, and legacy restore adapters
are injected. Format-valid scalar values are never authority.

1. Vendor staff browser to vendor portal
2. Vendor portal to vendor database and private signing services
3. Vendor provisioner to an authorized AWS account and exact customer stack
4. Customer connector to vendor channel endpoints
5. Vendor signed artifact to customer verifier and durable state
6. Customer local policy, overrides, evidence, and administrator recovery
7. Stripe to the exact raw-body webhook and vendor billing ledger

Customer A and Customer B never share a database, evidence directory,
credential, deployment identity, local override store, or customer
administrator. Vendor search is over vendor-owned business and allowlisted
operational metadata, not customer audit databases.

## Data classification

### Never centralized

- raw or tokenized prompts and responses
- held content or uploaded files
- file names and local paths
- direct user or device identities
- full URLs or sensitive subdomains
- credentials, bearer tokens, signing keys, or MFA material
- arbitrary errors, stack traces, notes, or free-form diagnostic text
- customer audit rows or database copies
- payment credentials or cardholder data

### Allowed only through an exact typed channel

- customer and deployment IDs derived from connector identity
- business plan and seat counts
- product and applied-artifact versions
- closed diagnostic taxonomy and coarse buckets
- authorized Shadow AI candidate metadata
- signed entitlement, catalog, policy, and audit-request artifacts
- customer-approved bounded audit/support summaries

## Threats and required controls

| Threat | Impact | Required controls and evidence |
|---|---|---|
| Cross-customer confused deputy | A can read or mutate B | Scope from connector identity, exact body match, per-deployment credentials, two-silo negative tests |
| Credential theft or replay | False heartbeat, ACK, or telemetry | Secret hashing, revocation, rotation, nonce/idempotency high-water, rate limit, bounded request age |
| Online registry or entitlement replay | Restore revoked service or expand seats | Separate signatures, independent monotonic registry generation and entitlement version, stable registry-state digest, same-generation and same-version conflict rejection, durable shared high-waters |
| Clock manipulation | Extend fallback or accept expired authority | Authenticated trusted-time anchor, same-boot monotonic deadline, reboot re-enrollment requirement, bounded skew, rollback detection, signed absolute deadline |
| Vendor outage abuse | Customer blocks egress to bypass control | Fallback only after proven active enrollment, 72-hour default, seven-day maximum, visible degraded state |
| Vendor pause or revoke bypass | Protected AI use continues | Pause/revoke latch above fallback and Stripe, newer signed restore only, authorization reconciliation on every request |
| Security control shutdown | Revocation disables DLP or evidence | Separate protected-egress disposition from inspection, audit, evidence, admin, status, and recovery paths |
| Diagnostic smuggling | Prompt or secret reaches vendor | Strict schema and enums, no metadata bag, size limits, pre-serialization sanitizer, canary storage/log scans |
| Diagnostic row tamper or replay | Forged portal evidence or restored deleted telemetry | Purpose-specific row MAC, vendor audit anchor, exact message/digest claim, durable time high-water, bounded authenticated tombstone |
| Diagnostic connector flood | Vendor storage or search exhaustion | Per-deployment durable quota, bounded request age, retention ceiling, paginated search/export, bounded compaction batches |
| Shadow AI poisoning | Bad domain becomes global policy | Provenance, analyst approval, dedicated signature, monotonic release, staged adoption, tenant overrides, rapid rollback |
| Policy weakening | Vendor or attacker removes hard stops | Mandatory-controls digest, local normalization against all 21 `alwaysBlock` types, signed version, rejection and rollback tests |
| Audit/support overreach | Vendor reads customer evidence directly | Signed expiring request, recent step-up, closed fields and purpose, customer approval, response summaries only |
| Stripe replay or reordering | Incorrect entitlement state | Exact raw-body signature, idempotent event ledger, reconciliation, precedence rules, no frontend grant |
| Provisioning confused deputy | Wrong stack or destructive rollback | Exact tenant/region/stack/artifact/secret/volume identity, idempotency, ownership proof before cleanup |
| Signing-key crossover | One compromised key controls all channels | Purpose-bound keyrings and IDs, independent domains, key ID inside the signed input, current/next bounded overlap, cross-purpose fingerprint rejection, offline-root rejection, full crossover tests |
| Vendor compromise | Broad multi-customer damage | Least privilege, MFA, recent step-up, dual control for high-risk actions, immutable audit, emergency key and service isolation |

## Authority precedence

The customer computes licensing authority in this order:

1. emergency vendor or online-registry revoke
2. explicit signed entitlement pause or revoke
3. Stripe-derived entitlement projection
4. current signed connected entitlement plus an accepted online-registry generation
5. bounded outage fallback from the last active connected entitlement

No lower source can lift a higher restriction. Stripe becoming active does not
automatically clear an explicit pause or revoke. An offline license cannot lift
any connected pause or revoke. An online-registry `active` verdict cannot clear
an entitlement pause or revoke, and an entitlement `active` release cannot clear
an online-registry revoke without a newer accepted registry generation.

## Protected-egress disposition

Licensing decides whether protected AI egress or an ordinary licensed action
may complete. It does not decide whether RedactWall performs inspection,
mandatory blocking, audit capture, evidence export, administrator status, or
recovery.

When paused, revoked, or fallback-expired:

- local inspection still runs
- mandatory `alwaysBlock` behavior remains active
- a held item may be reviewed and denied
- status and audit evidence remain visible
- token rehydration and final release remain blocked
- vendor and customer audit chains remain verifiable

## Provisioning completion gate

A customer is not production-ready until all of these facts are independently
verified:

- unique customer and deployment identity
- exact AWS stack and durable evidence-volume identity
- connector credential enrolled and claimed
- first authenticated prompt-free heartbeat received
- first signed online-registry generation durably accepted and reported back
- first signed entitlement issued and delivered
- entitlement durably applied and exact version acknowledged
- public health and authenticated readiness pass
- exact image, config, license, policy, and secret versions attested
- customer audit integrity passes
- two-tenant isolation check passes
- first customer `security_admin` completed primary auth and MFA

The vendor never stores the customer's permanent password or MFA seed.

## Two-silo proof

The non-production harness starts one vendor plane and two customer silos with
different databases, evidence directories, deployment credentials, and local
overrides. It must prove:

1. A credential cannot address B even if the body claims B.
2. A never-connected silo cannot become ready or enter fallback.
3. Active, pause, revoke, newer restore, disconnect, and fallback expiry affect only the target silo.
4. Replay, same-version conflict, cache deletion, restart, replica failover, and clock changes cannot lower authority.
5. Diagnostics canaries leave no vendor database, audit, log, response, queue, or export residue.
6. A local Shadow AI observation or override is not searchable or mutable from the other silo.
7. Policy, catalog, and audit-request versions and acknowledgements are isolated.
8. Vendor and both customer audit chains verify after every lifecycle.

## Incident response and rollback

- Entitlement, catalog, and policy releases are independently versioned.
- A rollback is a new, higher signed version that names the prior release.
- Compromised keys are removed from the accepted key set and replaced under a
  bounded dual-key migration.
- Customer connectors can be revoked without rotating unrelated tenants.
- A vendor outage does not stop local DLP, audit, evidence, or recovery.
- An uncertain durable commit fails readiness and preserves prior authenticated
  state for repair instead of retrying a potentially committed mutation.

## Residual external evidence

Code and synthetic tests cannot complete these release predicates:

- authorized disposable AWS customer deployment and teardown
- real Stripe test-mode lifecycle and webhook reconciliation
- approved vendor hosting, TLS, secret manager, and managed database boundary
- customer-approved diagnostics schema, retention, consent, and deletion policy
- authorized Shadow AI environmental data sources
- production Owner and customer raw-receipt verifiers plus publication CAS for
  the one-way legacy connected-authority commit
- production legacy recreate/restore adapter and real stopped-writer rollback
  drill under the external lease
- independent security review with no unresolved critical or high finding

Until those proofs exist, the implementation may be locally complete but is
not production-certified.
