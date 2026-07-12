# Durability & security hardening — July 2026

A record of the multi-day hardening pass that landed on `main` in July 2026,
what it changed, why, and the evidence that certifies it. This complements the
condensed CHANGELOG entry with the reasoning and the exact proofs, so a future
reader (or examiner) does not have to reconstruct it from git history.

## How this work was produced

The pass began as an autonomous whole-codebase audit ("review the codebase,
understand the intent, and fix anything that doesn't work; verify every problem
and every fix"). It ran as a reproduce → red test → fix → re-prove loop: a
fresh adversarial review finds a defect, a failing test reproduces it, a
targeted fix closes it, and the full release gate re-certifies the tree. That
loop cycled many times over several days across the audit chain, private
storage, backup/restore, browser extension, gateway/sensors, and identity.

The work was then finished and integrated: the remaining in-flight fixes were
completed, every changed area was re-proven, the full `review:ci` gate was run
clean end to end with **zero runner retries**, and the outstanding feature
branches (credit-union compliance batch, console redesign, owner platform) were
merged into `main`.

## What changed, and why

### Audit chain — authenticated and crash-safe

The audit log was SHA-linked, which detects casual edits but not a writer that
recomputes the chain. Entries are now **HMAC-authenticated** with an external
key: recomputing every hash link still fails verification without the key.

Crash safety was the harder problem. A committed audit tail could, after a
crash, be deleted and then accepted against an older external checkpoint. The
fix is a durable **pending high-water** protocol: a mutation records an
authenticated pending marker before commit and holds the checkpoint lock across
commit/rollback, so a lost tail is detectable as truncation rather than
indistinguishable from a pristine state. Checkpoint fields are authenticated
**before** any field influences protocol logic (an earlier version read an
unauthenticated `count` first, which a forged checkpoint could use to change the
failure classification).

For the Postgres customer-silo, the anchor is bound to a single **database
scope** (migration 10). Two restores of one backup, or a cloned database, can no
longer share a scope whose advisory locks live in different databases. A
one-time **legacy bootstrap** upgrades a valid pre-migration-8 chain exactly
once; a restart that already sees migration 8 but no checkpoint rejects even a
self-consistent forged tail.

### Windows private storage — exact identity, real ACLs

Private state (audit sidecars, tokens, keys, seeded config) is verified by the
real Windows owner **SID** and the complete **DACL**, not a permissive check.
Files are bound by **exact BigInt device/file identity**: Node's default
Number-based `ino` rounds distinct NTFS file IDs to the same value, which was a
genuine path-swap bypass. Removal uses an exact **delete-on-close** handle so a
verified file cannot be swapped between check and unlink.

Because each of those checks costs Windows subprocesses, a steady-state audit
commit was launching ~24 owner/ACL probes. A **trusted-parent fast path** carries
the startup owner proof across directory-entry churn and rechecks only the parent
DACL + inode, cutting that to 4 without weakening the initial full proof. Lock
budgets are **30 s** for routine mutation and **60 s** for first-boot
initialization only.

The Windows principal is now read from the **System32 `whoami.exe` by absolute
path**. A PATH-resolved `whoami` can be shadowed — Git's `sh` ships a coreutils
`whoami` that prints the bare user name without the machine prefix — which broke
every ACL owner comparison when tests ran under the git pre-commit hook, and
could otherwise let a planted binary lie about the principal.

### Backup / restore — authenticated, atomic, and honest about Postgres

Backup manifests are **HMAC-authenticated** with an externally configured key (a
manifest MAC keyed from bytes inside the backup is meaningless). Artifact
publication is **atomic** with exact-byte rollback and quarantine of any changed
replacement. A **post-commit cleanup failure** no longer turns an already-durable
backup or restore into a reported failure — it attaches a sanitized
committed-cleanup warning carrying exact recovery paths, because a false failure
would drive a retry that duplicates the operation.

Postgres restore no longer pretends in-place `--force` (`pg_restore --clean`) is
a true replacement — it leaves unrelated target-only objects behind. Restore now
requires a **fresh, guarded, connection-disabled, randomly-named** database,
proves it is empty immediately before `pg_restore`, re-signs the audit scope to
the new database, and enables it only after verification. The shipped image
carries PostgreSQL 17 `pg_dump`/`pg_restore` so this is exercised, not asserted.

### Browser extension — canonical signing and fail-closed trust

The defining bug: `chrome.storage` recursively **alphabetizes** stored object
keys, so a policy signed over raw `JSON.stringify(policy)` became unverifiable
after a round-trip through storage. Signing moved to a deterministic **canonical**
form across the server, Node sensors, and the browser verifier, with
rolling-compatible verification of already-issued bundles.

Signed-policy trust pins an **Ed25519** key, keeps a verified **last-known-good**
cache with rollback resistance, and denies before any handler when no trusted
policy exists. Managed-storage enablement is administrator-owned (a force-managed
user can't pause enforcement). Redacted-token rehydration happens on an isolated
extension-only page, never re-inserted into the provider DOM.

### Gateway & sensors — no encoded egress, bounded reads

Encoded-content bypasses are closed: unpadded and UTF-16LE Base64, Base64 split
across adjacent structured text parts, SSE delta reconstruction, and binary Git
diffs are all inspected. Every control-plane response read is **bounded** and
**time-boxed**. Remote control planes are **HTTPS-only** with a development-only
insecure override; production can never send an ingest key over cleartext.

Native endpoint handoff is **idempotent**: a lost response no longer produces a
second query or a different terminal decision, enforced by an immutable,
HMAC-authenticated replay snapshot committed in the same transaction as the query
and audit. The optional standalone AI gateway returns `501` for AWS Bedrock
event-stream routes instead of advertising support it did not implement.

### Identity / auth / control-plane atomicity

Per-source login **spray limiting** with finite, bounded integer parsing
(`Infinity`/`NaN`/negative config is rejected, not silently disabling the limit).
Local login, OIDC callback, recovery-code use, and privilege step-up append their
audit event **before** issuing a session cookie, so an audit-store outage cannot
still hand out authority; recovery-code consumption is transactional. SCIM `PUT`
clears omitted optional identity bindings and revokes sessions so a stale OIDC
subject can't retain access; an unassigned SCIM/OIDC identity gets **no default
role**. Every administrative or SCIM mutation is coupled to its hash-chained
audit append and rolls back together.

## Evidence

The certifying run of the repository's authoritative gate, `npm run review:ci`,
exited 0 with **zero runner retries**:

- 208 Node test files (sequential, process-isolated)
- 38 Playwright browser scenarios (real Chromium extension flows)
- console TypeScript build, native-binding check, generated-doc + AI-domain
  drift checks, detector engine parity (`sync-check`)
- held-out detector evaluation: **100% micro precision/recall**, zero benign
  false positives, all floors met

Supporting proofs on the same tree:

- **Live PostgreSQL 17** matrix in a container against a disposable PG 17.10
  server with real `pg_dump`/`pg_restore`: **71/71** (storage, RLS, pg-bridge,
  authenticated backup/restore, guarded-target restore, tamper rejection).
- **Isolated-server simulation**: benign prompts allowed; synthetic SSN, credit
  card, address+phone, secret key, and password+email prompts blocked and held.
- **Audit tamper proof** on an isolated database: clean `ok:true` → out-of-band
  row rewrite `ok:false reason:chain` → exact restoration `ok:true`.
- **Hardened Docker runtime smoke** on the production image: `/readyz`
  configuration `ok`; SSN hard-stop → `pending`; no raw SSN in container logs;
  non-root uid/gid 1000; `/data` mode `0700`, SQLite db `0600`; no test /
  Playwright / extension-metadata residue in the image; audit chain `ok`.

## Also merged in this integration

- **Credit-union compliance batch (v0.4.0).** FFIEC IT Handbook booklet labels
  on the control map, a board cybersecurity-training attestation recorded in the
  tamper-evident audit chain (`POST /api/ncua/board-training`), a CSV `--column`
  flag for local roster Exact Data Match fingerprinting, and counsel-handoff /
  pricing docs. (See the [0.4.0] CHANGELOG section.)
- **Operator console redesign.** A cohesive, accessible, responsive rework of the
  React console — design system, responsive shell, state-truthfulness, map
  controls — with no change to security semantics, plus new end-to-end console
  contract suites.
- **Owner platform.** An isolated internal operations control plane
  (`owner-platform/`) — its own Express app, database, auth/RBAC, and port,
  importing nothing from the customer product (enforced by a test).
