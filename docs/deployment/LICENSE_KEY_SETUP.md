# License Signing Key Setup

How the vendor generates the real Ed25519 license signing keypair, provisions
the public trust anchor, protects the private key, and issues customer
licenses. This is the mechanical companion to
`docs/process/CUSTOMER_LICENSING.md`, which defines the commercial model
(plans, seats, expiry behavior, pricing shape).

Do this **once, before the first commercial release**. `server/license.js`
ships with a placeholder public key for development. A production license will
not verify until its real public trust anchor is supplied through the supported
AWS secret or embedded in a separately distributed air-gapped build.

## How verification works

A license is an offline, signed file — never a phone-home check:

- `redactwall.lic` = `base64(payload JSON)` + `.` + `base64(Ed25519 signature)`.
- The server verifies it at boot and on every managed-license status check
  against a configured Ed25519 public key. AWS silos use
  `REDACTWALL_LICENSE_PUBLIC_KEY_B64`; air-gapped distributions may embed the
  same key in `server/license.js`.
- Every license must carry a tenant-style `customerId`: 2 to 63 lowercase
  letters, digits, underscores, or hyphens, starting with a letter or digit.
  At install and boot the
  server binds it to `REDACTWALL_LICENSE_CUSTOMER_ID`, or to
  `REDACTWALL_TENANT_ID` for a customer-silo deployment. If both settings are
  present they must identify the same customer.
- The private signing key exists only at the vendor, offline. Whoever holds it
  can mint licenses for any customer, any seat count, any expiry.
- Connected-mode heartbeat verdicts use a different Ed25519 keypair and
  signature domain. Never install this offline private key on the connected
  license server. That service requires the offline **public** key only so it
  can reject accidental key reuse.
- Tests are unaffected by the embedded key: the suite generates throwaway
  keypairs and injects them via `REDACTWALL_LICENSE_PUBLIC_KEY`, so replacing
  the placeholder breaks nothing.

## Step 1 — Generate the keypair (offline)

Run on a trusted machine, ideally offline:

```bash
npm run license:issue -- --init-keypair ~/redactwall-license-keys
```

This writes two files into the directory:

| File | What it is | Permissions |
|------|------------|-------------|
| `license-signing-key.pem` | **Private** signing key (PKCS8 PEM). Never leaves this machine unencrypted. | `0600` |
| `license-signing-pub.pem` | Public key (SPKI PEM). Safe to share; gets embedded in the product. | default |

The command also prints the public PEM to the terminal.

## Step 2 — Provision the public trust anchor

For an AWS customer silo, convert `license-signing-pub.pem` to one-line SPKI DER
base64 and set `REDACTWALL_LICENSE_PUBLIC_KEY_B64` in that customer's immutable
Secrets Manager version. `AWS_SAAS_DEPLOYMENT.md` has the exact command. The
public key is not secret. The private key must never enter AWS.

For a separately shipped air-gapped image, embed the public trust anchor at
build time without changing source:

```bash
PUBLIC_KEY_B64="$(openssl pkey -pubin -in ~/redactwall-license-keys/license-signing-pub.pem -outform DER | base64 | tr -d '\\r\\n')"
docker build --build-arg REDACTWALL_LICENSE_PUBLIC_KEY_B64="$PUBLIC_KEY_B64" -t redactwall:licensed .
```

The Docker build runs the same trust-anchor gate and fails if the value is not
a valid Ed25519 public key or is the known placeholder. The resulting image
verifies signatures with zero runtime configuration and zero egress. The
public key is intentionally visible in image metadata; never pass the private
signing key as a build argument or environment variable.

Run the gate to confirm nothing depended on the placeholder:

```bash
npm run license:trust-check -- --public-key-file ~/redactwall-license-keys/license-signing-pub.pem
npm test -- test/license.test.js test/license-api.test.js
```

Managed production preflight and the release trust check reject the known
placeholder. Complete this step before the first licensed deployment.

## Step 3 — Protect the private key

- **Custody:** keep `license-signing-key.pem` off the repo, off the Docker
  image, off AWS, and off any machine that syncs to cloud storage. A
  password-manager secure note or hardware token plus one encrypted offline
  backup (for example a USB drive in a safe) is proportionate.
- **Loss** means you cannot issue or renew any license — every renewal would
  require shipping a new embedded key to every customer (see Rotation).
- **Leak** means anyone can mint valid licenses; treat it as an incident and
  rotate.
- Record who has access. At silo scale that list should be one or two people.

## Step 4 — Issue a customer license

```bash
npm run license:issue -- \
  --key ~/redactwall-license-keys/license-signing-key.pem \
  --customer "Acme Credit Union" \
  --customer-id cu-acme \
  --plan standard \
  --seats 120 \
  --expires 2027-08-01 \
  --grace-days 30 \
  --out acme-redactwall.lic
```

Flag reference (`scripts/license-issue.js`):

| Flag | Meaning | Default |
|------|---------|---------|
| `--key <pem>` | Private signing key path | required |
| `--customer "<name>"` | Display name shown in the console | `Unknown` |
| `--customer-id <id>` | Required stable tenant-style customer slug, 2 to 63 characters | required |
| `--plan standard\|enterprise` | Plan; feature gates follow `docs/process/CUSTOMER_LICENSING.md` | required |
| `--seats <n>` | Licensed seat count | required |
| `--expires YYYY-MM-DD` | Expiry date | required |
| `--grace-days <n>` | Grace window after expiry | `30` |
| `--features a,b,c` | Optional feature flags | none |
| `--out <file>` | Output file | `redactwall.lic` |

The tool self-verifies the signed output against the public key derived from
your private key and refuses to write a file that does not verify.

## Step 5 — Install and verify at the customer

Two equivalent installs:

- **Console:** Configuration tab → paste the license file contents
  (Security Admin role).
- **API:** `POST /api/billing/license` with the license text — requires an
  authenticated Security Admin session and a CSRF token, and deliberately
  works even when an expired license has made config read-only, so a renewal
  can always be installed.

Alternatively, drop the file as `redactwall.lic` next to `.env` (or point
`REDACTWALL_LICENSE_PATH` at it) and restart.

Before installing, bind the deployment to the same customer id used when the
license was issued:

- Customer-silo/SaaS: set `REDACTWALL_TENANT_ID=cu-acme`.
- Licensed non-SaaS or air-gapped standalone: set
  `REDACTWALL_LICENSE_CUSTOMER_ID=cu-acme`.
- If both are set, they must match. A missing license `customerId`, a mismatch,
  or conflicting deployment settings is rejected during API install and boot.

Verify with `GET /api/billing/license` (state should be `active`, with the
expected plan/seats/expiry) and `GET /api/billing/seats` for usage. Installs
are recorded in the audit log as metadata only — never the license text.

## License states (what expiry actually does)

| State | Trigger | Effect |
|-------|---------|--------|
| `unlicensed` | No/invalid license file | Demo mode, clearly labeled; zero gating |
| `active` | Before expiry | Full product |
| `grace` | Expired, within `graceDays` | Full product plus a renewal banner |
| `readonly` | Past grace | Admin **config writes** return 403; detection, enforcement, approvals, audit, evidence export, and license install keep working |

Billing state never disables the security function — by design
(`docs/process/CUSTOMER_LICENSING.md`).

## Renewals

Issue a new license file with the new expiry and trued-up seats. Self-managed
installations may use an authenticated in-app install path. AWS customer silos
must publish a new immutable secret version and run `npm run silo:deploy`; their
in-app installers intentionally return `license_managed_externally`.

## Rotation (compromised or lost key)

There is no dynamic trust-key server. Rotation is an explicit customer rollout:

1. Generate a fresh keypair (Step 1) into a new directory.
2. Re-issue every active customer's license with the new private key.
3. For each AWS silo, publish one immutable secret version containing both the
   new signed license and new `REDACTWALL_LICENSE_PUBLIC_KEY_B64`, then apply it
   through `npm run silo:deploy`. The host validates the pair together before
   cutover.
4. For embedded air-gapped builds, rebuild with the new public key build
   argument, ship the matching image and license together, and verify before
   retiring the old pair.
5. Destroy the compromised private key and note the rotation in your customer
   registry.

Never update only the public key or only the license. Managed mode treats a
missing or unverifiable authoritative license as readonly and unready; it never
falls back to demo entitlements.
