# License Signing Key Setup

How the vendor generates the real Ed25519 license signing keypair, embeds the
public key in the product, protects the private key, and issues customer
licenses. This is the mechanical companion to
`docs/process/CUSTOMER_LICENSING.md`, which defines the commercial model
(plans, seats, expiry behavior, pricing shape).

Do this **once, before the first commercial release**. `server/license.js`
ships with a placeholder public key; a license signed with any key you
generate will not verify until the placeholder is replaced.

## How verification works

A license is an offline, signed file — never a phone-home check:

- `redactwall.lic` = `base64(payload JSON)` + `.` + `base64(Ed25519 signature)`.
- The server verifies it at boot and re-checks daily against a public key
  **embedded in the product** (`EMBEDDED_PUBLIC_KEY_PEM` in
  `server/license.js`).
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

## Step 2 — Embed the public key in the product

Open `server/license.js`, find the marked placeholder constant
`EMBEDDED_PUBLIC_KEY_PEM`, and replace its PEM block with the contents of
`license-signing-pub.pem`. Commit the change — the public key is not a
secret, and shipping it in the repo/image is the point: every deployed
control plane can then verify your signatures with zero egress.

Run the gate to confirm nothing depended on the placeholder:

```bash
npm test -- test/license.test.js test/license-api.test.js
```

Ship the change in the next image build. Any deployment still running an
older image verifies against the old embedded key, so replace the key
**before** the first licensed deployment rather than after.

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

Issue a new license file with the new expiry (and trued-up seats), install it
over the old one via either install path. No downtime, no restart required —
the server refreshes its license status on install.

## Rotation (compromised or lost key)

There is no key server, so rotation is a product update:

1. Generate a fresh keypair (Step 1) into a new directory.
2. Replace `EMBEDDED_PUBLIC_KEY_PEM` with the new public key and ship a new
   image version.
3. Update every customer stack to that image (standard upgrade path in
   `docs/deployment/PRODUCTION_LAUNCH_GUIDE.md`, Phase 9).
4. Re-issue and re-install every active customer's license signed with the
   new key — old licenses stop verifying on the new image, so coordinate the
   re-issue with the rollout (customers fall back to `grace`-style behavior
   only after their old license fails verification, so install the new
   license immediately after upgrading each stack).
5. Destroy the compromised private key and note the rotation in your customer
   registry.

If a customer cannot upgrade immediately, `REDACTWALL_LICENSE_PUBLIC_KEY` can
override the embedded key per deployment as a bridge — use it sparingly and
remove it once the image is current.
