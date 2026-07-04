# Security Trust Package

PromptWall's security trust package is the vendor-risk and procurement companion
to the examiner evidence pack. It gives a regulated buyer a prompt-free view of
the product's security posture before they connect a live environment.

## What It Contains

- Control coverage for local inspection, prompt-body minimization,
  tamper-evident audit, Security Admin MFA, secure sessions, encrypted retained
  approval data, default-deny AI apps, response scanning, required sensors,
  provider-runtime gateway coverage, and SOC handoff.
- A bounded CycloneDX-style dependency inventory generated from
  `package-lock.json`.
- Security questionnaire answers that map directly to package controls.
- Validation commands a reviewer can rerun locally, including `npm run
  review:ci`, audit-chain verification, examiner evidence export, and this trust
  package export.
- Documentation pointers for deployment, managed extension rollout, gateway
  enforcement, competitive alignment, and scheduled evidence packs.

## What It Excludes

The package is intentionally metadata-only. It does not include:

- raw prompt bodies
- redacted prompt bodies
- raw detector values
- token vault values
- secrets or credentials
- raw audit details
- local file paths
- raw URLs
- package-lock filesystem paths

## Dashboard Export

Open **Audit Log > Security Trust Package** as a Security Admin. The preview
shows verified controls, attention items, missing controls, SBOM component
count, and the privacy contract. Use **Download Trust Package** to export a ZIP
with:

- `manifest.json`
- `security-trust-package.json`
- `sbom/cyclonedx.json`
- `README.md`

## CLI Export

Generate JSON:

```powershell
npm run security:package
```

Generate JSON plus ZIP:

```powershell
npm run security:package:zip
```

Choose an output directory:

```powershell
npm run security:package:zip -- C:\PromptWall\security-packages
```

The CLI uses the active PromptWall environment, database, policy, audit chain,
coverage summary, posture summary, preflight state, and package lockfile. It
prints the output path, byte count, SHA-256, schema version, dependency count,
and control coverage.

## API Export

Authenticated Security Admin route:

```http
GET /api/security/package
GET /api/security/package?download=1
GET /api/security/package?format=zip
```

The route uses the same package builder as the CLI and applies the same privacy
contract.

## How To Use In A Review

1. Run `npm run review:ci`.
2. Run `npm run security:package:zip`.
3. Run `npm run evidence:pack:zip` if the reviewer also needs live examiner
   evidence.
4. Send the ZIP files through the customer's approved secure file-transfer path.
5. Keep the raw PromptWall database and `.env` files out of vendor-risk
   handoff unless the customer explicitly asks for a supervised technical
   review.
