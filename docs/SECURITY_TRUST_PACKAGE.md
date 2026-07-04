# Security Trust Package

PromptWall's security trust package is the vendor-risk and procurement companion
to the examiner evidence pack. It gives a regulated buyer a prompt-free view of
the product's security posture before they connect a live environment.

## What It Contains

- Control coverage for local inspection, prompt-body minimization,
  tamper-evident audit, Security Admin MFA, secure sessions, encrypted retained
  approval data, default-deny AI apps, response scanning, required sensors,
  provider-runtime gateway coverage, and SOC handoff.
- A SOC 2 readiness mapping (`soc2Readiness`): each control is tagged with the
  Trust Services Criteria it supports (CC6.x access and boundary, CC7.x
  monitoring and incident response, CC8.1 change management), and each
  criterion inherits the worst status of its mapped controls. Self-attested,
  not an audit opinion.
- A vulnerability and patch policy (`vulnerabilityPolicy`): severity-based
  patch SLAs (critical 72 hours, high 7 days, medium 30 days, low 90 days),
  the CI `npm audit` cadence, and the dependency pinning posture.
- A DPA/BAA posture block (`dpaBaaPosture`): local-first customer-silo
  deployment, no prompt egress, no vendor telemetry, no default
  sub-processors, and per-customer DPA and HIPAA BAA execution.
- Retention and legal-hold state (`retentionLegalHold`): the active
  `rawRetentionDays`, AES-256-GCM sealing posture, and an honest statement
  that automated legal hold is not yet supported (purge suspension requires
  operator action).
- A bounded CycloneDX-style dependency inventory generated from
  `package-lock.json`.
- Security questionnaire answers that map directly to package controls.
- Validation commands a reviewer can rerun locally, including `npm run
  review:ci`, audit-chain verification, examiner evidence export, and this trust
  package export.
- Documentation pointers for deployment, managed extension rollout, gateway
  enforcement, competitive alignment, scheduled evidence packs, the security
  whitepaper (`SECURITY_WHITEPAPER.md`), and the incident response runbook
  (`INCIDENT_RESPONSE.md`).

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
