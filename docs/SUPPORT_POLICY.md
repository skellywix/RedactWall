# Support Policy

Support severities, response targets, and maintenance windows for RedactWall
customers. Modeled on HashiCorp/GitLab severity definitions, sized for a
small vendor. This is the reference text for order forms and vendor-risk
questionnaires.

## Severity definitions

| Severity | Definition | Examples |
|----------|------------|----------|
| **Sev1** | Production detection or enforcement is down or silently failing, or a shipped vulnerability is exploitable, with no workaround | Sensors fail open; control plane won't start after upgrade; audit chain corruption |
| **Sev2** | Production is degraded but operating, or a blocking defect has a workaround | Approval queue errors with a manual API workaround; a detector class regresses |
| **Sev3** | Non-blocking defect, question, or tuning request | False-positive tuning, report formatting, how-to questions |

## Response targets (first response, not resolution)

| Severity | Target |
|----------|--------|
| Sev1 | 4 business hours |
| Sev2 | Next business day |
| Sev3 | 2 business days |

Channel: email to the support address on the order form. Hours: US business
hours, Monday–Friday, excluding US federal holidays. We do not sell 24/7
coverage we cannot staff; Sev1 vulnerability notifications follow the
24-hour commitment in `SECURITY.md` regardless of business hours.

## Maintenance and version support

- Monthly minor release train; patch releases as needed
  (`docs/RELEASE_PROCESS.md`).
- **Supported versions: the current and previous minor release.** Security
  fixes are backported to both. Older versions receive best-effort guidance
  to upgrade.
- Upgrades are customer-executed (self-hosted); every release ships with
  preflight checks (`npm run setup:check`, `/readyz`) and backup guidance.

## What customers should have ready when reporting

- RedactWall version (`/healthz` reports it), deployment shape (native,
  Docker, AWS silo), and the output of `npm run setup:check`.
- Relevant sanitized logs. **Never send raw prompts, member data, or `.env`
  contents** — RedactWall's own logs are prompt-free by design; if a log
  excerpt contains sensitive values, something is wrong (report that too).

## Incident communication

For vendor-side incidents (bad release, shipped vulnerability):

- Sev1: affected customers notified by email within 24 hours with impact,
  remediation, and upgrade path (contractual commitment; financial
  institutions need this feed for their own incident programs).
- Advisories are published to GitHub Releases/Security Advisories after the
  customer upgrade window.
- The security incident-response runbook for operators is
  `docs/INCIDENT_RESPONSE.md`.
