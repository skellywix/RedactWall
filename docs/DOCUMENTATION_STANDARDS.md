# Documentation Standards

How RedactWall documentation is organized, written, and kept honest. Based on
the Diátaxis framework (tutorials / how-to / reference / explanation), the
Google developer documentation style guide, and GitLab's docs-as-code
workflow.

## Docs are code

- Documentation lives in this repo and changes **in the same commit/PR as the
  code change it describes**. A feature is not done until its doc is updated.
- Generated sections stay generated: `DEMO_INSTALL_GUIDE.md`,
  `docs/SALES_DEMO_GUIDE.md`, and `docs/DEMO_TECHNICIAN_SETUP.md` are
  refreshed by `npm run docs:demo-guide`; CI fails on drift
  (`npm run docs:demo-guide:check`). Never hand-edit generated sections.
- Every doc must be reachable from the index in `docs/README.md`. An
  unindexed doc is a lost doc.
- Relative links must resolve; check them when moving or deleting files.

## The four document types (Diátaxis)

Each page is exactly one of these. Do not mix "why" into a how-to or
narrative into reference.

| Type | Purpose | RedactWall examples |
|------|---------|---------------------|
| Tutorial | Learning by doing, start to finish | `DEMO_INSTALL_GUIDE.md`, `docs/DEMO_TECHNICIAN_SETUP.md` |
| How-to | One task, for a competent operator | `docs/DEPLOYMENT.md` sections, `docs/MANAGED_EXTENSION_DEPLOYMENT.md`, `docs/EVIDENCE_PACK_TASK.md` |
| Reference | Complete, neutral facts | `README.md` API tables, `docs/ACCESS_ROLES.md`, connector docs |
| Explanation | Why it works this way | `docs/SECURITY_WHITEPAPER.md`, `docs/COMPETITIVE_ALIGNMENT.md`, `DECISIONS.md` |

## Style

Follow the Google developer documentation style guide defaults:

- Second person ("you configure"), present tense, active voice.
- One idea per sentence; spell out commands and paths in backticks.
- Use RFC-reserved placeholder domains (`*.example`, `*.example.com`,
  `customer.example`) for anything that is not a real, live URL — and never
  present a placeholder as clickable in customer-facing material.
- Synthetic data only, everywhere: `123-45-6789`, `4111111111111111`,
  `jane.doe@example.com`. Never real member, patient, cardholder, employee,
  prompt, file, OCR, or clipboard content — in docs, screenshots, or examples.

## Records that must stay current

| File | Role | Discipline |
|------|------|------------|
| `CHANGELOG.md` | Customer-visible history | Every merged change with user impact adds an `[Unreleased]` entry (Keep a Changelog sections) |
| `ROADMAP.md` | Forward product plan | Reviewed each release train |
| `STATUS.md` | Live TODO / working state | Pruned continuously; history lives in git |
| `DECISIONS.md` | Dated "why" ledger | Append-only, newest context wins |
| `ITERATIONS.md` | Historical iteration log | Archive; do not grow it with routine passes |

## Lifecycle: delete aggressively, archive never

One-time review logs, QA transcripts, and superseded plans are deleted once
their findings are resolved — git history is the archive. Before deleting,
fix any inbound references (grep for the filename). A doc that describes the
product as it used to be is worse than no doc.
