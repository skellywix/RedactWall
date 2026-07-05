# Changelog

All notable changes to PromptWall are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and PromptWall adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release process: `docs/RELEASE_PROCESS.md`. Entries before 0.3.0 are
reconstructed from `ITERATIONS.md` and git history.

## [Unreleased]

### Added

- OpenAPI 3.1 spec for the `/api/v1` sensor & scan surface at
  `GET /api/v1/openapi.json` (request schemas generated from the Zod validators;
  zero new dependencies) plus `docs/API_REFERENCE.md`.
- OTLP/HTTP (JSON) subscription destination type (`otlp`): stream sanitized AI
  activity events to a self-hosted OpenTelemetry collector at `<url>/v1/logs`,
  with an optional `serviceName` resource attribute. Label-only, prompt-free.
- `ROADMAP.md`: competitor-grounded product roadmap (Now / Next / Later).
- Standalone black-box regression suite in `suite/` with smoke/full tiers:
  API contract, security (authz/IDOR, CSRF, PII-leak, audit tamper), detector
  quality gates, and role-scoped Playwright UI flows. Run with
  `npm run suite:smoke` / `npm run suite`.
- Focused unit tests for previously untested modules: `server/audit-integrity.js`,
  `server/url-policy.js`, `server/sensor-metadata.js`, `server/ai-app-catalog.js`.
- Engineering process documentation: `docs/RELEASE_PROCESS.md`,
  `docs/TESTING_STRATEGY.md`, `docs/CUSTOMER_LICENSING.md`,
  `docs/SUPPORT_POLICY.md`, `docs/DOCUMENTATION_STANDARDS.md`.
- `SECURITY.md`: vulnerability disclosure policy.
- `package.json` now declares `repository`, `homepage`, and `bugs`.

### Changed

- `STATUS.md` restructured into a lean live TODO list; historical pass logs
  preserved in git history.
- `README.md` admin-console description updated to the current tab set.

### Removed

- Stale one-time QA artifacts (`.codex/`), the superseded project review
  (`REVIEW.md`), and the dead `server/index.js` re-export shim.
- Machine-specific personal helper scripts and their npm aliases and docs:
  the MECHA standing Docker test environment (`scripts/mecha-docker.ps1`,
  `docker:mecha*`) and the Windows daily docs-sync scheduled task
  (`scripts/sync-docs.ps1`, `scripts/install-docs-sync-task.ps1`,
  `docs:sync*`, `docs/DOCUMENTATION_SYNC_TASK.md`).

## [0.3.0] - 2026-07-02

The "platform" cycle (PLANS/platform-roadmap.md M1–M4).

### Added

- Deployable AI LLM gateway (`gateway/`): OpenAI-compatible, Anthropic,
  Gemini, and Bedrock upstreams; fail-closed prompt gating and buffered
  streamed-response scanning; agent tokens; rate limiting with SQLite or
  Redis/Valkey shared limiter; HA compose stack.
- Signed safe-to-send receipts for cleared gate outcomes and
  `POST /api/receipts/verify`.
- Persistent AI app catalog with prompt-free discovery import
  (`/api/v1/discovery`, `npm run discovery:import`) and review workflow.
- Posture subscriptions with retry and delivery history (Splunk, Sentinel,
  Chronicle, QRadar, Datadog, Slack, Teams, webhook) and offline SIEM/SOAR
  packages (`/api/integrations/siem/package`).
- MCP connectors: Microsoft 365, Google Drive, Slack, Teams, Atlassian,
  read-only database — all sanitize-before-model via the connector SDK.
- Ed25519 signed/versioned sensor policy bundles with fail-closed staleness.
- Postgres control plane behind the storage seam with row-level tenant
  isolation, append-only audit enforcement, migrations, and CI coverage.
- Detection: prompt-attack/jailbreak intent (`PROMPT_ATTACK`), international
  PII with real checksums (UK/CA/AU/IN), Exact Data Match via salted
  fingerprints, expanded secret detectors, tiered confidence.
- Console: Overview, Insights, App Catalog, Compliance, Deploy, and
  Integrations tabs; left-sidebar navigation; AI Security Command Center.
- Identity lifecycle hardening: SCIM deactivation revokes sessions/seats,
  dedicated step-up flow, single-use MFA recovery codes.
- Evidence pack schemaVersion 2 with AI-framework mappings (NIST AI RMF,
  ISO 42001, EU AI Act, OWASP LLM Top 10, MITRE ATLAS).
- Email notifications: zero-dependency SMTP sender and digest subscriptions.

## [0.2.0] - 2026-06-29

Production-hardening cycle.

### Added

- Security Admin TOTP MFA with production preflight enforcement; password
  step-up for approval release and raw prompt reveal; auditor read-only role.
- Deployment tooling: `npm run setup` / `setup:prod`, preflight checks,
  Docker Compose health via `/readyz`, backup/verify/restore with
  verifier-first manifests, data-key rotation, DR drill.
- Endpoint agent packaging with signed native handoff contract,
  protected-upload collector, clipboard guard, git-push guard, OCR bridge.
- Browser extension packaging with SHA-256 manifests, managed-storage
  deployment, download blocking, local text-upload inspection.
- Retention purge for finalized raw approval data; sanitized SIEM alerts;
  release tokens scoping approval-status polling.

## [0.1.0] - 2026-06-26

Initial production baseline: Express 5 control plane with hash-chained audit
log, shared detection engine with held-out eval gates, browser/endpoint/MCP
sensors running the same local engine, approval queue with redact/warn/
justify/block modes, examiner evidence export, and SQLite storage.

[Unreleased]: https://github.com/skellywix/promptwall/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/skellywix/promptwall/releases/tag/v0.3.0
[0.2.0]: https://github.com/skellywix/promptwall/releases/tag/v0.2.0
[0.1.0]: https://github.com/skellywix/promptwall/releases/tag/v0.1.0
