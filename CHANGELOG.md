# Changelog

All notable changes to RedactWall are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and RedactWall adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release process: `docs/RELEASE_PROCESS.md`. Entries before 0.3.0 are
reconstructed from `ITERATIONS.md` and git history.

## [Unreleased]

### Added

- **React admin console reaches full parity.** All 16 operator views are ported
  to the Vite/React/TypeScript console served at `/app`: Overview, Approval
  Queue, AI Command Center, All Activity, Insights, Sensor Coverage, Data
  Lineage, Decision Quality, App Catalog, Compliance, Identity, Configuration,
  Deploy, Integrations, Audit Log, and Updates — each wired to the same backend
  routes the legacy console uses. Shell chrome landed too: grouped
  Operate/Analyze/Govern/System navigation with per-tab icons and a live
  pending-count badge, a Ctrl/Cmd-K command palette, LIVE + last-updated
  indicators, sign out, and the system-status footer. The legacy design system
  (font tokens, base typography, leak-map animation, selector styling) was
  extracted verbatim from the inline `index.html` styles into the shared
  `server/public/console-base.css`, which both consoles now link, so light/dark
  theming (dark default) and every component render identically. Queue
  reassignment, the per-query audit trail, and the billing/seats surface that
  were absent from earlier console increments are restored. Evidence:
  `e2e/console-parity.spec.js` (all routes, zero console errors) and
  `e2e/console-design.spec.js` (dark+light screenshots of every view).
- Bundled offline WASM OCR fallback for the endpoint agent (`tesseract.js` as an
  optional dependency, with `eng.traineddata` language data vendored under
  `sensors/endpoint-agent/tessdata/`). When no native `tesseract` is present the
  agent now reads images on-box instead of dead-ending at `ocr_required`; model
  paths are hard-pinned to the vendored files so it never fetches weights from a
  network. Toggle with `ENDPOINT_AGENT_OCR_WASM` (default on). A new
  `ENDPOINT_AGENT_OCR_STRICT` mode (default off) routes images whose OCR yields
  little or no text to `ocr_required` instead of allowing them through on sparse
  extraction.
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
- Unsupported / unscannable file uploads now **fail closed**: `scan-file` records
  a new terminal `file_blocked_unscanned` status (was `flagged`/`allow`) so a
  renamed or unparseable file can no longer leave uninspected.

### Security

- A full-repo, line-by-line audit (18 scopes, adversarially verified) fixed 131
  confirmed defects. Data-safety highlights:
  - Policy: the admin ignore list was passed into detection, disabling those
    detectors — so a hard-stop (`alwaysBlock`) type placed on the ignore list
    was never detected and raw regulated PII could clear to send. Hard-stop
    types are now excluded from the detection-time ignore list.
  - AI Gateway: on a `redact` verdict, array-form `prompt`/`input` was forwarded
    raw, local redaction ran without policy/EDM options, the model response was
    replaced by a truncated audit preview, and with `n>1` only the first choice
    was rewritten (others returned raw PII). All response choices and inputs are
    now redacted/detokenized with full policy coverage.
  - The endpoint agent parsed attacker-controlled files in-process, bypassing
    the killable parse-pool isolation; extraction now routes through the pool so
    a crafted archive/PDF is SIGKILL-preempted instead of wedging the agent.
  - The browser extension now scans files pasted from the clipboard (e.g. a
    screenshot), which previously bypassed upload inspection.
  - Postgres row-level tenant isolation added in migration v3 was inert
    (`setTenantContext` was never called); it is now wired via
    `db.wireTenantContext` for the customer-silo tenant model.

### Fixed

- Postgres storage bridge: literal-aware identifier quoting (migration v3 no
  longer NULLs `orgId`), and per-call sequence tags so a single bridge timeout
  no longer desynchronizes every subsequent request/reply.
- SMTP: a mid-transaction socket error no longer crashes the process (a
  persistent error handler now survives the session).
- Detection engine: `detectStructured` no longer spins forever on a zero-length
  custom-detector match on the per-keystroke hot path, and `US_DRIVERS_LICENSE`
  no longer fires on any word following "license" (eval floors unchanged at
  100% precision/recall).
- Long-running agents: an un-awaited `response.json()` inside `try/catch` in the
  endpoint agent and MCP guard no longer becomes an unhandled rejection.
- Docker: the runtime image now copies `gateway/`, so the compose gateway
  profile no longer crash-loops; CI smoke-tests the gateway image.
- Console: OIDC-authenticated admins keep approve/reveal/bulk past the 5-minute
  step-up window (re-verify via `/api/auth/step-up`, bounce to the IdP when
  required); pivot routes carrying a query string now resolve to the right view.
- Roughly fifty further medium/low correctness, performance, and
  prototype-pollution fixes; high-severity items carry node:test regression
  tests. Verified green: `npm test`, detector eval floors, `sync-check`,
  console build, and all four Playwright suites.

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

[Unreleased]: https://github.com/skellywix/redactwall/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/skellywix/redactwall/releases/tag/v0.3.0
[0.2.0]: https://github.com/skellywix/redactwall/releases/tag/v0.2.0
[0.1.0]: https://github.com/skellywix/redactwall/releases/tag/v0.1.0
