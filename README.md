# RedactWall

RedactWall is a Node.js control plane and set of local sensors that scan prompts, files, clipboard content, and MCP tool results for sensitive data before they reach AI tools.

## What It Does

RedactWall has three main parts:

- A server in `server/` that owns policy, the admin dashboard, approvals, evidence export, and the hash-chained audit log.
- A shared detector in `detection-engine/` that finds structured sensitive data and semantic risk categories.
- Sensors in `sensors/` that run the detector locally for browser AI chat, endpoint file flows, clipboard checks, and MCP tool responses.

The repository does not have a `src/` directory. The source code lives under `server/`, `detection-engine/`, `sensors/`, and supporting scripts.

## Tech Stack

- Node.js `>=22`
- Express 5 for the HTTP API and dashboard server
- `better-sqlite3` for local SQLite storage
- `helmet` and `cookie-parser` for HTTP hardening and session cookies
- `zod` for request validation
- `adm-zip` and `pdf-parse` for Office/PDF text extraction
- Playwright for browser-level tests
- Node's built-in test runner, wrapped by `scripts/run-node-tests.js`
- Docker and Docker Compose files for containerized deployment

## Quick Start

Install dependencies and create a local `.env`:

```bash
npm run setup
```

Start the server:

```bash
npm start
```

The dashboard and API run on `http://localhost:4000` by default. The generated admin credentials and ingest API key are written to `.env`.

## Admin Console

The browser console is the operator-facing control plane. It ships as a
Vite/React/TypeScript app served at `/app` (behind the same login and CSRF gate
as the rest of the API), with a grouped sidebar — Operate, Analyze, Govern,
System — a Ctrl/Cmd-K command palette, and light/dark themes (dark by default).
It has one focused screen per task: overview, approval queue, AI Command Center,
all activity, insights, sensor coverage, data lineage, decision quality, app
catalog, compliance, identity, configuration, deploy, integrations, audit log,
and updates. The overview opens on the AI Data Leak Exposure Map, an interactive
graph that attributes sanitized flows to departments as they pass RedactWall
controls on the way to AI destinations. The queue, command-center, and
configuration views are optimized for guided operator flow, guided policy setup,
anomaly-score triage, redacted evidence review, live posture objectives, AI
threat guardrails, AI control graph mapping, Agentic MCP Control, control
outcomes, sensor posture, and fast approval or denial decisions without exposing
raw prompt content by default.

`/` redirects to `/app/`; it is the only operator console (the original static
console was retired). Build the React bundle with `npm run console:build` (CI
builds it automatically); it emits to `server/public/app/`.

Run the default test suite:

```bash
npm test
```

Run the full local review gate:

```bash
npm run review:ci
```

Install Playwright Chromium for browser tests:

```bash
npm run setup -- --with-browser
```

Run focused browser checks:

```bash
npm run test:browser
npm run test:admin-console
npm run test:browser-extension
```

Run detector quality and shared-engine checks:

```bash
npm run eval
npm run sync-check
```

Production-style setup:

```bash
npm run setup:prod
npm run mfa:uri
npm start
```

Docker setup:

```bash
npm run setup:prod -- --skip-install
npm run mfa:uri
docker compose up -d --build
```

## Common Scripts

| Script | What it does |
| --- | --- |
| `npm run setup` | Installs dependencies, writes `.env`, initializes SQLite, and checks local readiness. |
| `npm start` | Starts `server/app.js`. |
| `npm test` | Runs all `test/**/*.test.js` files sequentially through `scripts/run-node-tests.js`. |
| `npm run suite` | Runs the full standalone black-box regression suite in `suite/` (contract, security, detector tiers). |
| `npm run suite:smoke` | Runs the fast smoke tier of the regression suite. |
| `npm run suite:ui` | Runs the regression suite's Playwright UI journeys (auditor role, SSE, bulk actions, session expiry). |
| `npm run review:ci` | Runs whitespace checks, generated demo-doc checks, AI-domain checks, Node tests, the Playwright browser suite, detector sync, and detection eval. |
| `npm run ai-domains:check` | Verifies the reviewed AI-host catalog stays covered by destination policy and browser adapter tests. |
| `npm run sync-engine` | Copies `detection-engine/detect.js` into the browser extension detector copy. |
| `npm run sync-check` | Verifies the shared detector and browser detector copy match. |
| `npm run eval` | Runs held-out detector evaluation from `test/fixtures/semantic-eval.json`. |
| `npm run simulate` | Sends sample prompts through the API path. |
| `npm run endpoint:handoff` | Writes a signed, metadata-only native endpoint handoff event for a local file path. |
| `npm run desktop:collect` | Runs the protected-upload desktop collector and records handoff intent for endpoint scanning. |
| `npm run desktop:git-push` | Runs the local git pre-push guard and records only sanitized blocked-push evidence. |
| `npm run desktop:git-push:install` | Installs the local git pre-push guard into a selected repository. |
| `npm run security:package` | Exports a sanitized vendor-risk security trust package. |
| `npm run security:package:zip` | Exports the trust package as JSON plus ZIP with SBOM inventory. |
| `npm run package:extension` | Packages browser-extension artifacts. |
| `npm run package:endpoint-agent` | Packages the endpoint agent. |
| `npm run package:mcp-guard` | Packages the MCP guard. |
| `npm run release:extension:check` | Checks browser-extension release artifacts. |
| `npm run endpoint:check` | Validates endpoint-agent runtime/config health. |
| `npm run mcp:check` | Validates MCP guard runtime/config health. |
| `npm run docs:demo-guide` | Refreshes generated current-state demo documentation sections. |

## Project Structure

```text
redactwall/
|-- config/                 Runtime policy and detector configuration
|-- data/                   Local SQLite data path for development
|-- detection-engine/       Shared detector and AI-site adapter helpers
|-- docs/                   Deployment, rollout, identity, evidence, and demo docs
|-- e2e/                    Playwright browser tests
|-- infra/                  Customer-silo deployment templates
|-- PLANS/                  Planning notes
|-- scripts/                Setup, packaging, validation, docs, and smoke scripts
|-- sensors/
|   |-- browser-extension/  MV3 browser sensor
|   |-- endpoint-agent/     Local file, clipboard, OCR, and handoff sensor
|   `-- mcp-guard/          MCP tool-result guard, connector SDK, and shipped connectors
|-- server/                 Express app, policy, auth, database, evidence, and dashboard
|-- test/                   Node test suite and fixtures
|-- package.json            Scripts, package metadata, and dependencies
`-- README.md
```

## Runtime Configuration

`npm run setup` writes `.env`. The same app also supports environment variables.

Important settings:

| Variable | Purpose |
| --- | --- |
| `PORT` | Server port. Defaults to `4000`. |
| `REDACTWALL_DB_PATH` or `REDACTWALL_DB_PATH` | SQLite database path. Keep production data on local disk. |
| `ADMIN_USER` / `ADMIN_PASSWORD` | Local admin login. |
| `ADMIN_TOTP_SECRET` | Security Admin MFA secret. Required by production preflight. |
| `REDACTWALL_SECRET` or `REDACTWALL_SECRET` | Session signing secret. |
| `REDACTWALL_DATA_KEY` or `REDACTWALL_DATA_KEY` | Encryption key for retained approval prompt data. |
| `INGEST_API_KEY` or `REDACTWALL_INGEST_API_KEY` | API key used by sensors for `/api/v1/*` ingest routes. |
| `SCIM_BEARER_TOKEN` or `REDACTWALL_SCIM_BEARER_TOKEN` | Enables `/scim/v2/*` provisioning routes when set. |
| `OIDC_*` or `REDACTWALL_OIDC_*` | Optional console SSO settings. |
| `SIEM_WEBHOOK_URL` / `SIEM_WEBHOOK_TOKEN` | Optional HTTPS-only sanitized SOC/SIEM webhook for high-risk events and posture snapshots. |
| `SIEM_POSTURE_FEED_ENABLED` / `SIEM_POSTURE_MIN_INTERVAL_MS` | Enables throttled automatic posture snapshots for SOC/SIEM subscriptions. |
| `REDACTWALL_GATEWAY_TOKEN` | Client token required by the enforced AI LLM gateway. |
| `REDACTWALL_GATEWAY_UPSTREAM` / `REDACTWALL_GATEWAY_UPSTREAM_API_KEY` | Provider base URL and gateway-held provider key for OpenAI-compatible, Anthropic, Gemini, or private model upstreams. |
| `REDACTWALL_GATEWAY_UPSTREAM_AUTH_SCHEME` / `REDACTWALL_GATEWAY_AWS_REGION` | Use `aws-sigv4` plus an AWS region for direct Amazon Bedrock Runtime gateway enforcement. |
| `REDACTWALL_RATE_LIMITER_TOKEN` / `REDACTWALL_RATE_LIMITER_STORE` | Shared AI gateway limiter token and backend, `sqlite` for one limiter service or `redis`/`valkey` for active-active limiter replicas. |
| `ENDPOINT_AGENT_OCR_COMMAND` or `REDACTWALL_ENDPOINT_AGENT_OCR_COMMAND` | Optional local OCR command for endpoint image files. Without one, the agent falls back to a bundled offline WASM OCR engine (`ENDPOINT_AGENT_OCR_WASM`, default on). |

See `.env.example`, `docs/AI_LLM_GATEWAY.md`, and `docs/DEPLOYMENT.md` for the longer deployment reference.

## HTTP API Reference

### Authentication Model

- Public health routes do not require authentication.
- Sensor routes under `/api/v1/*` require `x-api-key: <INGEST_API_KEY>`.
- Admin dashboard routes require a signed session cookie from `/api/login`.
- Admin write routes also require a CSRF token from `/api/csrf`.
- SCIM routes under `/scim/v2/*` require `Authorization: Bearer <SCIM_BEARER_TOKEN>` when SCIM is configured.

### Public Routes

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Returns service health, service name, and package version. |
| `GET` | `/readyz` | Checks database access and deployment preflight readiness. |
| `GET` | `/` | Redirects to `/app/`. |
| `GET` | `/app/` | Serves the React admin console after login. |

### Sensor API

| Method | Path | Required body or params | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/v1/gate` | `prompt`; optional `user`, `destination`, `source`, `channel`, `orgId`, `sensor`, `clientOutcome`, and client analysis fields | Scans a prompt or sensor event, applies policy, records sanitized evidence, and returns `allow`, `block`, `redact`, or log-style decisions. Cleared outcomes (`allowed`, `redacted`, `warned_sent`, `justified`) include a signed, prompt-free safe-to-send `receipt`. |
| `POST` | `/api/v1/discovery` | `source`, `user`, and `sightings[]` with host-only `destination`; optional `vendor`, `orgId`, `sensor`, `events`, `firstSeen`, `lastSeen`, `category`, `confidence` | Imports privacy-safe AI asset sightings from proxy, firewall, SSE, or browser-isolation inventory. Raw prompts, raw URLs, and URL paths are rejected; imported observations feed shadow-AI coverage, posture, and the control graph. |
| `POST` | `/api/v1/heartbeat` | Optional `user`, `destination`, `source`, `orgId`, `sensor`, `checks` | Records bounded sensor install-health and endpoint AI-tool inventory evidence. |
| `GET` | `/api/v1/policy` | None | Returns the sensor-safe policy, detector controls, destination controls, and scanner config. |
| `GET` | `/api/v1/detectors` | None | Lists built-in and configured custom detectors. |
| `POST` | `/api/v1/scan-file` | `filename`, `contentBase64`; optional sensor context | Extracts supported file text, scans it, and returns an allow/block/redact decision. |
| `POST` | `/api/v1/scan-response` | `text`; optional sensor context | Scans AI response text for sensitive output and returns allow, flag, redact, or block state. |
| `POST` | `/api/v1/rehydrate` | `id`, `text`, `x-release-token` header | Replaces redaction tokens in an AI response using the sealed token vault for the query. |
| `GET` | `/api/v1/status/:id` | `x-release-token` header | Lets a sensor poll whether a held item was approved or denied. |

Example prompt scan:

```bash
INGEST_API_KEY="$(grep '^INGEST_API_KEY=' .env | cut -d= -f2-)"
curl -s http://localhost:4000/api/v1/gate \
  -H "content-type: application/json" \
  -H "x-api-key: ${INGEST_API_KEY}" \
  -d "{\"prompt\":\"Member SSN is 123-45-6789\",\"user\":\"demo@example.com\",\"destination\":\"chatgpt.com\"}"
```

Example discovery import dry run:

```bash
npm run discovery:import -- --input ./proxy-ai-export.csv --vendor zscaler --dry-run
```

### Admin API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/login` | Creates a dashboard session from `user`, `password`, and optional `otp`. |
| `GET` | `/api/login-options` | Returns public login options, including whether OIDC is configured. |
| `GET` | `/auth/oidc/start` | Starts optional OIDC login. |
| `GET` | `/auth/oidc/callback` | Handles OIDC callback and creates a dashboard session. |
| `GET` | `/api/csrf` | Returns a CSRF token for unsafe admin requests. |
| `POST` | `/api/logout` | Clears dashboard session cookies. |
| `GET` | `/api/me` | Returns current user, role, auth provider, and default-password state. |
| `GET` | `/api/queries` | Lists query/evidence rows, optionally filtered by `status`. |
| `GET` | `/api/queries/:id` | Returns one sanitized query row. |
| `POST` | `/api/queries/:id/reveal` | Reveals retained raw prompt data when available; requires admin role and password step-up. |
| `POST` | `/api/queries/:id/approve` | Approves a pending held item; requires decision role, CSRF, and password step-up. |
| `POST` | `/api/queries/:id/deny` | Denies a pending held item; requires decision role and CSRF. |
| `GET` | `/api/stats` | Returns dashboard counts. |
| `GET` | `/api/billing/seats` | Returns SaaS tenant seat usage. |
| `GET` | `/api/metrics` | Returns uptime, stats, and audit-chain status. |
| `GET` | `/api/preflight` | Returns current deployment preflight state. |
| `GET` | `/api/identity/setup-guide` | Builds a secret-free Entra or Okta setup guide from query parameters. |
| `POST` | `/api/retention/purge` | Runs retention purge for finalized raw approval data. |
| `GET` | `/api/risk` | Summarizes per-user risk from recorded evidence. |
| `GET` | `/api/coverage` | Returns governed-destination and sensor coverage posture. |
| `GET` | `/api/posture` | Returns sanitized AI security posture objectives, threat guardrails, trends, segment comparisons, surfaces, and control outcomes. Optional `segment=<id>` filters the command center to an organization, SCIM group, workflow queue, or sensor surface. |
| `POST` | `/api/posture/notify` | Sends a manual sanitized posture snapshot to the configured SIEM/SOC webhook. |
| `GET` | `/api/integrations/siem/package` | Returns a Security Admin-only offline SIEM/SOAR package for `profile=all`, `splunk`, `sentinel`, `chronicle`, or `servicenow`. Add `download=1` for a JSON attachment. Packages include sanitized mappings, searches, dashboards, sample payloads, and setup checklists only. |
| `GET` | `/api/security/package` | Returns a Security Admin-only vendor-risk trust package with sanitized control coverage, validation commands, and a CycloneDX-style SBOM inventory. Add `download=1` for JSON or `format=zip` for the ZIP bundle. |
| `GET` | `/api/lineage` | Returns sanitized lineage summaries. |
| `GET` | `/api/destinations/review` | Lists shadow-AI destination review candidates. |
| `POST` | `/api/destinations/review` | Applies a govern, allow, or block decision to a destination. |
| `GET` | `/api/policy/templates` | Lists built-in regulation policy templates. |
| `PUT` | `/api/policy/apply-template` | Applies a policy template by `id`. |
| `GET` | `/api/audit` | Lists audit entries and audit-chain integrity. |
| `POST` | `/api/receipts/verify` | Verifies a safe-to-send receipt was issued by this control plane and has not been edited. |
| `GET` | `/api/export/evidence` | Builds a sanitized examiner evidence pack. |
| `GET` | `/api/policy` | Returns full admin policy. |
| `POST` | `/api/policy/impact` | Previews a draft policy against recent metadata-only evidence before saving. Prompt bodies, masked values, and raw approval fields are excluded. |
| `PUT` | `/api/policy` | Updates policy fields accepted by `server/validation.js`. |
| `GET` | `/api/stream` | Server-sent events stream for dashboard updates. |

### SCIM API

These routes are mounted under `/scim/v2` by `server/scim.js`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/scim/v2/ServiceProviderConfig` | Returns SCIM service-provider capabilities. |
| `GET` | `/scim/v2/Users` | Lists SCIM users. Supports equality filters for `userName` and `externalId`. |
| `POST` | `/scim/v2/Users` | Creates a SCIM user. |
| `GET` | `/scim/v2/Users/:id` | Returns one SCIM user. |
| `PUT` | `/scim/v2/Users/:id` | Replaces a SCIM user. |
| `PATCH` | `/scim/v2/Users/:id` | Applies SCIM patch operations to a user. |
| `DELETE` | `/scim/v2/Users/:id` | Deactivates a SCIM user. |
| `GET` | `/scim/v2/Groups` | Lists SCIM groups. Supports equality filters for `displayName` and `externalId`. |
| `POST` | `/scim/v2/Groups` | Creates a SCIM group. |
| `GET` | `/scim/v2/Groups/:id` | Returns one SCIM group. |
| `PUT` | `/scim/v2/Groups/:id` | Replaces a SCIM group. |
| `PATCH` | `/scim/v2/Groups/:id` | Applies SCIM patch operations to a group. |
| `DELETE` | `/scim/v2/Groups/:id` | Deletes a SCIM group. |

## JavaScript API Reference

The package is private and is not published as a library. These CommonJS exports are used by tests, scripts, sensors, and local integrations.

### `require("./server/app")`

Exports the Express app.

| Export | Purpose |
| --- | --- |
| `app` | Express request handler with all routes mounted. |
| `app.startServer(port)` | Starts the HTTP server after preflight, retention purge, and workflow escalation setup. |
| `app.runRetentionPurge()` | Runs retained raw-data purge using policy retention settings. |
| `app.runWorkflowEscalation()` | Runs approval workflow SLA escalation. |

### `require("./detection-engine/detect")`

| Export | Purpose |
| --- | --- |
| `analyze(text, opts)` | Scans text and returns findings, categories, severity, risk score, and entity counts. |
| `redact(text, findings)` | Replaces finding values with typed redaction markers. |
| `maskValue(type, value)` | Returns a masked display value for a finding. |
| `tokenize(text, findings)` | Replaces findings with stable typed tokens and returns the token map. |
| `detokenize(text, map)` | Restores tokens from a token map. |
| `tokenizePrompt(text, opts)` | Runs `analyze` and `tokenize` together. |
| `classifySemantic(text)` | Runs the local semantic classifier. |
| `listDetectors(opts)` | Lists available built-in and custom detectors. |
| `normalizeCustomDetectors(value)` | Validates and normalizes custom detector config. |
| `publicCustomDetectorConfig(value)` | Returns custom detector config safe for sensors. |
| Validator helpers | `luhnValid`, `ssnPlausible`, `abaValid`, `ibanValid`, `vinValid`, `bankAccountPlausible`, `itinPlausible`, `npiValid`, `datePlausible`, `ipv6Valid`, and `cardNetwork`. |
| Constants | `SEVERITY` and `SEVERITY_LABEL`. |

### `require("./server/receipts")`

| Export | Purpose |
| --- | --- |
| `issueReceipt({ id, status, outboundText, policy, destination, user })` | Signs a prompt-free safe-to-send receipt binding the exact outbound text hash to the active policy hash. Returns `null` for statuses that are not cleared to send. |
| `verifyReceipt(receipt)` | Verifies a receipt's shape and HMAC signature. Returns `{ ok }` or `{ ok: false, reason }`. |
| `policyHash(policy)` / `sha256Hex(text)` | Canonical hashes used inside receipts. |
| Constants | `RECEIPT_VERSION` and `RECEIPT_STATUSES`. |

### `require("./detection-engine/adapters")`

| Export | Purpose |
| --- | --- |
| `sendButtonSelectors(host)` | Returns AI-site send-button selectors plus generic fallbacks. |
| `normalizeHost(value)` | Normalizes URLs, hostnames, and desktop labels for policy comparison. |
| `hostMatches(host, base)` | Checks exact, subdomain, and wildcard destination matches. |
| `isGoverned(host, governed)` | Checks whether a host is covered by policy. |
| `isAiHost(host)` | Checks whether a host is in the reviewed AI-host catalog. |
| `scanInjection(text)` | Detects and strips hidden Unicode prompt-injection characters. |
| Constants | `SEND_BUTTONS`, `GENERIC_SEND`, and `AI_HOSTS`. |

### `require("./server/processors")`

| Export | Purpose |
| --- | --- |
| `extractText(name, buffer, opts)` | Extracts bounded text from supported text, Office, PDF, and image-file inputs. |
| `supported(name)` | Returns whether a filename has a supported processor. |
| `PROCESSORS` | Processor registry. |
| Extension sets | `TEXT_EXT`, `OFFICE_EXT`, `PDF_EXT`, and `IMAGE_EXT`. |
| Defaults | `DEFAULT_EXTRACT_TIMEOUT_MS` and `DEFAULT_MAX_EXTRACTED_CHARS`. |

### `require("./sensors/mcp-guard/guard")`

| Export | Purpose |
| --- | --- |
| `guardToolResult(text, ctx, opts)` | Scans MCP tool output and returns safe text plus findings. |
| `wrapTool(handler, ctx)` | Wraps an MCP tool handler so results pass through the guard. |
| `reportBody(...)` | Builds sanitized sensor report payloads. |
| `publicFindings(...)` / `publicCategories(...)` | Converts analysis data to bounded public evidence. |
| `fetchPolicy()` / `refreshPolicy()` | Loads sensor policy from the control plane. |
| `detectionOptions()` | Builds detector options from sensor policy. |
| Request helpers | `requestTimeoutMs`, `fetchWithTimeout`, and `sensorMetadata`. |

### `require("./sensors/mcp-guard/sdk")`

| Export | Purpose |
| --- | --- |
| `sanitizeToolResult(result, ctx, opts)` | Sanitizes string, buffer, JSON, and MCP content results before model use. |
| `wrapConnectorTool(handler, ctx, opts)` | Wraps connector handlers with `sanitizeToolResult`. |
| `toolResultText(result)` | Converts tool results to text for scanning. |
| `connectorContext(ctx)` | Normalizes connector context for guard reporting. |
| `connectorHealthCheck(connector, ok, detail)` | Builds sanitized MCP connector health checks. |

Shipped connector runtimes live under `sensors/mcp-guard/connectors/` for
Microsoft 365, Google Drive, Slack, Microsoft Teams, Atlassian Jira/Confluence,
and read-only SQLite database access. Start with `docs/MCP_CONNECTOR_SDK.md`
and the connector-specific docs in `docs/` before wiring a pilot MCP server.

### `require("./sensors/endpoint-agent/agent")`

Exports endpoint-agent scanning, reporting, policy refresh, timeout, scanner-ignore, file-label, metadata, native-handoff, and `start()` helpers. The most important entry points are:

- `scanFile(file)`
- `scanAbsoluteFile(file, opts)`
- `processNativeHandoffFile(file, opts)`
- `processHandoffDirectory(dir, opts)`
- `report(body)`
- `fetchPolicy()`
- `refreshPolicy(opts)`
- `sensorPolicy()`
- `scannerConfig()`
- `safeFileLabel(file)`
- `start()`

### `require("./sensors/endpoint-agent/native-handoff")`

| Export | Purpose |
| --- | --- |
| `signHandoffEvent(event, secret)` | Signs a bounded native upload-intent event. |
| `validateHandoffEvent(event, opts)` | Validates and verifies a signed handoff event. |
| `readHandoffFile(file, opts)` | Reads and validates a handoff JSON file. |
| `signatureFor(event, secret)` | Computes a handoff signature. |
| Other exports | `EVENT_VERSION`, `MAX_EVENT_BYTES`, `DEFAULT_TTL_MS`, `defaultHandoffDir`, `configuredHandoffSecret`, and `publicDestination`. |

## Tests

The tests show the intended public behavior:

- `test/server-integration.test.js` verifies the importable Express app, `/healthz`, `/readyz`, and security headers.
- `test/detect.test.js`, `test/eval.test.js`, and `test/tokenize.test.js` cover detector output, false-positive protection, semantic categories, and tokenization.
- `test/validation.test.js`, `test/processors.test.js`, and `test/release-token.test.js` cover sensor request contracts and fail-closed behavior.
- `test/auth.test.js`, `test/admin-mfa.test.js`, `test/approval-stepup.test.js`, and role tests cover dashboard access control.
- `test/scim.test.js`, `test/oidc-login.test.js`, and `test/identity-setup.test.js` cover provisioning and login integration.
- `e2e/admin-console.spec.js` and `e2e/browser-extension.spec.js` cover browser-facing flows.
- `suite/` is the standalone black-box regression suite (API contracts, authz/IDOR, PII-leak sweeps, audit tamper-evidence, detector floors, role-scoped UI journeys). See `suite/README.md` and `docs/TESTING_STRATEGY.md`.

Run focused Node tests by passing files to `npm test`:

```bash
npm test -- test/detect.test.js test/server-integration.test.js
```

## Detector Sync Rule

The canonical detector is `detection-engine/detect.js`. The browser extension copy at `sensors/browser-extension/lib/detect.js` is generated from it.

After detector changes:

```bash
npm run sync-engine
npm run sync-check
```

Do not hand-edit `sensors/browser-extension/lib/detect.js`.

## Security Notes

- Sensor ingest routes require the ingest API key.
- Admin write routes require a session and CSRF token.
- Approval release and raw prompt reveal require password step-up.
- Raw approval prompt data is encrypted at rest only when a stable data key is configured.
- Stored and exported evidence is designed to use masked findings, redacted previews, hashes, and metadata instead of raw prompt, file, OCR, clipboard, or token-vault content.
- Cleared gate outcomes return a signed safe-to-send receipt (hashes and bounded metadata only, never prompt bodies) that `/api/receipts/verify` can check later, so an employee or examiner can prove a specific outbound text was scanned under a specific policy.
- The audit log is hash-chained. Check it with:

```bash
node -e "console.log(require('./server/db').verifyAuditChain())"
```

## Project Records

- [CHANGELOG.md](CHANGELOG.md) — release history (Keep a Changelog format).
- [ROADMAP.md](ROADMAP.md) — competitor-grounded product roadmap.
- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy.
- `docs/README.md` — full documentation index, including release, testing,
  licensing, and support process docs.

## Contribution Notes

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing code.

Local contribution flow:

```bash
npm run hooks:install
npm run review:ci
```

Use synthetic data only. Do not add real customer, member, patient, cardholder, employee, prompt, file, OCR, or clipboard content to tests, fixtures, logs, screenshots, or docs.
