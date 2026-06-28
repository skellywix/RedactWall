# PromptWall Product Alignment Plan

## Goal And Context

Rename the product to PromptWall and keep moving the codebase toward the stated
end goal: a compliance-grade safety layer that lets regulated companies allow
AI tools without leaking customer data. The target product is one policy, one
approval queue, one tamper-evident audit log, and three sensors using the same
local detection engine.

## Non-Negotiable Constraints

- Detector logic lives in `detection-engine/detect.js`; browser copies are
  generated through `npm run sync-engine`.
- `alwaysBlock` entities stay hard stops.
- Raw prompt or file content may only be retained as encrypted approval data
  when policy allows it.
- Existing `SENTINEL_*` env vars remain supported until a tested compatibility
  migration exists.
- `PROMPTWALL_*` env aliases may be added only as compatibility aliases; they
  must not break existing `SENTINEL_*` deployments or retained evidence.
- Existing encrypted approval records must remain decryptable after the
  PromptWall rename.
- The repo remains one source of truth. Source edits, tests, and commits run
  from the active app repo folder.

## Options

### Option A: Brand-Only Rename

Update display names, package names, Docker image names, docs, and generated
artifact names. Leave env vars and data formats alone.

Pros: lowest risk, fast to verify, avoids breaking current installs.

Cons: internal legacy names remain for now.

### Option B: Full Runtime Rename

Rename env vars, cookie names, crypto namespaces, database paths, scheduled
tasks, cloud resources, package names, and docs in one pass.

Pros: cleanest final state.

Cons: high risk of breaking encrypted data, deployed sensors, scripts, and
existing customer-style runbooks.

### Recommendation

Use Option A plus tested compatibility shims. Runtime-visible names can move to
PromptWall only when fresh installs use the new name by default and existing
installs keep a tested fallback. Keep encrypted-data namespaces and retained
evidence stable until a separate migration plan exists.

## Implementation Slices

1. Brand foundation: package metadata, extension label, admin UI text, Docker
   names, package artifact names, docs, and tests.
2. Compatibility guards: legacy encrypted-data salt, legacy canary prefix, and
   notes for env-var aliases.
3. Product alignment: competitor-backed roadmap note, coverage parity checks,
   and active protection for governed destinations.
4. Runtime compatibility cleanup: tested `PROMPTWALL_*` aliases, primary
   PromptWall session cookie with legacy fallback, and stable encrypted-data
   compatibility.
5. Next product gap: native desktop collector or deeper app/action policy
   controls beyond destination, file-upload, response scanning, browser paste,
   browser file-drop, and browser response-copy controls.
6. Exception lifecycle: owner group, reviewer role, review-after metadata, and
   sanitized expiry-review evidence for time-bound allow rules.
7. Workflow ticketing: sanitized approval-ticket webhook with dedupe keys,
   direct Jira and Linear issue adapters, and ticket system/project metadata for
   Jira, Linear, SOAR, or internal middleware.
8. Final audit: current-state search, docs check, package generation, tests,
   eval, sync-check, audit chain, and browser evidence.

## Acceptance Evidence

For this alignment track, completion requires evidence for every area below:

- Rename search: no user-facing `PromptSentinel` references remain except
  explicit backward-compatibility notes or literals.
- Package and sensor packaging tests pass.
- `npm run sync-check` passes.
- `npm test` passes.
- `npm run eval` passes.
- `verifyAuditChain()` returns `ok:true`.
- Browser E2E passes after UI or extension behavior changes.
- Documentation explains competitor positioning, deployment, operations, and
  remaining gaps under the PromptWall name.

## Completed Product Slice

- Added `blockedDestinations` to the shared policy model and admin Policy tab.
- Browser and endpoint sensors enforce blocked destinations locally before
  prompt/file inspection.
- Gate, file, and response APIs short-circuit as `destination_blocked` before
  prompt or file content is analyzed or retained.
- Coverage, stats, validation, audit, SIEM alerting, and tests recognize the
  new blocked-destination status.
- Added `blockedFileUploadDestinations` so admins can allow chat while blocking
  file uploads for selected AI hosts or desktop app labels.
- Browser uploads, endpoint file flows, and `scan-file` short-circuit as
  `file_upload_blocked` before uploaded bytes, extracted text, or sensitive
  filenames are retained.
- Added tested `PROMPTWALL_*` aliases for server, SaaS, ingest, timeout, policy,
  endpoint watch, and endpoint handoff runtime settings while keeping existing
  `SENTINEL_*`, `INGEST_API_KEY`, and endpoint-agent keys valid.
- Changed fresh admin sessions to use `promptwall_session`, while accepting
  legacy `sentinel_session` cookies and clearing both names on logout.
- Normalized scanner `maxFileBytes` to an integer in default policy, persisted
  config, policy load/save, and endpoint-agent scanner config so the admin
  policy API can round-trip its own full payload.
- Added policy-driven `requiredSensors` and `desiredSensorVersions` fleet
  posture so admins can see missing or outdated sensors in coverage, SIEM
  version-gap alerts, and examiner evidence exports.
- Expanded the sanitized examiner export with coverage posture, sensor-version
  posture, parsed policy diffs, and lineage summaries by user, destination,
  sensor, channel, category, and decision without prompt bodies.
- Changed examiner evidence packs so exported per-event query rows stay bounded
  while coverage and lineage summaries use the full local evidence history.
- Added the dashboard Lineage tab on top of the same sanitized aggregation so
  admins and auditors can inspect user, destination, sensor, channel, category,
  and decision buckets without exporting raw evidence.
- Added an MCP connector SDK that forces future content connectors through
  `sanitizeToolResult()` before model delivery, packages with the MCP guard, and
  contributes connector SDK health to install posture.
- Added the first Microsoft 365 Graph MCP content connector for text-readable
  OneDrive and SharePoint driveItems, packaged with the guard and sanitized
  before model delivery.
- Added SCIM-backed OIDC console login with state, nonce, authorization-code
  token exchange, RS256 JWKS ID-token validation, active SCIM user role mapping,
  PromptWall-prefixed env aliases, and production preflight checks.
- Added a secret-free enterprise identity handoff for Microsoft Entra and Okta
  through `server/identity-setup.js`, `/api/identity/setup-guide`, the dashboard
  Identity tab, `npm run identity:setup`, generated setup env placeholders, and
  `docs/IDENTITY_IDP_SETUP.md`.
- Extended approval routing rules to match SCIM user names, SCIM groups, and
  org ids so provisioned identity can route legal, lending, engineering, or
  other customer review queues without storing raw prompts or file text.
- Extended the browser extension release gate so a real Chrome Web Store
  extension id produces a prompt-free `ExtensionSettings` force-install policy
  artifact for managed rollout handoff.
- Added direct SMTP approval notifications for reviewer distribution lists while
  keeping workflow notification payloads prompt-free and secret-free.
- Added `responseScanMode` so Security Admins can flag, redact, or block
  sensitive AI replies through `/api/v1/scan-response` without retaining raw
  response text.
- Added `blockedBrowserActions` for destination-scoped browser paste blocking,
  with sanitized `action_blocked` evidence and no clipboard-text retention.
- Extended `blockedBrowserActions` to block destination-scoped browser file
  drops before file bytes are read while retaining only sanitized action
  metadata.
- Extended `blockedBrowserActions` to block destination-scoped browser copy
  events from AI response content while retaining only sanitized action
  metadata.
- Made local browser blocks evidence-aware so blocked sends, sensitive-paste
  blocks, destination/file-upload blocks, file-drop blocks, and response-copy
  blocks only claim recorded evidence after the control plane returns the
  expected id and status.
- Changed the endpoint installer's public server parameter to `-PromptWallUrl`
  for fresh installs while keeping `-SentinelUrl` as a tested compatibility
  alias, and made endpoint/MCP install-health messaging name `PROMPTWALL_URL`
  first.
- Changed fresh endpoint runner and protected-upload launcher paths to set
  `PROMPTWALL_ENV_PATH` while still accepting legacy `SENTINEL_ENV_PATH` in the
  shared env loader.
- Added a sanitized approval ticket bridge that sends deduplicated, issue-shaped
  workflow payloads to ticketing middleware without prompt bodies, raw findings,
  token vaults, release tokens, or decision notes.
- Added native Jira and Linear approval-ticket adapters that create sanitized
  reviewer issues directly from workflow metadata when customers do not want to
  operate ticket middleware.
- Added a one-shot endpoint clipboard guard that inspects clipboard content
  locally, records only masked detector evidence, and can clear sensitive
  clipboard content while recording sanitized `action_blocked` evidence.
- Added an optional endpoint-local OCR bridge for image files so configured
  workstations can inspect OCR text locally, while browser/API image uploads
  still fail closed as `ocr_required` and the control plane receives only
  sanitized detector evidence.

## Open Decisions

- The local checkout folder has been renamed to `promptwall/`; the remaining
  GitHub repository has also been renamed to `skellywix/promptwall`.
- Whether the next product build should prioritize deeper desktop interception,
  signed-update operations, step-up reauthentication polish, or broader
  app/action policy controls beyond browser paste, file drops, and response
  copy.
