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

Use Option A now, with explicit compatibility notes. Follow with a tested
runtime alias layer before changing `SENTINEL_*`, cookie names, or data
encryption namespaces.

## Implementation Slices

1. Brand foundation: package metadata, extension label, admin UI text, Docker
   names, package artifact names, docs, and tests.
2. Compatibility guards: legacy encrypted-data salt, legacy canary prefix, and
   notes for env-var aliases.
3. Product alignment: competitor-backed roadmap note, coverage parity checks,
   and active protection for governed destinations.
4. Next product gap: native desktop collector or deeper app/action policy
   controls beyond destination and file-upload blocking.
5. Final audit: current-state search, docs check, package generation, tests,
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

## Open Decisions

- Whether to rename the GitHub repository in this same branch or keep the remote
  repository migration separate from the code/product rename.
- The local checkout folder rename is ready, but this active Windows session is
  holding the dirty repo directory open. Close Codex/editors/terminals and run
  `Rename-Item -LiteralPath .\promptsentinel -NewName promptwall` from the
  wrapper folder.
- Whether the next product build should prioritize native desktop collection or
  app/action policy controls.
