# Managed Chrome Extension Deployment

This guide bridges the local demo extension to a controlled client pilot.

For a sales demo, `chrome://extensions` plus Load unpacked is fine. For a client pilot, use managed deployment so users cannot silently disable protection and so identity/server configuration comes from IT instead of the employee.

## Pilot Deployment Shape

1. Build and check a local handoff package with `npm run release:extension:check`.
   - Keep the generated `.zip` and `.manifest.json` together.
   - Keep the generated `.release-readiness.json` with the handoff packet.
   - Confirm the manifest SHA-256 matches the uploaded package.
2. Publish the extension through a controlled channel.
   - Preferred: private or unlisted Chrome Web Store item for the client tenant.
   - Alternative for lab pilots: self-hosted CRX with an update URL.
3. Force-install the extension with Chrome Enterprise policy.
4. Set managed storage values for:
   - `serverUrl`
   - `ingestKey`
   - `orgId`
   - `email` or `user`
5. Confirm the dashboard Coverage tab receives the browser install-health
   heartbeat for the correct user, org, version, and failed-check state.
6. Confirm the dashboard receives attributed prompt/file events.
7. Confirm the extension is active on governed AI destinations.

## Build The Package

Run the release readiness gate from the repo root:

```bash
npm run release:extension:check -- dist/browser-extension
```

The command wraps `npm run package:extension`, validates the force-install and
managed-storage examples, checks the private or unlisted release checklist, and
writes a prompt-free release-readiness JSON file. Use `--extension-id
<chrome-web-store-id>` after the private or unlisted Chrome Web Store item
exists.

For package-only development checks, run:

```bash
npm run package:extension
```

The command writes:

```text
dist/browser-extension/promptwall-extension-v<version>.zip
dist/browser-extension/promptwall-extension-v<version>.manifest.json
dist/browser-extension/promptwall-extension-v<version>.release-readiness.json
```

The manifest records the package SHA-256, every packaged file hash, the app and extension versions, the synced engine hashes, and packaging checks. It intentionally contains no prompt bodies or real keys.
The package check also verifies that the browser install-health heartbeat code
is present in the service worker.

The release-readiness report records the Chrome Web Store update URL, package
hash, policy-example checks, checklist checks, and required install-day evidence.
It intentionally does not include managed-storage values or ingest keys.

The command fails if:

- `sensors/browser-extension/manifest.json` is not Manifest V3.
- The extension version differs from `package.json`.
- Required service worker, popup, content scripts, or managed schema files are missing.
- The copied detection engine under `sensors/browser-extension/lib/` drifted from `detection-engine/`.
- Browser install-health heartbeat support is missing from the service worker.
- A development ingest key is present in packaged extension files.

## Extension Settings Example

Use `docs/examples/chrome-extension-settings.example.json` as the shape for Chrome Enterprise extension force-install policy. Replace `<extension-id>` after publishing or packaging the extension.

For a private Chrome Web Store item, the update URL is usually:

```text
https://clients2.google.com/service/update2/crx
```

## Managed Storage Example

Use `docs/examples/chrome-managed-storage.policy.json` for the values consumed by `sensors/browser-extension/schema.json`.

Never put a real ingest key in source control or a screenshot. Generate a long random ingest key per pilot and rotate it after demos.

Recommended values:

- `serverUrl`: HTTPS URL of the PromptWall control plane.
- `ingestKey`: pilot-specific ingest key, stored in MDM or Chrome policy.
- `orgId`: institution or tenant identifier.
- `email`: end-user email from directory attributes, preferred for the audit log.
- `user`: fallback username when email is unavailable.

## Validation Checklist

On a managed test device:

1. Open `chrome://policy` and reload policies.
2. Confirm the extension is force-installed.
3. Confirm managed storage is present.
4. Open the PromptWall popup and confirm protection is enabled.
5. Open ChatGPT or Claude and send a benign prompt.
6. Confirm the dashboard Coverage tab shows `browser_extension` install health.
   A healthy managed install should show passing checks for managed config,
   managed identity, tenant id, server URL, ingest-key presence, content-script
   coverage, and policy cache availability.
7. Confirm the dashboard shows the correct user and org.
8. Paste synthetic PII and confirm a block or redaction.
9. Visit an unreviewed AI host and confirm PromptWall blocks it by default, then
   records the reviewed allow/govern/block decision after a Security Admin enters
   a reason.

## Production Notes

- Use HTTPS for `serverUrl`.
- Use a stable, rotated `INGEST_API_KEY`.
- Use `docs/EXTENSION_RELEASE_CHECKLIST.md` before uploading a private or
  unlisted Chrome Web Store item.
- Pair extension force-install with browser policy that blocks unapproved AI destinations or routes them through governance.
- Keep the extension ID stable across updates.
- Treat managed policy as secret-bearing configuration because it contains the ingest key.
- Do not embed ingest keys in the extension package. The packaged extension fails closed until local or managed storage supplies a tenant key.
- Browser install-health heartbeats post only check IDs, boolean results, short
  details, sensor metadata, user, and org id. The ingest key is used only in the
  `x-api-key` header.
