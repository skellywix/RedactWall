# Managed Browser Extension Deployment

This guide bridges the local demo extension to a controlled client pilot.

For a sales demo, `chrome://extensions` plus Load unpacked is fine. For a
client pilot, use managed deployment so users cannot silently disable
protection and so identity/server configuration comes from IT instead of the
employee. PromptWall now builds browser-specific packages for Chrome, Edge, and Firefox
from the same source extension.

## Pilot Deployment Shape

1. Build and check the browser handoff package with `npm run release:extension:check`.
   - Keep each generated `.zip` and `.manifest.json` together.
   - Keep the generated `.release-readiness.json` with the handoff packet.
   - Confirm each manifest SHA-256 matches the uploaded package.
2. Publish the extension through the controlled channel for the customer's
   browser fleet.
   - Chrome: private or unlisted Chrome Web Store item.
   - Edge: private Microsoft Edge Add-ons item or customer-controlled Edge
     extension channel.
   - Firefox: signed XPI with an HTTPS install URL, or a Firefox Add-ons path
     approved by the customer.
3. Force-install the extension with the customer's browser-management policy.
4. Set managed storage values for:
   - `serverUrl`
   - `ingestKey`
   - `orgId`
   - `email` or `user`
5. Confirm the dashboard Coverage tab receives the browser install-health
   heartbeat for the correct user, org, version, platform, and failed-check
   state.
6. Confirm the dashboard receives attributed prompt/file events.
7. Confirm the extension is active on governed AI destinations.

## Build The Packages

Run the release readiness gate from the repo root:

```bash
npm run release:extension:check -- dist/browser-extension
```

The command wraps `npm run package:extension`, validates force-install and
managed-storage examples, checks the browser release checklist, and writes a
prompt-free release-readiness JSON file. It builds all three target packages:

```text
dist/browser-extension/promptwall-chrome-extension-v<version>.zip
dist/browser-extension/promptwall-chrome-extension-v<version>.manifest.json
dist/browser-extension/promptwall-edge-extension-v<version>.zip
dist/browser-extension/promptwall-edge-extension-v<version>.manifest.json
dist/browser-extension/promptwall-firefox-extension-v<version>.zip
dist/browser-extension/promptwall-firefox-extension-v<version>.manifest.json
dist/browser-extension/promptwall-browser-extension-v<version>.release-readiness.json
```

For package-only development checks, run:

```bash
npm run package:extension
```

The manifest records the package SHA-256, every packaged file hash, the app and
extension versions, the target browser, the generated background model, synced
engine hashes, and packaging checks. It intentionally contains no prompt bodies
or real keys.

The package check also verifies that the browser install-health heartbeat code
and WebExtension API bridge are present. Chrome and Edge packages keep the MV3
service-worker background. Firefox packages are generated with a Gecko extension
id and background scripts while using the same source files.

The command fails if:

- `sensors/browser-extension/manifest.json` is not Manifest V3.
- The extension version differs from `package.json`.
- Required background, popup, content scripts, managed schema, or browser API
  bridge files are missing.
- The copied detection engine under `sensors/browser-extension/lib/` drifted
  from `detection-engine/`.
- Browser install-health heartbeat support is missing from the background
  runtime.
- A development ingest key is present in packaged extension files.

## Force-Install Policy Examples

Use these examples as the shape for customer browser policy:

- Chrome: `docs/examples/chrome-extension-settings.example.json`
- Edge: `docs/examples/edge-extension-settings.example.json`
- Firefox: `docs/examples/firefox-extension-settings.example.json`

For Chrome and Edge store IDs, rerun the release gate with the real IDs:

```bash
npm run release:extension:check -- dist/browser-extension --chrome-extension-id <chrome-web-store-id> --edge-extension-id <edge-addons-id>
```

That writes prompt-free force-install policies:

```text
dist/browser-extension/promptwall-chrome-extension-v<version>.extension-settings.json
dist/browser-extension/promptwall-edge-extension-v<version>.extension-settings.json
```

For Firefox, provide the customer-approved signed XPI HTTPS URL:

```bash
npm run release:extension:check -- dist/browser-extension --firefox-install-url https://downloads.customer.example/promptwall-firefox.xpi
```

That writes:

```text
dist/browser-extension/promptwall-firefox-extension-v<version>.extension-settings.json
```

Generated force-install files contain only extension IDs, install or update
URLs, and force-install mode. They do not contain `serverUrl`, `orgId`, ingest
keys, or user identity.

## Managed Storage Examples

Use `docs/examples/browser-managed-storage.policy.json` for Chrome and Edge
managed storage values consumed by `sensors/browser-extension/schema.json`.

Use `docs/examples/firefox-managed-storage.policy.json` for Firefox enterprise
policies. The packaged Firefox extension id is `promptwall@example.com`, so the
managed-storage policy must use the same key.

Never put a real ingest key in source control or a screenshot. Generate a long
random ingest key per pilot and rotate it after demos.

Recommended values:

- `serverUrl`: HTTPS URL of the PromptWall control plane.
- `ingestKey`: pilot-specific ingest key, stored in MDM or browser policy.
- `orgId`: institution or tenant identifier.
- `email`: end-user email from directory attributes, preferred for the audit log.
- `user`: fallback username when email is unavailable.

## Validation Checklist

On a managed test device:

1. Open the browser policy page and reload policies.
   - Chrome: `chrome://policy`
   - Edge: `edge://policy`
   - Firefox: `about:policies`
2. Confirm the extension is force-installed.
3. Confirm managed storage is present.
4. Open the PromptWall popup and confirm protection is enabled.
5. Open ChatGPT or Claude and send a benign prompt.
6. Confirm the dashboard Coverage tab shows `browser_extension` install health.
   A healthy managed install should show passing checks for managed config,
   managed identity, tenant id, server URL, ingest-key presence, content-script
   coverage, and policy cache availability.
7. Confirm the dashboard shows the correct user, org, version, and platform
   (`chrome_mv3`, `edge_mv3`, or `firefox_mv3`).
8. Paste synthetic PII and confirm a block or redaction.
9. Visit an unreviewed AI host and confirm PromptWall blocks it by default, then
   records the reviewed allow/govern/block decision after a Security Admin
   enters a reason.

## Production Notes

- Use HTTPS for `serverUrl`.
- Do not include URL username or password credentials in `serverUrl`.
- Use a stable, rotated `INGEST_API_KEY`.
- Use `docs/EXTENSION_RELEASE_CHECKLIST.md` before uploading or distributing a
  managed browser package.
- Pair extension force-install with browser policy that blocks unapproved AI
  destinations or routes them through governance.
- Keep each browser extension ID stable across updates.
- Treat managed policy as secret-bearing configuration because it contains the
  ingest key.
- Do not embed ingest keys in the extension package. The packaged extension
  fails closed until local or managed storage supplies a tenant key.
- Browser install-health heartbeats post only check IDs, boolean results, short
  details, sensor metadata, user, and org id. The ingest key is used only in the
  `x-api-key` header.

## Works Cited

Google. "Automatically Install Apps and Extensions." Chrome Enterprise and
Education Help, Google, https://support.google.com/chrome/a/answer/6306504.
Accessed 28 June 2026.

Microsoft. "Microsoft Edge Browser Policy Documentation." Microsoft Learn,
Microsoft, https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies.
Accessed 28 June 2026.

Mozilla. "Policy Templates." Mozilla, https://github.com/mozilla/policy-templates.
Accessed 28 June 2026.
