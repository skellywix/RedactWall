# Managed Browser Extension Deployment

This guide bridges the local demo extension to a controlled client pilot.

For a sales demo, `chrome://extensions` plus Load unpacked is fine. For a
client pilot, use managed deployment so users cannot silently disable
protection and so identity/server configuration comes from IT instead of the
employee. RedactWall now builds browser-specific packages for Chrome, Edge, and Firefox
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
   - `policyPublicKey` (the out-of-band Ed25519 public-key pin)
   - `orgId`
   - `email` or `user`
   - `enabled: true` (administrator-owned; managed installs default on even when omitted)
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
dist/browser-extension/redactwall-chrome-extension-v<version>.zip
dist/browser-extension/redactwall-chrome-extension-v<version>.manifest.json
dist/browser-extension/redactwall-edge-extension-v<version>.zip
dist/browser-extension/redactwall-edge-extension-v<version>.manifest.json
dist/browser-extension/redactwall-firefox-extension-v<version>.zip
dist/browser-extension/redactwall-firefox-extension-v<version>.manifest.json
dist/browser-extension/redactwall-browser-extension-v<version>.release-readiness.json
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
dist/browser-extension/redactwall-chrome-extension-v<version>.extension-settings.json
dist/browser-extension/redactwall-edge-extension-v<version>.extension-settings.json
```

For Firefox, provide the customer-approved signed XPI HTTPS URL:

```bash
npm run release:extension:check -- dist/browser-extension --firefox-install-url https://downloads.customer.example/redactwall-firefox.xpi
```

That writes:

```text
dist/browser-extension/redactwall-firefox-extension-v<version>.extension-settings.json
```

Generated force-install files contain only extension IDs, install or update
URLs, and force-install mode. They do not contain `serverUrl`, `orgId`, ingest
keys, or user identity.

## Managed Storage Examples

Use `docs/examples/browser-managed-storage.policy.json` for Chrome and Edge
managed storage values consumed by `sensors/browser-extension/schema.json`.

Use `docs/examples/firefox-managed-storage.policy.json` for Firefox enterprise
policies. The packaged Firefox extension id is `redactwall@example.com`, so the
managed-storage policy must use the same key.

Never put a real ingest key in source control or a screenshot. Generate a long
random ingest key per pilot and rotate it after demos.

Recommended values:

- `serverUrl`: HTTPS URL of the RedactWall control plane.
- `ingestKey`: pilot-specific ingest key, stored in MDM or browser policy.
- `policyPublicKey`: exact PEM public key exported from the deployed control
  plane through a trusted operator channel. Do not let the extension learn this
  pin from `/api/v1/policy/pubkey`; a key fetched beside a bundle cannot
  authenticate that bundle.
- `orgId`: institution or tenant identifier.
- `email`: end-user email from directory attributes, preferred for the audit log.
- `user`: fallback username when email is unavailable.
- `enabled`: administrator-controlled protection state. The popup cannot override
  this value. A managed install without this key also defaults to enabled so an
  older managed policy cannot be bypassed by a stale local pause setting.

### Rotate the policy signing key

Treat a policy-key rotation as scheduled maintenance, not as recovery from an
unexplained signature failure. A cached bundle signed by the old key is a
durable anti-rollback high-water mark, so the extension will reject a new-key
bundle until a trusted administrator deliberately resets that cache.

1. Remove the browser force-install assignment and confirm the extension has
   been uninstalled, which clears its `chrome.storage.local` `policyBundle`.
2. Replace `policyPublicKey` in the managed storage policy through the trusted
   MDM channel.
3. Reapply the force-install assignment.
4. Confirm install health reports both `policy_public_key_pin` and
   `policy_cache` healthy before users resume AI access.

Do not clear extension storage merely to bypass `bad_signature`,
`rollback_detected`, or `policy_sequence_conflict`. Investigate those events
unless the signing-key change is an approved rotation.

## Validation Checklist

On a managed test device:

1. Open the browser policy page and reload policies.
   - Chrome: `chrome://policy`
   - Edge: `edge://policy`
   - Firefox: `about:policies`
2. Confirm the extension is force-installed.
3. Confirm managed storage is present.
4. Open the RedactWall popup. For a remote HTTPS `serverUrl`, grant the exact
   control-plane origin when prompted, then confirm protection is enabled. The
   extension stays fail closed and reports `server_host_permission=false` until
   this user-gesture permission succeeds.
5. If the signed policy contains administrator-added browser destinations,
   select **Allow exact sites** until the popup reports no pending origins.
   The extension requests only those HTTPS host patterns and keeps uncovered
   hosts blocked with a dynamic browser rule. Ensure Chrome/Edge
   `ExtensionSettings.runtime_allowed_hosts` does not prohibit them.
6. Open ChatGPT, Claude, and one administrator-added destination, then send a
   benign prompt on each.
7. Confirm the dashboard Coverage tab shows `browser_extension` install health.
   A healthy managed install should show passing checks for managed config,
   managed identity, tenant id, server URL, exact server-host permission,
   ingest-key presence, pinned policy-key presence, content-script coverage,
   and a fresh verified signed-policy cache.
8. Confirm the dashboard shows the correct user, org, version, and platform
   (`chrome_mv3`, `edge_mv3`, or `firefox_mv3`).
9. Paste synthetic PII and confirm a block or redaction.
10. Visit an unreviewed AI host and confirm RedactWall blocks it by default, then
   records the reviewed allow/govern/block decision after a Security Admin
   enters a reason.

## Production Notes

- Use HTTPS for `serverUrl`.
- Do not include URL username or password credentials in `serverUrl`.
- Use a stable, rotated `INGEST_API_KEY`.
- Provision `policyPublicKey` before enabling the extension. A missing pin,
  bad signature, key swap, malformed bundle, or expired cache blocks browser
  sends and uploads until a fresh bundle verifies under the existing pin.
- Use `docs/deployment/EXTENSION_RELEASE_CHECKLIST.md` before uploading or distributing a
  managed browser package.
- Pair extension force-install with browser policy that blocks unapproved AI
  destinations or routes them through governance.
- Built-in AI hosts use packaged content scripts. Administrator-added HTTPS
  hosts require their exact optional-host grant and runtime script registration;
  install health reports `custom_destination_coverage=false` and top-level
  navigation remains blocked until both are active. A broad `*`, cleartext URL,
  credentialed URL, or invalid host requires correction or proxy enforcement.
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
