# Browser extension release checklist

Use this checklist when the browser extension moves from local pilot zip to a
customer-controlled managed release. The goal is to give IT a stable extension
ID, force-install policy, safe update channel, and install-health evidence in
Coverage for Chrome, Edge, and Firefox fleets.

## Release Shape

- Chrome channel: private or unlisted Chrome Web Store item for the customer or
  pilot cohort.
- Edge channel: private Microsoft Edge Add-ons item or customer-controlled Edge
  extension channel.
- Firefox channel: signed XPI with an HTTPS install URL or a customer-approved
  Firefox Add-ons distribution path.
- Lab-only fallback: self-hosted CRX/XPI with an HTTPS update or install URL,
  used only when the customer cannot use a browser store yet.
- Each browser extension ID must stay stable across updates. Changing it creates
  a new fleet and breaks update continuity.
- The package must never contain ingest keys, prompt bodies, token vault data,
  handoff secrets, or customer content.

## Build And Readiness Gate

Run from the repo root:

```bash
npm run release:extension:check -- dist/browser-extension
```

The command builds the browser extension packages and writes:

```text
dist/browser-extension/redactwall-chrome-extension-v<version>.zip
dist/browser-extension/redactwall-chrome-extension-v<version>.manifest.json
dist/browser-extension/redactwall-edge-extension-v<version>.zip
dist/browser-extension/redactwall-edge-extension-v<version>.manifest.json
dist/browser-extension/redactwall-firefox-extension-v<version>.zip
dist/browser-extension/redactwall-firefox-extension-v<version>.manifest.json
dist/browser-extension/redactwall-browser-extension-v<version>.release-readiness.json
```

After Chrome and Edge store items exist, rerun with the final store IDs:

```bash
npm run release:extension:check -- dist/browser-extension --chrome-extension-id <chrome-web-store-id> --edge-extension-id <edge-addons-id>
```

That writes:

```text
dist/browser-extension/redactwall-chrome-extension-v<version>.extension-settings.json
dist/browser-extension/redactwall-edge-extension-v<version>.extension-settings.json
```

For Firefox, rerun with the customer-approved signed XPI URL:

```bash
npm run release:extension:check -- dist/browser-extension --firefox-install-url https://downloads.customer.example/redactwall-firefox.xpi
```

That writes:

```text
dist/browser-extension/redactwall-firefox-extension-v<version>.extension-settings.json
```

Generated ExtensionSettings files are safe to attach to the handoff packet
because they contain only extension IDs, force-install mode, and install/update
URLs. They do not contain managed-storage values or ingest keys.

Attach each `.manifest.json` and the shared `.release-readiness.json` to the
technician handoff packet. Do not attach managed storage files that contain real
ingest keys.

## Browser Store Preparation

Before upload:

- Confirm the store or signing account belongs to the customer, reseller, or
  controlled RedactWall release account.
- Set visibility to private, unlisted, or organization-scoped for pilot
  releases.
- Keep the version equal to `package.json` and `sensors/browser-extension/manifest.json`.
- Include a short single-purpose description: RedactWall inspects data headed to
  governed AI tools and blocks, redacts, warns, or requires justification by
  policy.
- Document the permission purpose for `storage`, `activeTab`, `tabs`, `alarms`,
  `downloads`, `scripting`, `declarativeNetRequest`, the packaged AI host list,
  and the optional HTTPS host permission used only for exact custom-site grants.
- Document that managed storage provides `serverUrl`, `ingestKey`,
  `policyPublicKey`, `orgId`, `enabled`, and user identity.
- State that prompt text is inspected locally by the extension before send, and
  that install-health heartbeats contain only bounded check IDs, version, user,
  org, platform, and failed-check state.

## Enterprise Policy Handoff

After store items or signed install URLs exist:

- Prefer generated force-install files from `npm run release:extension:check`.
- If generating by hand, start from:
  - `docs/examples/chrome-extension-settings.example.json`
  - `docs/examples/edge-extension-settings.example.json`
  - `docs/examples/firefox-extension-settings.example.json`
- Keep Chrome `update_url` set to `https://clients2.google.com/service/update2/crx`
  for Chrome Web Store installs.
- Keep Edge `update_url` set to `https://edge.microsoft.com/extensionwebstorebase/v1/crx`
  for Microsoft Edge Add-ons installs.
- Keep Firefox `install_url` set to the customer-approved signed XPI HTTPS URL.
- Keep Firefox managed policy keyed to the packaged Gecko extension id,
  `redactwall@example.com`.
- Configure managed storage from the customer MDM or browser enterprise policy.
- Store the real `ingestKey` only in the customer's policy system or vault.
- Export the final force-install policy and include it in the handoff packet.

## Install-Day Proof

On a managed test device:

- Open the browser policy page (`chrome://policy`, `edge://policy`, or
  `about:policies`) and reload policies.
- Confirm the extension is force-installed.
- Confirm the extension receives managed storage.
- Open the RedactWall popup, grant the exact control-plane origin and every
  pending custom governed destination, then confirm protection is enabled and
  custom destination coverage is healthy.
- Send a benign prompt to a packaged host and an administrator-added governed
  destination.
- Confirm Coverage shows the managed test user and org in Fleet Install Health
  with `browser_extension`, the released version, expected platform, `covered`,
  and `checks ok`.
- Paste `123-45-6789` as synthetic SSN test data and confirm the customer's
  configured policy action appears before anything is sent.

## Rollback

- Keep the previous approved package manifest and store/signing version in the
  handoff packet.
- If a rollout fails, publish a fixed higher version or restore the previous
  package as the next higher version. Browser extension versions generally
  cannot be downgraded in place by policy.
- Re-run `npm run release:extension:check` for the replacement package and
  confirm Coverage returns to `covered` for the managed test user.

## Works Cited

Google. "Automatically Install Apps and Extensions." Chrome Enterprise and
Education Help, Google, https://support.google.com/chrome/a/answer/6306504.
Accessed 28 June 2026.

Google. "Set Up Your Extension for Distribution." Chrome for Developers,
Google, https://developer.chrome.com/docs/webstore/cws-dashboard-distribution.
Accessed 28 June 2026.

Microsoft. "Microsoft Edge Browser Policy Documentation." Microsoft Learn,
Microsoft, https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies.
Accessed 28 June 2026.

Mozilla. "Policy Templates." Mozilla, https://github.com/mozilla/policy-templates.
Accessed 28 June 2026.
