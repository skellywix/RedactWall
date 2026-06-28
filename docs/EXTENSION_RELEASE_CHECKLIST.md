# Private or unlisted Chrome Web Store release checklist

Use this checklist when the browser extension moves from local pilot zip to a
customer-controlled Chrome Web Store release. The goal is to give IT a stable
extension ID, a force-install policy, a safe update channel, and install-health
evidence in Coverage.

## Release shape

- Preferred channel: private or unlisted Chrome Web Store item for the customer
  or pilot cohort.
- Lab-only fallback: self-hosted CRX with an update URL, used only when the
  customer cannot use the Chrome Web Store yet.
- The extension ID must stay stable across updates. Changing it creates a new
  fleet and breaks update continuity.
- The package must never contain ingest keys, prompt bodies, token vault data,
  handoff secrets, or customer content.

## Build and readiness gate

Run from the repo root:

```bash
npm run release:extension:check -- dist/browser-extension
```

The command builds the browser extension package and writes:

```text
dist/browser-extension/promptwall-extension-v<version>.zip
dist/browser-extension/promptwall-extension-v<version>.manifest.json
dist/browser-extension/promptwall-extension-v<version>.release-readiness.json
```

Attach the `.manifest.json` and `.release-readiness.json` to the technician
handoff packet. Do not attach managed storage files that contain real ingest
keys.

## Chrome Web Store preparation

Before upload:

- Confirm the Web Store developer account belongs to the customer, reseller, or
  controlled PromptWall release account.
- Set visibility to private or unlisted for pilot releases.
- Keep the version equal to `package.json` and `sensors/browser-extension/manifest.json`.
- Include a short single-purpose description: PromptWall inspects data headed to
  governed AI tools and blocks, redacts, warns, or requires justification by
  policy.
- Document the permission purpose for `storage`, `activeTab`, `tabs`, `alarms`,
  and the governed AI host list.
- Document that managed storage provides `serverUrl`, `ingestKey`, `orgId`, and
  user identity.
- State that prompt text is inspected locally by the extension before send, and
  that install-health heartbeats contain only bounded check IDs, version, user,
  org, and failed-check state.

## Enterprise policy handoff

After the Web Store item exists:

- Replace `<extension-id>` in
  `docs/examples/chrome-extension-settings.example.json`.
- Keep `update_url` set to `https://clients2.google.com/service/update2/crx` for
  Chrome Web Store installs.
- Configure managed storage from the customer MDM or Chrome Enterprise policy.
- Store the real `ingestKey` only in the customer's policy system or vault.
- Export the final ExtensionSettings policy and include it in the handoff packet.

## Install-day proof

On a managed test device:

- Open `chrome://policy`, reload policies, and confirm the extension is
  force-installed.
- Confirm the extension receives managed storage.
- Open the PromptWall popup and confirm protection is enabled.
- Send a benign prompt to a governed AI destination.
- Confirm Coverage shows the managed test user and org in Fleet Install Health
  with `browser_extension`, the released version, `covered`, and `checks ok`.
- Paste `123-45-6789` as synthetic SSN test data and confirm the customer's
  configured policy action appears before anything is sent.

## Rollback

- Keep the previous approved package manifest and Web Store version in the
  handoff packet.
- If a rollout fails, publish a fixed higher version or restore the previous
  package as the next higher version. Chrome extension versions cannot be
  downgraded in place.
- Re-run `npm run release:extension:check` for the replacement package and
  confirm Coverage returns to `covered` for the managed test user.

## Works Cited

Google. "Automatically Install Apps and Extensions." *Chrome Enterprise and
Education Help*, Google, https://support.google.com/chrome/a/answer/6306504.
Accessed 28 June 2026.

Google. "Set Up Your Extension for Distribution." *Chrome for Developers*,
Google, https://developer.chrome.com/docs/webstore/cws-dashboard-distribution.
Accessed 28 June 2026.
