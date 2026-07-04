# AI Chat DLP Proxy Lab

This lab is the smallest network-proxy spike for AI chat monitoring in
PromptWall. It is monitor-only: it observes cleartext request bodies, scans them
locally, reports sanitized evidence to the existing control plane, and does not
block, redact, approve, deny, or wait on upstream traffic.

## Surface Map

- AI-domain scope: `detection-engine/adapters.js` owns `AI_HOSTS`,
  `normalizeHost()`, and `isAiHost()`.
- Local detection: `detection-engine/detect.js` is the single detector engine
  used by server, browser, endpoint, MCP, and this lab.
- Policy and destination handling: `server/policy.js` owns governed,
  allowlisted, blocked, and unapproved AI destination logic.
- Sanitized evidence path: `POST /api/v1/gate` in `server/app.js` records
  prompt-free sensor evidence and audit rows.
- Enforcement reference: `scripts/squid-icap-bridge.js` remains the fail-closed
  ICAP sketch for a production enforcement proxy.
- Monitor-only spike: `scripts/ai-chat-dlp-proxy-lab.js` is the cleartext lab
  bridge. It sends `clientOutcome: "proxy_observed"` with
  `clientPreRedacted: true`.

## What The Lab Does

- Inspects only `POST`, `PUT`, and `PATCH` bodies whose host matches
  `AI_HOSTS`.
- Extracts chat text from common JSON request bodies using the existing proxy
  extraction helper.
- Runs the shared detector locally.
- Sends only a redacted prompt label such as `[REDACTED: US_SSN]` or
  `[proxy observed] chatgpt.com` to `/api/v1/gate`.
- Sends masked finding metadata, category labels, entity counts, risk score, and
  sensor metadata through the existing gate schema.
- Records `proxy_observed` evidence as `decision: "log"` and `mode: "monitor"`.
- Ignores the control-plane verdict for forwarding purposes.

## What The Lab Does Not Do

- It does not decrypt HTTPS or handle `CONNECT`.
- It does not enforce policy, hold requests, wait for approval, or redact the
  upstream request.
- It does not send raw prompt text, raw detector values, token vaults, release
  tokens, request bodies, uploaded file bytes, or decision secrets to the
  control plane.
- It is not a production proxy deployment. Use synthetic data and local upstream
  fixtures for validation.

## Run A Sample Observation

Start PromptWall in another terminal with a lab ingest key:

```powershell
$env:INGEST_API_KEY = "dev-ingest-key"
npm start
```

Then run the sample observer:

```powershell
$env:INGEST_API_KEY = "dev-ingest-key"
npm run proxy:lab -- --sample --sentinel http://127.0.0.1:4000
```

The console output is sanitized. It shows the destination, masked finding types,
and the control-plane `proxy_observed` id if PromptWall is reachable. If the
control plane is down, the result still reports `forward: true` because this lab
is monitor-only.

## Run As A Cleartext HTTP Lab Proxy

```powershell
$env:INGEST_API_KEY = "dev-ingest-key"
npm run proxy:lab -- --port 4181 --sentinel http://127.0.0.1:4000
```

For a local upstream fixture, send an absolute-form HTTP request through
`127.0.0.1:4181`. The lab forwards the original request after observation. Do
not use real customer data or real AI services for this spike.

## Validation

Focused checks:

```powershell
node --test test/ai-chat-dlp-proxy-lab.test.js test/validation.test.js
```

Useful broader checks after changes around this surface:

```powershell
node --test test/squid-icap-bridge.test.js test/adapters.test.js test/policy-history.test.js
npm run sync-check
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

## Promotion Path

Keep the monitor and enforcement paths separate. A production proxy or ICAP
plugin should either:

- call this monitor observer for visibility-only deployments, or
- use the existing `scripts/squid-icap-bridge.js` fail-closed gate and
  `awaitRelease()` path when the customer explicitly wants enforcement.

Do not make the monitor lab fail closed. Its safety property is that it reports
only sanitized evidence while leaving traffic behavior unchanged.
