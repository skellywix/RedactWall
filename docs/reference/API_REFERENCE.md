# Developer API Reference

RedactWall exposes a small REST surface under `/api/v1` for sensors and custom
integrations: scan text, scan files, scan model responses, report shadow-AI
sightings, fetch policy, and poll held-item status. A machine-readable OpenAPI
3.1 spec is served at **`GET /api/v1/openapi.json`** (public, no key) for
codegen; this page is the human-readable companion.

All values in the examples below are synthetic.

## Authentication

| Header | Used by | Purpose |
|--------|---------|---------|
| `x-api-key: <INGEST_API_KEY>` | every `/api/v1` route **except the public `GET /api/v1/openapi.json` spec** | the sensor ingest key (env `INGEST_API_KEY`). Missing/invalid → `401 {"error":"invalid ingest key"}`; repeated failures lock the client out with `429`. |
| `x-release-token: <token>` | `GET /api/v1/status/{id}`, `POST /api/v1/rehydrate` | the release token handed back when an item is held, so only the originating sensor can poll or rehydrate it. |

## Privacy contract

The control plane receives only **sanitized, masked** data. Findings carry a
`type`, `severity`, `confidence`, and a `masked` value (e.g. `•••• 6789`) —
never the raw match. Validation errors return field **names** only, never the
submitted values. Raw prompt text is retained only when an item is held for
approval, only when a data key is configured, and only encrypted at rest.

## Decision semantics

`POST /api/v1/gate` returns a `decision` and a `status`:

| decision | meaning |
|----------|---------|
| `allow` | nothing sensitive; a signed "safe-to-send" receipt is included. |
| `block` | withheld; ordinary policy blocks use `status: pending` plus a `releaseToken`, while uninspectable encoded content uses `status: blocked_unscannable` with no release token. |
| `redact` | structured findings tokenized locally; the tokenized prompt is safe to send. |
| `log` | monitor-only (proxy path); recorded, not enforced. |

## Endpoints

### `POST /api/v1/gate` — scan a prompt

```bash
curl -sX POST "$URL/api/v1/gate" -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -d '{"prompt":"Member SSN is 123-45-6789","destination":"chatgpt.com","user":"teller@cu.example"}'
```

Base64 and hex that decode to sensitive text are evaluated as that sensitive
type. Strict Base64 that decodes to non-text bytes is blocked as
`blocked_unscannable`; it cannot be changed to allow, warn, justify, redact, or
later approval because the text detector could not inspect its contents.

### `POST /api/v1/scan-file` — scan an uploaded file

`contentBase64` is inspected server-side and never persisted. Images without a
configured OCR path return `ocrRequired: true`. File types that cannot be parsed
for inspection **fail closed**: the request is held with status
`file_blocked_unscanned` (decision `block`) rather than allowed, so a renamed or
unsupported file cannot leave uninspected.
The `contentBase64` field is the API transport encoding. If extracted text
itself contains another reversible encoding, RedactWall recursively inspects
that text and applies the same fail-closed rule.

```bash
curl -sX POST "$URL/api/v1/scan-file" -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -d '{"filename":"notes.txt","contentBase64":"bWVtYmVyIFNTTiAxMjMtNDUtNjc4OQ==","destination":"chatgpt.com"}'
```

### `POST /api/v1/scan-response` — scan a model response

Detects sensitive data a model may have echoed back; the gateway uses this to
block or redact streamed output.

### `POST /api/v1/rehydrate` — restore a tokenized prompt

Requires `x-release-token`. Audit-logged.

### `GET /api/v1/status/{id}` — poll a held item

Requires `x-release-token`. Returns `{ id, status, released }`.

### `POST /api/v1/discovery` — import shadow-AI sightings

Host-only sightings from Zscaler/Netskope/Purview/firewall exports.

```bash
curl -sX POST "$URL/api/v1/discovery" -H "x-api-key: $KEY" -H 'content-type: application/json' \
  -d '{"source":"zscaler","sightings":[{"destination":"chatgpt.com","user":"teller@cu.example"}]}'
```

### `POST /api/v1/heartbeat` — sensor presence + install health

### `GET /api/v1/policy` — sensor-safe policy

The subset of policy sensors need (enforcement mode, thresholds, `alwaysBlock`,
governed destinations…), excluding admin-only fields like retention settings.
`GET /api/v1/policy/bundle` returns the sensor-safe policy in a versioned,
expiring Ed25519-signed envelope. `GET /api/v1/policy/pubkey` exposes the public
key for authenticated operator retrieval and inventory only. A sensor must use
an out-of-band pinned copy of that key. Fetching the key and the bundle from the
same untrusted connection does not establish policy authenticity.

### `GET /api/v1/detectors` — detector inventory

Ids, severities, and labels for every built-in and custom detector.

## Verify receipts

A cleared gate response includes a signed, prompt-free receipt proving the scan
happened. Verify it independently via `POST /api/receipts/verify` (admin) or the
published receipt public key.
