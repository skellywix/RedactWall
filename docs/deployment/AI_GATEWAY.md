# RedactWall AI Gateway

The AI Gateway is an OpenAI-compatible reverse proxy that sits between an
application (or agent) and an upstream LLM provider. It gates every prompt and
scans every response through the RedactWall control plane **before** anything
reaches the model or returns to the caller. It is the enforcement point for
private/homegrown apps and agents that call an LLM API directly — the paths a
browser extension or endpoint agent cannot see.

It is a **first-class deployable service** (`gateway/`), separate from the
control plane, sharing the same detection engine and policy.

## Guarantees

- **Fail closed.** If the control plane is unreachable, the request is blocked —
  it never silently reaches upstream. (`gateway/client.js` returns a synthetic
  block on any network/timeout error; the readiness probe reports `503`.)
- **Prompt gated before egress.** The prompt is sent to `/api/v1/gate`; a
  `block`/hold decision returns a structured refusal and the upstream is never
  called. A `redact` decision forwards a locally tokenized body (no real PII);
  the token map is held in the gateway process only.
- **Response scanned before release.** The model output is sent to
  `/api/v1/scan-response`; a leak blocks or redacts the output before the caller
  receives it. Streaming responses are **buffered and scanned, then re-emitted**
  as SSE — so model output cannot reach the caller until it passes.
- **Local rehydration.** For redacted requests, the gateway tokenizes every
  message locally before egress and rehydrates the scanned response from that
  in-process token map after scanning (`detect.detokenize`) — the map never
  leaves the gateway and the model never saw the real values.
- **Authenticated callers.** Each caller presents an agent token
  (`Authorization: Bearer pw_gw_...`) mapped to a managed identity + orgId. Only
  salted hashes are stored. Per-token rate limits apply.

## Surface

OpenAI-compatible, so existing SDKs work by changing the base URL:

| Method | Path |
| --- | --- |
| `POST` | `/v1/chat/completions` (supports `stream: true`) |
| `POST` | `/v1/completions` |
| `POST` | `/v1/embeddings` |
| `GET`  | `/healthz` — service liveness |
| `GET`  | `/readyz` — authenticated, bounded control-plane readiness (503 on bad credentials, wrong service, or outage) |
| `GET`  | `/metrics` — request/decision counters |

## Providers

`GATEWAY_PROVIDER` selects the upstream adapter (`gateway/adapters/`):

- `openai` — OpenAI or a bearer-authenticated endpoint with the same `/v1/*` paths
- `anthropic` — Anthropic Messages API for `/v1/chat/completions`, including
  text conversations and function-tool calls translated to and from OpenAI shape
- `internal-http` — an explicit no-auth OpenAI-compatible endpoint that requires
  `GATEWAY_UPSTREAM_URL`
- `mock` — no network; echoes the prompt back for local/CI verification and is rejected when `NODE_ENV=production`

Provider names are validated at startup. Unknown values fail closed instead of
silently selecting OpenAI, and `internal-http` never falls back to
`api.openai.com` when its upstream URL is missing. OpenAI and Anthropic require
a nonempty `GATEWAY_UPSTREAM_API_KEY`.

The Anthropic adapter accepts the text-chat subset it can translate without
semantic loss: `model`, messages, completion-token limits, `temperature`,
`top_p`, stop sequences, streaming, and OpenAI function tools/tool choices.
Completions, embeddings, multimodal content, and unsupported OpenAI options
return `400` before policy or upstream side effects. Azure OpenAI is not listed
as an alias because its deployment path, `api-version` query, and `api-key`
authentication contract are not implemented by the standard OpenAI adapter.

New providers are a small adapter implementing `requestText`,
`applyRedactedRequest`, `responseText`, `applyResponseText`, `callUpstream`, and
optionally a fail-fast `validateRequest`.

## Quick start (local)

```bash
# 1. Control plane
npm start                        # http://localhost:4000

# 2. Mint an agent token for a caller (printed once; only its hash is stored)
npm run gateway:token -- --user billing-bot@app.example --org acme --label "billing bot"

# 3. Start the gateway (mock provider needs no upstream key)
GATEWAY_PROVIDER=mock \
GATEWAY_CONTROL_PLANE_URL=http://127.0.0.1:4000 \
INGEST_API_KEY="$(grep '^INGEST_API_KEY=' .env | cut -d= -f2-)" \
npm run gateway                  # http://localhost:4100

# 4. Call it like OpenAI
curl http://localhost:4100/v1/chat/completions \
  -H "authorization: Bearer pw_gw_..." \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Summarize Q3 hours"}]}'
```

A prompt containing a hard-stop entity (SSN, card, secret, …) returns `403` with
`error.type = blocked_by_redactwall` and never reaches the upstream.

## Docker

The gateway ships as an opt-in compose profile:

```bash
docker compose --profile gateway up -d --build
```

It shares the `redactwall` service's network namespace so authenticated
control-plane traffic stays on loopback, and it shares the data volume for its
agent-token store. Compose pins `REDACTWALL_LOCK_HOSTNAME` to
`redactwall-gateway` because Docker forbids a container hostname together with
that shared-network mode. Keep this lock hostname stable and unique when a
singleton gateway is recreated against the same token store so its new Linux
PID-namespace generation can reclaim a crashed predecessor's lock.

## Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `GATEWAY_PORT` | Listen port | `4100` |
| `GATEWAY_CONTROL_PLANE_URL` | Control plane base URL | `http://127.0.0.1:4000` |
| `INGEST_API_KEY` | Sensor ingest key (same as the control plane) | — |
| `GATEWAY_PROVIDER` | Upstream adapter | `openai` |
| `GATEWAY_UPSTREAM_URL` | Upstream provider base URL | OpenAI/Anthropic provider default; required for `internal-http` |
| `GATEWAY_UPSTREAM_API_KEY` | Upstream provider key | Required for `openai` and `anthropic`; omitted for `internal-http` |
| `GATEWAY_REQUIRE_AGENT_TOKEN` | Reject unauthenticated callers | `true` |
| `GATEWAY_RATE_LIMIT_PER_MIN` | Per-token request cap | `120` |
| `GATEWAY_AGENT_TOKENS_PATH` | Agent-token store (hashes only) | `data/gateway-agent-tokens.json` |
| `REDACTWALL_LOCK_HOSTNAME` | Stable singleton identity for file-lock recovery | OS hostname |
| `GATEWAY_MAX_BODY_BYTES` | Max request body | `2097152` |
| `GATEWAY_REQUEST_BODY_TIMEOUT_MS` | Absolute inbound JSON body-read deadline | `15000` |
| `GATEWAY_TIMEOUT_MS` | Control-plane + upstream timeout | `60000` |

All settings honor the `REDACTWALL_` env names (with legacy `PROMPTWALL_`/`SENTINEL_` aliases) used elsewhere.

## Agent tokens

```bash
npm run gateway:token -- --user agent@app --org acme --label "name"   # mint (printed once)
npm run gateway:token -- --list                                       # list ids (no raw tokens)
npm run gateway:token -- --revoke tok_abc123                          # revoke
```

Revoking removes the token from the store; the next request with it is rejected.

## Evidence

Every gated request and scanned response is recorded in the control plane's
prompt-free evidence trail (masked findings, risk score, decision, agent
identity, orgId) exactly like the other sensors, and hard-stop blocks emit a
SIEM security event. The gateway itself logs only metadata.
