# RedactWall AI LLM Gateway

`scripts/ai-llm-gateway.js` is the deployable app-to-LLM enforcement path for
private apps and internal agents that can point at an OpenAI-compatible,
Anthropic Messages, Gemini `generateContent`, or Amazon Bedrock Runtime
Converse/InvokeModel style base URL. It is separate from the monitor-only proxy
lab: this gateway blocks fail-closed when
RedactWall cannot inspect the prompt or response.

## What It Enforces

- Client auth before any upstream traffic leaves the gateway.
- Per-client memory, same-host SQLite, or central HTTP-backed shared rate
  limiting.
- Model allowlisting before prompt inspection or upstream forwarding, including
  provider-native path model ids such as Gemini and Bedrock Runtime model ids.
- Prompt gating through `POST /api/v1/gate` with `source: "proxy"` and
  `channel: "llm_gateway"`.
- Redact-mode tokenized prompt forwarding when the control plane returns a
  `tokenizedPrompt`.
- Approval hold polling when `REDACTWALL_GATEWAY_APPROVAL_WAIT_MS` is set.
- Model-output scanning through `POST /api/v1/scan-response`.
- Response redaction or response blocking before the caller sees the model
  output.
- Buffered scanning for JSON/SSE `stream: true` and Gemini
  `streamGenerateContent` traffic. The gateway waits for the upstream stream,
  scans the complete output, then releases only allowed content.
- Explicit `501` rejection for Bedrock `converse-stream` and
  `invoke-with-response-stream`. AWS returns binary EventStream frames, which
  this dependency-free proxy does not decode or CRC-validate, so those routes
  never reach the control plane or Bedrock upstream.
- Optional AWS SigV4 signing for direct Bedrock Runtime upstreams. AWS
  credentials stay on the gateway host and are never accepted from callers.
- Default blocking for non-text image/file/tool payload blocks unless
  `--allow-multimodal` is explicitly set for a controlled pilot.
- Request correlation through `X-RedactWall-Request-Id`, rate-limit headers,
  `/healthz`, and `/readyz`.

## Run Locally

Start RedactWall first:

```powershell
$env:INGEST_API_KEY = "replace-with-32-plus-char-ingest-key"
npm start
```

Start the gateway in another shell:

```powershell
$env:REDACTWALL_GATEWAY_TOKEN = "replace-with-client-token"
$env:REDACTWALL_GATEWAY_UPSTREAM_API_KEY = "sk-or-provider-key"
node scripts/ai-llm-gateway.js --redactwall http://127.0.0.1:4000 --upstream https://api.openai.com --port 4182
```

For direct Amazon Bedrock Runtime pilots, use AWS SigV4 upstream signing and
point the upstream at the regional Bedrock Runtime endpoint. Keep AWS
credentials in the process environment or deployment secret manager, not in app
requests:

```powershell
$env:REDACTWALL_GATEWAY_TOKEN = "replace-with-client-token"
$env:AWS_ACCESS_KEY_ID = "<bedrock-runtime-access-key>"
$env:AWS_SECRET_ACCESS_KEY = "<bedrock-runtime-secret-key>"
$env:AWS_SESSION_TOKEN = "<optional-session-token>"
node scripts/ai-llm-gateway.js --redactwall http://127.0.0.1:4000 --upstream https://bedrock-runtime.us-east-1.amazonaws.com --upstream-auth-scheme aws-sigv4 --aws-region us-east-1 --allowed-models "anthropic.claude-*,amazon.nova-*"
```

Then point the private app at paths such as:

```http
POST /model/anthropic.claude-3-5-sonnet-20240620-v1%3A0/converse
Authorization: Bearer replace-with-client-token
Content-Type: application/json
```

For local production-style testing with multiple gateway workers on the same
host, use the shared SQLite limiter:

```powershell
$env:REDACTWALL_GATEWAY_RATE_LIMIT_STORE = "sqlite"
$env:REDACTWALL_GATEWAY_RATE_LIMIT_DB = "C:\RedactWall\data\gateway-rate-limits.db"
node scripts/ai-llm-gateway.js --redactwall http://127.0.0.1:4000 --upstream https://api.openai.com --port 4182
```

For multi-host deployments, start the shipped shared limiter service on an
internal host, then point every gateway replica at it. The service stores only
hashed gateway-client keys in SQLite and can be placed behind customer-managed
TLS, private networking, or an existing API gateway:

```powershell
$env:REDACTWALL_RATE_LIMITER_TOKEN = "<shared-limiter-token>"
$env:REDACTWALL_RATE_LIMITER_DB = "C:\RedactWall\data\gateway-shared-rate-limiter.db"
npm run gateway:rate-limiter -- --host 127.0.0.1 --port 4183
```

Then configure each gateway replica:

```powershell
$env:REDACTWALL_GATEWAY_RATE_LIMIT_STORE = "http"
$env:REDACTWALL_GATEWAY_RATE_LIMIT_URL = "http://127.0.0.1:4183/check"
$env:REDACTWALL_GATEWAY_RATE_LIMIT_TOKEN = "<shared-limiter-token>"
node scripts/ai-llm-gateway.js --redactwall http://127.0.0.1:4000 --upstream https://api.openai.com --port 4182
```

For single-host process redundancy, use the dedicated compose file. It runs
two gateway replicas behind Nginx and stores hashed rate-limit counters in one
SQLite file on a local named volume:

```powershell
$env:REDACTWALL_GATEWAY_TOKEN = "<client-token>"
$env:INGEST_API_KEY = "<sensor-ingest-key>"
$env:REDACTWALL_URL = "https://redactwall.internal.example"
$env:REDACTWALL_GATEWAY_UPSTREAM_API_KEY = "<provider-key>"
docker compose -f docker-compose.gateway-ha.yml up -d --build
Invoke-RestMethod http://127.0.0.1:4182/readyz
```

The load balancer binds `REDACTWALL_GATEWAY_BIND_ADDRESS` (default `127.0.0.1`)
and publishes only `REDACTWALL_GATEWAY_PUBLIC_PORT` (default `4182`). The two
replicas independently listen on the private Compose network and share only the
local `gateway-limiter-data` volume. No limiter bearer token or prompt crosses a
cleartext inter-container limiter hop. Use `npm run gateway:ha:smoke` to prove a
surviving and restarted replica retain the same rate-limit counter without
calling an external LLM provider.

This stack is not multi-host high availability. Nginx, the Docker host, and the
named volume remain one failure domain. Keep the default loopback bind for a
local client, or place an authenticated TLS reverse proxy in front before
exposing it to another host.

For multi-host gateways, deploy the limiter behind an HTTPS internal load
balancer and set `REDACTWALL_GATEWAY_RATE_LIMIT_URL` to that HTTPS endpoint.
Never send `REDACTWALL_GATEWAY_RATE_LIMIT_TOKEN` to non-loopback cleartext HTTP.
Redis or Valkey can back multiple HTTPS limiter instances:

```powershell
$env:REDACTWALL_RATE_LIMITER_STORE = "redis"
$env:REDACTWALL_RATE_LIMITER_REDIS_URL = "rediss://:<password>@redis.internal.example:6380/0"
$env:REDACTWALL_GATEWAY_RATE_LIMIT_URL = "https://gateway-limiter.internal.example/check"
```

The Redis backend uses a single atomic `EVAL` operation per check, sets a TTL
per hashed key, and stores only `REDACTWALL_RATE_LIMITER_REDIS_PREFIX` plus the
SHA-256 limiter key. It does not store raw gateway client tokens, users,
prompts, destinations, or model output. Remote Redis and Valkey connections
must use `rediss://`; the limiter refuses cleartext `redis://` before opening a
socket. For local development only, a numeric loopback address can be enabled
explicitly with `--allow-insecure-redis-loopback` or
`REDACTWALL_RATE_LIMITER_ALLOW_INSECURE_REDIS_LOOPBACK=true`. That exception is
rejected when `NODE_ENV=production`.

The limiter service receives:

```json
{
  "key": "<sha256-client-token-hash>",
  "limit": 60,
  "windowMs": 60000,
  "now": 1783150000000
}
```

It should return an allow/deny decision such as:

```json
{
  "ok": true,
  "limit": 60,
  "remaining": 58,
  "resetMs": 42000
}
```

If the shared limiter is unavailable, the gateway fails closed with HTTP 503
before calling the RedactWall control plane or the upstream model provider.

Check limiter liveness and readiness:

```powershell
Invoke-RestMethod http://127.0.0.1:4183/healthz
Invoke-RestMethod http://127.0.0.1:4183/readyz
```

Point an app or agent at `http://127.0.0.1:4182/v1/chat/completions` and send:

```http
Authorization: Bearer replace-with-client-token
Content-Type: application/json
```

The gateway strips caller auth before the upstream request and injects
`REDACTWALL_GATEWAY_UPSTREAM_API_KEY` as the provider credential. Audit and
policy attribution uses a one-way fingerprint of the authenticated client
token. Caller-supplied `X-RedactWall-User` and `X-RedactWall-Org` headers are
ignored so a client cannot impersonate another user or tenant. Issue distinct
client tokens to applications that need distinct attribution.

Check liveness and readiness without exposing secrets:

```powershell
Invoke-RestMethod http://127.0.0.1:4182/healthz
Invoke-RestMethod http://127.0.0.1:4182/readyz
```

`/healthz` proves only that the gateway process is alive. `/readyz` first proves
the configured ingest key against the control plane's authenticated, read-only
`/api/v1/detectors` inventory, then checks the public control-plane readiness,
the configured upstream network path, and the external shared limiter when
enabled. Every response read is bounded, redirects are rejected, and the ingest
key is sent only to the configured HTTPS or loopback control-plane origin and is
never included in the gateway readiness response. `/readyz` returns `503` if any
required dependency is unavailable; the limiter probe uses its own read-only
readiness endpoint and does not consume a rate-limit check.

## Useful Options

| Option | Env | Default | Purpose |
| --- | --- | --- | --- |
| `--token` | `REDACTWALL_GATEWAY_TOKEN` | none | Required client token. Comma-separated env values are allowed. |
| `--host` | `REDACTWALL_GATEWAY_HOST` | `127.0.0.1` | Bind address. Use `0.0.0.0` only inside a private container or behind a trusted load balancer. |
| `--upstream` | `REDACTWALL_GATEWAY_UPSTREAM` | `https://api.openai.com` | Provider base URL. |
| `--upstream-key` | `REDACTWALL_GATEWAY_UPSTREAM_API_KEY` | none | Provider API key the gateway uses upstream. |
| `--upstream-auth-header` | `REDACTWALL_GATEWAY_UPSTREAM_AUTH_HEADER` | `authorization` | Header that carries the upstream provider key, for example `authorization`, `x-api-key`, or `x-goog-api-key`. |
| `--upstream-auth-scheme` | `REDACTWALL_GATEWAY_UPSTREAM_AUTH_SCHEME` | `Bearer` | Prefix before the upstream key. Use `none` for raw key headers such as `x-goog-api-key`, or `aws-sigv4` for direct Bedrock Runtime signing. |
| `--aws-region` | `REDACTWALL_GATEWAY_AWS_REGION`, `AWS_REGION`, or `AWS_DEFAULT_REGION` | none | AWS region for `aws-sigv4` upstream signing. |
| `--aws-service` | `REDACTWALL_GATEWAY_AWS_SERVICE` | `bedrock` | AWS service name for SigV4 signing. |
| `--upstream-header` | `REDACTWALL_GATEWAY_UPSTREAM_HEADERS` | none | Bounded static upstream header in `Name=Value` form. Repeat the flag or comma-separate env values for provider version headers. |
| `--approval-wait-ms` | `REDACTWALL_GATEWAY_APPROVAL_WAIT_MS` | `0` | How long to poll held prompts before returning 403. |
| `--rate-limit` | `REDACTWALL_GATEWAY_RATE_LIMIT` | `60` | Requests per client token per window. |
| `--rate-window-ms` | `REDACTWALL_GATEWAY_RATE_WINDOW_MS` | `60000` | Rate limit window. |
| `--rate-store` | `REDACTWALL_GATEWAY_RATE_LIMIT_STORE` | `memory` | Rate limiter store. Use `sqlite` to share counters across local gateway workers, or `http` to delegate to a shared limiter service. |
| `--rate-db-path` | `REDACTWALL_GATEWAY_RATE_LIMIT_DB` | `./data/gateway-rate-limits.db` | SQLite rate-limit database path when `--rate-store sqlite` is used. |
| `--rate-url` | `REDACTWALL_GATEWAY_RATE_LIMIT_URL` | none | HTTPS endpoint for the shared limiter service when `--rate-store http` is used. |
| `--rate-token` | `REDACTWALL_GATEWAY_RATE_LIMIT_TOKEN` | none | Bearer token sent to the shared limiter service. |
| `--rate-timeout-ms` | `REDACTWALL_GATEWAY_RATE_LIMIT_TIMEOUT_MS` | `2000` | Timeout for shared limiter checks. |
| `--allowed-models` | `REDACTWALL_GATEWAY_ALLOWED_MODELS` | all models | Comma-separated model names or wildcard patterns, such as `gpt-4o-mini,company-*`. |
| `--allow-multimodal` | none | off | Allows non-text provider payload blocks. Leave off unless another local collector inspects those bytes. |
| none | `REDACTWALL_GATEWAY_MAX_UPSTREAM_RESPONSE_BYTES` | `4194304` | Maximum upstream response bytes buffered for complete scanning. |
| none | `REDACTWALL_GATEWAY_MAX_CONTROL_PLANE_RESPONSE_BYTES` | `524288` | Maximum gate or response-scan JSON bytes. |
| `--allow-insecure-dev` | `REDACTWALL_GATEWAY_ALLOW_INSECURE_HTTP` | off | Development-only remote HTTP override. It is ignored in production; never use it with real bearer credentials. |

## Shared Limiter Options

Run with `npm run gateway:rate-limiter -- <options>`.

| Option | Env | Default | Purpose |
| --- | --- | --- | --- |
| `--token` | `REDACTWALL_RATE_LIMITER_TOKEN` or `REDACTWALL_GATEWAY_RATE_LIMIT_TOKEN` | none | Bearer token required from gateway replicas. |
| `--store` | `REDACTWALL_RATE_LIMITER_STORE` | `sqlite` | Shared limiter backend. Use `sqlite` for one limiter service or `redis`/`valkey` for active-active limiter replicas. |
| `--db` | `REDACTWALL_RATE_LIMITER_DB` | `./data/gateway-shared-rate-limiter.db` | SQLite database for hashed limiter counters. |
| `--redis-url` | `REDACTWALL_RATE_LIMITER_REDIS_URL` | none | Redis or Valkey URL for active-active limiter replicas, such as `rediss://:<password>@redis.internal:6380/0`. |
| `--redis-prefix` | `REDACTWALL_RATE_LIMITER_REDIS_PREFIX` | `redactwall:gateway:rl:` | Prefix prepended to hashed limiter keys. Unsafe characters are stripped. |
| `--redis-timeout-ms` | `REDACTWALL_RATE_LIMITER_REDIS_TIMEOUT_MS` | `2000` | Timeout for Redis limiter commands. |
| `--allow-insecure-redis-loopback` | `REDACTWALL_RATE_LIMITER_ALLOW_INSECURE_REDIS_LOOPBACK` | off | Development-only exception for `redis://` on a numeric loopback address. Rejected in production. |
| `--body-timeout-ms` | `REDACTWALL_RATE_LIMITER_BODY_TIMEOUT_MS` | `5000` | Absolute deadline for reading an inbound `/check` request body. |
| `--host` | none | `127.0.0.1` | Bind address. Keep private; terminate TLS in front when exposed beyond localhost. |
| `--port` | none | `4183` | Listener port. |
| `--default-limit` | none | `60` | Fallback request limit if a gateway does not provide one. |
| `--default-window-ms` | none | `60000` | Fallback limiter window. |
| `--max-limit` | none | `100000` | Maximum accepted per-window limit. |
| `--max-window-ms` | none | `86400000` | Maximum accepted limiter window. |

## Current Boundaries

- Supports JSON POST/PUT/PATCH traffic for paths ending in `chat/completions`,
  `responses`, or `messages`, plus Gemini-style
  `/models/{model}:generateContent` and `/models/{model}:streamGenerateContent`
  paths, plus non-streaming Bedrock Runtime-style
  `/model/{modelId}/converse` and `/model/{modelId}/invoke` paths. Bedrock
  `converse-stream` and `invoke-with-response-stream` are recognized but return
  `501` before any policy or upstream network call because AWS EventStream
  decoding and CRC validation are not implemented.
- Model allowlist blocks are logged as sanitized `action_blocked` evidence with
  a placeholder prompt like `[LLM model blocked] model-name`; the blocked user
  prompt is not sent to the control plane or upstream provider.
- JSON/SSE streaming requests are buffered for complete-output scanning. If
  response scanning is unavailable, the stream is not released to the caller.
- Non-text content blocks are blocked by default because the gateway cannot
  inspect image bytes, file references, or arbitrary tool payloads locally.
- Does not perform TLS interception. Put TLS in front of the gateway and point
  private apps or internal agents at the gateway URL directly.
- The default memory rate limiter is process-local. The SQLite store shares
  counters across gateway workers on the same host and stores hashed client
  limiter keys only. Use the HTTP limiter mode for multi-worker or multi-host
  horizontal scale; the shipped limiter service centralizes counters and still
  stores only hashed limiter keys.
- The shipped shared limiter defaults to SQLite for simple pilots. Multi-host
  limiter instances may use the built-in Redis/Valkey backend, but their HTTP
  contract must be terminated behind customer-managed HTTPS. Redis/Valkey also
  requires TLS in production; the cleartext loopback exception is only for
  explicitly enabled local development.
- Bedrock Converse text blocks are inspected and redacted. Bedrock image,
  document, video, tool-use, and tool-result blocks are blocked by default
  unless another local collector inspects those bytes first.
- Azure OpenAI-compatible paths that end in `chat/completions` are accepted.

## Validation

```powershell
node --test test/ai-llm-gateway.test.js
npm run gateway:ha:smoke
```

The focused test covers auth, memory and shared SQLite rate limiting,
fail-closed RedactWall outages, prompt redaction before upstream, response
scanning and redaction, approval release polling, bounded request bodies, blocked paths,
provider-native Gemini/Anthropic/Bedrock shapes, buffered JSON/SSE streaming,
explicit Bedrock EventStream rejection, AWS SigV4 header signing, and non-text
fail-closed behavior. The redundancy smoke starts
two local gateway replicas on one SQLite limiter file, removes the first, then
verifies both the survivor and a restarted replica see its counter.
