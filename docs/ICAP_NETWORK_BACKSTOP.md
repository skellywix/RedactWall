# ICAP Network Backstop (Squid REQMOD Bridge)

`scripts/squid-icap-bridge.js` is a first-class, runnable ICAP/1.0 REQMOD
service (RFC 3507 subset). Paired with a Squid proxy, it is the network-layer
backstop for traffic the endpoint sensors cannot see: unmanaged browsers,
curl/scripts calling AI APIs directly, and third-party desktop apps.

Unlike the monitor-only proxy lab (`docs/AI_CHAT_DLP_PROXY_LAB.md`), this
bridge enforces: it can allow, block, or hold every intercepted request before
it leaves the network.

## Surface Map

- ICAP service + CLI entry: `scripts/squid-icap-bridge.js`
  (`npm run icap:bridge`).
- Squid configuration example: `infra/icap/squid.conf.example`.
- Hardened container deployment: `infra/icap/docker-compose.icap.yml`.
- Control-plane gate: `POST /api/v1/gate` and `GET /api/v1/status/:id` in
  `server/app.js` - the same endpoints every other sensor uses.
- Tests: `test/squid-icap-bridge.test.js` (drives the server over a real
  socket).

## How It Works

1. Squid receives a client request and forwards it to the bridge as an ICAP
   REQMOD message (`icap://127.0.0.1:1344/reqmod`).
2. The bridge parses the encapsulated HTTP request, decodes the chunked body
   (bounded, default 2 MB), and extracts the prompt from known AI JSON shapes
   (`messages[]`, `prompt`, `input`) with a raw-body fallback.
3. It calls `POST /api/v1/gate` with the prompt, user, destination host, and
   source IP (`source: "proxy"`, `channel: "submit"`), so detection, policy,
   approval routing, and the hash-chained audit trail are identical to the
   browser-extension and endpoint-agent paths. One policy, one evidence store.
4. Enforcement:
   - `allow` - ICAP `204 No Content` (request forwarded unmodified) when Squid
     offered `Allow: 204`, otherwise the request is echoed back.
   - `block` - the HTTP request is replaced with a synthesized
     `403 Forbidden` JSON refusal: `{"blocked":true,"decision":...,"queryId":...}`.
     The refusal never contains prompt text.
   - `pending` (hold) - the bridge polls `GET /api/v1/status/:id` until a
     Security Admin approves or denies (deny by default on timeout,
     `ICAP_BRIDGE_RELEASE_WAIT_MS`, default 5 minutes).

## Fail-Closed Semantics

Every failure path results in a block, never a silent forward:

- Control plane unreachable, timing out, returning non-2xx, or returning
  invalid JSON - synthesized 403.
- Body larger than `ICAP_BRIDGE_MAX_BODY_BYTES` (default 2 MB) - synthesized
  403 without contacting the control plane.
- Malformed ICAP framing, header overflow, or malformed embedded HTTP - ICAP
  `400` / 403 refusal and the connection is closed.
- On the Squid side, `bypass=off` plus `icap_service_failure_limit -1` means
  Squid errors out client requests when the bridge itself is down, instead of
  bypassing adaptation.

## Privacy

Bridge logs are metadata-only JSON lines: decision, verdict, destination host,
reason code, body byte count, and latency. Raw prompt text, request bodies,
PII, and secrets are never logged and never appear in block responses. Prompt
text goes to exactly one place: the local RedactWall control plane's `/api/v1/gate`,
same as every other sensor.

## Running

Host process (control plane already running on `REDACTWALL_URL`):

```bash
INGEST_API_KEY=dev-ingest-key npm run icap:bridge
# RedactWall Squid ICAP bridge (REQMOD) listening on icap://127.0.0.1:1344/reqmod
```

CLI flags: `--port`, `--host`, `--redactwall`, `--key`, `--max-body-bytes`.

Environment:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ICAP_BRIDGE_PORT` | `1344` | ICAP listen port |
| `ICAP_BRIDGE_HOST` | `127.0.0.1` | ICAP listen address |
| `REDACTWALL_URL` | `http://localhost:4000` | RedactWall control plane |
| `INGEST_API_KEY` | `dev-ingest-key` | Gate API key |
| `ICAP_BRIDGE_MAX_BODY_BYTES` | `2097152` | Max decoded request body |
| `ICAP_BRIDGE_MAX_HEADER_BYTES` | `16384` | Max ICAP/HTTP header block |
| `ICAP_BRIDGE_SOCKET_TIMEOUT_MS` | `30000` | Idle socket teardown |
| `ICAP_BRIDGE_RELEASE_WAIT_MS` | `300000` | Max hold-for-approval wait |
| `REDACTWALL_REQUEST_TIMEOUT_MS` | `10000` | Per control-plane call timeout |

Squid deployment:

1. `cp infra/icap/squid.conf.example /etc/squid/squid.conf` (or the compose
   copy step below) and review the access ACLs.
2. Keep `bypass=off` and `icap_service_failure_limit -1` - they are the
   fail-closed guarantees.
3. Point managed egress (firewall/PAC/WPAD) at the Squid port.

Containerized (hardened: read-only rootfs, `cap_drop: ALL`,
`no-new-privileges`):

```bash
cp infra/icap/squid.conf.example infra/icap/squid.conf
# edit squid.conf: icap_service ... icap://icap-bridge:1344/reqmod bypass=off
docker compose -f infra/icap/docker-compose.icap.yml up --build
```

## Testing

```bash
node --test test/squid-icap-bridge.test.js
```

The suite covers the OPTIONS handshake, benign-prompt allow (204 and echo),
seeded-SSN block with a prompt-free refusal, hold-then-release, control-plane
outage (fail closed), oversized bodies, malformed ICAP input, and asserts that
raw prompt text never appears in bridge logs or ICAP responses.

## Honest Limitations

- **TLS interception is required for HTTPS AI endpoints.** REQMOD only sees
  what Squid can decrypt. You must run ssl-bump with an enterprise CA that
  managed devices trust; certificate-pinned apps cannot be intercepted and
  should be blocked at the firewall instead. This is deployment-specific and
  intentionally not preconfigured (see comments in `squid.conf.example`).
- **No RESPMOD yet.** The bridge gates outbound prompts only; AI responses are
  not scanned on the way back.
- **No ICAP Preview negotiation.** The OPTIONS response does not advertise
  `Preview`, so Squid sends complete messages (`icap_preview_enable off`).
  A REQMOD carrying an unnegotiated partial preview is rejected (fail closed).
- **Prompt extraction is JSON-shape based.** Unknown body formats fall back to
  scanning the raw body text; multipart uploads and binary bodies are not
  parsed field-by-field.
- **Bounded inspection.** Bodies over the configured limit are blocked, not
  partially scanned.
- **Held requests hold the connection.** An inline hold keeps the client
  request open while waiting for approval; size `icap_io_timeout` above
  `ICAP_BRIDGE_RELEASE_WAIT_MS`.
