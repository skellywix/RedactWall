# RedactWall License Heartbeat Server (connected mode)

> **Legacy v1 reference only:** this directory still implements the removed
> shared-token `/heartbeat` contract. It is not the connected-first production
> license service and must not be deployed for a new customer. The supported
> licensing service exposes only `POST /v1/heartbeat`; the separate
> `POST /v1/acknowledgements` channel is routed to Owner. They use distinct
> credentials. The heartbeat returns the signed registry verdict plus signed
> entitlement projection and the service never receives the offline private
> root. See `docs/reference/VENDOR_CONTROL_PROTOCOL.md`. Keep this service
> disabled until the committed replacement lands and the old route is deleted.

This is the vendor-side reference service for
`docs/process/CONNECTED_DEPLOYMENT.md`. A customer control plane sends a
prompt-free, authenticated heartbeat. The service returns an Ed25519-signed
`active` or `revoked` verdict.

The online verdict key is a separate identity from the offline license root.
The service refuses the legacy `LICENSE_SIGNING_KEY_PATH` setting and refuses
to start if the configured verdict key has the same public key as the offline
root. The offline private key must never be copied to this host.

## Required files

| File | Purpose |
|------|---------|
| `server.js` | Loopback HTTP service. Put Caddy in front for public HTTPS. |
| `Caddyfile` | HTTPS front end. |
| `redactwall-license.service` | Hardened systemd unit for the `rwlicense` account. |
| `docker-compose.connected.override.yml` | Customer-side connected-mode settings. |

Provision these access-controlled files on the service host:

| Default path | Contents |
|--------------|----------|
| `/etc/redactwall-license/verdict-signing-key.pem` | Dedicated online Ed25519 private key. |
| `/etc/redactwall-license/license-signing-pub.pem` | Offline license-root public key, used only to reject accidental key reuse. |
| `/etc/redactwall-license/customers.json` | Customer allowlist and SHA-256 bearer-token digests. |
| `/etc/redactwall-license/revoked.json` | JSON array of revoked customer IDs. |

Generate the online key independently from the offline license-root machine:

```bash
openssl genpkey -algorithm ED25519 -out verdict-signing-key.pem
openssl pkey -in verdict-signing-key.pem -pubout -out verdict-signing-pub.pem
TOKEN=$(openssl rand -hex 32)
TOKEN_SHA256=$(printf '%s' "$TOKEN" | sha256sum | cut -d ' ' -f 1)
```

After copying the authority files into `/etc/redactwall-license`, make them
readable by the dedicated service account but never writable by it or any
unrelated account:

```bash
sudo chown -R root:rwlicense /etc/redactwall-license
sudo chmod 0750 /etc/redactwall-license
sudo chmod 0640 /etc/redactwall-license/*.pem /etc/redactwall-license/*.json
```

Create a unique random token for each customer and store only its SHA-256
digest in `customers.json`. The service rejects a registry that reuses one
token digest across customer identities:

```json
{
  "cu-acme": {
    "tokenSha256": "64-lowercase-hex-characters",
    "plans": ["standard"]
  },
  "cu-example": {
    "tokenSha256": "another-64-lowercase-hex-digest",
    "plans": ["standard", "enterprise"]
  }
}
```

Deliver the raw token and `verdict-signing-pub.pem` to that customer through a
separate authenticated channel. Configure their control plane with:

```dotenv
REDACTWALL_LICENSE_SERVER_URL=https://license.vendor.example/heartbeat
REDACTWALL_LICENSE_SERVER_TOKEN=<customer-specific-random-token>
REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

The token must be 32 to 256 characters from the bearer-safe character set.
Customer IDs, plans, counts, versions, timestamps, content type, and the exact
heartbeat JSON shape are validated before signing. A token is accepted only
for its allowlisted customer and plan.

## Failure and abuse controls

- Missing, malformed, oversized, symlinked, changing, or writable authority
  files make `/healthz` unready and prevent verdict signing.
- Request bodies are capped at 16 KiB and have an absolute read deadline.
- Requests are limited per client address and per authenticated customer.
- The supplied public Caddy route forwards only `/heartbeat`; `/healthz` stays
  on the loopback service for local monitoring and cannot be hammered remotely.
- Heartbeat logs use a one-way customer reference, never include bearer
  credentials, and stop growing at the configured byte cap.
- `revoked.json` is read for every heartbeat, so an atomic replacement takes
  effect without a restart. Use `[]` when no customer is revoked.

The optional bound settings are `LICENSE_BODY_TIMEOUT_MS`,
`LICENSE_RATE_LIMIT_PER_MINUTE`, and `LICENSE_HEARTBEAT_LOG_MAX_BYTES`.
`LICENSE_TRUST_PROXY=1` trusts a syntactically valid `X-Forwarded-For` value
only when the direct peer is loopback, which matches the supplied Caddy setup.

Once a customer enables `REDACTWALL_LICENSE_SERVER_URL`, failure to receive a
fresh valid verdict within `REDACTWALL_LICENSE_MAX_STALENESS_DAYS` causes the
customer control plane to fail closed.
