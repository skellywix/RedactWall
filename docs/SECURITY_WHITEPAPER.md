# RedactWall Security Whitepaper

RedactWall is an inline DLP control for AI usage: it inspects prompts before
they leave a device or workload, blocks or holds sensitive content, and keeps
tamper-evident evidence — all without shipping prompt bodies to any vendor.
This paper describes the architecture, data flows, cryptography, and threat
model as implemented in this codebase, including its honest limits.

## 1. Architecture

One control plane, three sensors, and enforcement gateways.

**Control plane** (`server/`): a Node.js/Express service with a local
`better-sqlite3` database. It evaluates policy for every event, runs the
approval workflow, maintains the hash-chained audit log, serves the admin
dashboard, and exports evidence, SIEM, and trust packages. It deploys inside
the customer's environment (single node, Docker, or a customer-silo AWS
shape) — there is no RedactWall-hosted multi-tenant backend.

**Sensors** (`sensors/`), all running the same shared detection engine
(`detection-engine/detect.js`) locally:

- **Browser extension** — intercepts paste, drop, copy, and file-upload flows
  on governed AI destinations (ChatGPT, Claude, Gemini, Copilot, and others)
  inside managed browsers.
- **Endpoint agent** — watches AI-bound activity on the workstation beyond the
  browser.
- **MCP guard** — gates Model Context Protocol tool traffic between agents and
  connectors (Microsoft 365, Google Drive, Slack, Teams, Atlassian, databases).

**Gateways** for server-side and unmanaged paths:

- **AI Gateway** (`gateway/`) — an OpenAI-compatible reverse proxy that gates
  every prompt and scans every response through the control plane before
  anything reaches the upstream model. Streaming responses are buffered and
  scanned before release. It fails closed: if the control plane is
  unreachable, the request is blocked.
- **AI LLM Gateway** (`scripts/ai-llm-gateway.js`) — a provider-aware
  enforcement gateway for private apps and internal agents with
  provider-native OpenAI, Anthropic, Gemini, and Bedrock Runtime routes. It
  keeps upstream provider credentials on the gateway side and requires a
  client token before any app can send traffic.
- **Squid ICAP bridge** (`scripts/squid-icap-bridge.js`) — a reference REQMOD
  integration so an explicit proxy can enforce RedactWall verdicts for
  browsers that cannot run the managed extension.

## 2. Data Flow

```
                        employee / agent / app
                                 |
        +------------------------+-------------------------+
        |                        |                         |
  browser extension        endpoint agent              MCP guard
  (paste/drop/copy)        (workstation AI use)        (MCP tool calls)
        |                        |                         |
        |   local detection engine runs ON the sensor      |
        +------------------------+-------------------------+
                                 |
                 sanitized event: detector ids, masked
                 findings, categories, hashes -- no raw text
                 (raw prompt only for HELD approvals, sealed
                  AES-256-GCM in transit to the control plane)
                                 |
                                 v
                       RedactWall control plane
              policy verdict | approval queue | audit chain
                                 |
              +------------------+------------------+
              |                                     |
      signed Ed25519 policy bundles          prompt-free exports:
      back down to sensors (fail closed)     SIEM events, evidence
                                             packs, trust package
                                             receipts (HMAC-signed)

   server-side path:  app --> AI Gateway / AI LLM Gateway --> control-plane
   verdict --> upstream model (response scanned before returning)
```

### What leaves the device, and what never does

The prompt-free contract, enforced in code and regression-tested:

| Never leaves the device / deployment | Allowed to flow |
|--------------------------------------|-----------------|
| Raw prompt bodies (except sealed held-approval retention inside the deployment) | Detector ids and categories |
| Redacted prompt bodies (in exports and alerts) | Masked findings and entity counts |
| Raw detector finding values | SHA-256 prompt hashes |
| Token vault values | Policy decisions and timestamps |
| Secrets, credentials, key material | Signed prompt-free receipts |
| Local file paths and raw URLs (in exports) | Sanitized SIEM/SOAR events |

No telemetry is sent to RedactWall the vendor. SIEM delivery history is
recorded without payload bodies.

## 3. Cryptographic Inventory

| Mechanism | Implementation | Purpose |
|-----------|----------------|---------|
| AES-256-GCM at rest | `server/crypto.js` | Seals the one piece of cleartext sometimes retained: the raw prompt of an item held for admin approval. No stable key configured means raw retention is refused — cleartext is never written by accident. |
| HMAC-signed receipts | `server/receipts.js` | Safe-to-send receipts: signed, prompt-free proof that specific outbound text was scanned and cleared under a specific policy at a specific time. Carries hashes and bounded metadata only. |
| Ed25519 policy bundles | `server/policy-bundle.js` | Sensor policy is wrapped with version, issue time, and expiry, and signed. Sensors verify with the public key and fail closed when a bundle is unverifiable, tampered, or stale. |
| SHA-256 hash-chained audit | `server/audit-integrity.js` | Every audit entry chains over a canonical (key-sorted) serialization of the previous entry; any edit to stored history breaks verification. |
| Salted SHA-256 token hashes | `gateway/tokens.js`, release tokens | Gateway agent tokens and release tokens are stored only as salted hashes; raw tokens exist only at mint time. |
| HMAC-signed sessions + CSRF | `server/auth.js` | Admin sessions are HMAC-signed; unsafe admin writes require a CSRF token; production preflight enforces secret strength and TOTP MFA. |

Key material sources: `REDACTWALL_SECRET` (sessions, derived keys) and
`REDACTWALL_DATA_KEY` (data sealing), both required to be stable and at least 32
characters by production preflight.

## 4. Threat Model

What RedactWall defends against, and where the honest limits are.

**Covered:**

- Employee pastes or uploads regulated data into a governed AI chat app —
  blocked or held at the sensor before submission.
- Unknown AI destination — default-deny (`blockUnapprovedAiDestinations`)
  blocks unreviewed AI apps until governed.
- Internal app or agent sends sensitive data to a model API — gateway gates
  the prompt and scans the response; provider credentials never sit in the app.
- Network attacker feeds a sensor forged policy — bundles are Ed25519-signed
  and expire; sensors fail closed on any verification failure.
- Insider edits stored evidence — the hash chain breaks and
  `verifyAuditChain()` reports it.
- Control plane outage as a bypass — gateways and bundle-verifying sensors
  fail closed, not open.

**Known limits (bypass paths) and the compensating story:**

- **Unmanaged browsers and devices.** The extension only covers managed
  browsers. The compensating control is network-path enforcement: route
  egress through the Squid ICAP bridge or allow AI traffic only via the
  gateways. Fully unmanaged personal devices on outside networks are out of
  scope.
- **Screenshots, photos, retyping.** Content re-entered by a human outside
  monitored input paths is not inspected. This is a policy and training
  problem, not a technical one; RedactWall does not claim to solve it.
- **Local administrators.** A user with admin rights on their machine can
  disable the endpoint agent or extension. Coverage dashboards and required
  sensor baselines exist to make that visible quickly, not impossible.
- **Detection is probabilistic at the margins.** Regex, validator, and
  semantic detectors have false-negative rates tracked by the detection eval
  in CI; `alwaysBlock` categories and exact-match packs harden the cases that
  must never leak.
- **TLS interception is not performed.** RedactWall inspects at the input
  surface, MCP layer, and gateway — it does not man-in-the-middle arbitrary
  traffic.

## 5. Deployment Models

- **Single node, local-first**: control plane and database on one host;
  the default for pilots and demos.
- **Docker / Compose**: containerized control plane (`Dockerfile`,
  `docker-compose.yml`).
- **HA gateway**: `docker-compose.gateway-ha.yml` runs multiple gateway
  instances with a shared rate limiter in front of one control plane.
- **Customer-silo AWS**: per-customer isolated deployment described in
  `docs/AWS_SAAS_DEPLOYMENT.md`; no shared multi-tenant data plane.

In every model the customer operates the environment and owns the data.

## 6. Sub-Processor Stance

RedactWall introduces no sub-processors by default. The product makes no
vendor-bound calls: no telemetry, no cloud detection service, no external
model calls of its own. Self-hosted deployments add only the vendors the
operator chooses (hosting provider, SIEM destination), and outbound SIEM
delivery is HTTPS-only and prompt-free by construction.

## 7. Verifying These Claims

Every claim above is testable from the repository:

```
npm run review:ci          # full gate: tests, detector sync, detection eval
npm run security:package   # this posture as a machine-readable trust package
npm run evidence:pack      # examiner evidence from a live deployment
node -e "console.log(require('./server/db').verifyAuditChain())"
```

Related reading: `docs/SECURITY_TRUST_PACKAGE.md`,
`docs/INCIDENT_RESPONSE.md`, `docs/AI_LLM_GATEWAY.md`, `docs/DEPLOYMENT.md`.
