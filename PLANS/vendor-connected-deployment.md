# Vendor-Connected Deployment — Codebase Audit And Plan

Audited 2026-07-08 against the full codebase. Direction (vendor decision,
supersedes the prior zero-egress-only posture): deployments may have **full
egress to the vendor's AWS** — online license checks, seat-count reporting,
a vendor kill-switch, and vendor-side second-layer content scanning
(Nightfall-style) — while the air-gapped mode remains available as a
separate SKU. Every claim below carries verified references.

## What Already Works (config, not code)

1. **Vendor-hosted control plane.** All three sensors take a configurable
   server URL: endpoint agent `REDACTWALL_URL`
   (`sensors/endpoint-agent/agent.js:32`), browser extension MDM managed
   storage `serverUrl`/`ingestKey`
   (`sensors/browser-extension/background.js:19-48`), MCP guard
   `REDACTWALL_URL` (`sensors/mcp-guard/guard.js:17`). Point them at a
   plane in your AWS and the sensor fleet follows — no re-architecture.
   The AWS silo template (`infra/aws/customer-silo.yml`) already deploys
   the plane per customer.
2. **Vendor-side second-layer scanning: the seam exists and is live-path.**
   `server/semantic-remote.js` is an opt-in remote classifier — set
   `REDACTWALL_SEMANTIC_REMOTE_URL` (+`_KEY`, `_TIMEOUT_MS`) and every gate
   and file scan sends up to 20k chars of raw prompt text to that endpoint
   and max-combines the returned categories into the verdict
   (`server/app.js:1150,1626`; merge rules `semantic-remote.js:50-77`;
   tests `test/semantic-remote.test.js`). Run your Nightfall-style scanner
   behind that URL in your AWS and the second layer is a config change.
3. **Gateway hop.** The AI gateway forwards prompts upstream with a fully
   configurable base URL (`gateway/config.js:37-38`, adapters for
   OpenAI/Anthropic shapes) and is fail-closed to the control plane
   (`gateway/client.js:41-68`). A vendor scan hop can sit behind the
   control-plane gate call or around `adapter.callUpstream`
   (`gateway/server.js:218`) — note it deliberately redacts locally before
   upstream (`redactBodyLocally`), so a raw-content vendor hop belongs
   before redaction and must be an explicit choice.
4. **Seat enforcement (local).** `saasMode` + `REDACTWALL_SEAT_LIMIT`
   already deny *new* billable identities at the limit with `402
   seat_limit_blocked` on every ingest path (`server/tenant.js:106-191`,
   `server/app.js:426-474`), with SCIM deactivation releasing seats.
5. **License plumbing.** Ed25519 license files with plan/seats/features,
   an issuer CLI (`scripts/license-issue.js`), console install route that
   works even in readonly (`server/app.js:2052-2077`), `entitled()`
   feature gating, and a daily refresh timer (`server/app.js:3121`).

## What Does Not Exist Yet (the build list)

1. **No vendor-bound network channel at all.** License verification is
   offline by construction (`server/license.js:9` "no license server, no
   phone-home"); the only periodic timer re-reads the local file. The
   updater is admin-triggered git-pull, not telemetry. Seat counts never
   leave the box (served only on the authenticated
   `GET /api/billing/seats`). **Build: a vendor-link heartbeat** —
   `REDACTWALL_LICENSE_SERVER_URL`, authenticated with the license itself,
   POSTing `{customerId, licenseId, seatsUsed, version}` on the existing
   daily refresh cadence and receiving an Ed25519-signed verdict
   (`active | revoked | reissue`), reusing the embedded-public-key trust
   model so the vendor server cannot be spoofed.
2. **No `revoked` state / kill-switch.** `evaluate()` knows
   unlicensed/active/grace/readonly (`server/license.js:72-80`);
   `requireWritable` only gates config writes and the philosophy comment
   ("the license NEVER disables the security function",
   `license.js:11-14`) is enforced by tests
   (`test/license-api.test.js:54-82`). **Build: a `revoked` state** set by
   the heartbeat verdict, which (a) locks the console like readonly,
   (b) adds an ingest-time gate parallel to `enforceTenantForSensor`
   returning a distinct fail-closed `license_revoked` block — sensors
   already fail closed on non-ok responses
   (`sensors/browser-extension/background.js:431-432`,
   `sensors/endpoint-agent/agent.js:458,469`), so AI access stops with an
   honest status instead of a fake outage, and (c) makes the gateway
   license-aware (today it checks nothing — zero license/tenant hits in
   `gateway/`). Philosophy update: detection/blocking still never turns
   off — a revoked customer loses *use of AI through the product*, not
   data protection; nothing ever fails open.
3. **Second-layer hardening.** `semantic-remote.js` accepts plain
   `http://` and private IPs (its own regex at `:20-30` bypasses
   `outboundHttpsUrl`), and a vendor outage silently degrades to
   local-only detection. **Build:** route the URL through
   `outboundHttpsUrl` (HTTPS-only, metadata-endpoint blocking,
   `server/url-policy.js:48-61`) with an explicit dev override, and add a
   per-deployment fail mode (`degrade` today vs `hold` = queue for
   approval when the vendor scanner is unreachable).
4. **Sensor transport hardening.** The extension accepts `http:` server
   origins (`background.js:67-72`) and the agent has no TLS controls —
   fine for localhost, wrong for a remote vendor plane (ingest key in
   cleartext). **Build: reject non-HTTPS server URLs for non-localhost
   hosts** in all three sensors.
5. **No proxy support.** Nothing respects `HTTPS_PROXY` (global fetch/
   undici default). Optional: `EnvHttpProxyAgent` wiring for customers
   whose egress must transit a proxy.
6. **Seat-count semantics discrepancy.** `docs/CUSTOMER_LICENSING.md`
   says a seat is a "distinct user identity observed … in the trailing 30
   days," but `db.seatStats` counts **all-time** distinct users with no
   window (`server/db.js:326-350`). Fix one or the other before billing
   against it — recommend implementing the documented 30-day window.
7. **Positioning split.** Twenty-plus zero-egress/no-phone-home claims
   need rewording into a two-SKU story (inventory with file:line in the
   audit: `docs/SECURITY_WHITEPAPER.md:80-94` "no telemetry to the
   vendor" is the most load-bearing; also `docs/BATTLECARD_NIGHTFALL.md:24`,
   `docs/CUSTOMER_LICENSING.md:20-22`, `ROADMAP.md:28,79`,
   `docs/COMPETITIVE_*`, `docs/DETECTION_BENCHMARKS.md:9,13`,
   `PLANS/nightfall-competitive-improvement-plan.md`,
   `PLANS/ncua-readiness-center.md:283,413-416`). **Two SKUs:**
   *Air-gapped* (current behavior, offline license, no egress — keeps the
   examiner wedge) and *Connected* (vendor plane or phone-home silo:
   online license + seat telemetry + kill-switch + second-layer scan).
   The connected SKU's data flow goes into the customer contract: with
   member NPI transiting your AWS you become a GLBA service provider
   (due-diligence packet, SOC 2 posture, breach obligations) — priced in,
   not discovered later.

## Implementation Sequence

- **Phase A — connected licensing** (`server/vendor-link.js` + license
  `revoked` state + ingest gate + gateway check + heartbeat with seat
  counts + tests updating `test/license*.test.js` pins + 30-day seat
  window fix).
- **Phase B — second-layer hardening** (HTTPS enforcement + fail-mode
  config + sensor transport hardening + operator doc
  `docs/CONNECTED_DEPLOYMENT.md`).
- **Phase C — positioning split** (two-SKU rewrite across the claim
  inventory + CUSTOMER_LICENSING/SECURITY_WHITEPAPER updates + order-form
  language).

## Decisions For The Vendor

1. **Vendor-outage tolerance** for the heartbeat: recommended — keep
   last-known-good license state for 7 days of unreachability before
   degrading to `grace`, so your AWS outage never bricks a credit union
   mid-exam; alternative: strict (degrade in 24h).
2. **Kill-switch depth**: recommended — `revoked` = console readonly +
   fail-closed `license_revoked` ingest blocks + gateway refusal (AI use
   stops, data protection never silently off); alternative: readonly-only
   (soft kill).
3. **What reaches the vendor scanner**: raw prompt text (max fidelity,
   heavier compliance load) vs post-redaction text (second layer sees
   tokenized identifiers only). Per-customer config either way.
4. **Keep selling the air-gapped SKU?** Recommended yes — it is the
   competitive wedge and costs nothing to retain; connected is additive.
