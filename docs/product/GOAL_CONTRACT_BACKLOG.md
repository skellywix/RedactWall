# RedactWall Goal Contract Backlog

This backlog turns the connected-first vendor-control objective into
RedactWall-specific epics. It is not permission to call a collection of protocol
sketches production-ready. Run one complete vertical slice per goal contract
and preserve the trust boundaries below.

## Security notice

The password included in the shared conversation is compromised because it was disclosed in chat and in a public share. Do not reuse it, quote it in an issue, or place it in source, tests, configuration, commands, CI, screenshots, logs, or documentation. Rotate it anywhere it was used. Supply any future bootstrap secret through an approved secret manager or one-time secure channel.

## Current architecture reality

The original draft assumed capabilities that this repository does not yet have:

- `server/`, `console/`, and the three sensors form a customer data plane. The AWS path in `infra/aws/customer-silo.yml` deploys an isolated customer silo, not a shared vendor control plane.
- The current `security_admin` role is a customer-tenant administrator. It is not a vendor superadmin and must never gain cross-customer access.
- `server/vendor-control-client.js`, `server/vendor-control-connector.js`, and
  `server/connected-license-runtime.js` provide customer-side connected
  licensing. The removed `server/vendor-link.js` v1 client is not a supported
  compatibility path.
- Billing is currently enforced through signed offline or connected licenses in `server/license.js` and `server/tenant.js`. The repository has no Stripe SDK or Stripe-backed subscription model.
- Shadow AI inventory already exists in `server/app-catalog.js`, `server/ai-app-catalog.js`, `scripts/import-ai-discovery.js`, `console/src/views/Catalog.tsx`, and the destination-policy APIs in `server/app.js`.
- The client overview already contains a data-flow visualization in `console/src/components/overview/LeakMap.tsx`. It is not a geographic user map.
- The React console already has a persisted sun/light and moon/dark segmented control in `console/src/components/ThemeToggle.tsx`, plus visual regression coverage in `e2e/console-design.spec.js`.
- Local administrator authentication already has roles, TOTP, recovery codes, session controls, step-up, CSRF, invitation flows, and audit events. The vendor portal still needs a separate identity boundary and per-identity MFA lifecycle.

These facts change the work from seven greenfield features into a new vendor-control-plane foundation plus targeted extensions to existing customer-silo features.

## Initiative contract

### Objective

Create a separately authenticated vendor control plane that is the mandatory
primary management and licensing authority for every production customer while
preserving RedactWall's independent customer data planes. Signed offline
licenses remain only as bounded outage fallback after connected enrollment.

### Non-negotiable boundary

- Never turn `server/app.js` or the customer React console into a cross-customer database browser.
- Never centralize raw prompts, responses, held items, uploaded files, direct identities, full URLs, credentials, or customer audit databases.
- Customer enforcement remains local. A vendor outage must not disable detection, mandatory `alwaysBlock` handling, local policy, or local audit evidence.
- Cross-boundary identifiers must be tenant-scoped, keyed, rotatable, and non-linkable across tenants.
- Customer-to-vendor transport must be authenticated, encrypted, schema-versioned, replay-resistant, bounded, and fail closed before sensitive bytes leave the customer boundary.
- Vendor-to-customer policy or catalog artifacts must be signed, versioned, rollback-safe, and unable to remove mandatory hard stops.
- Online-registry generation, entitlement version, policy version, and catalog
  version are independent monotonic domains. A lower generation is rejected,
  and an online `active` verdict cannot clear an explicit entitlement pause or
  revocation.
- A production silo must remain unready until its first signed connected
  entitlement and signed online-registry generation are durably applied and
  acknowledged. Generation `0` is not proof of enrollment.
- Offline fallback cannot be manually selected, expand plan, seats, or
  features, or override any newer connected restriction.
- Every vendor privileged action must be server-authorized, recently reauthenticated when sensitive, and audit recorded without secrets or customer content.
- Do not deploy, create cloud resources, change credentials, or mutate Stripe without explicit authorization.

### Foundation gate

Do not begin Epics 1, 2, 5, 6, or 7 as UI-only work. First approve and prove a foundation slice with:

1. An architecture decision that separates the vendor control plane from every customer silo.
2. A data-flow and threat model covering tenant isolation, telemetry egress, provisioning authority, Stripe, signed entitlements, catalog distribution, incident response, deletion, and vendor compromise.
3. Versioned API schemas with strict field allowlists and size limits.
4. A vendor identity and authorization model distinct from customer `security_admin`.
5. A non-production test topology that can prove two customer silos cannot read, write, correlate, or authorize each other.
6. A migration and rollback plan that leaves existing customer deployments operational.

The foundation is complete only when a fresh security review has no unresolved critical or high finding and the two-tenant negative tests pass.

### Current incomplete gates

The following are stop conditions, not deferred polish:

1. The Owner worktree is not an integration dependency until it is committed,
   its exact merge base and authority map are known, and its focused and full
   validation are green.
2. Customer state now atomically applies the signed online-registry verdict and
   optional signed entitlement, persists their independent high-waters, creates
   ordered delivery/application acknowledgements, and enforces the most
   restrictive result across startup, readiness, seats, and protected egress.
   Release still requires exact integration against the committed Owner
   projection and acknowledgement service.
3. Vendor diagnostics, Shadow AI, policy, entitlement lifecycle, and governed
   support modules must move out of the customer image into the Owner service
   or a shared protocol-only package. A fresh review found that the provisional
   entitlement ledger still uses a vendor-driven delivery transition instead
   of the frozen customer delivered-then-applied ACK sequence, and the
   provisional diagnostics runtime duplicates the reserved Owner diagnostic
   integrity authority. Neither module is an integration source until those
   findings are repaired and re-reviewed.
4. Reference SQLite and same-host witness adapters are not production vendor
   storage. They must reject the actual production process environment even if
   a caller supplies a spoofed environment, preopened store, or assurance
   label. Managed Postgres and independently retained exact-CAS witness
   providers remain required.
5. Owner sessions expose a current principal, role, permissions, and session ID,
   but no purpose-bound recent step-up timestamp, authentication event, or
   immutable session-linked audit reference yet. Sensitive billing, licensing,
   export, policy, catalog, and audit-request operations must fail closed until
   that authority exists.
6. The Owner portal still needs integrated Billing & Licensing, diagnostics,
   Shadow AI, policy, and governed support surfaces backed by the real durable
   services, not UI-only status.
7. The customer image now builds from an explicit positive inventory and its
   provisional scanner rejects vendor authorities, credential files, and
   private PEM, DER, OpenSSH, JWK/JWKS, and OpenPGP material across application,
   dependency, system, home, and runtime-volume roots. The gate remains open
   until the final neutral-verifier changes are rebuilt and the fresh reviewer
   reruns its exact bypass probes against the final image.
8. AWS sandbox provisioning, Stripe test-mode lifecycle, real browser portal
   proof, and two independent silo certification require explicit authorized
   external evidence before the parent goal can complete.
9. Owner and customer source now agree on the strict v2
   `rw-online-verdict-<64 lowercase hex SPKI SHA-256>` key-ID grammar. This
   contract still needs committed integration proof. No compatibility shim may
   accept an alias or trial-verify an unidentified key. Entitlement key IDs
   have the parallel exact `rw-entitlement-<64 lowercase hex SPKI SHA-256>`
   rule; provisional vendor manifests that accepted prefix-only aliases are
   under repair.
10. The strict Owner heartbeat response is implemented customer-side: the
    connector parses and independently verifies the mandatory signed registry
    verdict and nullable signed entitlement, then reverifies and commits them
   with audit evidence in one transaction. The legacy v1 vendor client is
   removed. The remaining gate is committed Owner integration and transport
   proof against the exact frozen routes, bytes, keys, replay, and ACK rules.
   Projection publication must remain `issued`; only the customer's delivered
   ACK may advance delivery, and applied acceptance must durably finish
   acknowledgement before returning `204`.

### Execution order

Use this dependency order for the control-plane track:

1. Foundation, authority manifest, threat model, tenant registry, and two-silo topology.
2. Vendor identity, MFA, roles, purpose-bound step-up, and vendor audit.
3. Connected enrollment, signed online-registry verdict, provisioning acknowledgement, and readiness.
4. Signed entitlement lifecycle, heartbeat, ACK, pause, revoke, restore, and bounded outage fallback.
5. Stripe ledger, reconciliation, manual overrides, and Billing & Licensing portal.
6. Strict diagnostics with consent, retention, deletion, search, and export governance.
7. Shadow AI candidates, analyst workflow, signed catalog, tenant overrides, rollout, and rollback.
8. Signed policy desired state and governed customer audit/support broker.
9. Full portal UX, production storage, packaging, disaster recovery, key rotation, external smokes, and release proof.

Epics 4 and 3 are customer-console polish and can run independently after baseline screenshots and current behavior are captured.

### External prerequisites

| Epic | Required before claiming the epic complete |
|---|---|
| Foundation and 7 | Approved vendor hosting boundary and secret manager; Duo tenant only if Duo is selected |
| 5 | Authorized non-production AWS account, least-privilege role, region, artifact bucket, and disposable tenant/domain |
| 6 | Stripe test account, test API credentials, webhook signing secret, product/price fixtures, and approved billing rules |
| 1 | Customer-approved telemetry schema, retention rules, opt-in posture, and non-production packet/storage inspection |
| 2 | Approved public-intelligence sources and explicit customer authorization for every environmental telemetry source |

Mocked unit tests can complete a slice, but they cannot satisfy an epic predicate that explicitly requires a real Stripe test event, AWS sandbox deployment, Duo flow, or customer-authorized telemetry path.

## Epic 1: Privacy-preserving diagnostic intelligence

### Existing anchors

- Local enforcement and ingest: `server/app.js`, `server/db.js`, `server/alerts.js`
- Existing customer-side views: `console/src/views/Activity.tsx`, `Insights.tsx`, `Lineage.tsx`, `Monitor.tsx`, and `Audit.tsx`
- Privacy regressions: `test/signal-monitor-privacy.test.js`, `test/alerts.test.js`, `test/ingest-auth.test.js`

### Corrected end state

Add a vendor Log Intelligence surface that receives only an explicit allowlist of locally sanitized diagnostic metadata. Do not forward "all prompts," tokenized prompt bodies, stable prompt hashes, file names, free-form exception text, or fragments that can reconstruct customer content. The customer silo remains the authoritative detailed audit source.

The approved schema may include tenant-scoped pseudonymous component and device references, random correlation IDs, coarse timestamps, component and policy versions, approved catalog IDs or categories, outcome, detector type counts, coarse size buckets, bounded stage timings, retry state, and locally generated error fingerprints from a safe taxonomy. Do not send arbitrary hostnames or subdomains. If a destination label is essential, allow only a validated eTLD+1 from an explicit approved list and test malicious or sensitive subdomain inputs.

### First executable slice

Define and test the versioned diagnostic envelope and customer-side sanitizer before adding transport, storage, analytics, or UI. The slice is complete only when:

- Unknown fields, oversized values, free text, direct identifiers, secrets, full URLs, and raw stack traces are rejected before serialization.
- Tenant-scoped pseudonyms differ across two tenants and rotate without accepting the previous key beyond the documented overlap.
- Sanitizer failure produces a local sanitized warning and no outbound event.
- Synthetic canaries do not appear in the serialized body, process logs, local audit detail, or error output.
- Focused tests pass and a fresh security reviewer supplies one additional adverse payload.

### Epic acceptance predicates

- Authenticated, schema-versioned, idempotent ingestion handles duplicates, replay, retry, offline buffering, ordering, clock skew, and stale clients.
- Packet capture plus queue, database, log, export, and error-monitor inspection prove forbidden canaries never cross or persist.
- Customer administrators can preview the exact schema, control retention and authorized analytics, revoke collection, and request deletion.
- Support diagnostics are not used for model training or unrelated product analytics without a separate, explicit customer opt-in.
- Superadmin search, view, and export actions are least-privilege and audited in the vendor plane.
- Incident-support mode is customer-approved, time-bounded, previewable, revocable, and no less strict than the base schema.
- Performance evidence shows no material regression on the hot prompt path.
- A vendor outage or rejected event cannot weaken local enforcement or readiness.

### Minimum evidence

Run focused unit and boundary tests, a real non-production transport capture with synthetic PII and secret canaries, two-tenant isolation tests, retention/deletion tests, failure injection, and performance comparison. For a PR-sized slice also run `npm run review:ci`, `npm run suite:smoke`, and asserted audit verification from the goal-contract skill.

## Epic 2: Shadow AI intelligence and policy enforcement

### Existing anchors

- Seed and customer catalog: `server/ai-app-catalog.js`, `server/app-catalog.js`
- Import path: `scripts/import-ai-discovery.js`
- APIs and policy review: `/api/catalog`, `/api/destinations/review`, and `/api/policy` in `server/app.js`
- Customer UI: `console/src/views/Catalog.tsx`
- Current coverage: `test/ai-app-catalog-module.test.js`, `test/app-catalog.test.js`, `test/catalog-api.test.js`, `test/ai-discovery-import.test.js`, `test/browser-destination-coverage.test.js`, and `test/extension.test.js`

### Corrected end state

Extend the current customer catalog with a vendor-managed, evidence-backed global AI application feed. Keep tenant observations and overrides local. A newly inferred application may enter review or preview, but it must not become a globally enforced block without human approval.

Approved AI destinations still pass through normal RedactWall inspection and mandatory hard stops. Destination allowlisting never bypasses data policy. Unapproved or uncategorized AI can be blocked according to the existing tenant policy, with a safe default page and bounded tenant branding.

### First executable slice

Define a canonical catalog record, signing format, trust pin, monotonic version rule, and last-known-good rollback behavior. Extend the customer silo to accept a signed fixture feed in preview mode only. The slice is complete only when invalid signatures, stale versions, unknown fields, wildcard hazards, alias conflicts, and oversized feeds fail closed without changing the active catalog.

### Epic acceptance predicates

- Public intelligence and customer telemetry record source, timestamp, evidence class, confidence, reason codes, analyst state, and provenance without raw customer content.
- Environment discovery runs only for explicitly authorized sources and scopes.
- Analysts can approve, reject, merge, split, classify, version, publish, and roll back entries.
- Tenant overrides cannot mutate the global catalog or another tenant.
- Policy precedence is specified and regression-tested against the existing destination controls and all mandatory `alwaysBlock` types.
- Signed feeds are consumable by supported sensors or the customer control plane without weakening disconnected fallback behavior.
- Intelligence fetches use approved exact origins, reject redirects and private-network targets, bound response time and bytes, and never carry customer credentials to an unapproved host.
- Candidate rules or models are versioned, explainable, drift-monitored, previewed, and rollback-safe; customer content is never training data.
- False-positive reporting and emergency rollback are fast, audited, and test-proven.
- Default and customized block pages do not render unsafe HTML, leak the attempted URL, or create an exception bypass.

### Minimum evidence

Run the catalog/import/API tests above, destination-policy and browser-extension tests, signature/staleness/rollback negatives, two-tenant override tests, and a real browser proof that an unapproved destination is blocked while an approved destination still redacts synthetic PII.

## Epic 3: Client overview leak-map polish

### Existing anchors

- Visualization: `console/src/components/overview/LeakMap.tsx` and `LeakMap.css`
- Data and page composition: `console/src/views/Overview.tsx` and the posture APIs
- Browser proof: `e2e/console-design.spec.js` and `e2e/console-parity.spec.js`

### Corrected end state

Improve the existing data-flow leak map into a visually distinctive, polished, and tasteful operator surface. Do not replace it with a geographic map or invent location precision. Preserve its segment, channel, destination, edge, selection, filter, posture, and accessibility semantics while making hierarchy and operator triage clearer. Custom SVG markers, depth, lighting, and motion are welcome only when they communicate state.

### First executable slice

Capture current dark and light screenshots at desktop and narrow viewports, identify the highest-value readability or interaction problem, and ship one reusable visual or interaction improvement. Avoid an unbounded redesign.

### Epic acceptance predicates

- Existing filters, selection, keyboard access, detail panels, and data meanings remain intact.
- Blocked, redacted, shadow, error, and normal states differ through more than color.
- Dense representative data remains responsive and legible; empty, loading, error, and partial-data states remain useful.
- Motion communicates flow, respects reduced motion, and has a static fallback.
- Narrow layouts keep critical controls and equivalent summarized detail.
- No new asset, animation, or marker increases privacy precision or exposes a user.
- Before/after screenshots and an interaction recording show the improvement in both themes.

### Minimum evidence

Run `npm run console:check`, `npm run console:build`, `npm run test:console-app`, and `npm run console:verify-design`. Inspect screenshots at relevant desktop and mobile viewports and review the rendered result in a real browser.

## Epic 4: Theme semantics and navigation polish

### Existing anchors

- Theme control: `console/src/components/ThemeToggle.tsx` and `console/src/lib/theme.ts`
- Navigation: `console/src/components/NavRail.tsx`, `Topbar.tsx`, and `CommandPalette.tsx`
- Design coverage: `e2e/console-design.spec.js`

### Corrected end state

Preserve the existing two-option segmented control: the sun selects light and the moon selects dark. Make the accessible names action-clear, keep preference persistence, and improve navigation polish without converting normal route links into ARIA tabs.

System-theme support is not required by the original request. Treat it as a separate product decision because the current console intentionally defaults to dark and persists `redactwall.theme`.

### First executable slice

Audit the rendered control and primary rail at desktop and narrow viewports. Correct only verified ambiguity, focus, active-state, overflow, or contrast gaps, then update focused browser assertions.

### Epic acceptance predicates

- The sun always sets `data-theme="light"`; the moon always sets `data-theme="dark"`.
- Accessible names state the action or outcome unambiguously and `aria-pressed` matches the selected theme.
- Preference survives reload and navigation with no normal-load wrong-theme flash.
- Route navigation remains keyboard operable, has visible focus, identifies the current route without color alone, and handles long labels and narrow widths.
- Both themes meet WCAG AA for text, icons, focus, active, hover, disabled, and notification states.
- Shared components remain the only implementation path; no legacy console code is revived.

### Minimum evidence

Run `npm run console:check`, `npm run console:verify-design`, and focused accessibility checks. Capture both themes, reload persistence, keyboard navigation, and narrow-width behavior in a real browser.

## Epic 5: Vendor-driven customer-silo provisioning

### Existing anchors

- Tracked customer-silo boundary: `infra/aws/customer-silo.yml`, `scripts/aws-silo-smoke.js`, and `test/aws-silo-smoke.test.js`
- In-flight local deployment work: `infra/aws/customer-data-volume.yml`, `scripts/aws-silo-deploy.js`, `scripts/aws-silo-maintenance.js`, `scripts/aws-artifacts.js`, and `scripts/aws-artifact-bucket.js` are present but untracked in the current working tree. Do not treat them as a durable interface until they land in an authorized coherent change.
- Customer identity lifecycle: `/api/admin/users` routes in `server/app.js`, `server/identity-setup.js`, and `console/src/views/Identity.tsx`
- Tracked identity tests: `test/admin-api.test.js` and `test/identity-lifecycle.test.js`; use the in-flight AWS tests only with the in-flight implementation above

### Corrected end state

Add a vendor control-plane wizard that orchestrates the existing customer-silo deployment boundary rather than duplicating CloudFormation or storing customer admin passwords. The first customer global administrator is a tenant-local `security_admin`, established through a dedicated bootstrap or invitation flow with mandatory MFA.

### First executable slice

Define a durable, idempotent provisioning state machine and a dry-run adapter around the existing deployment workflow. Use fake AWS responses and a disposable state store. No cloud resources are created in this slice.

### Epic acceptance predicates

- Every request has an idempotency key and exact tenant, region, stack, artifact, secret-version, license, and evidence-volume identity.
- Retry cannot create a second stack, tenant, license, or administrator.
- Partial failure is resumable or rolls back only resources whose exact identity and ownership are proven.
- The UI shows queued, validating, provisioning, waiting, failed, remediation, and complete states with sanitized errors.
- The wizard presents a step-by-step checklist for tenant identity, domains, region, entitlements, baseline policy, retention, enabled sensors, administrator setup, deployment health, and final handoff.
- Customer resources are not marked ready until `/readyz`, authenticated readiness, exact image/config/license attestation, audit integrity, and tenant isolation pass.
- The initial administrator receives a single-use, expiring setup path and cannot access the portal before primary authentication and MFA enrollment.
- The vendor superadmin never knows or stores the customer's permanent password or MFA seed.
- Every step, retry, cancellation, and privileged read is audited without cloud credentials or customer content.
- A tested non-production AWS run and operator runbook prove create, retry, failure recovery, and safe teardown.

### Minimum evidence

Run the focused AWS, setup, preflight, license, admin, and identity tests; failure injection for every state transition; dry-run UI E2E; and, only with explicit authorization, a disposable non-production silo smoke. Deployment changes also require the Docker and release gates selected by the goal-contract skill.

## Epic 6: Stripe billing and signed entitlement management

### Existing anchors

- Customer enforcement: `server/connected-license-runtime.js`,
  `server/connected-entitlement-store.js`,
  `server/connected-online-registry-store.js`, `server/license.js`, and
  `server/tenant.js`
- Vendor license service: `infra/license-server/`
- Customer operations: `console/src/views/Licensing.tsx` and `/api/admin/license` routes
- Tests: `test/license.test.js`, `test/license-api.test.js`, `test/license-server.test.js`, and `test/tenant.test.js`

### Corrected end state

Stripe belongs in the vendor control plane and is authoritative for payment and subscription lifecycle. RedactWall remains authoritative for enforcement state. Bridge the two through an explicit entitlement projection and the existing signed offline or connected licensing boundary. Never put Stripe secrets or payment data in customer silos.

### First executable slice

Define the Stripe-to-entitlement state machine and process signed webhook fixtures into an idempotent vendor billing ledger. Do not add a production dependency or call Stripe until that architecture and dependency choice are approved.

### Epic acceptance predicates

- Webhook signatures are verified over the exact bounded raw request bytes before JSON parsing, with the route ordered ahead of any global JSON parser. Event age, body limits, timeouts, event type, customer mapping, and replay are validated before mutation.
- Duplicate, delayed, missing, and out-of-order events converge through reconciliation without duplicate entitlement changes.
- Plan, quantity, trial, renewal, past-due, cancellation, reactivation, and refund or dispute policy are documented and tested against approved business rules.
- Frontend success never grants entitlement. Only the server-side projection can issue or update a signed license or connected verdict.
- Customer silos store only required opaque Stripe references and public subscription state, never full card, bank, payment-authentication, API-secret, or webhook-secret data.
- Vendor billing operations require least privilege, recent reauthentication, confirmation of tenant/current/proposed/financial state, idempotency, and sanitized audit.
- The vendor portal can search and filter every customer, inspect plan, quantity, billing period, trial, renewal or cancellation, invoice and payment state, reconciliation freshness, and entitlement projection without exposing payment credentials.
- Supported plan, seat, trial, pause, resume, cancellation, discount, repair, and resynchronization actions show their timing and financial effect before confirmation.
- Stripe test-mode evidence proves every supported lifecycle and reconciliation path before production enablement.

### Minimum evidence

Run focused ledger and webhook tests with official Stripe test fixtures, existing license/tenant regressions, two-tenant authorization negatives, reconciliation and reordering tests, and real Stripe test-mode events when credentials are available. Without Stripe test access, report the epic incomplete rather than substituting mocks for the external predicate.

## Epic 7: Vendor superadmin authentication with mandatory MFA

### Existing anchors

- Customer-local authentication: `server/auth.js` and login/session routes in `server/app.js`
- Customer identity lifecycle: `server/identity-setup.js` and `server/db.js`
- Tests: `test/admin-mfa.test.js`, `test/identity-lifecycle.test.js`, `test/login-audit-order.test.js`, `test/admin-csrf.test.js`, and `test/access-roles.test.js`

### Corrected end state

Reserve username `superadmin` for the separate vendor control plane. Do not rename the customer-local default account or grant it cross-customer authority as a shortcut. Provision a new bootstrap credential through a secret manager, force rotation and MFA enrollment before portal access, and retain a separately governed recovery path.

TOTP must work with standard authenticators such as Proton Pass. If Duo is selected, integrate through an approved Duo or organizational identity flow. Never treat a reusable Duo code as a static password.

### First executable slice

Implement the vendor identity state machine and route guards in isolation: bootstrap pending, password rotation required, MFA enrollment required, active, recovery pending, disabled. Protect a minimal health/profile page before any customer, billing, telemetry, or provisioning data exists.

### Epic acceptance predicates

- No vendor portal content or API is available to unauthenticated, password-only, partially enrolled, expired, disabled, or wrong-role sessions.
- Bootstrap secrets are generated at high entropy, delivered once through approved secret storage, stored only as modern salted hashes, rotated on first login, and never logged or audited.
- TOTP seeds and recovery codes are per identity; recovery codes are shown once, stored as hashes, single-use, and revocable.
- Locally managed TOTP seeds are envelope-encrypted under a separately managed key, never disclosed after enrollment or included in logs, audit, analytics, backup exports, or support surfaces, and readable only by the narrow verification path. Key rotation and recovery are tested. Prefer an external IdP or Duo flow when the vendor should not store a TOTP seed.
- Session identifiers rotate after primary auth, MFA, password changes, and privilege changes; cookies, CSRF, timeouts, revocation, rate limits, lockout, and recent reauthentication are tested.
- MFA reset and recovery require strong verification and sanitized audit. There is no universal bypass, security question, or undocumented account.
- Cross-tenant authorization is denied server-side even for a valid vendor user without the required scoped role.
- The compromised credential from the shared conversation is absent from repository content, history, artifacts, images, configuration, containers, and logs. Supply it to an approved local scanner only through an ephemeral secret input that does not print or persist it.
- A fresh security review finds no authn, authz, session, recovery, secret, confused-deputy, or audit blocker.

### Minimum evidence

Run failing-first auth and authorization tests, direct API bypass tests, invalid and replayed OTP tests, recovery reuse tests, session fixation and revocation tests, brute-force/rate-limit tests, two-tenant role tests, sanitized audit inspection, and a real browser enrollment/login/recovery journey. Duo completion additionally requires an authorized Duo non-production flow.

## Initiative definition of done

The seven-epic initiative is complete only when every epic predicate is evidenced, the foundation gate remains valid, and all of the following are true:

- Vendor and customer identity, storage, encryption, audit, and deployment boundaries are separate and threat-modeled.
- Two independent customer silos cannot read, write, correlate, authorize, provision, bill, or override each other.
- No raw customer prompt data, held content, files, credentials, direct identifiers, or payment data is centralized.
- Customer enforcement remains available and fail closed during vendor outage, stale catalog, rejected telemetry, and billing reconciliation failure.
- Privileged operations are least-privilege, recently reauthenticated where sensitive, idempotent, recoverable, and audit recorded.
- UI surfaces use real backend behavior, remain accessible and responsive, and have browser evidence for success and deny states.
- Every PR-sized slice passes the targeted gates, `npm run review:ci`, `npm run suite:smoke`, asserted audit verification, and a fresh-context review.
- A release candidate passes the local release commands in `docs/process/RELEASE_PROCESS.md`, `npm run suite:ui`, and the hosted CI matrix defined by `docs/process/TESTING_STRATEGY.md` and `.github/workflows/ci.yml` on a clean release commit.
- No task is closed because a screen exists, a mock passes, a retry recovered, a happy path worked once, or the implementation budget expired.
