# AWS SaaS Deployment Plan

## Goal And Context

RedactWall is moving from local pilot software toward a hosted SaaS offer.
The immediate goal is to make the current product deployable on AWS for paying
customers with tenant identity, paid-seat accounting, and a repeatable launch
path.

The current server is a single Node.js control plane backed by SQLite. That is
valid for demos, pilots, and a customer-silo model, but it is not the right
foundation for a shared multi-tenant control plane. A shared SaaS plane needs a
managed database, row-level tenant boundaries, migrations, customer identity,
and billing integration. Half-building that migration would weaken the audit
and privacy guarantees the product sells.

## Non-Negotiable Invariants

- Detector logic stays in `detection-engine/detect.js`; changes there require
  `npm run sync-engine` and `npm run sync-check`.
- No raw PII is written to logs or audit details.
- `verifyAuditChain()` must remain `ok:true`.
- Existing Docker and local demo paths must keep working.
- Tenant and seat enforcement must fail closed for SaaS mode.

## Options

### Option A: Customer-Silo AWS Stack Now

Each paying customer gets an isolated AWS stack running one RedactWall
control plane with its own encrypted local EBS-backed SQLite store, secrets, ALB,
and managed extension configuration.

Pros:
- Fits the current codebase without a risky data-store rewrite.
- Strong tenant isolation by infrastructure boundary.
- Simple sales/pilot story for regulated smaller institutions.
- Per-seat enforcement can be implemented in the app now.

Cons:
- More stacks to operate as customer count grows.
- Not as cost-efficient as a mature shared multi-tenant plane.
- Does not yet support one central operator console across all customers.

### Option B: Shared Multi-Tenant AWS Control Plane Now

Move to a shared ECS/Fargate service and managed Postgres before selling.

Pros:
- Better long-term SaaS economics.
- Easier central operations and billing analytics.
- Cleaner path to high availability and autoscaling.

Cons:
- Requires async datastore work, migrations, tenant-scoped queries, and SSO.
- Touches the audit store, policy store, dashboard, and tests at once.
- Higher regression risk before the first paid deployment.

### Option C: Fargate Plus EFS SQLite

Run the existing container on ECS/Fargate and put SQLite on EFS.

Pros:
- Looks cloud-native and avoids EC2 management.

Cons:
- Violates the app's current SQLite local-disk preflight intent.
- Network filesystems and SQLite locking are the wrong operational tradeoff for
  evidence integrity.
- Creates a production shape that would need to be undone.

## Recommendation

Implement Option A now. Add SaaS-mode tenant checks and seat accounting to the
app, then provide a customer-silo AWS deployment template that runs the existing
container with durable local disk. Treat the Postgres/shared-plane migration as
the next major roadmap item after the first paid customer stack is proven.

## Decisions For The Human

- Pick the first production tenant ID, for example `cu-acme`.
- Pick the purchased seat count for that tenant.
- Decide whether the first launch uses a real domain and ACM certificate or
  plain HTTP while DNS/TLS is still being configured.
- Decide whether the first paid customer stack lives in your AWS account or in
  the customer's AWS account.

## Acceptance Evidence

Run these checks after implementation:

```bash
npm test
npm run sync-check
npm run setup:check
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

For AWS launch readiness, also validate the template locally or in a sandbox
account:

```bash
aws cloudformation validate-template --template-body file://infra/aws/customer-silo.yml
```
