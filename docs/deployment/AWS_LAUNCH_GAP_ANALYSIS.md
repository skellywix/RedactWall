# AWS Launch Gap Analysis — What Is Missing For A Paid SaaS Deployment

Date: 2026-07-12. Companion to `AWS_SAAS_DEPLOYMENT.md` (the how) and
`PLANS/aws-saas-deployment.md` (the why / Option A decision). This document is
the honest delta between what the repo ships today and what a real paying
customer on AWS requires. Re-audit it before the first customer handover.

## What already ships (verified in-repo)

| Piece | Where | State |
|---|---|---|
| Customer-silo CloudFormation (ALB + HTTPS-only, EC2, external retained encrypted evidence volume, hardened Docker, Secrets Manager, CloudWatch Logs, SSM access) | `infra/aws/customer-data-volume.yml`, `infra/aws/customer-silo.yml` | Shipped; bootstrap the private artifact bucket, create the durable-data stack once, then use synchronous deploy or explicit maintenance replacement per runbook |
| SaaS-mode tenant + seat enforcement (fail closed) | server (`REDACTWALL_SAAS_MODE`, `REDACTWALL_TENANT_ID`, `REDACTWALL_SEAT_LIMIT`) | Shipped, test-covered |
| Deploy runbook (image → secret → stack → sensors → validate → evidence timer) | `docs/deployment/AWS_SAAS_DEPLOYMENT.md` | Complete for the in-template scope |
| Acceptance smoke for a deployed silo | `npm run silo:smoke` (`scripts/aws-silo-smoke.js`) | Shipped |
| Offline Ed25519 licensing + issuance CLI | `server/license.js`, `docs/deployment/LICENSE_KEY_SETUP.md`, `docs/process/CUSTOMER_LICENSING.md` | Shipped — but see Blocker 1 |
| Signed customer-license bootstrap | `infra/aws/customer-silo.yml`, secret field `REDACTWALL_LICENSE` | Shipped; tenant/seat-bound, journaled, crash-recoverable, private-key-free |
| Connected-mode license verdict server (vendor side) | `infra/license-server/` (Caddy + systemd + verdict-only Ed25519 service) | Scaffolded + interop-tested; needs a deployed vendor instance |
| Postgres driver + migrations + RLS (future shared plane) | `REDACTWALL_DB_DRIVER=postgres`, `docs/deployment/MANAGED_POSTGRES.md` | Shipped; NOT used for silo v1 |
| Backup/restore + drills | `npm run backup`, `backup:drill`, scheduled installers | Shipped app-level |
| Production launch checklist | `docs/deployment/PRODUCTION_LAUNCH_GUIDE.md` | Exists; fold the blockers below into it |

## Launch blockers (do these before taking money)

1. **Production license signing key.** `server/license.js` retains a placeholder
   only for development. Follow `LICENSE_KEY_SETUP.md`: generate the offline
   Ed25519 keypair on a trusted machine, put the public SPKI DER base64 in the
   customer secret, and protect the private key (it can mint licenses for any
   customer). Production preflight and `npm run license:trust-check` reject the
   known placeholder.
2. **Vendor license/heartbeat server is not deployed.** `infra/license-server/`
   is code, not a running endpoint. Stand it up (the free-tier EC2 + Caddy +
   systemd shape it was built for), give it a stable DNS name + TLS, and keep
   the verdict signing key separate from the offline root. Remember the
   7-day heartbeat staleness fails CLOSED for connected-mode customers — the
   vendor box needs monitoring, or first customers ship offline-mode only
   (which is a valid v1 call; decide explicitly).
3. **DNS + ACM per customer.** The template requires `CertificateArn` +
   `PublicHostname`. You need a domain strategy (e.g.
   `<tenant>.redactwall.example`), an ACM cert in the deployment region, and a
   Route53 (or customer-DNS) alias step. The runbooks document the handoff, but
   account ownership, certificate validation, and alias creation remain manual
   third-party integration steps.
4. **Pricing + legal sign-off.** `docs/product/CU_PRICING.md` figures are DRAFT
   and the `docs/legal/` DPA/GLBA templates are samples pending counsel
   (`COUNSEL_HANDOFF_CHECKLIST.md`). A paid deployment needs a signed order
   form, executed DPA, and a committed per-seat price.
5. **Remaining security decisions need a call before a regulated customer
   audit:** N2 (EDM fingerprints use a fast hash), G2 (connected production
   still accepts an environment override for the offline license-root public
   key), and N8 (HA gateway TLS certificates are supplied at deploy). C1 is no
   longer open: audit entries, pending high-water state, and the external
   checkpoint are HMAC-authenticated. G3 clock-rollback protection and G5
   wiped-cache recovery are also implemented and test-covered. If the remaining
   risks are accepted for v1, record the decision in `DECISIONS.md`.

## Operational gaps (template/runbook additions, first week of ownership)

1. **No alarms.** The stack has CloudWatch Logs only. Add: ALB
   `UnHealthyHostCount` > 0, target 5xx rate, EC2 status-check failure,
   disk-space on `/var/lib/redactwall` (evidence store growth), and an SNS
   topic → email/phone. Without these, the first sign of an outage is the
   customer calling.
2. **No automated EBS snapshots.** Evidence durability currently depends on one
   encrypted EBS volume. Add AWS Backup (or DLM) daily snapshots of the data
   volume with a 30–35 day retention, and document the restore drill
   (`npm run backup:drill` covers app-level; the volume snapshot covers host
   loss). Test one restore before the first customer.
3. **Single-AZ, single-instance by design.** Fine for silo v1 — but write the
   recovery objective down: RTO = time to restore snapshot + redeploy stack;
   rehearse it once and record the number in the customer-facing SLA language.
4. **No WAF.** The console is a public HTTPS endpoint protecting regulated
   evidence. Attach AWS WAF (managed common + rate-based rule) to the ALB, or
   document the compensating control (the app's own auth/step-up/throttles).
5. **No deploy pipeline.** Image build/push is manual `docker build` from a dev
   box. Minimum: a GitHub Actions job that builds on tag, pushes
   digest-pinned to ECR, and records the digest; deploys can stay manual
   `cloudformation deploy` per customer.
6. **Patching cadence.** AL2023 host + Docker base image updates: enable SSM
   Patch Manager baseline or schedule a monthly planned-outage replacement
   through `npm run silo:maintenance -- --mode replace-instance`. Ordinary
   deploys freeze host topology and the stack policy denies create-before-delete
   replacement because gp3 cannot be attached to two instances. The separately
   modeled data volume is retained and identity-checked across maintenance;
   never perform an ad hoc AMI replacement or accept health without the
   applied-state attestation.
7. **Cost guardrails.** Per-silo cost is roughly ALB (~$16/mo) + t3.small/medium
   + EBS + logs ≈ $40–60/mo/customer. Set an AWS Budget alert per account and
   fold the number into pricing floor math.

## Post-first-customer roadmap (already planned, keep sequenced)

- Shared multi-tenant plane on ECS/Fargate + RDS Postgres (driver, migrations,
  RLS already shipped; see `MANAGED_POSTGRES.md`) — only after the silo model
  proves out (`PLANS/aws-saas-deployment.md` Option A → B).
- Central operator console: the Owner Platform (super-admin control plane with
  AWS discovery, licensing + heartbeat-ledger integrations) exists on the
  `claude/product-owner-platform` worktree branch — merge it once the base
  gate is green, then deploy it vendor-side next to the license server.
- Billing-provider integration (Stripe/invoicing) to replace manual seat truth.

## Step-by-step: first paid customer (consolidated order)

Vendor-side one-time:
1. Generate + embed the production license root key (`LICENSE_KEY_SETUP.md`);
   store the private key offline.
2. Deploy the license verdict server (`infra/license-server/README.md`) with
   TLS + monitoring, or explicitly decide "offline licenses only" for v1.
3. Set up the AWS account baseline: dedicated account (or OU) for customer
   silos, CloudTrail on, AWS Budget alert, ECR repo, GitHub Actions image
   build.
4. Get counsel sign-off on DPA/GLBA templates; owner signs off pricing.

Per customer:
5. Pick `TenantId` (= license `customerId`) and seat count; issue the license.
6. Provision DNS hostname + ACM certificate in the target region.
7. Create the customer secret in Secrets Manager with all required runtime
   values plus the signed `REDACTWALL_LICENSE` envelope and public trust anchor,
   never the private signing key, and record the returned immutable `VersionId`
   (runbook §2).
8. Build/push or reuse the digest-pinned image (runbook §1).
9. Bootstrap the private versioned CloudFormation artifact bucket once, then
   run `npm run silo:deploy` (runbook §3), passing the exact AMI, artifact bucket,
   and secret version. The command uploads the content-addressed template,
   binds validation and deployment to its exact S3 `VersionId`, verifies its
   S3 checksum, encryption, and expected bucket owner, and returns only after the
   exact image, secret version, license, container, and data-volume identities
   are applied and attested.
10. Verify the Licensing tab reports the contracted active tenant, plan, seats,
    and expiry. No manual Session Manager copy is required.
11. Add alarms + AWS Backup plan (until they are folded into the template).
12. Configure managed sensors (runbook §4); verify tenant rejection + seat
    blocking (runbook §5); run `npm run silo:smoke`.
13. Confirm the evidence-pack timer (runbook §6) and take a first EBS snapshot.
14. Record the handover: license file hash, image digest, stack name, DNS,
    alarm subscriptions, and executed agreements in the customer file.
