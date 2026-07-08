# Production Launch Guide

This is the end-to-end sequence for taking RedactWall from this repository to a
paying-customer SaaS on AWS. It stitches together the focused runbooks that
already exist — it does not replace them. Each phase links the deeper doc.

The launch shape is the **customer-silo model**: one isolated AWS stack per
customer, one tenant id, one seat limit, one evidence store. One and the same
application image serves three roles on three stacks:

| Surface | Who uses it | What it is |
|---------|-------------|------------|
| Vendor admin stack (`admin.<domain>`) | You | Your own RedactWall silo: dogfooding, reference environment, and the anchor for the client/license registry (Phase 8). |
| Demo stack (`demo.<domain>`) | Sales | The same app with **no license installed** — unlicensed demo mode, seeded with synthetic data. |
| Client tenant stacks (`<customer>.<domain>`) | Each client | The customer's own console at `/app`: approval queue, posture, coverage, seats, audit — how they monitor their environment. |

There is no separate portal codebase for any of these; the React console served
at `/app` inside the server image is the only console.

## Launch Checklist (one page)

- [ ] Phase 0 — AWS account, region, and naming decisions made
- [ ] Phase 1 — Domain in Route 53, ACM wildcard certificate issued
- [ ] Phase 2 — Real license keypair generated, placeholder public key replaced, image in ECR
- [ ] Phase 3 — Backup and snapshot strategy in place
- [ ] Phase 4 — Vendor admin stack live at `admin.<domain>`
- [ ] Phase 5 — Demo stack live at `demo.<domain>`, seeded, reset procedure written down
- [ ] Phase 6 — First client silo deployed, licensed, and validated
- [ ] Phase 7 — Sensors rolled out pilot-first, then org-wide
- [ ] Phase 8 — Client/license registry started, renewal calendar armed
- [ ] Phase 9 — Monitoring, backups, evidence packs, and upgrade path verified

## Phase 0 — Decisions And Prerequisites

1. **Commit to the customer-silo model for launch.** The product's SQLite
   store with a hash-chained audit log is built for local disk, and one stack
   per customer gives hard tenant isolation with zero shared-plane code to
   operate. The shared multi-tenant Postgres plane is a documented later
   migration (`docs/deployment/AWS_SAAS_DEPLOYMENT.md`, "Next Migration"), not a launch
   requirement.
2. **AWS account.** Use a dedicated production AWS account (or an AWS
   Organization with a production OU if you already have one). Enable MFA on
   the root user, create an IAM identity for yourself with admin rights, and
   do day-to-day work from that identity, never root.
3. **Pick one region** close to your customers (for example `us-east-1`) and
   deploy everything there. Every command below assumes a single region.
4. **Decide the naming scheme now**, because DNS, secrets, stacks, and the
   registry all key off it:
   - Vendor admin stack: `admin.<domain>`, tenant id `vendor-ops`
   - Demo stack: `demo.<domain>`, tenant id `demo`
   - Clients: `<customer-slug>.<domain>`, tenant id `<customer-slug>`
     (for example `cu-acme`), secret `redactwall/<customer-slug>`, stack
     `redactwall-<customer-slug>`
5. **Prerequisites on your workstation:** AWS CLI authenticated to the
   production account, Docker, Node >= 22, and a clean checkout of this repo.

## Phase 1 — Domain And TLS

You need one domain and one wildcard certificate. Every stack's ALB terminates
HTTPS with the same certificate; DNS decides which stack a hostname reaches.

1. **Register the domain** (or transfer it) in Route 53. Registering it there
   creates the public hosted zone automatically; if the domain lives at
   another registrar, create a hosted zone and point the registrar's NS
   records at it.
2. **Request an ACM certificate** in your deployment region covering the apex
   and the wildcard:

   ```bash
   aws acm request-certificate \
     --domain-name "example.com" \
     --subject-alternative-names "*.example.com" \
     --validation-method DNS
   ```

   Create the validation CNAME records ACM asks for (one click from the ACM
   console when the zone is in Route 53), wait for status `ISSUED`, and record
   the certificate ARN. This ARN is the `CertificateArn` parameter you will
   pass to **every** stack deploy.
3. **Rule:** never run a production stack without `CertificateArn`. Without
   it, `infra/aws/customer-silo.yml` exposes plain HTTP on the ALB — that mode
   exists only for short sandbox smoke tests.
4. **Per-stack DNS** happens at deploy time: after each CloudFormation stack
   comes up, create an alias A record (`admin`, `demo`, or the customer slug)
   pointing at that stack's ALB DNS name (the stack's `Url` output).

## Phase 2 — Release Engineering (One-Time Hardening)

Do these once before the first production deploy.

1. **Replace the placeholder license public key.** `server/license.js` ships
   with a placeholder Ed25519 public key; licenses you issue will not verify
   against it. Generate the real vendor keypair **offline**:

   ```bash
   npm run license:issue -- --init-keypair ~/redactwall-license-keys
   ```

   Paste the printed public PEM into `server/license.js` (the marked
   placeholder), commit that change, and store the private key
   (`license-signing-key.pem`) somewhere durable and offline (password
   manager plus an offline backup). The private key never enters the repo,
   the image, or AWS. Losing it means you cannot issue or renew any customer
   license; leaking it means anyone can mint licenses. Full walkthrough,
   including rotation: `docs/deployment/LICENSE_KEY_SETUP.md`.
2. **Run the full review gate** on the commit you are about to ship:

   ```bash
   npm run review:ci
   ```

   This runs the docs checks, console build, Node tests, Playwright suite,
   detector sync check, and the detection eval — the same gate CI enforces.
3. **Build and push the image to ECR** (full commands in
   `docs/deployment/AWS_SAAS_DEPLOYMENT.md` §1):

   ```bash
   aws ecr create-repository --repository-name redactwall   # once
   # then build and push, tagged with the app version:
   # <account>.dkr.ecr.<region>.amazonaws.com/redactwall:0.3.0
   ```

   Tag images with the package version (`redactwall:0.3.0`), never `latest`.
   The image URI is the `ImageUri` parameter for every stack, and upgrades
   (Phase 9) are "push a new tag, update the stack".

## Phase 3 — Database

You do not install a database server for launch. Each silo runs SQLite on its
own encrypted EBS volume, and the app manages its own schema.

- **What each stack gets automatically:** SQLite at `/data/redactwall.db`
  (host path `/var/lib/redactwall`, encrypted EBS), ordered migrations
  auto-applied at startup, and an append-only, hash-chained `audit` table.
- **Do not** move the database to EFS or run this on Fargate. SQLite over
  network storage is a documented anti-pattern here; audit-chain integrity is
  built around local disk (`docs/deployment/AWS_SAAS_DEPLOYMENT.md`).
- **Backups, two layers:**
  1. App-level: `npm run backup` / `npm run backup:verify` /
     `npm run backup:restore`, with `npm run backup:drill` as the periodic
     restore rehearsal. `docs/deployment/DEPLOYMENT.md` covers the scheduled-backup
     installers.
  2. Volume-level: an EBS snapshot schedule via Data Lifecycle Manager (for
     example daily snapshots, 14-day retention) per customer volume.
- **Later, not now:** the Postgres driver is already shipped
  (`REDACTWALL_DB_DRIVER=postgres`, tenant row-level security, same migration
  history). When you outgrow silos and build the shared plane,
  `docs/deployment/MANAGED_POSTGRES.md` is the operator runbook. Nothing about launch
  depends on it.

## Phase 4 — The Vendor Admin Stack (The Portal You Use)

Deploy yourself a silo first. It proves the whole path before a customer is
watching, and it is the environment you will use daily.

1. Create the secret `redactwall/vendor-ops` in Secrets Manager using the
   customer-secret template from `docs/deployment/AWS_SAAS_DEPLOYMENT.md` §2. Generate
   strong values with:

   ```bash
   npm run setup:prod -- --skip-install --env vendor-ops.env
   npm run mfa:uri -- --env vendor-ops.env --issuer "RedactWall vendor-ops"
   ```

2. Deploy the stack:

   ```bash
   aws cloudformation deploy \
     --template-file infra/aws/customer-silo.yml \
     --stack-name redactwall-vendor-ops \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides \
       VpcId=<vpc> PublicSubnetIds=<a,b> InstanceSubnetId=<a> \
       ImageUri=<ecr-image> SecretArn=<vendor-ops-secret-arn> \
       TenantId=vendor-ops SeatLimit=10 \
       CertificateArn=<acm-arn>
   ```

3. Point `admin.<domain>` at the stack's ALB, enroll the admin TOTP secret in
   your authenticator, log in at `https://admin.<domain>/app`, and confirm
   `/healthz` and `/readyz` are green.
4. Optionally issue yourself an internal license (Phase 6 step 4) so the
   vendor stack runs in the same licensed state customers see.

Be honest with yourself about what this portal is at launch: there is **no
cross-customer single pane yet** — each silo has its own console, and the
central operator view is on the roadmap for after the first customers are
live. Your vendor stack plus the registry in Phase 8 is the launch answer to
"how do I track my clients".

## Phase 5 — The Sales Demo Stack

The demo portal is the same image in **unlicensed demo mode** — with no
`redactwall.lic` installed there is zero license gating and the console labels
itself accordingly. That is a feature: sales never handles license files.

1. Repeat the Phase 4 flow with `TenantId=demo`, secret `redactwall/demo`,
   stack `redactwall-demo`, DNS `demo.<domain>`. Do **not** install a license.
2. Seed synthetic traffic so the console has something to show:

   ```bash
   npm run simulate      # sample prompts through the API path
   npm run fire-drill    # scripted block/approve scenarios
   ```

   Synthetic data only — never paste real customer or employee data into the
   demo stack.
3. Write down the reset procedure and treat it as routine between demos: stop
   the container, wipe `/var/lib/redactwall` on the host (Session Manager
   shell), restart, re-run the seed commands.
4. Keep the generated demo docs current before any client-facing session:

   ```bash
   npm run docs:demo-guide:check
   ```

5. Hand sales the runbooks: `docs/demo/SALES_DEMO_GUIDE.md` (the story to present),
   `docs/demo/DEMO_TECHNICIAN_SETUP.md` (machine prep), and `DEMO_INSTALL_GUIDE.md`
   at the repo root.

## Phase 6 — Client Tenant Silos (Repeat Per Customer)

This is the onboarding runbook you will run for every sale. With practice it
is under an hour of operator time. Full detail: `docs/deployment/AWS_SAAS_DEPLOYMENT.md`.

1. **Secret.** Create `redactwall/<customer-slug>` in Secrets Manager from the
   §2 template; generate values with `npm run setup:prod` and the MFA URI with
   `npm run mfa:uri -- --issuer "RedactWall <customer-slug>"`.
2. **Stack.** Deploy `redactwall-<customer-slug>` with `TenantId`, the
   purchased `SeatLimit`, the shared `CertificateArn`, and the current
   `ImageUri`. The stack enables SaaS mode (`REDACTWALL_SAAS_MODE=true`,
   tenant context and managed identity required), so events with the wrong or
   missing `orgId` are rejected and over-seat identities are blocked as
   `SEAT_LIMIT_BLOCKED` without storing prompt bodies.
3. **DNS.** Alias `<customer-slug>.<domain>` to the stack's ALB.
4. **License.** Issue the signed license with the offline private key from
   Phase 2, then install it:

   ```bash
   npm run license:issue -- \
     --key ~/redactwall-license-keys/license-signing-key.pem \
     --customer "Acme Credit Union" --customer-id cu-acme \
     --plan standard --seats 120 \
     --expires 2027-08-01 --grace-days 30 \
     --out redactwall.lic
   ```

   Install via the console's Configuration tab (paste the file contents) or
   `POST /api/billing/license`. The install is recorded in the audit log,
   metadata only. Plans and feature flags are described in
   `docs/process/CUSTOMER_LICENSING.md`; pilots get a 90-day, seat-capped,
   full-featured license.
5. **Handover.** Deliver the admin credentials and TOTP enrollment to the
   customer's security admin over a secure channel. If they want SSO and
   automatic user lifecycle, wire their IdP: `docs/identity/IDENTITY_IDP_SETUP.md`
   (Entra/Okta OIDC) and `docs/identity/SCIM_PROVISIONING.md`.
6. **Validate** (checklist from `docs/deployment/AWS_SAAS_DEPLOYMENT.md` §5):
   - `https://<customer-slug>.<domain>/healthz` and `/readyz` return ok
   - Console login works; the stats row shows `Seats used`
   - A test event with `orgId=<customer-slug>` is accepted
   - A test event with a different tenant id is rejected
   - A test event beyond the seat count is blocked
7. **Sensors.** Roll out in the Phase 7 order.
8. **Registry.** Record the customer in the Phase 8 registry the same day you
   issue the license.

## Phase 7 — Backend-To-Frontend Rollout Order

Within each customer, roll out in dependency order. Nothing user-facing goes
first.

1. **Control plane** (the backend) is deployed and green: `/readyz` passes,
   which includes the production preflight (secrets present, MFA configured,
   database reachable).
2. **Console** (the frontend) needs no separate deploy — it ships inside the
   same image at `/app`. Verify login, MFA, and the approval queue render.
3. **Policy before sensors.** Apply the regulation template that matches the
   customer (`ncua_glba`, `hipaa`, `pci_dss`, or `baseline`) from the console,
   and preview changes against recent metadata with the policy impact view so
   enforcement day one is deliberate, not default.
4. **Sensors, pilot-first:**
   - **Managed browser extension** first — broadest coverage, centrally
     pushed via Intune/Group Policy with managed storage
     (`serverUrl=https://<customer-slug>.<domain>`, the ingest key, and
     `orgId=<customer-slug>`). Runbook: `docs/deployment/MANAGED_EXTENSION_DEPLOYMENT.md`.
   - **Endpoint agent** next (file, clipboard, OCR flows), packaged with
     `npm run package:endpoint-agent` and validated with
     `npm run endpoint:check`.
   - **MCP guard / AI gateway** where the plan includes them
     (`docs/deployment/AI_LLM_GATEWAY.md`).
5. **Pilot cohort → tune → enforce.** Start 10–20 users in monitor/warn mode,
   tune policy on real (sanitized) evidence for a week or two, then flip to
   block mode and expand org-wide. `docs/deployment/TECHNICIAN_DEPLOYMENT_GUIDE.md` is
   the field guide for this handoff.

## Phase 8 — Tracking Clients And Licenses

Two halves: what the product already shows per silo, and the vendor-side
registry you maintain because licensing is deliberately offline.

**In each silo (you and the client see the same thing):**

- License state, plan, seats, and expiry: console Configuration tab,
  `GET /api/billing/license`
- Seat usage (distinct billable identities, trailing window):
  `GET /api/billing/seats` and the `Seats used` stat
- Every license install and seat-limit block is in the hash-chained audit log

**Vendor-side client registry (start it with customer #1):**

Because `license:issue` runs offline against your private key, the issuance
workstation is the natural system of record. Keep a version-controlled
registry — a private git repo with one file per customer (or one
`customers.csv`) — updated the same day any license is issued:

| Field | Example |
|-------|---------|
| Customer / slug | Acme Credit Union / `cu-acme` |
| Stack / region | `redactwall-cu-acme` / `us-east-1` |
| URL | `https://cu-acme.example.com` |
| Plan / seats | standard / 120 |
| License issued / expires / grace | 2026-08-01 / 2027-08-01 / 30d |
| Renewal owner / contacts | you / security-admin@acme.example |
| Image version | 0.3.0 |

Add each expiry date minus 60 days to a renewal calendar.

**The renewal loop** (behavior defined in `docs/process/CUSTOMER_LICENSING.md`):

1. ~60 days out: seat true-up conversation using the customer's own
   `/api/billing/seats` report — that report is the audit mechanism, no
   intrusive vendor audits.
2. Issue the renewal `redactwall.lic` (new expiry, adjusted seats) and install
   it — `POST /api/billing/license` works even if the old license lapsed.
3. If a renewal slips: expiry starts the 30-day grace banner; past grace the
   console's **config writes** go read-only. Detection, enforcement,
   approvals, audit, and evidence export never stop for billing reasons.

**Later:** once several customers are live, the documented next migration adds
the shared Postgres plane, a central operator view across tenants, and billing
integration. Do not build those before the first licenses are sold; the
registry above is sufficient at silo scale.

## Phase 9 — Production Operations

- **Monitoring.** Container logs are already in CloudWatch Logs
  (`/redactwall/<tenant>`). Add, per stack: a Route 53 health check on
  `https://<host>/healthz` with an alarm to your email/SMS, and CloudWatch
  alarms on ALB 5xx and unhealthy-host count.
- **Backups.** Phase 3's two layers, plus a quarterly `npm run backup:drill`
  restore rehearsal on the vendor stack.
- **Evidence packs.** Each stack installs a systemd timer for quarterly
  sanitized examiner evidence packs; inspect or adjust via Session Manager
  (`docs/deployment/AWS_SAAS_DEPLOYMENT.md` §6, `docs/deployment/EVIDENCE_PACK_TASK.md`).
- **Key hygiene.** Rotate the data-encryption key on schedule with
  `npm run rotate:data-key`; rotate ingest keys via the customer secret and a
  stack update.
- **Upgrades.** Build and push the new image tag, run `npm run review:ci` at
  that tag, then update each stack's `ImageUri` (CloudFormation stack update)
  starting with vendor-ops, then demo, then clients. Release discipline:
  `docs/process/RELEASE_PROCESS.md`.
- **Incidents and support.** `docs/security/INCIDENT_RESPONSE.md` is the runbook;
  `docs/process/SUPPORT_POLICY.md` defines the severities and response targets you
  are committing to customers.

## Cost Sketch Per Silo

Rough monthly figures per customer stack in `us-east-1` (verify against
current AWS pricing): ALB ~$20, `t3.small`–`t3.medium` EC2 ~$15–30, encrypted
EBS + snapshots ~$5, Secrets Manager + CloudWatch ~$3. Roughly **$45–60 per
customer per month**, which comfortably fits a per-seat annual price with a
50-seat minimum (`docs/process/CUSTOMER_LICENSING.md`). The vendor and demo stacks are
the same cost — budget for two internal silos from day one.

## Related Documents

- `docs/deployment/AWS_SAAS_DEPLOYMENT.md` — the detailed silo deploy commands
- `docs/deployment/DEPLOYMENT.md` — Docker, secrets, health checks, backups
- `docs/deployment/LICENSE_KEY_SETUP.md` — signing keypair, issuing, rotation
- `docs/process/CUSTOMER_LICENSING.md` — license format, seat model, pricing shape
- `docs/deployment/MANAGED_POSTGRES.md` — the later shared-plane database runbook
- `docs/deployment/TECHNICIAN_DEPLOYMENT_GUIDE.md` — customer pilot field guide
- `docs/deployment/MANAGED_EXTENSION_DEPLOYMENT.md` — browser sensor rollout
- `docs/identity/IDENTITY_IDP_SETUP.md`, `docs/identity/SCIM_PROVISIONING.md` — customer SSO
- `docs/demo/SALES_DEMO_GUIDE.md`, `docs/demo/DEMO_TECHNICIAN_SETUP.md` — demo runbooks
- `docs/security/INCIDENT_RESPONSE.md`, `docs/process/SUPPORT_POLICY.md` — operations
