# AWS SaaS Deployment

This deployment path is for paid customer access today. It uses a
customer-silo model: one isolated AWS stack per customer, one tenant id, one
seat limit, one evidence store.

That is intentional. The current product uses SQLite with a hash-chained audit
store. Running one customer per stack preserves strong tenant isolation and
local-disk SQLite semantics while you sell the first version. A shared
multi-tenant SaaS plane should be a later migration to managed Postgres, tenant
scoped queries, SSO, and centralized billing operations. When that migration
happens, `docs/deployment/MANAGED_POSTGRES.md` is the operator runbook for the Postgres
control plane (RDS role setup, migrations, backups, monitoring, sizing).

## AWS Shape

- Application Load Balancer at the edge.
- One Amazon Linux 2023 EC2 host running the existing Docker image.
- Encrypted EBS root volume with `/var/lib/redactwall` mounted into the
  container at `/data`.
- Docker runtime state under `/data`: `redactwall.db`, `policy.json`,
  `.policy-bundle-key.pem`,
  `custom-detectors.json`, backups, and scheduled examiner evidence packs.
- Hardened container flags: init process, read-only root filesystem, writable
  `/tmp` tmpfs, dropped Linux capabilities, and `no-new-privileges`.
- Secrets Manager for admin, optional approver and auditor, MFA, session,
  data-encryption, and ingest secrets.
- CloudWatch Logs for container stdout/stderr.
- Systems Manager Session Manager for operator access. No SSH ingress is
  required by the template.
- App-level SaaS mode:
  - `REDACTWALL_SAAS_MODE=true`
  - `REDACTWALL_TENANT_ID=<customer-slug>`
  - `REDACTWALL_SEAT_LIMIT=<paid-seat-count>`
  - `REDACTWALL_REQUIRE_TENANT_CONTEXT=true`
  - `REDACTWALL_REQUIRE_USER_IDENTITY=true`

The current CloudFormation template writes the canonical `REDACTWALL_*` and
`INGEST_API_KEY` names. The runtime also accepts the legacy
`PROMPTWALL_*`/`SENTINEL_*` aliases for those values, including `PROMPTWALL_SECRET`,
`PROMPTWALL_DATA_KEY`, `PROMPTWALL_INGEST_API_KEY`, and
`PROMPTWALL_SCIM_BEARER_TOKEN`, so customer secret stores that still emit the
older names keep working across the rebrand.

The AWS template pins mutable customer state to the mounted `/data` volume:
`REDACTWALL_DB_PATH=/data/redactwall.db`,
`REDACTWALL_POLICY_PATH=/data/policy.json`, and
`REDACTWALL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json`. Do not store
customer policy edits or detector packs only in the image layer.

The container image entrypoint atomically seeds `/data/policy.json` from the
shipped policy on first boot. If a customer policy already exists on the EBS
volume, the entrypoint leaves it untouched. The CloudFormation `docker run`
uses that default entrypoint, so a new customer silo starts with the same policy
that passed repository validation without risking later policy overwrite.
The same durable volume owns the Ed25519 sensor-policy signing key. Production
readiness fails if that key cannot be created or read, and a corrupt or partial
existing key is never silently replaced. Export the public half from the
trusted instance after deployment and distribute it through browser MDM and
Node-sensor configuration; do not bootstrap pins from the public-key API.
The template also pins the container hostname to `redactwall`. Preserve that
hostname on replacement containers that reuse `/var/lib/redactwall`; it lets
the file-mutation lock distinguish a new PID 1 process instance from a crashed
PID 1 predecessor without deleting ambiguous locks from another host.

Do not run this app on Fargate with SQLite over EFS. The current preflight and
database comments are built around local disk because audit evidence integrity
matters more than making the first AWS shape look serverless.

## 1. Build And Push The Image

Create an ECR repository once:

```bash
aws ecr create-repository --repository-name redactwall
```

Build and push:

```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=us-east-1
REPOSITORY="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/redactwall"
IMAGE_TAG=0.3.0
TAGGED_IMAGE="$REPOSITORY:$IMAGE_TAG"

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

docker build -t "$TAGGED_IMAGE" .
docker push "$TAGGED_IMAGE"

IMAGE_DIGEST=$(aws ecr describe-images \
  --repository-name redactwall \
  --image-ids imageTag="$IMAGE_TAG" \
  --query 'imageDetails[0].imageDigest' \
  --output text \
  --region "$AWS_REGION")
IMAGE="$REPOSITORY@$IMAGE_DIGEST"
```

CloudFormation accepts only the digest-pinned `IMAGE` value. Keep the tag for
human release naming, but never deploy a mutable tag into `ImageUri`.

## 2. Create The Customer Secret

Create a local `customer-secret.json` outside the repo or in a secure temporary
folder:

```json
{
  "ADMIN_PASSWORD": "replace-with-16-plus-random-chars",
  "ADMIN_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
  "REDACTWALL_SECRET": "replace-with-32-plus-random-chars",
  "REDACTWALL_DATA_KEY": "replace-with-32-plus-random-chars",
  "INGEST_API_KEY": "ps_ingest_replace_with_32_plus_random_chars",
  "SCIM_BEARER_TOKEN": "",
  "APPROVER_USER": "approver",
  "APPROVER_PASSWORD": "replace-with-16-plus-random-chars",
  "AUDITOR_USER": "auditor",
  "AUDITOR_PASSWORD": "replace-with-16-plus-random-chars",
  "SIEM_WEBHOOK_URL": "",
  "SIEM_WEBHOOK_TOKEN": ""
}
```

Then create the secret:

```bash
aws secretsmanager create-secret \
  --name redactwall/cu-acme \
  --secret-string file://customer-secret.json
```

The `ADMIN_TOTP_SECRET` must be enrolled in an authenticator app before customer
admins use the console. You can generate production-safe values with:

```bash
npm run setup:prod -- --customer-id cu-acme --skip-install --env aws-customer.env
npm run mfa:uri -- --env aws-customer.env --issuer "RedactWall cu-acme"
```

## 3. Deploy The Customer Stack

Validate the template:

```bash
aws cloudformation validate-template \
  --template-body file://infra/aws/customer-silo.yml
```

Deploy:

```bash
SECRET_ARN=$(aws secretsmanager describe-secret \
  --secret-id redactwall/cu-acme \
  --query ARN \
  --output text)

aws cloudformation deploy \
  --template-file infra/aws/customer-silo.yml \
  --stack-name redactwall-cu-acme \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    VpcId=vpc-xxxxxxxx \
    PublicSubnetIds='subnet-aaaaaaa,subnet-bbbbbbb' \
    InstanceSubnetId=subnet-aaaaaaa \
    ImageUri="$IMAGE" \
    SecretArn="$SECRET_ARN" \
    TenantId=cu-acme \
    SeatLimit=25 \
    CertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/example \
    PublicHostname=redactwall.customer.example
```

`CertificateArn` and `PublicHostname` are required. The ALB always redirects
port 80 to its HTTPS listener, which prevents the console from advertising
secure session cookies over an HTTP-only endpoint. Use an ACM certificate issued
in the deployment region that covers `PublicHostname`.

Get the ALB DNS target, create the customer DNS alias to that value, and wait for
DNS propagation:

```bash
aws cloudformation describe-stacks \
  --stack-name redactwall-cu-acme \
  --query "Stacks[0].Outputs[?OutputKey=='LoadBalancerDnsName'].OutputValue" \
  --output text
```

The canonical URL output uses `PublicHostname`, so it matches the ACM
certificate after the alias is live:

```bash
aws cloudformation describe-stacks \
  --stack-name redactwall-cu-acme \
  --query "Stacks[0].Outputs[?OutputKey=='Url'].OutputValue" \
  --output text
```

### Apply image and configuration updates

Rerun the same `aws cloudformation deploy` command with a new digest-pinned
`ImageUri` whenever a release is promoted. The instance runs `cfn-hup`, which
detects the `AWS::CloudFormation::Init` metadata change and invokes `cfn-init`;
the update does not depend on EC2 user data running a second time. The deploy
script refreshes Secrets Manager values, pulls the image, starts it, and waits
for both Docker health and `/readyz`. The previous container is restored if the
candidate does not become ready. After every update, verify `/readyz`, the ALB
healthy-host count, and `systemctl is-active cfn-hup` through Session Manager.

## 4. Configure The Customer Sensors

For the managed browser extension storage policy, set:

```json
{
  "serverUrl": "https://redactwall.customer.example",
  "ingestKey": "same-value-as-INGEST_API_KEY",
  "orgId": "cu-acme",
  "email": "${user_email}"
}
```

The server runs in SaaS mode and will reject sensor events that omit `orgId`, use
the wrong tenant id, or send an unmanaged user identity. A new user beyond
`REDACTWALL_SEAT_LIMIT` is blocked and recorded as `SEAT_LIMIT_BLOCKED` without
storing the prompt body.

On each managed Chrome or Edge test device, open the extension popup and grant
the exact remote HTTPS control-plane origin. This runtime permission must come
from a user gesture; until it is granted, control-plane requests fail closed and
install health reports `server_host_permission=false`.

## 5. Validate

From the project folder before deployment:

```bash
npm test
npm run sync-check
npm run setup:check
node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
```

After deployment:

```bash
curl https://redactwall.customer.example/healthz
curl https://redactwall.customer.example/readyz
```

Log in to the dashboard and confirm:

- The stats row shows `Seats used`.
- `/api/billing/seats` lists the expected customer users.
- A managed extension event with `orgId=cu-acme` is accepted.
- A test event for a second tenant is rejected.
- A test event beyond the purchased seat count is blocked.

## 6. Schedule Examiner Evidence Packs

The CloudFormation bootstrap installs a host-level systemd timer for recurring
sanitized evidence packs. It copies the Linux runner and schedule template out
of the running container, then creates:

```bash
/var/lib/redactwall/evidence-schedule.json
/etc/redactwall/evidence-pack.env
/etc/systemd/system/redactwall-evidence-pack.service
/etc/systemd/system/redactwall-evidence-pack.timer
/var/log/redactwall/evidence-pack.log
```

The default schedule is `OnCalendar=quarterly` with `Persistent=true`, and the
default config writes packs to `/data/evidence-packs` inside the container,
which maps to the encrypted EBS-backed `/var/lib/redactwall/evidence-packs`
folder on the EC2 host.

After deployment, use Systems Manager Session Manager to inspect or adjust the
schedule config:

```bash
sudo editor /var/lib/redactwall/evidence-schedule.json
sudo systemctl restart redactwall-evidence-pack.timer
sudo systemctl start redactwall-evidence-pack.service
systemctl list-timers redactwall-evidence-pack.timer
```

The timer calls the running container with `npm run evidence:pack:scheduled`,
writes run status to `/var/log/redactwall/evidence-pack.log`, and stores only
mode, container name, config path, and log path in
`/etc/redactwall/evidence-pack.env`. Do not put admin passwords, ingest keys,
data-encryption keys, raw prompt bodies, release tokens, or uploaded file bytes
in the unit environment.

## Next Migration

Move to a shared SaaS control plane after the first paid customer stack is
operational. That migration should include:

- Postgres datastore: SHIPPED behind `REDACTWALL_DB_DRIVER=postgres` with
  tenant-scoped queries (indexed `orgId` + forced row-level security) and a
  database-enforced append-only audit table.
- Database migrations: SHIPPED (auto-applied ordered history on startup for
  SQLite and Postgres). Backup/restore runbooks: SHIPPED (`npm run backup`,
  `npm run backup:drill`, scheduled-backup installers; `pg_dump`/snapshots on
  Postgres).
- Shared-SaaS identity lifecycle on top of the current customer-silo
  SCIM-backed OIDC login.
- Billing provider integration for subscription and seat updates.
- Central operator view across customer stacks or tenants.

## Works Cited

Amazon Web Services. "Tenant Isolation." *AWS Well-Architected SaaS Lens*, Amazon Web Services, https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/tenant-isolation.html. Accessed 26 June 2026.

Amazon Web Services. "Application Load Balancers." *Elastic Load Balancing User Guide*, Amazon Web Services, https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html. Accessed 26 June 2026.

Amazon Web Services. "What Is AWS Secrets Manager?" *AWS Secrets Manager User Guide*, Amazon Web Services, https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html. Accessed 26 June 2026.

SQLite. "Appropriate Uses For SQLite." *SQLite Documentation*, SQLite Consortium, https://www.sqlite.org/whentouse.html. Accessed 26 June 2026.
