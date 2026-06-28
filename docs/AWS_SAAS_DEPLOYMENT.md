# AWS SaaS Deployment

This deployment path is for paid customer access today. It uses a
customer-silo model: one isolated AWS stack per customer, one tenant id, one
seat limit, one evidence store.

That is intentional. The current product uses SQLite with a hash-chained audit
store. Running one customer per stack preserves strong tenant isolation and
local-disk SQLite semantics while you sell the first version. A shared
multi-tenant SaaS plane should be a later migration to managed Postgres, tenant
scoped queries, SSO, and centralized billing operations.

## AWS Shape

- Application Load Balancer at the edge.
- One Amazon Linux 2023 EC2 host running the existing Docker image.
- Encrypted EBS root volume with `/var/lib/promptwall` mounted into the
  container at `/data`.
- Secrets Manager for admin, optional approver and auditor, MFA, session,
  data-encryption, and ingest secrets.
- CloudWatch Logs for container stdout/stderr.
- Systems Manager Session Manager for operator access. No SSH ingress is
  required by the template.
- App-level SaaS mode:
  - `SENTINEL_SAAS_MODE=true`
  - `SENTINEL_TENANT_ID=<customer-slug>`
  - `SENTINEL_SEAT_LIMIT=<paid-seat-count>`
  - `SENTINEL_REQUIRE_TENANT_CONTEXT=true`
  - `SENTINEL_REQUIRE_USER_IDENTITY=true`

The current CloudFormation template still writes the existing `SENTINEL_*` and
`INGEST_API_KEY` names for upgrade safety. The runtime also accepts
`PROMPTWALL_*` aliases for those values, including `PROMPTWALL_SECRET`,
`PROMPTWALL_DATA_KEY`, `PROMPTWALL_INGEST_API_KEY`, and
`PROMPTWALL_SCIM_BEARER_TOKEN`, when a future template or customer secret
standard moves to the new prefix.

Do not run this app on Fargate with SQLite over EFS. The current preflight and
database comments are built around local disk because audit evidence integrity
matters more than making the first AWS shape look serverless.

## 1. Build And Push The Image

Create an ECR repository once:

```bash
aws ecr create-repository --repository-name promptwall
```

Build and push:

```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION=us-east-1
IMAGE="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/promptwall:0.3.0"

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"

docker build -t "$IMAGE" .
docker push "$IMAGE"
```

## 2. Create The Customer Secret

Create a local `customer-secret.json` outside the repo or in a secure temporary
folder:

```json
{
  "ADMIN_PASSWORD": "replace-with-16-plus-random-chars",
  "ADMIN_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
  "SENTINEL_SECRET": "replace-with-32-plus-random-chars",
  "SENTINEL_DATA_KEY": "replace-with-32-plus-random-chars",
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
  --name promptwall/cu-acme \
  --secret-string file://customer-secret.json
```

The `ADMIN_TOTP_SECRET` must be enrolled in an authenticator app before customer
admins use the console. You can generate production-safe values with:

```bash
npm run setup:prod -- --skip-install --env aws-customer.env
npm run mfa:uri -- --env aws-customer.env --issuer "PromptWall cu-acme"
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
  --secret-id promptwall/cu-acme \
  --query ARN \
  --output text)

aws cloudformation deploy \
  --template-file infra/aws/customer-silo.yml \
  --stack-name promptwall-cu-acme \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    VpcId=vpc-xxxxxxxx \
    PublicSubnetIds='subnet-aaaaaaa,subnet-bbbbbbb' \
    InstanceSubnetId=subnet-aaaaaaa \
    ImageUri="$IMAGE" \
    SecretArn="$SECRET_ARN" \
    TenantId=cu-acme \
    SeatLimit=25 \
    CertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/example
```

If you do not pass `CertificateArn`, the template exposes HTTP on the ALB. Use
that only for a short sandbox smoke test. Production should use ACM and DNS.

Get the URL:

```bash
aws cloudformation describe-stacks \
  --stack-name promptwall-cu-acme \
  --query "Stacks[0].Outputs[?OutputKey=='Url'].OutputValue" \
  --output text
```

## 4. Configure The Customer Sensors

For the Chrome extension managed-storage policy, set:

```json
{
  "serverUrl": "https://promptwall.customer.example",
  "ingestKey": "same-value-as-INGEST_API_KEY",
  "orgId": "cu-acme",
  "email": "${user_email}"
}
```

The server runs in SaaS mode and will reject sensor events that omit `orgId`, use
the wrong tenant id, or send an unmanaged user identity. A new user beyond
`SENTINEL_SEAT_LIMIT` is blocked and recorded as `SEAT_LIMIT_BLOCKED` without
storing the prompt body.

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
curl https://promptwall.customer.example/healthz
curl https://promptwall.customer.example/readyz
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
/var/lib/promptwall/evidence-schedule.json
/etc/promptwall/evidence-pack.env
/etc/systemd/system/promptwall-evidence-pack.service
/etc/systemd/system/promptwall-evidence-pack.timer
/var/log/promptwall/evidence-pack.log
```

The default schedule is `OnCalendar=quarterly` with `Persistent=true`, and the
default config writes packs to `/data/evidence-packs` inside the container,
which maps to the encrypted EBS-backed `/var/lib/promptwall/evidence-packs`
folder on the EC2 host.

After deployment, use Systems Manager Session Manager to inspect or adjust the
schedule config:

```bash
sudo editor /var/lib/promptwall/evidence-schedule.json
sudo systemctl restart promptwall-evidence-pack.timer
sudo systemctl start promptwall-evidence-pack.service
systemctl list-timers promptwall-evidence-pack.timer
```

The timer calls the running container with `npm run evidence:pack:scheduled`,
writes run status to `/var/log/promptwall/evidence-pack.log`, and stores only
mode, container name, config path, and log path in
`/etc/promptwall/evidence-pack.env`. Do not put admin passwords, ingest keys,
data-encryption keys, raw prompt bodies, release tokens, or uploaded file bytes
in the unit environment.

## Next Migration

Move to a shared SaaS control plane after the first paid customer stack is
operational. That migration should include:

- Postgres datastore with tenant-scoped query and audit tables.
- Database migrations and backup/restore runbooks.
- Shared-SaaS identity lifecycle on top of the current customer-silo
  SCIM-backed OIDC login.
- Billing provider integration for subscription and seat updates.
- Central operator view across customer stacks or tenants.

## Works Cited

Amazon Web Services. "Tenant Isolation." *AWS Well-Architected SaaS Lens*, Amazon Web Services, https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/tenant-isolation.html. Accessed 26 June 2026.

Amazon Web Services. "Application Load Balancers." *Elastic Load Balancing User Guide*, Amazon Web Services, https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html. Accessed 26 June 2026.

Amazon Web Services. "What Is AWS Secrets Manager?" *AWS Secrets Manager User Guide*, Amazon Web Services, https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html. Accessed 26 June 2026.

SQLite. "Appropriate Uses For SQLite." *SQLite Documentation*, SQLite Consortium, https://www.sqlite.org/whentouse.html. Accessed 26 June 2026.
