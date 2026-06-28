# Technician Production Deployment Guide

This guide is for the technicians who install PromptWall for a paying
customer and hand the environment over as production ready.

Use it as the install-day runbook. `docs/DEPLOYMENT.md` and
`docs/AWS_SAAS_DEPLOYMENT.md` are the deeper reference docs.

## Production-Ready Definition

A customer is production ready only when all of these are true:

- The customer has one isolated AWS customer-silo stack.
- The public console URL is HTTPS with a customer-approved DNS name.
- `/healthz` and `/readyz` return HTTP 200.
- Production preflight has no blockers.
- Security Admin MFA is enrolled and tested.
- Browser extension policy, endpoint agent config, and any MCP guard config use
  the customer's `serverUrl`, `ingestKey`, `orgId`, and managed user identity.
- Browser extension install validation has reported sanitized health evidence to
  the Coverage tab.
- Endpoint install validation has reported sanitized health evidence to the
  Coverage tab when endpoint rollout is in scope.
- MCP guard install validation has reported sanitized health evidence to the
  Coverage tab when MCP rollout is in scope.
- A synthetic sensitive-data test is blocked, redacted, or held according to
  the customer's selected policy.
- The dashboard shows attributed events, seat usage, sensor versions, fleet
  install health by user/org/sensor, and audit entries.
- Audit-chain verification returns `ok:true`.
- A backup is created and verified.
- The customer handoff packet is complete and contains no secrets.

Do not use real member, patient, cardholder, employee, customer, loan, contract,
or source-code data during setup. Use synthetic prompts only.

## Supported Production Shape

The supported paid-customer deployment today is one AWS stack per customer:

- Application Load Balancer at the edge.
- Amazon Linux 2023 EC2 host running the Docker image.
- Encrypted EBS-backed local disk mounted into the container at `/data`.
- SQLite evidence store at `/data/sentinel.db`.
- AWS Secrets Manager for admin, MFA, session, data encryption, and ingest
  secrets.
- CloudWatch Logs for container logs.
- Systems Manager Session Manager for operator access. No SSH ingress is
  required by the template.
- App-level SaaS controls:
  - `SENTINEL_SAAS_MODE=true`
  - `SENTINEL_TENANT_ID=<customer-slug>`
  - `SENTINEL_SEAT_LIMIT=<paid-seat-count>`
  - `SENTINEL_REQUIRE_TENANT_CONTEXT=true`
  - `SENTINEL_REQUIRE_USER_IDENTITY=true`

PromptWall also accepts `PROMPTWALL_*` aliases for those `SENTINEL_*` runtime
keys, plus `PROMPTWALL_INGEST_API_KEY`, `PROMPTWALL_ENDPOINT_AGENT_WATCH_DIR`,
`PROMPTWALL_SCIM_BEARER_TOKEN`, `PROMPTWALL_ENDPOINT_AGENT_HANDOFF_DIR`, and
`PROMPTWALL_ENDPOINT_AGENT_HANDOFF_SECRET`. Use one key family per setting in a
customer env file.

Do not deploy the current product as a shared multi-tenant stack for paid
customers. Do not run SQLite over EFS, a network share, OneDrive, Google Drive,
Dropbox, or any other synced folder. The current audit evidence model depends on
local disk semantics.

## Technician Rules

- Run all repo commands from the active repo root:

  ```powershell
  cd C:\Source\promptwall
  ```

- Never commit `.env`, customer secret JSON, ingest keys, MFA seeds, screenshots
  containing secrets, or customer production data.
- Do not bake ingest keys into extension, endpoint agent, or MCP guard packages.
- Do not use HTTP for production except for a short sandbox smoke test before
  DNS and ACM are ready.
- Do not promise a kernel driver or native desktop app hook. The supported
  endpoint deployment is the watched-folder agent plus the signed native
  handoff contract.
- Do not delete retained AWS volumes, backups, logs, or evidence stores without
  written approval from the customer owner and PromptWall owner.

## Customer Intake Worksheet

Collect this before install day:

| Item | Required value |
| --- | --- |
| Customer display name | Legal or operating name. |
| Tenant slug | Lowercase, 2-63 chars, `a-z`, `0-9`, `_`, or `-`; example `cu-acme`. |
| Paid seat count | Positive integer for `SENTINEL_SEAT_LIMIT`. |
| AWS account id and region | Region must have ACM, ECR, EC2, ELB, CloudWatch, Secrets Manager, and SSM. |
| VPC id | VPC for the customer stack. |
| Public subnet ids | At least two public subnets for the ALB. |
| Instance subnet id | Subnet with outbound internet access to pull from ECR. |
| Customer DNS name | Example `promptwall.customer.example`. |
| ACM certificate ARN | Required for production HTTPS. |
| Security Admin owner | Name, email, phone, and MFA enrollment window. |
| Optional approver account | Username owner, assignment scope, and password delivery path. |
| Optional auditor account | Username owner and password delivery path. |
| SIEM webhook | URL, token delivery path, and alert recipient. |
| Chrome deployment owner | Admin console, MDM, or GPO owner. |
| Endpoint agent scope | Pilot users, device groups, watch directory, all-user or per-user install. |
| MCP guard scope | Host runtime owner and environment variable delivery path. |
| Policy template | Baseline, NCUA/GLBA, PCI-DSS, HIPAA, or redact-first. |
| Retention requirement | Raw approval retention days and backup retention owner. |

The tenant slug must match the `orgId` that managed sensors send. A mismatch is
a production blocker.

## Technician Workstation

Install or confirm:

- Node.js 22 or newer.
- npm.
- Docker Desktop or Docker Engine.
- AWS CLI v2 configured for the customer AWS account.
- AWS Session Manager plugin if the technician will open shell sessions through
  `aws ssm start-session`.
- Git.
- Access to the release branch or tag.
- Permission to create or update ECR repositories, CloudFormation stacks, EC2,
  ELB, IAM roles, Secrets Manager secrets, CloudWatch log groups, and ACM-backed
  ALB listeners.

Confirm AWS identity before doing anything destructive:

```powershell
aws sts get-caller-identity
aws configure get region
```

## Phase 1: Validate The Release Locally

From the repo root:

```powershell
git status --short
npm ci
npm test
npm run sync-check
npm run eval
git diff --check
```

For a production-style configuration smoke check, write the generated env file
outside the repo:

```powershell
$TenantId = "cu-acme"
$EnvPath = Join-Path $env:TEMP "promptwall-$TenantId.env"
npm run setup:prod -- --skip-install --env $EnvPath
npm run mfa:uri -- --env $EnvPath --issuer "PromptWall $TenantId"
npm run setup:check -- --env $EnvPath
```

The `mfa:uri` output contains the TOTP seed. Treat it as a secret. Enroll it
with the Security Admin over the approved secure channel, not in a ticket or
normal email.

## Phase 2: Build Sensor Packages

Build the three customer handoff artifacts:

```powershell
npm run release:extension:check -- dist/browser-extension
npm run package:endpoint-agent
npm run package:mcp-guard
```

After browser store items or signed Firefox install URLs exist, rerun the
extension gate with the final values so the handoff packet includes exact
force-install policies:

```powershell
npm run release:extension:check -- dist/browser-extension --chrome-extension-id <chrome-web-store-id> --edge-extension-id <edge-addons-id> --firefox-install-url https://downloads.customer.example/promptwall-firefox.xpi
```

Record the generated artifact names and SHA-256 manifests:

- `dist/browser-extension/`
- `dist/endpoint-agent/`
- `dist/mcp-guard/`

The browser extension folder should include Chrome, Edge, and Firefox zips,
integrity manifests, and the shared release-readiness report. When browser store
IDs or a Firefox install URL are supplied, it should also include target-specific
`promptwall-<browser>-extension-v<version>.extension-settings.json` files with
the real extension id or install URL and no managed-storage secrets.

The manifests belong in the handoff packet. The packages must not contain real
ingest keys or prompt bodies.

## Phase 3: Build And Push The Server Image

Set install variables:

```powershell
$TenantId = "cu-acme"
$AwsRegion = "us-east-1"
$ImageTag = "0.3.0"
$AccountId = aws sts get-caller-identity --query Account --output text
$Registry = "$AccountId.dkr.ecr.$AwsRegion.amazonaws.com"
$Image = "$Registry/promptwall:$ImageTag"
```

Create the ECR repository once if it does not already exist:

```powershell
aws ecr describe-repositories --repository-names promptwall --region $AwsRegion 2>$null
if ($LASTEXITCODE -ne 0) {
  aws ecr create-repository --repository-name promptwall --region $AwsRegion
}
```

Build, authenticate, and push:

```powershell
aws ecr get-login-password --region $AwsRegion |
  docker login --username AWS --password-stdin $Registry

docker build -t $Image .
docker push $Image
```

Record `$Image` in the handoff packet.

## Phase 4: Create The Customer Secret

Use the env file from Phase 1 as the source for strong generated values, or use
the customer's approved vault-generated values. Create a temporary secret JSON
outside the repo:

```powershell
$SecretPath = Join-Path $env:TEMP "promptwall-$TenantId-secret.json"
$SecretJson = @{
  ADMIN_PASSWORD = "<16-plus-random-chars>"
  ADMIN_TOTP_SECRET = "<base32-totp-secret>"
  SENTINEL_SECRET = "<32-plus-random-chars>"
  SENTINEL_DATA_KEY = "<32-plus-random-chars>"
  INGEST_API_KEY = "<32-plus-random-chars>"
  SCIM_BEARER_TOKEN = "<32-plus-random-chars-or-empty>"
  OIDC_ISSUER = "<tenant-specific-issuer-or-empty>"
  OIDC_CLIENT_ID = "<web-client-id-or-empty>"
  OIDC_CLIENT_SECRET = "<32-plus-random-chars-or-empty>"
  OIDC_REDIRECT_URI = "https://<customer-host>/auth/oidc/callback"
  APPROVER_USER = "approver"
  APPROVER_PASSWORD = "<16-plus-random-chars-or-empty>"
  AUDITOR_USER = "auditor"
  AUDITOR_PASSWORD = "<16-plus-random-chars-or-empty>"
  SIEM_WEBHOOK_URL = ""
  SIEM_WEBHOOK_TOKEN = ""
} | ConvertTo-Json -Depth 2

[System.IO.File]::WriteAllText(
  $SecretPath,
  $SecretJson,
  [System.Text.UTF8Encoding]::new($false)
)
```

Create or update the AWS secret:

```powershell
$SecretName = "promptwall/$TenantId"
aws secretsmanager create-secret `
  --name $SecretName `
  --secret-string file://$SecretPath `
  --region $AwsRegion
```

If the secret already exists, use the customer's approved secret-update process.
Do not overwrite production secrets casually. After the secret exists and the MFA
seed is enrolled, remove the local temporary secret file according to the
customer's secure deletion process.

## Phase 5: Deploy The Customer Stack

Set the stack parameters:

```powershell
$StackName = "promptwall-$TenantId"
$VpcId = "vpc-xxxxxxxx"
$PublicSubnetIds = "subnet-aaaaaaa,subnet-bbbbbbb"
$InstanceSubnetId = "subnet-aaaaaaa"
$CertificateArn = "arn:aws:acm:us-east-1:123456789012:certificate/example"
$SeatLimit = 25
$SecretArn = aws secretsmanager describe-secret `
  --secret-id "promptwall/$TenantId" `
  --query ARN `
  --output text `
  --region $AwsRegion
```

Validate the template:

```powershell
aws cloudformation validate-template `
  --template-body file://infra/aws/customer-silo.yml `
  --region $AwsRegion
```

Deploy:

```powershell
aws cloudformation deploy `
  --template-file infra/aws/customer-silo.yml `
  --stack-name $StackName `
  --capabilities CAPABILITY_NAMED_IAM `
  --region $AwsRegion `
  --parameter-overrides `
    VpcId=$VpcId `
    PublicSubnetIds=$PublicSubnetIds `
    InstanceSubnetId=$InstanceSubnetId `
    ImageUri=$Image `
    SecretArn=$SecretArn `
    TenantId=$TenantId `
    SeatLimit=$SeatLimit `
    CertificateArn=$CertificateArn
```

Get the deployed URL:

```powershell
$Url = aws cloudformation describe-stacks `
  --stack-name $StackName `
  --query "Stacks[0].Outputs[?OutputKey=='Url'].OutputValue" `
  --output text `
  --region $AwsRegion
$Url
```

Point the customer DNS name to the ALB according to the customer's DNS process.
Production is not ready until HTTPS is working at the final customer DNS name.

## Phase 6: Server Health And Audit Checks

Check the public endpoints:

```powershell
Invoke-WebRequest "$Url/healthz" -UseBasicParsing
Invoke-WebRequest "$Url/readyz" -UseBasicParsing
```

Check the ALB target:

```powershell
$TargetGroupArn = aws cloudformation describe-stack-resources `
  --stack-name $StackName `
  --logical-resource-id TargetGroup `
  --query "StackResources[0].PhysicalResourceId" `
  --output text `
  --region $AwsRegion

aws elbv2 describe-target-health `
  --target-group-arn $TargetGroupArn `
  --region $AwsRegion
```

Find the instance id and open a Session Manager shell when deeper checks are
needed:

```powershell
$InstanceId = aws cloudformation describe-stack-resources `
  --stack-name $StackName `
  --logical-resource-id AppInstance `
  --query "StackResources[0].PhysicalResourceId" `
  --output text `
  --region $AwsRegion

aws ssm start-session --target $InstanceId --region $AwsRegion
```

Inside the SSM session:

```bash
sudo docker ps
sudo docker logs --tail 100 promptwall
sudo docker exec promptwall node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
sudo docker exec promptwall npm run backup -- /data/backups
```

Also check CloudWatch logs:

```powershell
aws logs tail "/promptwall/$TenantId" --since 30m --region $AwsRegion
```

Save health, readiness, audit-chain, backup, and log evidence in the handoff
packet. Do not include secret values.

## Phase 7: Security Admin Setup

With the customer's Security Admin:

1. Open the final HTTPS console URL.
2. Log in with `ADMIN_USER` and `ADMIN_PASSWORD`.
3. Enter the current MFA code from the enrolled authenticator app.
4. Open the dashboard preflight view and confirm no blockers.
5. Select the agreed policy template.
6. Confirm the approval queue is empty before sensor rollout.
7. Confirm approver login, if configured, can approve or deny assigned approval
   items and cannot reveal raw prompts, purge retention, edit policy, or review
   governed destinations.
8. Confirm auditor login, if configured, can view sanitized evidence and cannot
   approve, deny, reveal, purge, or edit policy.
9. If SCIM or OIDC is planned, open the dashboard Identity tab or run
   `npm run identity:setup -- --provider entra --base-url https://<customer-host> --tenant-id <tenant>`
   or `npm run identity:setup -- --provider okta --base-url https://<customer-host> --tenant-id <customer.okta.com>`
   and attach only the secret-free values to the handoff.
10. If SCIM is configured, have the identity admin call
   `/scim/v2/ServiceProviderConfig` with the bearer token and confirm
   `patch.supported=true` and `filter.supported=true`.
11. If OIDC is configured, confirm the login page shows `Continue with SSO`,
    sign in as one active SCIM-provisioned test user, and verify `/api/me`
    reports the expected role without using a local console password.

If MFA enrollment fails, stop the rollout and rotate `ADMIN_TOTP_SECRET` through
the approved secret process.

## Phase 8: Browser Extension Rollout

Use `docs/MANAGED_EXTENSION_DEPLOYMENT.md` for the full managed browser policy reference.
Use `docs/EXTENSION_RELEASE_CHECKLIST.md` before uploading or handing over a
Chrome, Edge, or Firefox managed extension package.
For install day, the technician must confirm these values in managed storage:

```json
{
  "serverUrl": "https://promptwall.customer.example",
  "ingestKey": "customer-ingest-key-from-approved-vault",
  "orgId": "cu-acme",
  "email": "${user_email}"
}
```

Validation on one managed test device:

1. Open the browser policy page and reload policies: `chrome://policy`,
   `edge://policy`, or `about:policies`.
2. Confirm the extension is force-installed.
3. Confirm the extension receives managed storage.
4. Open the extension popup and confirm protection is enabled.
5. Open an approved AI destination.
6. Confirm the Coverage tab shows a `browser_extension` install-health heartbeat
   with passing checks for managed config, managed identity, org id, server URL,
   ingest-key presence, content-script coverage, and policy cache availability.
   The Fleet Install Health table should show the test user, org, browser
   sensor version, platform, `covered` state, and `checks ok`.
7. Send a benign prompt and confirm it is attributed to the test user.
8. Paste `123-45-6789` as synthetic SSN test data.
9. Confirm the configured policy action appears in the browser.
10. Confirm the dashboard shows the event under the right user and tenant.
11. Add a disposable host to `blockedDestinations`, refresh policy, and confirm
    a send attempt records `destination_blocked` without prompt text.
12. Add the same host to `blockedFileUploadDestinations`, remove it from
    `blockedDestinations`, and confirm an upload attempt records
    `file_upload_blocked` without file content.
13. Visit an ungoverned AI host and confirm shadow-AI discovery appears.

Do not proceed to broad rollout until this managed test device passes.

## Phase 9: Endpoint Agent Rollout

For a per-user Windows pilot install:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -PromptWallUrl "https://promptwall.customer.example" `
  -IngestKey "<customer-ingest-key>" `
  -WatchDir "$env:USERPROFILE\PromptWallWatch"
```

For an all-user managed install from elevated PowerShell, use a managed config
directory:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -PromptWallUrl "https://promptwall.customer.example" `
  -IngestKey "<customer-ingest-key>" `
  -WatchDir "C:\PromptWallWatch" `
  -ConfigDir "$env:ProgramData\PromptWall"
```

Validate:

```powershell
Get-ScheduledTask -TaskName PromptWallEndpointAgent
Get-Content "$env:LOCALAPPDATA\PromptWall\logs\endpoint-agent.log" -Tail 40
npm run endpoint:check -- `
  --env "$env:LOCALAPPDATA\PromptWall\endpoint-agent.env" `
  --emit-heartbeat `
  --user "tech@example.test" `
  --org-id "<tenant-slug>"
```

If native file-flow handoff is included, add `--require-desktop-collector` to
the `endpoint:check` command. The checker posts only bounded install-check IDs,
boolean results, and short details to `/api/v1/heartbeat`; it must not expose
the ingest key, handoff secret, prompt text, extracted text, or file bytes.

Drop a synthetic test file into the watch directory. The file can contain:

```text
Synthetic test only. Member SSN 123-45-6789.
```

Confirm the dashboard receives a sanitized endpoint event and the configured
policy action is applied. Remove the synthetic file after validation.

If native file-flow handoff is included in the pilot, set a 32-plus-character
`ENDPOINT_AGENT_HANDOFF_SECRET` during install and validate only with the
packaged writer. The handoff event must reference an absolute local file path
and must not contain file bytes or prompt text.

## Phase 10: MCP Guard Rollout

For MCP guard hosts:

1. Install the packaged MCP guard artifact from `dist/mcp-guard/`.
2. Configure the host runtime environment with:
   - `PROMPTWALL_URL=https://promptwall.customer.example`
   - `INGEST_API_KEY=<customer-ingest-key>`
   - Managed user identity, if the host runtime supports it.
   - `orgId` or equivalent tenant value set to the customer tenant slug.
3. Validate the runtime and emit install-health evidence:

   ```powershell
   npm run mcp:check -- `
     --env ".env" `
     --emit-heartbeat `
     --user "tech@example.test" `
     --org-id "<tenant-slug>"
   ```

4. Run the customer's synthetic document retrieval test.
5. Confirm sensitive content is redacted or blocked before model access.
6. Confirm the dashboard shows sanitized MCP guard evidence.

Do not store MCP guard secrets in source code, shared scripts, screenshots, or
chat transcripts.

## Phase 11: SaaS And Seat Enforcement Tests

Run these before customer handoff:

- Correct tenant event is accepted.
- Missing tenant context is rejected.
- Wrong tenant id is rejected.
- Unmanaged user identity is rejected.
- Events beyond the paid seat limit are blocked and recorded as
  `SEAT_LIMIT_BLOCKED`.
- `/api/billing/seats` shows the expected test users.

Coordinate seat-limit tests with the customer. If the customer purchased only a
small number of seats, use a temporary test stack or reset test data before
production use.

## Phase 12: Backup And Recovery Evidence

Create and verify at least one backup before handoff:

```bash
sudo docker exec promptwall npm run backup -- /data/backups
sudo docker exec promptwall ls -l /data/backups
```

Copy the backup manifest, not the sensitive `.db` file, into the handoff packet.
The `.db` backup is production evidence and must stay in the approved protected
backup location.

Document:

- Backup file path.
- Manifest path.
- Backup SHA-256 from the manifest.
- Audit-chain status from the manifest.
- Retention owner.
- Restore test status, if performed.

Generate the sanitized examiner pack after backup verification. Include the
restore-drill path only when a restore test was actually performed:

```bash
sudo docker exec promptwall npm run evidence:pack:zip -- /data/evidence-packs \
  /data/backups/sentinel-YYYY-MM-DDTHH-MM-SS-sssZ.db \
  /data/restored-sentinel.db
```

For recurring reporting, copy `config/evidence-schedule.example.json` to
`config/evidence-schedule.json`, set the cadence and output folder, and invoke
`npm run evidence:pack:scheduled -- <file>` from Task Scheduler, cron, or the
customer's runbook scheduler. On Windows hosts, install the standard local task:

```powershell
npm run evidence:pack:install-task
```

The task writes run status to
`%LOCALAPPDATA%\PromptWall\logs\evidence-pack.log` and keeps raw prompt bodies,
environment secrets, release tokens, and uploaded file bytes out of the task
definition and generated pack. Keep the generated JSON or zip in the approved
evidence location, not in email or a synced personal folder.

On Linux or AWS Docker hosts, put the schedule config in the mounted data folder
and install the standard systemd timer:

```bash
sudo cp config/evidence-schedule.example.json /var/lib/promptwall/evidence-schedule.json
sudo editor /var/lib/promptwall/evidence-schedule.json
sudo npm run evidence:pack:install-systemd -- \
  --mode docker \
  --container promptwall \
  --config /data/evidence-schedule.json \
  --on-calendar quarterly
```

Set `outDir` to `/data/evidence-packs`. The timer writes status to
`/var/log/promptwall/evidence-pack.log`, uses `Persistent=true` for missed
runs, and keeps raw prompt bodies, environment secrets, release tokens, and
uploaded file bytes out of the systemd unit.

## Production Handoff Packet

Deliver a packet with:

- Customer name, tenant slug, stack name, AWS account, and region.
- Console HTTPS URL.
- CloudFormation stack outputs.
- Server image URI and tag.
- Sensor package names and SHA-256 manifest paths.
- Extension release-readiness report.
- ExtensionSettings force-install policy generated with the final Chrome Web
  Store extension id.
- `/healthz` and `/readyz` evidence.
- Preflight status evidence.
- Sanitized examiner pack from `npm run evidence:pack`, including coverage,
  policy diffs, approval routing metadata, lineage summaries, control mappings,
  backup status, and restore-drill status when available.
- Fleet Install Health evidence from Coverage showing each required sensor by
  user, org, current state, version, and failed check ID.
- Audit-chain verification output.
- Backup manifest.
- Managed browser policy confirmation.
- Browser extension install-health heartbeat evidence in Coverage.
- Endpoint agent scheduled task/log evidence.
- Endpoint install-health heartbeat evidence in Coverage.
- MCP guard install-health and sanitized redaction evidence, if deployed.
- Policy template selected.
- Seat limit and first seat report.
- Known gaps, if any, with owner and due date.
- Approval routing spot-check showing a synthetic held prompt assigned to the
  expected group and SLA without raw prompt text in the exported evidence.

The handoff packet must not contain:

- Admin password.
- MFA seed or `otpauth://` URI.
- Ingest key.
- `SENTINEL_SECRET`.
- `SENTINEL_DATA_KEY`.
- `PROMPTWALL_SECRET`.
- `PROMPTWALL_DATA_KEY`.
- SIEM token.
- Raw prompts.
- Real customer data.

## Rollback And Emergency Actions

If deployment fails before customer use:

1. Stop sensor rollout.
2. Save CloudFormation events and CloudWatch logs.
3. Fix the blocker and redeploy, or delete the failed stack.
4. Confirm whether the EC2 root EBS volume was retained.
5. Do not delete retained volumes until evidence disposition is approved.

If a secret is exposed:

1. Stop sensor rollout.
2. Rotate the exposed secret in Secrets Manager or the customer vault.
3. Redeploy or restart the container so it receives the new value.
4. Update managed sensor policy or endpoint/MCP config if the ingest key changed.
5. Record the rotation evidence in the handoff packet.

If production is live and unhealthy:

1. Check `/readyz`.
2. Check CloudWatch logs.
3. Open SSM only through approved IAM access.
4. Verify the container is running.
5. Verify audit-chain integrity before any backup or restore.
6. Escalate before deleting data, changing retention, or replacing the database.

## Common Troubleshooting

| Symptom | Check |
| --- | --- |
| `/readyz` is not 200 | Open `/api/preflight` as admin, then check secret lengths, MFA, secure cookie, local SQLite path, tenant id, seat limit, SCIM token length, and OIDC completeness if configured. |
| ALB target is unhealthy | Check instance user data, Docker pull, container logs, security groups, and `/readyz` from the instance. |
| Docker cannot pull from ECR | Check instance role permissions, ECR repository region, image URI, and subnet outbound internet access. |
| Admin login fails | Confirm password delivery, MFA seed enrollment, current TOTP code, and lockout status. |
| OIDC login fails | Confirm `OIDC_ISSUER`, client id, client secret, redirect URI, issuer discovery or explicit endpoints, clock sync, and that the IdP user maps to an active SCIM `userName`. |
| Extension has no config | Reload `chrome://policy`, confirm extension id, force-install policy, and managed storage keys. |
| Browser install health shows attention | In Coverage, inspect failed check IDs. Reload `chrome://policy`, confirm managed config, tenant id, user identity, and extension version, then restart Chrome or wait for the `installHeartbeat` alarm. |
| Events are rejected | Check `orgId`, managed user identity, ingest key, tenant slug, and seat limit. |
| SCIM provisioning fails | Confirm the IdP base URL ends in `/scim/v2`, the bearer token matches `SCIM_BEARER_TOKEN`, the token is at least 32 characters, and writes use `application/scim+json`. |
| Endpoint agent does not start | Check Node on PATH, scheduled task status, config ACL, log path, and ingest key. |
| Endpoint install health shows attention | Run `npm run endpoint:check -- --env <path> --json`, fix the failed check IDs, then rerun with `--emit-heartbeat`. |
| MCP guard install health shows attention | Run `npm run mcp:check -- --env <path> --json`, fix the failed check IDs, then rerun with `--emit-heartbeat`. |
| Fleet row is missing or unknown | Confirm the sensor emits `user`, `orgId`, `source`, `sensor.version`, and install-health checks. Missing required sensors are expected until each user has a heartbeat or event from that sensor. |
| Audit verification fails | Stop handoff, preserve the database and logs, and escalate before backup, restore, or data deletion. |

## Works Cited

Amazon Web Services. "Amazon EBS Encryption." *Amazon EBS User Guide*, Amazon
Web Services, https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html.
Accessed 27 June 2026.

Amazon Web Services. "AWS Systems Manager Session Manager." *AWS Systems
Manager User Guide*, Amazon Web Services,
https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html.
Accessed 27 June 2026.

Amazon Web Services. "Deploy." *AWS CLI Command Reference*, Amazon Web
Services, https://docs.aws.amazon.com/cli/latest/reference/cloudformation/deploy/index.html.
Accessed 27 June 2026.

Amazon Web Services. "Pushing a Docker Image to an Amazon ECR Private
Repository." *Amazon ECR User Guide*, Amazon Web Services,
https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-push-ecr-image.html.
Accessed 27 June 2026.

Amazon Web Services. "Tenant Isolation." *AWS Well-Architected SaaS Lens*,
Amazon Web Services,
https://docs.aws.amazon.com/wellarchitected/latest/saas-lens/tenant-isolation.html.
Accessed 27 June 2026.

Amazon Web Services. "What Is AWS Secrets Manager?" *AWS Secrets Manager User
Guide*, Amazon Web Services,
https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html.
Accessed 27 June 2026.

Google. "Automatically Install Apps and Extensions." *Chrome Enterprise and
Education Help*, Google, https://support.google.com/chrome/a/answer/6306504.
Accessed 27 June 2026.

Microsoft. "Tutorial: Develop and Plan Provisioning for a SCIM Endpoint in
Microsoft Entra ID." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups.
Accessed 28 June 2026.

Joint Task Force. *Security and Privacy Controls for Information Systems and
Organizations*. NIST Special Publication 800-53 Revision 5, National Institute
of Standards and Technology, Sept. 2020,
https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final. Accessed 27 June 2026.

SQLite Consortium. "Appropriate Uses for SQLite." *SQLite Documentation*,
SQLite Consortium, https://www.sqlite.org/whentouse.html. Accessed 27 June
2026.
