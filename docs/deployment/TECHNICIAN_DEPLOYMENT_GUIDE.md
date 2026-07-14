# Technician Production Deployment Guide

> **Connected-first prerequisite:** Owner enrollment must first publish the
> exact deployment identity, purpose-separated channel credentials, verifier
> pins, signed entitlement, and deployment-bound active outage artifact. The
> customer deployment command fails closed when any value is missing or stale.

This guide describes the technician workflow for installing RedactWall and
handing the environment over as production ready after the release gate above
has closed.

Use it as the install-day runbook. `docs/deployment/DEPLOYMENT.md` and
`docs/deployment/AWS_SAAS_DEPLOYMENT.md` are the deeper reference docs.

## Production-Ready Definition

A customer is production ready only when all of these are true:

- The customer has one isolated AWS customer-silo stack.
- The public console URL is HTTPS with a customer-approved DNS name.
- `/healthz` and `/readyz` return HTTP 200.
- The Licensing tab reports `active` with the contracted tenant, plan, seats,
  and expiry.
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
- Separately modeled, encrypted, retained EBS data volume mounted through the
  identity-verified `/var/lib/redactwall/runtime` host path at `/data`.
- SQLite evidence store at `/data/redactwall.db`.
- AWS Secrets Manager for the signed bounded outage fallback plus admin, MFA, session,
  data encryption, and ingest secrets. The private license signing key remains
  on the approved offline signing workstation.
- CloudWatch Logs for container logs.
- Systems Manager Session Manager for operator access. No SSH ingress is
  required by the template.
- App-level SaaS controls:
  - `REDACTWALL_SAAS_MODE=true`
  - `REDACTWALL_TENANT_ID=<customer-slug>`
  - `REDACTWALL_CONNECTED_DEPLOYMENT_ID=dep_<32-lowercase-hex>`
  - `REDACTWALL_LICENSE_MANAGED_EXTERNALLY=true`
  - `REDACTWALL_LICENSE_MODE=connected`
  - `REDACTWALL_REQUIRE_TENANT_CONTEXT=true`
  - `REDACTWALL_REQUIRE_USER_IDENTITY=true`

RedactWall also accepts the legacy `PROMPTWALL_*`/`SENTINEL_*` aliases for those `REDACTWALL_*` runtime
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
  cd C:\Source\redactwall
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
  written approval from the customer owner and RedactWall owner.

## Customer Intake Worksheet

Collect this before install day:

| Item | Required value |
| --- | --- |
| Customer display name | Legal or operating name. |
| Tenant slug | Lowercase, 2-63 chars, `a-z`, `0-9`, `_`, or `-`; example `cu-acme`. |
| Owner enrollment | Exact tenant, immutable `dep_` deployment id, plan, seats, and feature entitlement. |
| Outage fallback expiry | Owner-issued active fallback expiry and approved maximum outage window. |
| AWS account id and region | Region must have ACM, ECR, EC2, ELB, CloudWatch, Secrets Manager, and SSM. |
| VPC id | VPC for the customer stack. |
| Public subnet ids | At least two public subnets for the ALB. |
| Instance subnet id | Subnet with outbound internet access to pull from ECR. |
| Customer DNS name | Example `redactwall.customer.example`. |
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
$EnvPath = Join-Path $env:TEMP "redactwall-$TenantId.env"
npm run setup:prod -- --customer-id $TenantId --skip-install --env $EnvPath
npm run mfa:uri -- --env $EnvPath --issuer "RedactWall $TenantId"
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
npm run release:extension:check -- dist/browser-extension --chrome-extension-id <chrome-web-store-id> --edge-extension-id <edge-addons-id> --firefox-install-url https://downloads.customer.example/redactwall-firefox.xpi
```

Record the generated artifact names and SHA-256 manifests:

- `dist/browser-extension/`
- `dist/endpoint-agent/`
- `dist/mcp-guard/`

The browser extension folder should include Chrome, Edge, and Firefox zips,
integrity manifests, and the shared release-readiness report. When browser store
IDs or a Firefox install URL are supplied, it should also include target-specific
`redactwall-<browser>-extension-v<version>.extension-settings.json` files with
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
$TaggedImage = "$Registry/redactwall:$ImageTag"
```

Create the ECR repository once if it does not already exist:

```powershell
aws ecr describe-repositories --repository-names redactwall --region $AwsRegion 2>$null
if ($LASTEXITCODE -ne 0) {
  aws ecr create-repository --repository-name redactwall --region $AwsRegion
}
```

Build, authenticate, and push:

```powershell
aws ecr get-login-password --region $AwsRegion |
  docker login --username AWS --password-stdin $Registry

docker build -t $TaggedImage .
docker push $TaggedImage
$ImageDigest = aws ecr describe-images `
  --repository-name redactwall `
  --image-ids imageTag=$ImageTag `
  --query "imageDetails[0].imageDigest" `
  --output text `
  --region $AwsRegion
$Image = "$Registry/redactwall@$ImageDigest"
```

Record the digest-pinned `$Image` in the handoff packet. Do not substitute the
human-readable tag when supplying CloudFormation `ImageUri`.

## Phase 4: Create The Customer Secret

Use the env file from Phase 1 as the source for strong generated values, or use
the customer's approved vault-generated values. Obtain the exact active,
deployment-bound fallback and public trust pins from Owner enrollment. Create a
temporary secret JSON outside the repo:

```powershell
$DeploymentId = "dep_0123456789abcdef0123456789abcdef"
$OfflineRootPublicKey = "X:\secure-offline\license-signing-public.pem"
$LicensePath = "X:\owner-handoff\$TenantId-$DeploymentId-fallback.lic"

$LicenseText = [System.IO.File]::ReadAllText($LicensePath).TrimEnd([char[]]"`r`n")
if ([string]::IsNullOrWhiteSpace($LicenseText) -or
    $LicenseText.Length -gt 65535 -or
    $LicenseText -match '[\x00-\x1f\x7f]') {
  throw "The issued license is not a bounded one-line envelope."
}
$LicenseRootPublicKeyB64 = node -e "const c=require('crypto'),f=require('fs');const k=c.createPublicKey(f.readFileSync(process.argv[1]));process.stdout.write(k.export({type:'spki',format:'der'}).toString('base64'))" $OfflineRootPublicKey
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($LicenseRootPublicKeyB64)) {
  throw "The production license-root public key could not be encoded."
}
npm run license:trust-check -- --public-key-file $OfflineRootPublicKey
if ($LASTEXITCODE -ne 0) { throw "The production license-root trust check failed." }

$SecretPath = Join-Path $env:TEMP "redactwall-$TenantId-secret.json"
$SecretJson = @{
  ADMIN_PASSWORD = "<16-plus-random-chars>"
  ADMIN_TOTP_SECRET = "<base32-totp-secret>"
  REDACTWALL_SECRET = "<32-plus-random-chars>"
  REDACTWALL_DATA_KEY = "<32-plus-random-chars>"
  REDACTWALL_LICENSE = $LicenseText
  REDACTWALL_LICENSE_PUBLIC_KEY_B64 = $LicenseRootPublicKeyB64
  INGEST_API_KEY = "<32-plus-random-chars>"
  OPERATOR_USER = ""
  OPERATOR_PASSWORD = ""
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
  REDACTWALL_LICENSE_SERVER_URL = "https://license.vendor.example"
  REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN = "<owner-issued-32-plus-chars>"
  REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN = "<distinct-owner-issued-32-plus-chars>"
  REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN = ""
  REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN = ""
  REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED = "false"
  REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED = "false"
  REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS = ""
  REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS = ""
  REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64 = "<current-online-verdict-public-SPKI-DER-base64>"
  REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64 = ""
  REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64 = "<current-entitlement-public-SPKI-DER-base64>"
  REDACTWALL_ENTITLEMENT_KEY_ID = "rw-entitlement-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64 = ""
  REDACTWALL_ENTITLEMENT_NEXT_KEY_ID = ""
} | ConvertTo-Json -Depth 2

[System.IO.File]::WriteAllText(
  $SecretPath,
  $SecretJson,
  [System.Text.UTF8Encoding]::new($false)
)
$LicenseText = $null
$LicenseRootPublicKeyB64 = $null
```

The `.lic` file is a signed bounded outage artifact, not primary commercial
authority. Its embedded `status` must be `active`; `customerId` and
`deploymentId` must exactly equal `$TenantId` and `$DeploymentId`.
Never add the private signing key or its passphrase to the secret JSON. The
CloudFormation bootstrap writes only the signed envelope to the encrypted data
volume after the pulled production image verifies its Ed25519 signature,
tenant and deployment binding, purpose-separated public pins, credential and
consent pairings, and active state over stdin with no network. The artifact is
never a process argument. The application verifies it again at startup.

Create or update the AWS secret:

```powershell
$SecretName = "redactwall/$TenantId"
aws secretsmanager describe-secret --secret-id $SecretName --region $AwsRegion 2>$null
if ($LASTEXITCODE -eq 0) {
  $LicenseSecretVersionId = aws secretsmanager put-secret-value `
    --secret-id $SecretName `
    --secret-string file://$SecretPath `
    --query VersionId `
    --output text `
    --region $AwsRegion
} else {
  $LicenseSecretVersionId = aws secretsmanager create-secret `
    --name $SecretName `
    --secret-string file://$SecretPath `
    --query VersionId `
    --output text `
    --region $AwsRegion
}
if ($LASTEXITCODE -ne 0 -or
    $LicenseSecretVersionId -notmatch '^[A-Za-z0-9-]{32,64}$') {
  throw "The immutable Secrets Manager version id was not returned."
}
```

`$LicenseSecretVersionId` is non-secret deployment metadata. It binds cfn-init to
the exact immutable secret snapshot and must be passed to CloudFormation. Merely
changing `AWSCURRENT` behind the same secret ARN does not trigger cfn-hup.

If the secret already exists, use the customer's approved secret-update process.
Do not overwrite production secrets casually. After the secret exists and the
MFA seed is enrolled, remove the local temporary secret file according to the
customer's secure deletion process. Move the issued `.lic` file into the
approved customer handoff record or remove its temporary copy; keep the offline
private key in its original protected location.

## Phase 5: Deploy The Customer Stack

Set the stack parameters:

```powershell
$StackName = "redactwall-$TenantId"
$VpcId = "vpc-xxxxxxxx"
$PublicSubnetIds = "subnet-aaaaaaa,subnet-bbbbbbb"
$InstanceSubnetId = "subnet-aaaaaaa"
$InstanceAvailabilityZone = "us-east-1a" # must be the AZ of InstanceSubnetId
$DataStackName = "$StackName-data"
$CertificateArn = "arn:aws:acm:us-east-1:123456789012:certificate/example"
$PublicHostname = "$TenantId.redactwall.customer.example"
$SecretArn = aws secretsmanager describe-secret `
  --secret-id "redactwall/$TenantId" `
  --query ARN `
  --output text `
  --region $AwsRegion
$AmiId = aws ssm get-parameter `
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 `
  --query Parameter.Value --output text --region $AwsRegion
$ArtifactBucket = npm run --silent silo:artifacts:init -- --region $AwsRegion
```

The artifact bootstrap is a one-time account-and-region step. It enforces
private access, default encryption, versioning, bucket-owner enforcement,
TLS-only access, same-account bucket-policy writers, and expected-owner checks
on every S3 operation. Store CloudFormation templates only. Never upload
customer secret JSON, licenses, private keys, or other runtime secrets.

Create the retained data stack once and capture its exact volume id:

```powershell
aws cloudformation deploy `
  --template-file infra/aws/customer-data-volume.yml `
  --stack-name $DataStackName `
  --region $AwsRegion `
  --parameter-overrides TenantId=$TenantId AvailabilityZone=$InstanceAvailabilityZone
$DataVolumeId = aws cloudformation describe-stacks `
  --stack-name $DataStackName --region $AwsRegion `
  --query "Stacks[0].Outputs[?OutputKey=='DataVolumeId'].OutputValue" --output text
if ($DataVolumeId -notmatch '^vol-[a-f0-9]{8,17}$') { throw "Invalid retained data volume id" }
```

Snapshot recovery is explicit: create a new durable-data stack and pass both
`SnapshotId=snap-...` and `SourceDataVolumeId=vol-...`, then use the maintenance
restore workflow below. The source id and tenant must match the marker stored in
the snapshot. A preformatted volume without that marker is rejected. Only a
blank, no-snapshot companion volume no more than one hour old can receive a new
version 3 marker. Snapshot recovery rewrites the existing marker as version 4
with the new volume and retained source lineage.

Validate the small durable-data template directly. The application template is
larger than CloudFormation's inline template limit. The deploy wrapper uploads
it by SHA-256, captures the exact S3 `VersionId`, verifies that version's S3
checksum and encryption, then uses the same version-bound `TemplateURL` for
validation and stack mutation:

```powershell
aws cloudformation validate-template `
  --template-body file://infra/aws/customer-data-volume.yml `
  --region $AwsRegion
```

Deploy:

```powershell
npm run silo:deploy -- `
  --stack-name $StackName `
  --region $AwsRegion `
  --vpc-id $VpcId `
  --public-subnet-ids $PublicSubnetIds `
  --instance-subnet-id $InstanceSubnetId `
  --instance-availability-zone $InstanceAvailabilityZone `
  --data-stack-name $DataStackName `
  --data-volume-id $DataVolumeId `
  --ami-id $AmiId `
  --artifact-bucket $ArtifactBucket `
  --image-uri $Image `
  --secret-arn $SecretArn `
  --secret-version-id $LicenseSecretVersionId `
  --tenant-id $TenantId `
  --deployment-id $DeploymentId `
  --certificate-arn $CertificateArn `
  --public-hostname $PublicHostname
```

This is the supported update command. It prevalidates the image and immutable
secret on the current host, applies the stack, then waits for a bounded SSM
apply-and-attest command. Do not accept CloudFormation `UPDATE_COMPLETE` alone
as evidence that the requested runtime is live.
It refuses to change the tenant, deployment identity, data stack, data volume, Availability Zone,
AMI, instance type, or root volume on an existing silo. A stack policy denies
ordinary instance and attachment replacement. It also validates the live
volume's encryption, gp3 and non-MultiAttach topology, CloudFormation ownership
tags, tenant tags, exact attachment, and the certificate's account, region,
`ISSUED` status, and hostname coverage before mutation.

The command intentionally refuses an older root-volume-only stack that does
not publish `DataVolumeId` and `InstanceAvailabilityZone`. Take and verify a
backup, create the retained-volume stack, and restore through the documented
backup/restore workflow. Do not let an in-place template update create an empty
data volume beside the only copy of customer evidence.

Owner-signed connected entitlements are the plan, seat, feature, pause, and
revoke authority. Do not use the in-console license installer. For an outage
fallback or public-pin rotation, publish a new immutable secret version, capture
its returned version id, and rerun this command with the same exact
`--deployment-id`. The host rejects an inactive, missing, malformed, or sibling
deployment fallback before changing the installed file. The template also sets
`REDACTWALL_LICENSE_MANAGED_EXTERNALLY=true`; both in-app license-install APIs
return `license_managed_externally` without changing the file.

For an AMI, instance-type, or root-volume replacement, schedule an outage,
copy the complete deploy command above, keep every argument, set only the
approved replacement values, and replace its first line with:

```powershell
npm run silo:maintenance -- --mode replace-instance `
```

For volume snapshot recovery, create a new durable-data stack from the snapshot,
copy the complete deploy command, change only its data stack, volume, and source
volume arguments, and replace its first line with:

```powershell
npm run silo:maintenance -- --mode restore-volume `
```

The maintenance command creates a verified authenticated recovery set in a
root-owned sibling outside the candidate data mount, captures and verifies the
exact prior versioned template contract, stops and drains the only writer,
deregisters it from the ALB, deletes the application stack to detach the gp3
volume, and creates the requested stack. If creation fails, it deletes the
failed stack, redeploys that captured prior template version, restores the
retained backup, verifies the audit chain, and only then starts the prior
writer. A failed restore or verification remains stopped and deregistered.
Update customer DNS to the returned ALB DNS name after either cutover or
rollback. Never update the original durable-data stack in place and never
attach or detach the evidence volume by hand.

If apply-and-attest reports `committed_cleanup_pending`, the healthy runtime is
already committed but exact prior artifacts remain journaled. Rerun the same
deploy command. Cleanup runs before the same-configuration fast path on every
attempt, the warning remains visible while failure repeats, and a different
configuration is rejected until cleanup and warning removal both succeed.

Every production silo is connected. Heartbeat and acknowledgement credentials
are mandatory and distinct. Enabled diagnostic or Shadow AI candidate channels
require their own distinct credential and exact consent. Current offline,
online-verdict, and entitlement public pins are mandatory and pairwise distinct;
next entitlement key and exact key ID rotate as a pair. Never reuse signing
identities across purposes or add the removed shared license-server token.

Get the ALB DNS target for the customer alias and the canonical URL:

```powershell
$AlbDnsName = aws cloudformation describe-stacks `
  --stack-name $StackName `
  --query "Stacks[0].Outputs[?OutputKey=='LoadBalancerDnsName'].OutputValue" `
  --output text `
  --region $AwsRegion
$Url = aws cloudformation describe-stacks `
  --stack-name $StackName `
  --query "Stacks[0].Outputs[?OutputKey=='Url'].OutputValue" `
  --output text `
  --region $AwsRegion
$AlbDnsName
$Url
```

Point `$PublicHostname` to `$AlbDnsName` according to the customer's DNS
process. Production is not ready until the alias resolves and HTTPS works at
the final customer DNS name. Do not health-check the raw ALB hostname because
it is not covered by the customer certificate.

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
sudo docker logs --tail 100 redactwall
sudo stat -c '%u:%g %a %h %s' /etc/redactwall/license/redactwall.lic
sudo /usr/local/sbin/redactwall-verify-data-volume
sudo docker exec redactwall node -e "const v=require('./server/db').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"
sudo docker exec redactwall npm run backup -- /data/backups
```

Also check CloudWatch logs:

```powershell
$LogGroupName = aws cloudformation describe-stacks `
  --stack-name $StackName `
  --query "Stacks[0].Outputs[?OutputKey=='LogGroupName'].OutputValue | [0]" `
  --output text `
  --region $AwsRegion

if ([string]::IsNullOrWhiteSpace($LogGroupName) -or $LogGroupName -eq "None") {
  throw "Stack output LogGroupName was not found."
}

aws logs tail $LogGroupName --since 30m --region $AwsRegion
```

Save health, readiness, audit-chain, backup, and log evidence in the handoff
packet. Do not include secret values.

## Phase 7: Security Admin Setup

With the customer's Security Admin:

1. Open the final HTTPS console URL.
2. Log in with `ADMIN_USER` and `ADMIN_PASSWORD`.
3. Enter the current MFA code from the enrolled authenticator app.
4. Open the dashboard preflight view and confirm no blockers.
5. Open the Licensing tab and confirm `active`, the expected tenant, plan,
   seats, and expiry. Do not paste or capture the license envelope in evidence.
6. Select the agreed policy template.
7. Confirm the approval queue is empty before sensor rollout.
8. Confirm approver login, if configured, can approve or deny assigned approval
   items and cannot reveal raw prompts, purge retention, edit policy, or review
   governed destinations.
9. Confirm auditor login, if configured, can view sanitized evidence and cannot
   approve, deny, reveal, purge, or edit policy.
10. If SCIM or OIDC is planned, open the dashboard Identity tab or run
   `npm run identity:setup -- --provider entra --base-url https://<customer-host> --tenant-id <tenant>`
   or `npm run identity:setup -- --provider okta --base-url https://<customer-host> --tenant-id <customer.okta.com>`
   and attach only the secret-free values to the handoff.
11. If SCIM is configured, have the identity admin call
   `/scim/v2/ServiceProviderConfig` with the bearer token and confirm
   `patch.supported=true` and `filter.supported=true`.
12. If OIDC is configured, confirm the login page shows `Continue with SSO`,
    sign in as one active SCIM-provisioned test user, and verify `/api/me`
    reports the expected role without using a local console password.

If MFA enrollment fails, stop the rollout and rotate `ADMIN_TOTP_SECRET` through
the approved secret process.

## Phase 8: Browser Extension Rollout

Use `docs/deployment/MANAGED_EXTENSION_DEPLOYMENT.md` for the full managed browser policy reference.
Use `docs/deployment/EXTENSION_RELEASE_CHECKLIST.md` before uploading or handing over a
Chrome, Edge, or Firefox managed extension package.
For install day, the technician must confirm these values in managed storage:

```json
{
  "serverUrl": "https://redactwall.customer.example",
  "ingestKey": "customer-ingest-key-from-approved-vault",
  "policyPublicKey": "-----BEGIN PUBLIC KEY-----\\ncustomer-policy-pin\\n-----END PUBLIC KEY-----",
  "orgId": "cu-acme",
  "email": "${user_email}",
  "enabled": true
}
```

Validation on one managed test device:

1. Open the browser policy page and reload policies: `chrome://policy`,
   `edge://policy`, or `about:policies`.
2. Confirm the extension is force-installed.
3. Confirm the extension receives managed storage.
4. Open the extension popup, grant the exact remote HTTPS control-plane origin,
   and confirm protection is enabled. If the grant is denied, the extension
   remains fail closed and install health reports `server_host_permission=false`.
5. In the popup, select **Allow exact sites** for every pending custom governed
   destination. Built-in AI hosts are already covered. A custom host remains
   browser-blocked and reports `custom_destination_coverage=false` until its
   exact optional host grant and dynamic content-script registration succeed.
6. Open an approved AI destination.
7. Confirm the Coverage tab shows a `browser_extension` install-health heartbeat
   with passing checks for managed config, managed identity, org id, server URL,
   ingest-key presence, content-script coverage, and policy cache availability.
   The Fleet Install Health table should show the test user, org, browser
   sensor version, platform, `covered` state, and `checks ok`.
8. Send a benign prompt and confirm it is attributed to the test user.
9. Paste `123-45-6789` as synthetic SSN test data.
10. Confirm the configured policy action appears in the browser.
11. Confirm the dashboard shows the event under the right user and tenant.
12. Add a disposable host to `blockedDestinations`, refresh policy, and confirm
    a send attempt records `destination_blocked` without prompt text.
13. Add the same host to `blockedFileUploadDestinations`, remove it from
    `blockedDestinations`, and confirm an upload attempt records
    `file_upload_blocked` without file content.
14. Visit an ungoverned AI host and confirm shadow-AI discovery appears.

Do not proceed to broad rollout until this managed test device passes.

## Phase 9: Endpoint Agent Rollout

For a per-user Windows pilot install:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -RedactWallUrl "https://redactwall.customer.example" `
  -IngestKey "<customer-ingest-key>" `
  -WatchDir "$env:USERPROFILE\RedactWallWatch"
```

For an all-user managed install from elevated PowerShell, use a managed config
directory:

```powershell
.\scripts\install-endpoint-agent.ps1 `
  -RedactWallUrl "https://redactwall.customer.example" `
  -IngestKey "<customer-ingest-key>" `
  -WatchDir "C:\RedactWallWatch" `
  -ConfigDir "$env:ProgramData\RedactWall"
```

Validate:

```powershell
Get-ScheduledTask -TaskName RedactWallEndpointAgent
Get-Content "$env:LOCALAPPDATA\RedactWall\logs\endpoint-agent.log" -Tail 40
npm run endpoint:check -- `
  --env "$env:LOCALAPPDATA\RedactWall\endpoint-agent.env" `
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
   - `REDACTWALL_URL=https://redactwall.customer.example`
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

Coordinate the signed-entitlement seat test with the customer and Owner. If the
customer purchased only a small number of seats, use an Owner-approved temporary
entitlement on a test deployment; never add a local static seat override.

## Phase 12: Backup And Recovery Evidence

Create and verify at least one backup before handoff:

```bash
sudo docker exec redactwall npm run backup -- /data/backups
sudo docker exec redactwall ls -l /data/backups
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
sudo docker exec redactwall npm run evidence:pack:zip -- /data/evidence-packs \
  /data/backups/redactwall-YYYY-MM-DDTHH-MM-SS-sssZ.db \
  /data/restored-redactwall.db
```

For recurring reporting, copy `config/evidence-schedule.example.json` to
`config/evidence-schedule.json`, set the cadence and output folder, and invoke
`npm run evidence:pack:scheduled -- <file>` from Task Scheduler, cron, or the
customer's runbook scheduler. On Windows hosts, install the standard local task:

```powershell
npm run evidence:pack:install-task
```

The task writes run status to
`%LOCALAPPDATA%\RedactWall\logs\evidence-pack.log` and keeps raw prompt bodies,
environment secrets, release tokens, and uploaded file bytes out of the task
definition and generated pack. Keep the generated JSON or zip in the approved
evidence location, not in email or a synced personal folder.

On Linux or AWS Docker hosts, put the schedule config in the mounted data folder
and install the standard systemd timer:

```bash
sudo cp config/evidence-schedule.example.json /var/lib/redactwall/runtime/evidence-schedule.json
sudo editor /var/lib/redactwall/runtime/evidence-schedule.json
sudo npm run evidence:pack:install-systemd -- \
  --mode docker \
  --container redactwall \
  --config /data/evidence-schedule.json \
  --on-calendar quarterly
```

Set `outDir` to `/data/evidence-packs`. The timer writes status to
`/var/log/redactwall/evidence-pack.log`, uses `Persistent=true` for missed
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
- `REDACTWALL_SECRET`.
- `REDACTWALL_DATA_KEY`.
- `REDACTWALL_DATA_KEY_PREVIOUS`.
- `REDACTWALL_SECRET`.
- `REDACTWALL_DATA_KEY`.
- `REDACTWALL_DATA_KEY_PREVIOUS`.
- SIEM token.
- Raw prompts.
- Real customer data.

## Rollback And Emergency Actions

If deployment fails before customer use:

1. Stop sensor rollout.
2. Save CloudFormation events and CloudWatch logs.
3. Fix the blocker and redeploy, or delete the failed stack.
4. Record the `DataVolumeId` output and verify the separately modeled customer
   data volume remains retained. The replaceable EC2 root volume is disposable.
5. Do not delete retained volumes until evidence disposition is approved.

If a secret is exposed:

1. Stop sensor rollout.
2. Rotate the exposed secret in Secrets Manager or the customer vault.
3. Redeploy or restart the container so it receives the new value.
4. Update managed sensor policy or endpoint/MCP config if the ingest key changed.
5. Record the rotation evidence in the handoff packet.

If `REDACTWALL_DATA_KEY` (or `REDACTWALL_SECRET` while no dedicated data key is
set) is the exposed value, rotate it without losing sealed evidence:

1. Set `REDACTWALL_DATA_KEY` to the new key and `REDACTWALL_DATA_KEY_PREVIOUS` to
   the exposed key in Secrets Manager or the customer vault, then restart the
   container. Sealed records stay readable during the transition.
2. Run `node scripts/rotate-data-key.js --dry-run` inside the container to
   preview, then run it without `--dry-run` to re-encrypt retained raw prompts
   and token vaults under the new key. Output is counts only; it never prints
   prompt text or key material, and it appends a `DATA_KEY_ROTATED` audit
   entry.
3. When the run reports `unreadable: 0`, remove `REDACTWALL_DATA_KEY_PREVIOUS`
   and restart. A non-zero exit means some sealed values opened with neither
   key — keep the old key configured and escalate before retiring it.
4. Record the rotation evidence in the handoff packet.

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
