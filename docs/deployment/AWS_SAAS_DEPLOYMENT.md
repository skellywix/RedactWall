# AWS SaaS Deployment

This is the connected-first customer-silo model: one isolated customer data
plane per stack, managed by the vendor Owner control plane. Owner provisioning
must supply the exact tenant, immutable `dep_` deployment identity, scoped
channel credentials, signed outage fallback, and current trust pins before this
customer-side deployment command can run.

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
- A separate durable-data CloudFormation stack (`customer-data-volume.yml`)
  that owns one encrypted EBS data volume with retain policies,
  tenant-bound identity marker, and boot-time mount verification. Planned host
  replacement uses the outage-safe maintenance workflow to detach and reattach
  this volume instead of silently starting an empty evidence store.
  Automatic first format is allowed only after the instance role proves the
  blank device is the companion stack's newly created, encrypted, no-snapshot EBS volume;
  an old or ambiguous blank retained volume fails closed.
- Docker runtime state under `/data`: `redactwall.db`, `policy.json`,
  `.policy-bundle-key.pem`,
  `custom-detectors.json`, backups, and scheduled examiner evidence packs.
- Hardened container flags: init process, read-only root filesystem, writable
  `/tmp` tmpfs, dropped Linux capabilities, and `no-new-privileges`.
- Secrets Manager for the signed bounded outage fallback plus admin, optional approver
  and auditor, MFA, session, data-encryption, and ingest secrets. The offline
  license signing key is never deployed to AWS.
- CloudWatch Logs for container stdout/stderr.
- Systems Manager Session Manager for operator access. No SSH ingress is
  required by the template.
- App-level SaaS mode:
  - `REDACTWALL_SAAS_MODE=true`
  - `REDACTWALL_TENANT_ID=<customer-slug>`
  - `REDACTWALL_CONNECTED_DEPLOYMENT_ID=dep_<32-lowercase-hex>`
  - `REDACTWALL_LICENSE_MANAGED_EXTERNALLY=true`
  - `REDACTWALL_LICENSE_MODE=connected`
  - `REDACTWALL_REQUIRE_TENANT_CONTEXT=true`
  - `REDACTWALL_REQUIRE_USER_IDENTITY=true`

The current CloudFormation template writes the canonical `REDACTWALL_*` and
`INGEST_API_KEY` names. The runtime also accepts the legacy
`PROMPTWALL_*`/`SENTINEL_*` aliases for those values, including `PROMPTWALL_SECRET`,
`PROMPTWALL_DATA_KEY`, `PROMPTWALL_INGEST_API_KEY`, and
`PROMPTWALL_SCIM_BEARER_TOKEN`, so customer secret stores that still emit the
older names keep working across the rebrand.

The AWS template pins mutable customer state to the retained volume's
`/var/lib/redactwall/runtime` directory, mounted at `/data`:
`REDACTWALL_DB_PATH=/data/redactwall.db`,
`REDACTWALL_POLICY_PATH=/data/policy.json`, and
`REDACTWALL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json`. The selected
signed license is separately published under the root-owned
`/etc/redactwall/license/` directory and mounted read-only at
`/license/redactwall.lic`. The root-only `0700` parent prevents host traversal;
the file is UID/GID 1000 mode `0400` so the container's non-root UID can read
it, while the single-file read-only bind prevents the application from
replacing, unlinking, or modifying it.
Do not store customer policy edits or detector packs only in the image layer.

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

Create the exact customer and deployment enrollment in Owner first. Record the exact immutable deployment identity,
for example `dep_0123456789abcdef0123456789abcdef`. Owner must issue a signed
connected-fallback license whose `status` is `active` and whose `customerId` and
`deploymentId` exactly match this stack. Copy only that signed one-line envelope
and public trust pins into the customer secret. Never copy the private signing key.
Do not copy any other private signing key, passphrase, vendor database credential,
Stripe credential, or unsigned payload into AWS.

Create a local `customer-secret.json` outside the repo or in a secure temporary
folder:

```json
{
  "ADMIN_PASSWORD": "replace-with-16-plus-random-chars",
  "ADMIN_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
  "REDACTWALL_SECRET": "replace-with-32-plus-random-chars",
  "REDACTWALL_DATA_KEY": "replace-with-32-plus-random-chars",
  "REDACTWALL_LICENSE": "base64-payload.base64-ed25519-signature",
  "REDACTWALL_LICENSE_PUBLIC_KEY_B64": "base64-SPKI-DER-production-root-public-key",
  "INGEST_API_KEY": "ps_ingest_replace_with_32_plus_random_chars",
  "OPERATOR_USER": "",
  "OPERATOR_PASSWORD": "",
  "SCIM_BEARER_TOKEN": "",
  "APPROVER_USER": "approver",
  "APPROVER_PASSWORD": "replace-with-16-plus-random-chars",
  "AUDITOR_USER": "auditor",
  "AUDITOR_PASSWORD": "replace-with-16-plus-random-chars",
  "OIDC_ISSUER": "",
  "OIDC_CLIENT_ID": "",
  "OIDC_CLIENT_SECRET": "",
  "OIDC_REDIRECT_URI": "",
  "OIDC_AUTHORIZATION_ENDPOINT": "",
  "OIDC_TOKEN_ENDPOINT": "",
  "OIDC_JWKS_URI": "",
  "OIDC_SCOPE": "openid profile email",
  "SIEM_WEBHOOK_URL": "",
  "SIEM_WEBHOOK_TOKEN": "",
  "REDACTWALL_LICENSE_SERVER_URL": "https://license.vendor.example",
  "REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN": "owner-issued-heartbeat-token-at-least-32-chars",
  "REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN": "owner-issued-acknowledgement-token-at-least-32-chars",
  "REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN": "",
  "REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN": "",
  "REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED": "false",
  "REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED": "false",
  "REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS": "",
  "REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS": "",
  "REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64": "base64-current-online-verdict-SPKI-DER",
  "REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64": "",
  "REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64": "base64-current-entitlement-SPKI-DER",
  "REDACTWALL_ENTITLEMENT_KEY_ID": "rw-entitlement-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64": "",
  "REDACTWALL_ENTITLEMENT_NEXT_KEY_ID": ""
}
```

`REDACTWALL_LICENSE` is the exact contents of the issued `.lic` file without
its trailing newline. The bootstrap rejects missing, oversized, multiline,
control-character, malformed, inactive, wrong-tenant, and sibling-deployment envelopes before
it changes the installed file. The bootstrap asks the pulled production image
to run the actual production connected-config and license preflight with no
network. It verifies Ed25519 signatures, public-only and purpose-separated trust
pins, exact credential and consent pairing, tenant and deployment binding, and
active fallback state. It never passes license bytes in process arguments or
prints secret values. The application verifies the file again at startup.

Convert the production offline-root public PEM to one-line SPKI DER base64 for
`REDACTWALL_LICENSE_PUBLIC_KEY_B64`:

```bash
node -e 'const c=require("crypto"),f=require("fs");const k=c.createPublicKey(f.readFileSync(process.argv[1]));process.stdout.write(k.export({type:"spki",format:"der"}).toString("base64"))' \
  /secure/offline/license-signing-public.pem
```

The value is a public trust anchor, not the signing key. Production preflight
rejects the repository's known placeholder. Run `npm run license:trust-check --
--public-key-file /secure/offline/license-signing-public.pem` before publishing
the customer secret.

The secret schema is closed. Unknown fields and partial integration groups fail
before any running container or license is changed. Approver, auditor, SCIM,
OIDC, SIEM, and connected-license fields shown above are the fields the stack
actually wires into the container.

Every production silo is connected. The heartbeat and acknowledgement tokens
are mandatory, distinct, customer-and-deployment scoped credentials. Diagnostic
and Shadow AI candidate tokens are optional only while their exact consent flags
are `false`; enabling a channel requires its separate token. Current offline,
online-verdict, and entitlement public identities are mandatory and pairwise
distinct. Next verdict is optional. Next entitlement public key and exact
`rw-entitlement-<64 lowercase hex>` key ID must appear together. Unknown fields,
the removed `REDACTWALL_LICENSE_SERVER_TOKEN`, partial key rotation, private key
material, or reused public identities fail before runtime mutation.

The host stages license bytes through a retained descriptor inside the root-only
deployment directory. A private, fsynced journal records the exact container
IDs and the device, inode, link count, size, and SHA-256 of every license
artifact before container or license mutation. An interrupted checked host apply is
reconciled before a new secret version is read. Rollback first confirms removal
of the exact candidate container, then restores only identity-proven artifacts;
it stops and retains recovery state instead of overwriting a changed path. Once
the ready candidate and journal reach the durable `committed` phase, later
cleanup or evidence-scheduler errors cannot turn the deployment into a failed
rollback.

Then create the secret:

```bash
LICENSE_SECRET_VERSION_ID=$(aws secretsmanager create-secret \
  --name redactwall/cu-acme \
  --secret-string file://customer-secret.json \
  --query VersionId \
  --output text)

test -n "$LICENSE_SECRET_VERSION_ID"
```

`LICENSE_SECRET_VERSION_ID` is not secret. It binds this deployment to one
immutable secret snapshot and is the CloudFormation change trigger for later
license or runtime-secret rotations.

The `ADMIN_TOTP_SECRET` must be enrolled in an authenticator app before customer
admins use the console. You can generate production-safe values with:

```bash
npm run setup:prod -- --customer-id cu-acme --skip-install --env aws-customer.env
npm run mfa:uri -- --env aws-customer.env --issuer "RedactWall cu-acme"
```

## 3. Deploy The Customer Stack

Create or verify the account-and-region CloudFormation artifact bucket once:

```bash
ARTIFACT_PREFIX=${ARTIFACT_PREFIX:-redactwall/cloudformation}
ARTIFACT_BUCKET=$(npm run --silent silo:artifacts:init -- \
  --region us-east-1 \
  --prefix "$ARTIFACT_PREFIX")
```

The bootstrap enforces block-public-access, bucket-owner enforcement, default
encryption, versioning, a TLS-only bucket policy, and rejects public or
cross-account bucket-policy writers. On the exact selected prefix it also denies
operation-authority `PutObject` calls unless either `If-Match` or
`If-None-Match` is present, and it unconditionally denies `DeleteObject` and
`DeleteObjectVersion` for that authority prefix so a current generation cannot
be erased and recreated from generation 1. The bucket must be initialized again with the new
prefix before a custom `ARTIFACT_PREFIX` can be used. Every S3 operation is
bound to the active account with `--expected-bucket-owner`. The deploy wrapper copies the exact
local template through a private file, uploads it under its SHA-256, captures
the returned S3 `VersionId`, verifies that exact version's checksum and
encryption, and uses the same version-bound `TemplateURL` for validation and
stack create or update. It never performs a second implicit upload. The bucket
contains CloudFormation templates only. Never put a license, secret JSON,
private key, or other runtime secret in it.

Create the durable data authority first, in the instance subnet's Availability
Zone. Never put this volume back into the replaceable application stack:

```bash
aws cloudformation deploy \
  --template-file infra/aws/customer-data-volume.yml \
  --stack-name redactwall-cu-acme-data \
  --region us-east-1 \
  --parameter-overrides TenantId=cu-acme AvailabilityZone=us-east-1a

DATA_VOLUME_ID=$(aws cloudformation describe-stacks \
  --stack-name redactwall-cu-acme-data --region us-east-1 \
  --query "Stacks[0].Outputs[?OutputKey=='DataVolumeId'].OutputValue" --output text)
```

For an explicit snapshot recovery, also pass `SnapshotId=snap-...` and
`SourceDataVolumeId=vol-...` to the durable-data stack. The source volume id
must be the exact id stored in the snapshot's tenant-bound volume marker. A
fresh volume can receive its first version 3 marker only when the host proves
it was created from no snapshot, is blank, and is no more than one hour old.
A preformatted volume without a marker is never adopted. Snapshot recovery
requires the existing marker and rewrites it as version 4 with the new volume
id, original source id, tenant id, and filesystem UUID. Audit startup must
still authenticate the restored checkpoint before readiness.

The durable-data template is small enough for direct validation. The application
template exceeds CloudFormation's inline 51,200-byte limit and is validated by
the artifact-backed deploy wrapper, so do not pass it to `--template-body`:

```bash
aws cloudformation validate-template \
  --template-body file://infra/aws/customer-data-volume.yml
```

Deploy:

```bash
SECRET_ARN=$(aws secretsmanager describe-secret \
  --secret-id redactwall/cu-acme \
  --query ARN \
  --output text)
AMI_ID=$(aws ssm get-parameter \
  --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query Parameter.Value --output text --region us-east-1)

npm run silo:deploy -- \
  --stack-name redactwall-cu-acme \
  --region us-east-1 \
  --vpc-id vpc-xxxxxxxx \
  --public-subnet-ids subnet-aaaaaaa,subnet-bbbbbbb \
  --instance-subnet-id subnet-aaaaaaa \
  --instance-availability-zone us-east-1a \
  --data-stack-name redactwall-cu-acme-data \
  --data-volume-id "$DATA_VOLUME_ID" \
  --ami-id "$AMI_ID" \
  --artifact-bucket "$ARTIFACT_BUCKET" \
  --image-uri "$IMAGE" \
  --secret-arn "$SECRET_ARN" \
  --secret-version-id "$LICENSE_SECRET_VERSION_ID" \
  --tenant-id cu-acme \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/example \
  --public-hostname redactwall.customer.example
```

`npm run silo:deploy` is the supported mutation path. Before changing the
stack, it asks the current instance to pull the exact image and validate the
exact secret/license snapshot. It then deploys CloudFormation, invokes the
bounded host apply through SSM, and returns success only after
`/etc/redactwall/applied-deployment.json` proves the requested image digest,
secret ARN and version, canonical rendering-config digest, container identity,
license digest, exact template and host-protocol digests, retained data-volume
identity, and retained recovery point. Even when the image and secret are
unchanged, the wrapper reruns the checked host apply and verifies the complete deployment
contract, so stale host files cannot satisfy the attestation fast path.
A failed image, secret, candidate, certificate, subnet, or volume topology
returns a nonzero command result. Existing stacks freeze `TenantId`,
`DeploymentId`,
`DataStackName`, `DataVolumeId`, Availability Zone, AMI, instance type, and root
volume size. A stack policy also denies ordinary replacement or deletion of the
instance and attachment. Use the maintenance workflow below for those changes.
Do not treat CloudFormation `UPDATE_COMPLETE` alone as runtime completion;
`cfn-hup` remains a recovery/drift mechanism, not the operator success signal.

`CertificateArn` and `PublicHostname` are required. The ALB always redirects
port 80 to its HTTPS listener, which prevents the console from advertising
secure session cookies over an HTTP-only endpoint. Use an ACM certificate issued
in the deployment region and account that is `ISSUED` and covers
`PublicHostname` exactly or through a one-label wildcard.

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

The supported command refuses to update a legacy stack that does not already
publish `DataVolumeId`, `InstanceAvailabilityZone`, and the exact immutable
`DeploymentId`. That guard prevents an older root-volume-only or
pre-`DeploymentId` stack from silently adopting empty storage or an invented
connected identity. `silo:maintenance` also refuses such a stack because it
cannot infer the missing identity. Use the explicit legacy reprovisioning outage
below instead of an ordinary update.

#### Reprovision a pre-`DeploymentId` AWS stack

This is a planned outage, not an in-place parameter update. The checked tool
uses two independently keyed private files: an authenticated manifest and a
monotonic witness/tombstone. It also acquires a deterministic external
CloudFormation lease that survives application-stack deletion. Keep the
operation directory outside the repository and outside the retained customer
volume.

Set the complete target facts first. `CONNECTED_SECRET_VERSION_ID` is the exact
Secrets Manager version that contains the deployment-bound active fallback,
current trust pins, and distinct heartbeat and acknowledgement credentials.

```bash
set -euo pipefail
umask 077
OP_DIR=/root/redactwall-connected-migration
install -d -m 700 "$OP_DIR"
openssl rand -base64 32 | tr -d '\n' > "$OP_DIR/manifest.key"
openssl rand -base64 32 | tr -d '\n' > "$OP_DIR/witness.key"
chmod 600 "$OP_DIR/manifest.key" "$OP_DIR/witness.key"
cmp -s "$OP_DIR/manifest.key" "$OP_DIR/witness.key" && exit 1

MANIFEST="$OP_DIR/migration.json"
WITNESS="$OP_DIR/migration.witness.json"
DEPLOY_ARGS="$OP_DIR/deploy-args.json"
SOURCE_TEMPLATE="$OP_DIR/source-template.json"
TARGET_SECRET="$OP_DIR/target-secret.json"
ARTIFACT_PREFIX=${ARTIFACT_PREFIX:-redactwall/cloudformation}
```

Create the complete deploy argument snapshot before `plan`. The plan copies it
through a bounded no-follow read into the private operation directory and binds
its bytes and SHA-256. Do not edit either copy afterward.

```bash
jq -n \
  --arg stack "$STACK_NAME" --arg region "$AWS_REGION" --arg vpc "$VPC_ID" \
  --arg publicSubnets "$PUBLIC_SUBNET_IDS" --arg instanceSubnet "$INSTANCE_SUBNET_ID" \
  --arg az "$INSTANCE_AVAILABILITY_ZONE" --arg image "$IMAGE_URI" \
  --arg secretArn "$SECRET_ARN" --arg secretVersion "$CONNECTED_SECRET_VERSION_ID" \
  --arg tenant "$TENANT_ID" --arg deployment "$DEPLOYMENT_ID" \
  --arg certificate "$CERTIFICATE_ARN" --arg hostname "$PUBLIC_HOSTNAME" \
  --arg volume "$DATA_VOLUME_ID" --arg bucket "$ARTIFACT_BUCKET" \
  --arg prefix "$ARTIFACT_PREFIX" --arg ami "$AMI_ID" --arg dataStack "$DATA_STACK_NAME" \
  --arg sourceVolume "${SOURCE_DATA_VOLUME_ID:-}" --arg instanceType "${INSTANCE_TYPE:-t3.small}" \
  --arg rootGb "${ROOT_VOLUME_GB:-20}" --arg timeout "${TIMEOUT_SECONDS:-1200}" '
    ["--stack-name",$stack,"--region",$region,"--vpc-id",$vpc,
     "--public-subnet-ids",$publicSubnets,"--instance-subnet-id",$instanceSubnet,
     "--instance-availability-zone",$az,"--image-uri",$image,
     "--secret-arn",$secretArn,"--secret-version-id",$secretVersion,
     "--tenant-id",$tenant,"--deployment-id",$deployment,
     "--certificate-arn",$certificate,"--public-hostname",$hostname,
     "--data-volume-id",$volume,"--artifact-bucket",$bucket,
     "--artifact-prefix",$prefix,"--ami-id",$ami,"--data-stack-name",$dataStack,
     "--source-data-volume-id",$sourceVolume,"--instance-type",$instanceType,
     "--root-volume-gb",$rootGb,"--timeout-seconds",$timeout]
  ' > "$DEPLOY_ARGS"
chmod 600 "$DEPLOY_ARGS"
```

The resulting `deploy-args.json` is the immutable complete argument source for
both the migration plan and cutover.

Capture the exact live original template, normalize only an object-valued JSON
template, and upload those bytes to the already hardened private, encrypted,
versioned artifact bucket. The migration tool downloads that exact version,
checks its metadata, checksum, size, and bytes, and compares its semantic digest
with `get-template` before acquiring the lease.

```bash
SOURCE_STACK_ID=$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" --region "$AWS_REGION" \
  --query 'Stacks[0].StackId' --output text)
aws cloudformation get-template --stack-name "$SOURCE_STACK_ID" \
  --template-stage Original --region "$AWS_REGION" --output json \
  > "$OP_DIR/get-template.json"
node - "$OP_DIR/get-template.json" "$SOURCE_TEMPLATE" <<'NODE'
const fs = require('fs');
const [input, output] = process.argv.slice(2);
const body = JSON.parse(fs.readFileSync(input, 'utf8')).TemplateBody;
const canonical = (value) => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]))
    : value;
fs.writeFileSync(output, typeof body === 'string' ? body : JSON.stringify(canonical(body)), { mode: 0o600 });
NODE
chmod 600 "$SOURCE_TEMPLATE"

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
SOURCE_TEMPLATE_SHA256=$(sha256sum "$SOURCE_TEMPLATE" | awk '{print $1}')
SOURCE_TEMPLATE_BYTES=$(wc -c < "$SOURCE_TEMPLATE" | tr -d ' ')
SOURCE_TEMPLATE_CHECKSUM=$(openssl dgst -sha256 -binary "$SOURCE_TEMPLATE" | openssl base64 -A)
SOURCE_TEMPLATE_KEY="redactwall/legacy/$STACK_NAME/$SOURCE_TEMPLATE_SHA256.template"
SOURCE_TEMPLATE_VERSION_ID=$(aws s3api put-object \
  --bucket "$ARTIFACT_BUCKET" --key "$SOURCE_TEMPLATE_KEY" --body "$SOURCE_TEMPLATE" \
  --checksum-algorithm SHA256 --checksum-sha256 "$SOURCE_TEMPLATE_CHECKSUM" \
  --server-side-encryption AES256 --metadata "sha256=$SOURCE_TEMPLATE_SHA256" \
  --expected-bucket-owner "$ACCOUNT_ID" --region "$AWS_REGION" \
  --query VersionId --output text)
test -n "$SOURCE_TEMPLATE_VERSION_ID" && test "$SOURCE_TEMPLATE_VERSION_ID" != None
S3_SUFFIX=amazonaws.com
case "$AWS_REGION" in cn-*) S3_SUFFIX=amazonaws.com.cn ;; esac
SOURCE_TEMPLATE_VERSION_URL=$(node -e '
  const [bucket,region,suffix,key,version]=process.argv.slice(1);
  process.stdout.write(`https://${bucket}.s3.${region}.${suffix}/${key}?versionId=${encodeURIComponent(version)}`);
' "$ARTIFACT_BUCKET" "$AWS_REGION" "$S3_SUFFIX" "$SOURCE_TEMPLATE_KEY" "$SOURCE_TEMPLATE_VERSION_ID")
```

Read only the exact target secret version into the private operation directory,
then calculate the fallback artifact digest and canonical Ed25519 SPKI DER
fingerprints. The plan stores digests and opaque field references, never secret
values.

```bash
aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" \
  --version-id "$CONNECTED_SECRET_VERSION_ID" --region "$AWS_REGION" \
  --query SecretString --output text > "$TARGET_SECRET"
chmod 600 "$TARGET_SECRET"
FALLBACK_ARTIFACT_SHA256=$(jq -jer '.REDACTWALL_LICENSE' "$TARGET_SECRET" | sha256sum | awk '{print $1}')
node - "$TARGET_SECRET" "$OP_DIR/trust-pins.json" <<'NODE'
const crypto = require('crypto');
const fs = require('fs');
const secret = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const pin = (name) => {
  const der = Buffer.from(secret[name], 'base64');
  if (!der.length || der.toString('base64') !== secret[name]) throw new Error('non-canonical public key');
  const key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') throw new Error('invalid public key');
  return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
};
fs.writeFileSync(process.argv[3], JSON.stringify({
  offline: pin('REDACTWALL_LICENSE_PUBLIC_KEY_B64'),
  verdict: pin('REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64'),
  entitlement: pin('REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64'),
}), { mode: 0o600 });
NODE
OFFLINE_TRUST_PIN_SHA256=$(jq -r '.offline' "$OP_DIR/trust-pins.json")
VERDICT_TRUST_PIN_SHA256=$(jq -r '.verdict' "$OP_DIR/trust-pins.json")
ENTITLEMENT_TRUST_PIN_SHA256=$(jq -r '.entitlement' "$OP_DIR/trust-pins.json")
```

Create the plan. The source stack must contain exact `TenantId`, `SecretArn`,
and immutable `LicenseSecretVersionId` parameters and publish the retained
volume, instance, target group, and digest-pinned image. Missing or ambiguous
source facts fail before the lease is acquired.

```bash
node scripts/aws-legacy-connected-migrate.js plan \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key" \
  --stack-name "$STACK_NAME" --region "$AWS_REGION" \
  --deploy-args-file "$DEPLOY_ARGS" --source-template-url "$SOURCE_TEMPLATE_VERSION_URL" \
  --tenant-id "$TENANT_ID" --deployment-id "$DEPLOYMENT_ID" \
  --fallback-artifact-sha256 "$FALLBACK_ARTIFACT_SHA256" \
  --offline-trust-pin-sha256 "$OFFLINE_TRUST_PIN_SHA256" \
  --verdict-trust-pin-sha256 "$VERDICT_TRUST_PIN_SHA256" \
  --entitlement-trust-pin-sha256 "$ENTITLEMENT_TRUST_PIN_SHA256" \
  --heartbeat-credential-ref "$SECRET_ARN#REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN" \
  --acknowledgement-credential-ref "$SECRET_ARN#REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN"
```

Expected phase is `planned`. `plan` snapshots the complete deploy arguments and
source parameters, captures and verifies the versioned source template, and
acquires the external lease. Ordinary supported deploys re-read that
deterministic lease and stop while it exists.

Start the outage and create the final stopped-writer checkpoint:

```bash
node scripts/aws-legacy-connected-migrate.js freeze \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key" \
  --timeout-seconds "${TIMEOUT_SECONDS:-1200}"
```

The command acquires the shared host deployment lock, rechecks the exact source
writer and target secret, drains the ALB, stops that writer, creates and verifies
the authenticated backup, and copies its bounded artifact set to
`/var/lib/redactwall/runtime/legacy-connected-migration/<migration-id>`. Record
the printed `REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256`,
`REDACTWALL_LEGACY_FREEZE_AUDIT_HEAD`, audit count, and audit sequence.
Keep the writer stopped while taking the encrypted volume snapshot:

```bash
SNAPSHOT_ID=$(aws ec2 create-snapshot --volume-id "$DATA_VOLUME_ID" \
  --description "RedactWall stopped-writer legacy cutover $STACK_NAME" \
  --tag-specifications "ResourceType=snapshot,Tags=[{Key=RedactWallTenant,Value=$TENANT_ID},{Key=RedactWallPurpose,Value=legacy-cutover-recovery}]" \
  --region "$AWS_REGION" --query SnapshotId --output text)
aws ec2 wait snapshot-completed --snapshot-ids "$SNAPSHOT_ID" --region "$AWS_REGION"
aws ec2 describe-snapshots --snapshot-ids "$SNAPSHOT_ID" --owner-ids self --region "$AWS_REGION" \
  --query "Snapshots[?SnapshotId=='$SNAPSHOT_ID' && VolumeId=='$DATA_VOLUME_ID' && Encrypted==\`true\`]" \
  --output json | jq -e 'length == 1' >/dev/null
```

Before source deletion, the supported abort is:

```bash
node scripts/aws-legacy-connected-migrate.js abort \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key" \
  --timeout-seconds "${TIMEOUT_SECONDS:-1200}"
```

It starts the exact stopped container, waits for `/readyz`, re-registers the
exact target, waits for ALB service, and only then releases the lease. It cannot
clear a post-cutover connected authority.

To cut over using the immutable argument snapshot captured by `plan`:

```bash
node scripts/aws-legacy-connected-migrate.js cutover \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key"
```

`cutover` re-verifies the stopped recovery set and audit coordinates, persists
the preallocated operation ID before deleting the exact source StackId, and
persists the exact returned candidate StackId before waiting for CloudFormation
or runtime attestation. Ambiguous outcomes stay fenced by the lease and durable
witness.

After an interrupted `cutover`, reconcile the exact source StackId, candidate
operation tag, returned candidate StackId, and external lease before retrying:

```bash
node scripts/aws-legacy-connected-migrate.js reconcile \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key"
```

`reconcile` may advance only to facts independently read back from CloudFormation.
Candidate-attestation reconciliation remains `RELEASE-BLOCKED` until the production
applied-attestation verifier is injected.

Use authenticated status and the rollback fence with the same four files:

```bash
node scripts/aws-legacy-connected-migrate.js status \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key"
node scripts/aws-legacy-connected-migrate.js rollback-check \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key"
```

Never delete a same-name stack or lease by name. Candidate cleanup is authorized
only by the recorded operation ID and exact returned StackId:

```bash
node scripts/aws-legacy-connected-migrate.js cleanup-failed-candidate \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key"
```

The production legacy recreate/restore adapter must consume the captured
versioned template, source parameter snapshot, stopped-writer recovery set, and
preallocated restore operation ID. It must return a new exact StackId and attest
the image, data volume, template digest, parameter digest, checkpoint digest,
recovery-set digest, container, writer readiness, and ALB target health. Only
then may the tool release the lease:

```bash
node scripts/aws-legacy-connected-migrate.js restore-precommit \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key"
```

Current release status: this command intentionally returns `RELEASE-BLOCKED`
until that production adapter is injected. Do not substitute manual
same-name deletion/recreation or claim a completed rollback.

Authority commit accepts no scalar CLI claims. It requires the raw Owner
durable-ACK receipt and raw customer acknowledged-high-water receipt, each bound
to the exact customer, deployment, operation, StackId, instance, container,
registry generation/state digest, entitlement version/artifact digest,
delivered then applied ACKs, audit heads, audit references, and authority
fingerprints:

The verified receipt pair must prove a nonzero monotonic registry generation,
the delivered ACK, and the applied ACK for the same effective authority pair.

```bash
node scripts/aws-legacy-connected-migrate.js commit \
  --manifest "$MANIFEST" --witness "$WITNESS" \
  --manifest-key "$OP_DIR/manifest.key" --witness-key "$OP_DIR/witness.key" \
  --owner-receipt-file "$OP_DIR/owner-ack-receipt.json" \
  --customer-receipt-file "$OP_DIR/customer-high-water-receipt.json"
```

Current release status: the CLI intentionally returns `RELEASE-BLOCKED` until
the production Owner receipt verifier, customer raw-receipt verifier, and
publication CAS adapter are injected. When those authorities are integrated,
the exact result is `connected_authority_committed`; the independently keyed
witness publishes a permanent tombstone, `rollback-check` fails forever, and
the external lease remains. Release also requires Owner to revoke the legacy
license and every legacy channel credential. This supported-workflow fence does not claim that it can cryptographically disable a manually reconstructed
obsolete image.

Downtime begins when `freeze` stops the writer and ends only when either the
connected candidate has completed both authenticated acknowledgements or the
attested legacy restore has returned the exact target to service. Never add a
fabricated `DeploymentId` to the legacy stack in place.

Rerun the same `npm run silo:deploy` command with a new digest-pinned
`ImageUri` whenever a release is promoted. Ordinary image and secret updates
do not replace the host. For any Secrets Manager change,
create a new immutable version, capture its returned `VersionId`, and pass that
new value as `LicenseSecretVersionId`. Changing only the value behind the same
secret ARN does not trigger CloudFormation and is not a supported rollout.

The supported operator command applies and attests the metadata synchronously
through SSM. The instance also runs `cfn-hup` as a recovery path. The host deploy
script reconciles any private journal, fetches the exact selected secret
version, and creates and verifies an authenticated pre-update backup using the
old image before stopping the old writer. It then pulls the candidate, starts
it, and waits for Docker health plus `/readyz`. Before commit, a failed
candidate restores the exact runtime evidence and identity-proven prior license
before restarting the prior container. The root-owned recovery point is retained
outside the candidate's `/data` mount and recorded in applied state. After
commit, cleanup failures retain the private journal and emit an operator warning
without removing the healthy candidate. The durable applied-state warning is
`committed_cleanup_pending`; every later apply retries exact journal cleanup
before its same-configuration fast path, and clears the warning only after
cleanup conclusively succeeds. Do not begin a different deployment while this
warning remains. Evidence-scheduler failure is recorded
as `evidence_scheduler_setup_failed`; treat that warning as committed-but-
degraded and repair the timer. If even the durable warning publication fails,
the SSM result says `committed but degraded:
evidence_scheduler_warning_persistence_failed`; preserve the applied state and
repair the host instead of retrying the already committed runtime mutation.
After every update, verify `/readyz`, the Licensing tab, the
ALB healthy-host count, `systemctl is-active cfn-hup`, and the applied-state
attestation. A successful `silo:deploy` already verifies the last item.

### Replace a host or restore a volume

These are planned-outage operations. Before stopping the old writer, the
command copies its authenticated backup, manifest, and required sidecars into
a root-owned sibling outside the candidate `/data` mount and verifies that
retained set with the exact old image. It also captures and verifies the exact
prior version-bound template URL, template digest, protocol digest, and
rendered-config digest before the outage begins. The host publishes a root-only,
private record so the authenticated evidence remains in root-owned retained storage.
fsynced maintenance latch under the same lock used by ordinary deploy and
`cfn-hup`. The latch binds the applied-state bytes, exact container id and image,
and verified recovery set. It blocks both update paths through backup, retained
copy verification, writer stop, deregistration, and the stack-deletion commit
boundary. The controller revalidates the exact stable source stack immediately
before drain and again before deletion. It then deletes the application stack so
the non-MultiAttach gp3 volume is detached and creates the replacement. If
replacement fails, the command deletes the failed stack, recreates the prior
stack from that captured template version, restores and verifies the retained
backup, and only then allows the prior writer to start. A failed restore or
verification, changed source stack, or ambiguous deletion retains the latch and
recovery evidence. Abort clears the latch only after the exact prior container is
healthy and the exact target is registered in service. The ALB is recreated, so
update the customer DNS alias to the returned DNS name.

For an AMI, instance-type, or root-volume change, copy the complete deploy
command above, keep every argument, set only the approved replacement values,
and replace its first line with:

```bash
npm run silo:maintenance -- --mode replace-instance \
```

For snapshot recovery, first create a new durable-data stack from the snapshot
with `SnapshotId` and `SourceDataVolumeId`. Copy the complete deploy command,
change only the data stack name, volume id, and source volume id, and replace
its first line with:

```bash
npm run silo:maintenance -- --mode restore-volume \
```

If a post-drain failure retains evidence, the command prints one sanitized
`checked recovery:` command. Run that exact command before any recovery action;
do not reconstruct the lease or checkpoint from a stack name:

```bash
node scripts/aws-silo-maintenance.js --mode status \
  --stack-name "$STACK_NAME" --region "$AWS_REGION" \
  --lease-stack-id "$EXACT_LEASE_STACK_ID" \
  --maintenance-id "$EXACT_MAINTENANCE_ID" \
  --latch-sha256 "$EXACT_LATCH_SHA256"
```

The status path re-reads the exact external lease StackId and all lease tags,
then, when the source still exists, reads the host latch through SSM and
requires the same maintenance ID and SHA-256. A missing, changed, or ambiguous
lease, source, or host checkpoint fails closed. Preserve the printed command in
the incident record with the stopped-writer snapshot and recovery artifacts.

Do not update the original durable-data stack in place and do not manually
attach or detach a volume. Record the maintenance checkpoint, old and new ALB
DNS names, rollback result, volume lineage, and post-cutover `/readyz` proof.

A local staging-directory cleanup error after a successful attestation is
reported only as `local_template_snapshot_cleanup_failed`. The deployment is
already committed, so investigate workstation cleanup without retrying the
runtime mutation.

If the checked host apply reports an invalid, uncertain, or unreconciled deployment journal,
do not rename containers or delete `license.*.<transaction-id>` files manually.
Rerun the exact same `npm run silo:deploy -- ...` command. It invokes the
bounded `/usr/local/sbin/redactwall-apply-and-attest` path through SSM and
reconciles the journal before reading a new secret version. Never invoke
`cfn-init` directly. A repeated warning means an artifact changed after it was
recorded; preserve `/etc/redactwall/license-deploy-journal.json`, the named
transaction containers, and the private license artifacts for incident review.

### Connected entitlement and fallback rotation

For an AWS customer silo, Owner-signed connected entitlements are the commercial
source of truth. Do not install a renewal through the customer console. The
template sets `REDACTWALL_LICENSE_MANAGED_EXTERNALLY=true`, so both in-app
license-install APIs reject mutation with `license_managed_externally`. Plan,
seat, feature, pause, and revoke changes happen in Owner and arrive as signed
connected artifacts. To rotate the bounded outage fallback or a trust pin:

1. Have Owner issue an active fallback whose `customerId` and `deploymentId`
   exactly match this stack, plus the approved current/next public pins.
2. Update the secure local JSON, call `aws secretsmanager put-secret-value`, and
   capture the returned `VersionId`.
3. Rerun `npm run silo:deploy` with that exact secret version id and the unchanged
   deployment identity.
4. Verify the connected registry generation, entitlement version, acknowledgement
   state, `/readyz`, and the Licensing tab before retiring the handoff copy.

The version publication command is:

```bash
LICENSE_SECRET_VERSION_ID=$(aws secretsmanager put-secret-value \
  --secret-id redactwall/cu-acme \
  --secret-string file://customer-secret.json \
  --query VersionId \
  --output text)
test -n "$LICENSE_SECRET_VERSION_ID"
```

Then use the complete deployment command from section 3 with
`--secret-version-id "$LICENSE_SECRET_VERSION_ID"`. Do not use a mutable
stage label such as `AWSCURRENT` as the stack parameter.

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
the wrong tenant id, or send an unmanaged user identity. Seat authority comes
only from the latest valid signed connected entitlement; an over-limit user is
blocked and recorded as `SEAT_LIMIT_BLOCKED` without storing the prompt body.

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
/var/lib/redactwall/runtime/evidence-schedule.json
/etc/redactwall/evidence-pack.env
/etc/systemd/system/redactwall-evidence-pack.service
/etc/systemd/system/redactwall-evidence-pack.timer
/var/log/redactwall/evidence-pack.log
```

The default schedule is `OnCalendar=quarterly` with `Persistent=true`, and the
default config writes packs to `/data/evidence-packs` inside the container,
which maps to the encrypted EBS-backed `/var/lib/redactwall/runtime/evidence-packs`
folder on the EC2 host.

After deployment, use Systems Manager Session Manager to inspect or adjust the
schedule config:

```bash
sudo editor /var/lib/redactwall/runtime/evidence-schedule.json
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
  database-enforced append-only audit table. A multi-replica plane also needs
  one POSIX-compatible shared audit-anchor volume mounted at the same absolute
  `REDACTWALL_AUDIT_DIR` on every host; independent sidecars are unsupported.
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
