'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const deployer = require('./aws-silo-deploy');
const maintenance = require('./aws-silo-maintenance');
const artifacts = require('./aws-artifacts');
const privatePath = require('../server/private-path');
const vendorProtocol = require('../server/vendor-control-protocol');

const DIGEST = /^[a-f0-9]{64}$/;
const ISO_MILLIS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ACK_MESSAGE_ID_SCHEMA = vendorProtocol.CHANNEL_SCHEMAS[
  vendorProtocol.CHANNEL_KINDS.ACKNOWLEDGEMENT
].shape.messageId;
const OWNER_AUDIT_REF = /^owner_audit_[a-f0-9]{64}$/;
const CUSTOMER_AUDIT_REF = /^customer_audit_[a-f0-9]{64}$/;
const CREDENTIAL_REF = /^arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}#[A-Z][A-Z0-9_]{2,63}$/;
const RECEIPT_PURPOSES = Object.freeze({
  owner: 'owner.durable-ack-acceptance.v1',
  customer: 'customer.acknowledged-high-water.v1',
});
const MAX_RECEIPT_BYTES = 64 * 1024;
const COMMIT_PREPARED_PHASE = 'connected_authority_commit_prepared';
const COMMIT_UNCERTAIN_PHASE = 'connected_authority_commit_uncertain';
const COMMIT_FINAL_PHASE = 'connected_authority_committed';
const ROLLBACK_AUTHORITY_KIND = 'legacy.connected-authority-high-water.v1';
const ROLLBACK_AUTHORITY_PURPOSE = 'legacy.rollback-one-way-authority.v1';
const ABORT_CLEANUP_RECEIPT_KIND = 'legacy.abort-cleanup-receipt.v1';
const ABORT_CLEANUP_INTENT_KIND = 'legacy.abort-cleanup-intent.v1';
const COMMIT_TOMBSTONE_PHASES = new Set([
  COMMIT_PREPARED_PHASE,
  COMMIT_UNCERTAIN_PHASE,
  COMMIT_FINAL_PHASE,
]);
const FREEZE_RECOVERY_PHASES = new Set([
  'freeze_intent',
  'freeze_deregister_intent',
  'freeze_target_drained',
  'freeze_failed',
  'abort_intent',
  'source_restored',
  'retryable',
]);
const TRUST_PIN_PROGRAM = `'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const raw = fs.readFileSync(0);
if (raw.length < 2 || raw.length > 65536) throw new Error('trust pin input is invalid');
const secret = JSON.parse(raw.toString('utf8'));
function fingerprint(name) {
  const encoded = secret[name];
  if (typeof encoded !== 'string' || encoded.length < 1 || encoded.length > 4096
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Error('trust pin input is invalid');
  const der = Buffer.from(encoded, 'base64');
  if (!der.length || der.toString('base64') !== encoded) throw new Error('trust pin input is invalid');
  try {
    crypto.createPrivateKey({ key: der, type: 'pkcs8', format: 'der' });
    throw new Error('trust pin input contains private key material');
  } catch (error) {
    if (error.message === 'trust pin input contains private key material') throw error;
  }
  const key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new Error('trust pin input is not an Ed25519 public key');
  }
  return crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
}
process.stdout.write(JSON.stringify({
  offline: fingerprint('REDACTWALL_LICENSE_PUBLIC_KEY_B64'),
  onlineVerdict: fingerprint('REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64'),
  entitlement: fingerprint('REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64'),
}));`;

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(canonical(value)), 'utf8');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function payloadDigest(payload) {
  return sha256(canonicalBytes(payload));
}

function hmac(payload, key) {
  return crypto.createHmac('sha256', key).update('redactwall-legacy-connected-migration-v1\0')
    .update(canonicalBytes(payload)).digest('hex');
}

function signingKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('migration manifest key must be exactly 32 bytes');
  return key;
}

function witnessHmac(payload, key) {
  return crypto.createHmac('sha256', signingKey(key)).update('redactwall-legacy-connected-witness-v1\0')
    .update(canonicalBytes(payload)).digest('hex');
}

function signWitness(payload, key) {
  return { payload: structuredClone(payload), mac: witnessHmac(payload, key) };
}

function verifyWitness(envelope, key) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
    || Object.keys(envelope).sort().join(',') !== 'mac,payload'
    || !DIGEST.test(String(envelope.mac || ''))) throw new Error('migration witness envelope is invalid');
  const expected = Buffer.from(witnessHmac(envelope.payload, key), 'hex');
  const actual = Buffer.from(envelope.mac, 'hex');
  if (!crypto.timingSafeEqual(expected, actual)) throw new Error('migration witness authentication failed');
  return structuredClone(envelope.payload);
}

function verifyStateAgainstWitness(payload, witness, key) {
  const state = verifyWitness(witness, key);
  if (!Number.isSafeInteger(state.sequence) || state.sequence < 1
    || state.migrationId !== payload.migrationId || state.phase !== payload.phase
    || state.manifestDigest !== payloadDigest(payload)
    || payloadDigest(state.payload) !== state.manifestDigest
    || JSON.stringify(canonical(state.payload)) !== JSON.stringify(canonical(payload))) {
    throw new Error('migration manifest replay or witness mismatch detected');
  }
  return structuredClone(payload);
}

function signEnvelope(payload, key) {
  return { payload: structuredClone(payload), mac: hmac(payload, signingKey(key)) };
}

function verifyEnvelope(envelope, key) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
    || Object.keys(envelope).sort().join(',') !== 'mac,payload'
    || !DIGEST.test(String(envelope.mac || ''))) {
    throw new Error('migration manifest authentication envelope is invalid');
  }
  const expected = Buffer.from(hmac(envelope.payload, signingKey(key)), 'hex');
  const actual = Buffer.from(envelope.mac, 'hex');
  if (!crypto.timingSafeEqual(expected, actual)) throw new Error('migration manifest authentication failed');
  return structuredClone(envelope.payload);
}

function outputs(stack) {
  return Object.fromEntries((stack.Outputs || []).map((entry) => [entry.OutputKey, String(entry.OutputValue ?? '')]));
}

function validatedTemplate(input) {
  let parsed;
  try { parsed = new URL(String(input.sourceTemplateUrl || '')); }
  catch { throw new Error('source template URL is invalid'); }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash
    || !/\.s3\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$/.test(parsed.hostname)
    || [...parsed.searchParams.keys()].some((key) => key !== 'versionId')
    || parsed.searchParams.getAll('versionId').length !== 1 || !parsed.searchParams.get('versionId')) {
    throw new Error('source template URL must be one exact private version-bound S3 object');
  }
  const bytes = Number(input.sourceTemplateBytes);
  if (!Number.isInteger(bytes) || bytes < 1 || bytes > 1024 * 1024
    || !DIGEST.test(String(input.sourceTemplateSha256 || ''))) {
    throw new Error('source template byte identity is invalid');
  }
  return { url: parsed.toString(), sha256: input.sourceTemplateSha256, bytes };
}

function snapshotIdentity(input, prefix, maxBytes = 262144) {
  const value = {
    path: String(input[`${prefix}Path`] || ''),
    sha256: String(input[`${prefix}Sha256`] || ''),
    bytes: Number(input[`${prefix}Bytes`]),
  };
  if (!/^[A-Za-z0-9._/-]{1,512}$/.test(value.path) || value.path.includes('..')
    || path.isAbsolute(value.path) || !DIGEST.test(value.sha256)
    || !Number.isInteger(value.bytes) || value.bytes < 2 || value.bytes > maxBytes) {
    throw new Error(`${prefix} snapshot identity is invalid`);
  }
  return value;
}

function deploymentAwsContract(values) {
  return {
    stackName: values['stack-name'], region: values.region,
    vpcId: values['vpc-id'], publicSubnetIds: values['public-subnet-ids'],
    instanceSubnetId: values['instance-subnet-id'], availabilityZone: values['instance-availability-zone'],
    imageUri: values['image-uri'], secretArn: values['secret-arn'], secretVersionId: values['secret-version-id'],
    dataVolumeId: values['data-volume-id'], dataStackName: values['data-stack-name'],
    sourceDataVolumeId: values['source-data-volume-id'], amiId: values['ami-id'],
    instanceType: values['instance-type'], rootVolumeGb: values['root-volume-gb'],
    certificateArn: values['certificate-arn'], publicHostname: values['public-hostname'],
    artifactBucket: values['artifact-bucket'], artifactPrefix: values['artifact-prefix'],
  };
}

function sourceTenant(stack, sourceOutputs) {
  const parameterValues = (stack.Parameters || [])
    .filter((entry) => entry.ParameterKey === 'TenantId').map((entry) => String(entry.ParameterValue || ''));
  const values = [...new Set([String(sourceOutputs.TenantId || ''), ...parameterValues].filter(Boolean))];
  if (values.length !== 1 || !deployer.PATTERNS.tenant.test(values[0])) {
    throw new Error('legacy source customer identity is missing or ambiguous');
  }
  return values[0];
}

function sourceParameter(stack, name) {
  const values = [...new Set((stack.Parameters || [])
    .filter((entry) => entry.ParameterKey === name).map((entry) => String(entry.ParameterValue || '')).filter(Boolean))];
  if (values.length !== 1) throw new Error(`legacy source ${name} is missing or ambiguous`);
  return values[0];
}

function validateTarget(input) {
  let deployValues;
  try { deployValues = deployer.validate(structuredClone(input.deployValues)); }
  catch (error) {
    const sanitized = new Error('deployment snapshot does not define a valid connected target');
    sanitized.validationErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  if (!deployer.PATTERNS.tenant.test(String(input.tenantId || ''))
    || !deployer.PATTERNS.deployment.test(String(input.deploymentId || ''))
    || !deployer.PATTERNS.region.test(String(input.region || ''))
    || !deployer.PATTERNS.secretVersion.test(String(input.connectedSecretVersionId || ''))
    || ![input.fallbackArtifactSha256, input.offlineTrustPinSha256,
      input.verdictTrustPinSha256, input.entitlementTrustPinSha256].every((value) => DIGEST.test(String(value || '')))
    || !CREDENTIAL_REF.test(String(input.heartbeatCredentialRef || ''))
    || !CREDENTIAL_REF.test(String(input.acknowledgementCredentialRef || ''))
    || input.heartbeatCredentialRef === input.acknowledgementCredentialRef
    || !String(input.heartbeatCredentialRef).startsWith(`${input.secretArn}#`)
    || !String(input.acknowledgementCredentialRef).startsWith(`${input.secretArn}#`)) {
    throw new Error('connected target identity, trust pins, fallback digest, or credential references are invalid');
  }
  if (deployValues['tenant-id'] !== input.tenantId || deployValues['deployment-id'] !== input.deploymentId
    || deployValues['secret-version-id'] !== input.connectedSecretVersionId
    || deployValues['secret-arn'] !== input.secretArn) {
    throw new Error('deployment snapshot and connected target identity do not match');
  }
  return deployValues;
}

function createManifestPayload(input, stack, now, migrationId) {
  const deployValues = validateTarget(input);
  if (!ISO_MILLIS.test(String(now || '')) || !/^[a-f0-9]{32}$/.test(String(migrationId || ''))) {
    throw new Error('migration identity or timestamp is invalid');
  }
  const sourceOutputs = outputs(stack);
  if (Object.prototype.hasOwnProperty.call(sourceOutputs, 'DeploymentId')) {
    throw new Error('legacy migration accepts only a source stack without DeploymentId');
  }
  const tenantId = sourceTenant(stack, sourceOutputs);
  if (tenantId !== input.tenantId) throw new Error('legacy source customer does not match the connected target customer');
  const sourceSecretArn = sourceParameter(stack, 'SecretArn');
  const sourceSecretVersionId = sourceParameter(stack, 'LicenseSecretVersionId');
  if (!deployer.PATTERNS.secretArn.test(sourceSecretArn)
    || !deployer.PATTERNS.secretVersion.test(sourceSecretVersionId)) {
    throw new Error('legacy source secret ARN or immutable version is invalid');
  }
  if (!deployer.exactStackId(stack.StackId, stack.StackName, input.region)
    || !['CREATE_COMPLETE', 'IMPORT_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE'].includes(stack.StackStatus)
    || !DIGEST.test(String(stack.RedactWallTemplateSha256 || ''))
    || !/^i-[a-f0-9]{8,17}$/.test(sourceOutputs.InstanceId)
    || !/^arn:(?:aws|aws-us-gov|aws-cn):elasticloadbalancing:/.test(sourceOutputs.TargetGroupArn)
    || !deployer.PATTERNS.volume.test(sourceOutputs.DataVolumeId)
    || !deployer.PATTERNS.image.test(sourceOutputs.ImageUri)) {
    throw new Error('legacy source stack lacks a stable retained-volume writer contract');
  }
  if (deployValues['stack-name'] !== stack.StackName || deployValues.region !== input.region
    || deployValues['data-volume-id'] !== sourceOutputs.DataVolumeId
    || deployValues['image-uri'] !== sourceOutputs.ImageUri) {
    throw new Error('deployment snapshot does not match the source stack and target material');
  }
  const deployArgsSnapshot = snapshotIdentity(input, 'deployArgs', 65536);
  const sourceParametersSnapshot = snapshotIdentity(input, 'sourceParameters', 262144);
  return {
    version: 1, migrationId, phase: 'planned', createdAt: now, updatedAt: now,
    source: {
      stackId: stack.StackId, stackName: stack.StackName, region: input.region, tenantId,
      fingerprint: maintenance.sourceFingerprint(stack), templateSha256: stack.RedactWallTemplateSha256,
      lastUpdatedTime: String(stack.LastUpdatedTime || ''), roleArn: String(stack.RoleARN || ''),
      deploymentIdPresent: false, instanceId: sourceOutputs.InstanceId,
      targetGroupArn: sourceOutputs.TargetGroupArn, dataVolumeId: sourceOutputs.DataVolumeId,
      imageUri: sourceOutputs.ImageUri, secretArn: sourceSecretArn,
      secretVersionId: sourceSecretVersionId, rollbackTemplate: validatedTemplate(input),
      parametersSha256: sha256(canonicalBytes((stack.Parameters || []).map((entry) => ({
        key: String(entry.ParameterKey || ''), value: String(entry.ParameterValue ?? ''),
      })).sort((left, right) => left.key.localeCompare(right.key)))),
      parametersSnapshot: sourceParametersSnapshot,
    },
    target: {
      tenantId: input.tenantId, deploymentId: input.deploymentId,
      connectedSecretVersionId: input.connectedSecretVersionId,
      fallbackArtifactSha256: input.fallbackArtifactSha256,
      trustPins: { offline: input.offlineTrustPinSha256, onlineVerdict: input.verdictTrustPinSha256,
        entitlement: input.entitlementTrustPinSha256 },
      credentialRefs: { heartbeat: input.heartbeatCredentialRef,
        acknowledgement: input.acknowledgementCredentialRef },
      aws: deploymentAwsContract(deployValues),
      deployArgsSnapshot,
    },
    lease: null, checkpoint: null, cutover: null, authorityCommit: null,
  };
}

function singleQuote(value) {
  if (!/^[A-Za-z0-9_./:@-]+$/.test(String(value || ''))) throw new Error('legacy shell input is invalid');
  return `'${value}'`;
}

function legacyFreezeCommand(payload) {
  const source = payload.source;
  const migrationId = payload.migrationId;
  const image = singleQuote(source.imageUri);
  const expectedStack = singleQuote(source.stackId);
  return `set -euo pipefail
umask 077
exec 9>/run/redactwall-deploy.lock
flock -w 30 9
MIGRATION_ID=${singleQuote(migrationId)}
EXPECTED_IMAGE=${image}
EXPECTED_STACK_ID=${expectedStack}
ROOT=/var/lib/redactwall/runtime/legacy-connected-migration/$MIGRATION_ID
RUNTIME=/var/lib/redactwall/runtime
PARENT=$RUNTIME/legacy-connected-migration
CONTAINER_ID=$(docker inspect -f '{{.Id}}' redactwall)
[[ "$CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]]
[ "$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID")" = "$EXPECTED_IMAGE" ]
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")" = true ]
[ "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}|{{.RW}}{{end}}{{end}}' "$CONTAINER_ID")" = '/var/lib/redactwall/runtime|true' ]
[ ! -L "$RUNTIME" ] && [ -d "$RUNTIME" ] && [ "$(stat -c '%u:%g:%a' "$RUNTIME")" = '1000:1000:700' ]
if [ -e "$PARENT" ] || [ -L "$PARENT" ]; then
  [ ! -L "$PARENT" ] && [ -d "$PARENT" ] && [ "$(stat -c '%u:%g:%a' "$PARENT")" = '0:0:700' ]
else
  mkdir -- "$PARENT"
  chown root:root "$PARENT"
  chmod 700 "$PARENT"
  sync -f "$RUNTIME"
fi
[ ! -e "$ROOT" ] && [ ! -L "$ROOT" ]
mkdir -- "$ROOT"
chown root:root "$ROOT"
chmod 700 "$ROOT"
sync -f "$PARENT"
root_identity=$(stat -c '%d:%i:%u:%g:%a' "$ROOT")
intent_tmp=$(mktemp "$ROOT/.freeze-intent.XXXXXX")
jq -cn --arg migrationId "$MIGRATION_ID" --arg sourceStackId "$EXPECTED_STACK_ID" \\
  --arg containerId "$CONTAINER_ID" --arg imageUri "$EXPECTED_IMAGE" --arg rootIdentity "$root_identity" \\
  '{version:1,phase:"freeze_intent",migrationId:$migrationId,sourceStackId:$sourceStackId,containerId:$containerId,imageUri:$imageUri,rootIdentity:$rootIdentity}' > "$intent_tmp"
chmod 600 "$intent_tmp"
sync -f "$intent_tmp"
mv -T "$intent_tmp" "$ROOT/freeze-intent.json"
sync -f "$ROOT"
docker stop -t 30 "$CONTAINER_ID" >/dev/null
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")" = false ]
recovery_digest() {
  local root=$1 expected_count=$2 names digests name count
  names=$(mktemp /run/redactwall-legacy-names.XXXXXX)
  digests=$(mktemp /run/redactwall-legacy-digests.XXXXXX)
  find "$root" -mindepth 1 -maxdepth 1 ! -name checkpoint.json ! -name freeze-intent.json -printf '%f\n' | LC_ALL=C sort > "$names"
  count=$(wc -l < "$names" | tr -d ' ')
  [ "$count" -eq "$expected_count" ]
  while IFS= read -r name; do
    [[ "$name" =~ ^[A-Za-z0-9._-]{1,180}$ ]]
    [ ! -L "$root/$name" ] && [ -f "$root/$name" ] \
      && [ "$(stat -c '%u:%g:%a:%h' "$root/$name")" = '0:0:600:1' ]
    printf '%s  %s\n' "$(sha256sum "$root/$name" | awk '{print $1}')" "$name" >> "$digests"
  done < "$names"
  sha256sum "$digests" | awk '{print $1}'
  rm -- "$names" "$digests"
}
container_out="/data/backups/legacy-connected/$MIGRATION_ID"
legacy_backup() {
  docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \\
    --cap-drop ALL --security-opt no-new-privileges --env-file /etc/redactwall/env \\
    -v /var/lib/redactwall/runtime:/data --entrypoint node "$EXPECTED_IMAGE" "$@"
}
result=$(legacy_backup scripts/backup-store.js create --out "$container_out")
backup_file=$(printf '%s' "$result" | jq -er --arg prefix "$container_out/" '.file | select(type == "string" and startswith($prefix))')
manifest_file=$(printf '%s' "$result" | jq -er --arg prefix "$container_out/" '.manifestFile | select(type == "string" and startswith($prefix))')
audit_checkpoint_file=$(printf '%s' "$result" | jq -er --arg prefix "$container_out/" '.auditCheckpointFile | select(type == "string" and startswith($prefix))')
legacy_backup scripts/backup-store.js verify --file "$backup_file" --manifest "$manifest_file" >/dev/null
backup_name=$(basename "$backup_file")
manifest_name=$(basename "$manifest_file")
audit_checkpoint_name=$(basename "$audit_checkpoint_file")
[[ "$backup_name" =~ ^[A-Za-z0-9._-]{1,180}$ ]]
[[ "$manifest_name" =~ ^[A-Za-z0-9._-]{1,180}$ ]]
[[ "$audit_checkpoint_name" =~ ^[A-Za-z0-9._-]{1,180}$ ]]
source_root="/var/lib/redactwall/runtime/backups/legacy-connected/$MIGRATION_ID"
artifact_count=0
while IFS= read -r source_file; do
  [ ! -L "$source_file" ] && [ -f "$source_file" ] && [ "$(stat -c '%h:%u:%g:%a' "$source_file")" = '1:1000:1000:600' ]
  source_name=$(basename -- "$source_file")
  [[ "$source_name" =~ ^[A-Za-z0-9._-]{1,180}$ ]]
  artifact_count=$((artifact_count + 1))
  [ "$artifact_count" -le 8 ]
  [ ! -e "$ROOT/$source_name" ] && [ ! -L "$ROOT/$source_name" ]
  cp --reflink=never --no-clobber -- "$source_file" "$ROOT/$source_name"
  chown root:root "$ROOT/$source_name"
  chmod 600 "$ROOT/$source_name"
  sync -f "$ROOT/$source_name"
done < <(find "$source_root" -mindepth 1 -maxdepth 1 -type f -print)
[ "$artifact_count" -ge 4 ]
[ "$(find "$source_root" -mindepth 1 -maxdepth 1 | wc -l)" -eq "$artifact_count" ]
[ "$(stat -c '%d:%i:%u:%g:%a' "$ROOT")" = "$root_identity" ]
recovery_set_sha256=$(recovery_digest "$ROOT" "$artifact_count")
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \\
  --cap-drop ALL --security-opt no-new-privileges --env-file /etc/redactwall/env \\
  -v "$ROOT:/recovery:ro" --entrypoint node "$EXPECTED_IMAGE" scripts/backup-store.js verify \\
  --file "/recovery/$backup_name" --manifest "/recovery/$manifest_name" >/dev/null
audit_head=$(jq -er '.head | select(type == "string" and test("^[a-f0-9]{64}$"))' "$ROOT/$audit_checkpoint_name")
audit_count=$(jq -er '.count | select(type == "number" and floor == . and . >= 0)' "$ROOT/$audit_checkpoint_name")
audit_sequence=$(jq -er '.seq | select(type == "number" and floor == . and . >= 0)' "$ROOT/$audit_checkpoint_name")
checkpoint_tmp=$(mktemp "$ROOT/.checkpoint.XXXXXX")
jq -cn --arg migrationId "$MIGRATION_ID" --arg sourceStackId "$EXPECTED_STACK_ID" \\
  --arg containerId "$CONTAINER_ID" --arg imageUri "$EXPECTED_IMAGE" --arg rootIdentity "$root_identity" \\
  --arg backup "$backup_name" --arg manifest "$manifest_name" --arg auditCheckpoint "$audit_checkpoint_name" \\
  --arg auditHead "$audit_head" --argjson auditCount "$audit_count" --argjson auditSequence "$audit_sequence" \\
  --arg recoverySetSha256 "$recovery_set_sha256" --argjson artifactCount "$artifact_count" \\
  --arg intentSha256 "$(sha256sum "$ROOT/freeze-intent.json" | awk '{print $1}')" \\
  '{version:1,migrationId:$migrationId,sourceStackId:$sourceStackId,containerId:$containerId,imageUri:$imageUri,rootIdentity:$rootIdentity,backup:$backup,manifest:$manifest,auditCheckpoint:$auditCheckpoint,auditHead:$auditHead,auditCount:$auditCount,auditSequence:$auditSequence,recoverySetSha256:$recoverySetSha256,artifactCount:$artifactCount,intentSha256:$intentSha256}' > "$checkpoint_tmp"
chmod 600 "$checkpoint_tmp"
sync -f "$checkpoint_tmp"
mv -T "$checkpoint_tmp" "$ROOT/checkpoint.json"
sync -f "$ROOT"
checkpoint_sha=$(sha256sum "$ROOT/checkpoint.json" | awk '{print $1}')
printf 'REDACTWALL_LEGACY_FREEZE_PHASE=frozen\\n'
printf 'REDACTWALL_LEGACY_FREEZE_BACKUP=%s\\n' "$backup_name"
printf 'REDACTWALL_LEGACY_FREEZE_MANIFEST=%s\\n' "$manifest_name"
printf 'REDACTWALL_LEGACY_FREEZE_CONTAINER_ID=%s\\n' "$CONTAINER_ID"
printf 'REDACTWALL_LEGACY_FREEZE_ROOT_IDENTITY=%s\\n' "$root_identity"
printf 'REDACTWALL_LEGACY_FREEZE_RECOVERY_SHA256=%s\\n' "$recovery_set_sha256"
printf 'REDACTWALL_LEGACY_FREEZE_ARTIFACT_COUNT=%s\\n' "$artifact_count"
printf 'REDACTWALL_LEGACY_FREEZE_AUDIT_HEAD=%s\\n' "$audit_head"
printf 'REDACTWALL_LEGACY_FREEZE_AUDIT_COUNT=%s\\n' "$audit_count"
printf 'REDACTWALL_LEGACY_FREEZE_AUDIT_SEQUENCE=%s\\n' "$audit_sequence"
printf 'REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=%s\\n' "$checkpoint_sha"`;
}

function legacyPreflightCommand(payload) {
  const trustPinProgram = Buffer.from(TRUST_PIN_PROGRAM, 'utf8').toString('base64');
  return `set -euo pipefail
exec 9>/run/redactwall-deploy.lock
flock -w 30 9
TARGET_IMAGE=${singleQuote(payload.target.aws.imageUri)}
CONTAINER_ID=$(docker inspect -f '{{.Id}}' redactwall)
[[ "$CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]]
[ "$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID")" = ${singleQuote(payload.source.imageUri)} ]
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")" = true ]
[ "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}|{{.RW}}{{end}}{{end}}' "$CONTAINER_ID")" = '/var/lib/redactwall/runtime|true' ]
test -x /usr/local/sbin/redactwall-validate-release-input
/usr/local/sbin/redactwall-validate-release-input \\
  --image-uri ${singleQuote(payload.target.aws.imageUri)} \\
  --secret-arn ${singleQuote(payload.target.aws.secretArn)} \\
  --secret-version-id ${singleQuote(payload.target.aws.secretVersionId)} \\
  --tenant-id ${singleQuote(payload.target.tenantId)} \\
  --deployment-id ${singleQuote(payload.target.deploymentId)}
SECRET_JSON=$(aws secretsmanager get-secret-value \\
  --secret-id ${singleQuote(payload.target.aws.secretArn)} \\
  --version-id ${singleQuote(payload.target.aws.secretVersionId)} \\
  --region ${singleQuote(payload.target.aws.region)} --query SecretString --output text)
secret_string_digest() {
  printf '%s' "$SECRET_JSON" | jq -jer --arg key "$1" '.[$key] | select(type == "string" and length > 0)' \\
    | sha256sum | awk '{print $1}'
}
[ "$(secret_string_digest REDACTWALL_LICENSE)" = ${singleQuote(payload.target.fallbackArtifactSha256)} ]
trust_fingerprints=$(printf '%s' "$SECRET_JSON" | docker run --rm -i --network none --read-only \\
  --tmpfs /tmp:rw,noexec,nosuid,size=16m --cap-drop ALL --security-opt no-new-privileges \\
  --entrypoint node "$TARGET_IMAGE" -e "eval(Buffer.from('${trustPinProgram}','base64').toString('utf8'))")
printf '%s' "$trust_fingerprints" | jq -e '
  type == "object" and (keys | sort) == ["entitlement","offline","onlineVerdict"]
  and all(.[]; type == "string" and test("^[a-f0-9]{64}$"))' >/dev/null
[ "$(printf '%s' "$trust_fingerprints" | jq -er '.offline')" = ${singleQuote(payload.target.trustPins.offline)} ]
[ "$(printf '%s' "$trust_fingerprints" | jq -er '.onlineVerdict')" = ${singleQuote(payload.target.trustPins.onlineVerdict)} ]
[ "$(printf '%s' "$trust_fingerprints" | jq -er '.entitlement')" = ${singleQuote(payload.target.trustPins.entitlement)} ]
heartbeat=$(printf '%s' "$SECRET_JSON" | jq -er --arg key ${singleQuote(payload.target.credentialRefs.heartbeat.split('#')[1])} '.[$key] | select(type == "string" and length >= 32)')
acknowledgement=$(printf '%s' "$SECRET_JSON" | jq -er --arg key ${singleQuote(payload.target.credentialRefs.acknowledgement.split('#')[1])} '.[$key] | select(type == "string" and length >= 32)')
[ "$heartbeat" != "$acknowledgement" ]
unset heartbeat acknowledgement trust_fingerprints SECRET_JSON
curl --fail --silent --show-error --max-time 3 http://127.0.0.1:4000/readyz >/dev/null`;
}

function legacyAbortCommand(payload, dependencies = {}) {
  assertRollbackAllowed(payload, dependencies);
  const baseline = validateFreezeBaseline(payload.freezeBaseline);
  if (payload.checkpoint && payload.checkpoint.containerId !== baseline.containerId) {
    throw new Error('legacy abort checkpoint does not match the exact pre-freeze writer identity');
  }
  const checkpointDigest = payload.checkpoint?.digest || 'none';
  const baselineContainer = baseline.containerId;
  return `set -euo pipefail
umask 077
exec 9>/run/redactwall-deploy.lock
flock -w 30 9
MIGRATION_ID=${singleQuote(payload.migrationId)}
ROOT=/var/lib/redactwall/runtime/legacy-connected-migration/$MIGRATION_ID
PARENT=$(dirname "$ROOT")
CLEANUP="$PARENT/$MIGRATION_ID.abort-cleanup"
RECEIPT="$PARENT/$MIGRATION_ID.abort-cleanup-receipt.json"
PENDING="$PARENT/$MIGRATION_ID.abort-cleanup-receipt.pending"
EXPECTED_CHECKPOINT=${singleQuote(checkpointDigest)}
EXPECTED_CONTAINER=${singleQuote(baselineContainer)}
EXPECTED_STACK_ID=${singleQuote(payload.source.stackId)}
EXPECTED_INSTANCE_ID=${singleQuote(payload.source.instanceId)}
EXPECTED_IMAGE=${singleQuote(payload.source.imageUri)}
EXPECTED_CUSTOMER_ID=${singleQuote(payload.target.tenantId)}
EXPECTED_DEPLOYMENT_ID=${singleQuote(payload.target.deploymentId)}
RECEIPT_KIND=${singleQuote(ABORT_CLEANUP_RECEIPT_KIND)}
[ ! -L "$PARENT" ] && [ -d "$PARENT" ] && [ "$(stat -c '%u:%g:%a' "$PARENT")" = '0:0:700' ]
if { [ -e "$ROOT" ] || [ -L "$ROOT" ]; } && { [ -e "$CLEANUP" ] || [ -L "$CLEANUP" ]; }; then
  exit 1
fi
if [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
  [ ! -L "$PENDING" ] && [ -f "$PENDING" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$PENDING")" = '0:0:600:1' ]
  rm -- "$PENDING"
  sync -f "$PARENT"
fi
validate_receipt() {
  [ ! -L "$RECEIPT" ] && [ -f "$RECEIPT" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$RECEIPT")" = '0:0:600:1' ]
  jq -e --arg kind "$RECEIPT_KIND" --arg migrationId "$MIGRATION_ID" \
    --arg stackId "$EXPECTED_STACK_ID" --arg container "$EXPECTED_CONTAINER" \
    --arg instanceId "$EXPECTED_INSTANCE_ID" --arg image "$EXPECTED_IMAGE" \
    --arg customerId "$EXPECTED_CUSTOMER_ID" --arg deploymentId "$EXPECTED_DEPLOYMENT_ID" \
    --arg checkpoint "$EXPECTED_CHECKPOINT" '
      (keys | sort) == (["checkpointDigest","containerId","currentName","cursor","customerId","deploymentId",
        "entries","entryCount","imageUri","instanceId","journalSetSha256","kind","migrationId","phase",
        "rootIdentity","schemaVersion","sourceStackId"] | sort)
      and .schemaVersion == 1 and .kind == $kind and .migrationId == $migrationId
      and .sourceStackId == $stackId and .instanceId == $instanceId and .containerId == $container
      and .customerId == $customerId and .deploymentId == $deploymentId and .imageUri == $image
      and .checkpointDigest == $checkpoint
      and (.rootIdentity | type == "string" and test("^[0-9]+:[0-9]+:0:0:700$"))
      and (.journalSetSha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and (.entries | type == "array") and (.entryCount | type == "number" and floor == . and . >= 1 and . <= 16)
      and (.entries | length) == .entryCount
      and all(.entries[]; (keys | sort) == ["name","sha256"]
        and (.name | type == "string" and test("^[A-Za-z0-9._-]{1,180}$"))
        and (.sha256 | type == "string" and test("^[a-f0-9]{64}$")))
      and ([.entries[].name] == ([.entries[].name] | sort))
      and ([.entries[].name] | unique | length) == .entryCount
      and (.cursor | type == "number" and floor == . and . >= 0 and . <= .entryCount)
      and (.phase == "prepared" or .phase == "deleting" or .phase == "removing" or .phase == "complete")
      and (if .phase == "deleting" then .cursor < .entryCount and .currentName == .entries[.cursor].name
        elif .phase == "prepared" then .currentName == null
        else .cursor == .entryCount and .currentName == null end)' "$RECEIPT" >/dev/null
  entries_json=$(jq -c '.entries' "$RECEIPT")
  [ "$(printf '%s' "$entries_json" | sha256sum | awk '{print $1}')" = "$(jq -r '.journalSetSha256' "$RECEIPT")" ]
  root_identity=$(jq -r '.rootIdentity' "$RECEIPT")
  journal_set_sha256=$(jq -r '.journalSetSha256' "$RECEIPT")
  entry_count=$(jq -r '.entryCount' "$RECEIPT")
}
publish_receipt() {
  local next_phase=$1 next_cursor=$2 next_name=$3 current_json
  [ ! -e "$PENDING" ] && [ ! -L "$PENDING" ]
  if [ "$next_name" = none ]; then current_json=null; else current_json=$(jq -cn --arg value "$next_name" '$value'); fi
  jq -cn --arg kind "$RECEIPT_KIND" --arg migrationId "$MIGRATION_ID" \
    --arg stackId "$EXPECTED_STACK_ID" --arg instanceId "$EXPECTED_INSTANCE_ID" \
    --arg container "$EXPECTED_CONTAINER" --arg image "$EXPECTED_IMAGE" \
    --arg customerId "$EXPECTED_CUSTOMER_ID" --arg deploymentId "$EXPECTED_DEPLOYMENT_ID" \
    --arg checkpoint "$EXPECTED_CHECKPOINT" --arg rootIdentity "$root_identity" \
    --arg journalSetSha256 "$journal_set_sha256" --arg phase "$next_phase" \
    --argjson entryCount "$entry_count" --argjson cursor "$next_cursor" \
    --argjson currentName "$current_json" --argjson entries "$entries_json" \
    '{schemaVersion:1,kind:$kind,phase:$phase,migrationId:$migrationId,customerId:$customerId,
      deploymentId:$deploymentId,sourceStackId:$stackId,instanceId:$instanceId,containerId:$container,
      imageUri:$image,checkpointDigest:$checkpoint,rootIdentity:$rootIdentity,
      journalSetSha256:$journalSetSha256,entryCount:$entryCount,cursor:$cursor,currentName:$currentName,entries:$entries}' > "$PENDING"
  chown root:root "$PENDING"
  chmod 600 "$PENDING"
  sync -f "$PENDING"
  mv -T "$PENDING" "$RECEIPT"
  sync -f "$PARENT"
  validate_receipt
}
verify_entry() {
  local directory=$1 name=$2 expected_sha=$3
  [ ! -L "$directory/$name" ] && [ -f "$directory/$name" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$directory/$name")" = '0:0:600:1' ]
  [ "$(sha256sum "$directory/$name" | awk '{print $1}')" = "$expected_sha" ]
}
verify_journal_state() {
  local directory=$1 phase cursor index name expected_sha
  phase=$(jq -r '.phase' "$RECEIPT")
  cursor=$(jq -r '.cursor' "$RECEIPT")
  [ ! -L "$directory" ] && [ -d "$directory" ] && [ "$(stat -c '%u:%g:%a' "$directory")" = '0:0:700' ]
  [ "$(stat -c '%d:%i:%u:%g:%a' "$directory")" = "$root_identity" ]
  index=0
  while [ "$index" -lt "$entry_count" ]; do
    name=$(printf '%s' "$entries_json" | jq -er --argjson index "$index" '.[$index].name')
    expected_sha=$(printf '%s' "$entries_json" | jq -er --argjson index "$index" '.[$index].sha256')
    if [ "$index" -lt "$cursor" ]; then
      [ ! -e "$directory/$name" ] && [ ! -L "$directory/$name" ]
    elif [ "$phase" = deleting ] && [ "$index" -eq "$cursor" ]; then
      if [ -e "$directory/$name" ] || [ -L "$directory/$name" ]; then verify_entry "$directory" "$name" "$expected_sha"; fi
    else
      verify_entry "$directory" "$name" "$expected_sha"
    fi
    index=$((index + 1))
  done
  [ "$(find "$directory" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -eq "$((entry_count - cursor))" ] \
    || { [ "$phase" = deleting ] && [ "$(find "$directory" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -eq "$((entry_count - cursor - 1))" ]; }
}
if [ ! -e "$RECEIPT" ] && [ ! -L "$RECEIPT" ]; then
  [ ! -e "$CLEANUP" ] && [ ! -L "$CLEANUP" ]
  [ -e "$ROOT" ] || [ -L "$ROOT" ]
  [ ! -L "$ROOT" ] && [ -d "$ROOT" ] && [ "$(stat -c '%u:%g:%a' "$ROOT")" = '0:0:700' ]
  [ ! -L "$ROOT/freeze-intent.json" ] && [ -f "$ROOT/freeze-intent.json" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$ROOT/freeze-intent.json")" = '0:0:600:1' ]
  jq -e --arg migrationId "$MIGRATION_ID" --arg stackId "$EXPECTED_STACK_ID" \
    --arg image "$EXPECTED_IMAGE" --arg container "$EXPECTED_CONTAINER" \
    '.version == 1 and .phase == "freeze_intent" and .migrationId == $migrationId
     and .sourceStackId == $stackId and .imageUri == $image and .containerId == $container
     and (.rootIdentity | type == "string") and (.rootIdentity | test("^[0-9]+:[0-9]+:0:0:700$"))' \
    "$ROOT/freeze-intent.json" >/dev/null
  root_identity=$(jq -er '.rootIdentity' "$ROOT/freeze-intent.json")
  [ "$(stat -c '%d:%i:%u:%g:%a' "$ROOT")" = "$root_identity" ]
  if [ "$EXPECTED_CHECKPOINT" != none ]; then
    [ ! -L "$ROOT/checkpoint.json" ] && [ -f "$ROOT/checkpoint.json" ] \
      && [ "$(stat -c '%u:%g:%a:%h' "$ROOT/checkpoint.json")" = '0:0:600:1' ]
    [ "$(sha256sum "$ROOT/checkpoint.json" | awk '{print $1}')" = "$EXPECTED_CHECKPOINT" ]
    [ "$(sha256sum "$ROOT/freeze-intent.json" | awk '{print $1}')" = "$(jq -r '.intentSha256' "$ROOT/checkpoint.json")" ]
  else
    [ ! -e "$ROOT/checkpoint.json" ] && [ ! -L "$ROOT/checkpoint.json" ]
  fi
  NAMES=$(mktemp /run/redactwall-legacy-abort-names.XXXXXX)
  ENTRIES=$(mktemp /run/redactwall-legacy-abort-entries.XXXXXX)
  trap 'rm -f -- "$NAMES" "$ENTRIES"' EXIT
  find "$ROOT" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort > "$NAMES"
  entry_count=$(wc -l < "$NAMES" | tr -d ' ')
  [ "$entry_count" -ge 1 ] && [ "$entry_count" -le 16 ]
  : > "$ENTRIES"
  while IFS= read -r name; do
    [[ "$name" =~ ^[A-Za-z0-9._-]{1,180}$ ]]
    [ "$name" != . ] && [ "$name" != .. ]
    [ ! -L "$ROOT/$name" ] && [ -f "$ROOT/$name" ]
    [ "$(stat -c '%u:%g:%a:%h' "$ROOT/$name")" = '0:0:600:1' ]
    jq -cn --arg name "$name" --arg sha256 "$(sha256sum "$ROOT/$name" | awk '{print $1}')" \
      '{name:$name,sha256:$sha256}' >> "$ENTRIES"
  done < "$NAMES"
  entries_json=$(jq -sc '.' "$ENTRIES")
  journal_set_sha256=$(printf '%s' "$entries_json" | sha256sum | awk '{print $1}')
  publish_receipt prepared 0 none
else
  validate_receipt
fi
receipt_phase=$(jq -r '.phase' "$RECEIPT")
receipt_cursor=$(jq -r '.cursor' "$RECEIPT")
if [ "$receipt_phase" = complete ]; then
  [ ! -e "$ROOT" ] && [ ! -L "$ROOT" ] && [ ! -e "$CLEANUP" ] && [ ! -L "$CLEANUP" ]
else
  if [ -e "$ROOT" ] || [ -L "$ROOT" ]; then
    [ "$receipt_phase" = prepared ] && [ "$receipt_cursor" -eq 0 ]
    verify_journal_state "$ROOT"
    mv -T "$ROOT" "$CLEANUP"
    sync -f "$PARENT"
  elif [ -e "$CLEANUP" ] || [ -L "$CLEANUP" ]; then
    verify_journal_state "$CLEANUP"
  else
    [ "$receipt_phase" = removing ]
  fi
fi
while :; do
  validate_receipt
  receipt_phase=$(jq -r '.phase' "$RECEIPT")
  cursor=$(jq -r '.cursor' "$RECEIPT")
  if [ "$receipt_phase" = complete ]; then break; fi
  if [ "$receipt_phase" = prepared ]; then
    if [ "$cursor" -eq "$entry_count" ]; then
      publish_receipt removing "$entry_count" none
    else
      current_name=$(printf '%s' "$entries_json" | jq -er --argjson index "$cursor" '.[$index].name')
      publish_receipt deleting "$cursor" "$current_name"
    fi
    continue
  fi
  if [ "$receipt_phase" = deleting ]; then
    current_name=$(jq -er '.currentName' "$RECEIPT")
    current_sha=$(printf '%s' "$entries_json" | jq -er --argjson index "$cursor" '.[$index].sha256')
    if [ -e "$CLEANUP/$current_name" ] || [ -L "$CLEANUP/$current_name" ]; then
      verify_entry "$CLEANUP" "$current_name" "$current_sha"
      rm -- "$CLEANUP/$current_name"
    fi
    sync -f "$CLEANUP"
    publish_receipt prepared "$((cursor + 1))" none
    continue
  fi
  [ "$receipt_phase" = removing ] && [ "$cursor" -eq "$entry_count" ]
  if [ -e "$CLEANUP" ] || [ -L "$CLEANUP" ]; then
    [ ! -L "$CLEANUP" ] && [ -d "$CLEANUP" ] && [ "$(stat -c '%d:%i:%u:%g:%a' "$CLEANUP")" = "$root_identity" ]
    [ -z "$(find "$CLEANUP" -mindepth 1 -maxdepth 1 -print -quit)" ]
    rmdir -- "$CLEANUP"
  fi
  sync -f "$PARENT"
  publish_receipt complete "$entry_count" none
done
[ ! -e "$ROOT" ] && [ ! -L "$ROOT" ] && [ ! -e "$CLEANUP" ] && [ ! -L "$CLEANUP" ]
validate_receipt
[ "$(jq -r '.phase' "$RECEIPT")" = complete ]
receipt_sha256=$(sha256sum "$RECEIPT" | awk '{print $1}')
CONTAINER_ID=$(docker inspect -f '{{.Id}}' redactwall)
[[ "$CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]]
[ "$CONTAINER_ID" = "$EXPECTED_CONTAINER" ]
[ "$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID")" = "$EXPECTED_IMAGE" ]
[ "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}|{{.RW}}{{end}}{{end}}' "$CONTAINER_ID")" = '/var/lib/redactwall/runtime|true' ]
running=$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")
if [ "$running" = false ]; then docker start "$CONTAINER_ID" >/dev/null; else [ "$running" = true ]; fi
for attempt in $(seq 1 12); do
  if curl --fail --silent --show-error --max-time 3 http://127.0.0.1:4000/readyz >/dev/null; then
    printf 'REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=%s\n' "$receipt_sha256"
    exit 0
  fi
  sleep 5
done
exit 1`;
}

function legacyFreezeProbeCommand(payload) {
  const checkpointDigest = payload.checkpoint?.digest || 'none';
  return `set -euo pipefail
umask 077
exec 9>/run/redactwall-deploy.lock
flock -w 30 9
MIGRATION_ID=${singleQuote(payload.migrationId)}
ROOT=/var/lib/redactwall/runtime/legacy-connected-migration/$MIGRATION_ID
PARENT=$(dirname "$ROOT")
CLEANUP="$PARENT/$MIGRATION_ID.abort-cleanup"
RECEIPT="$PARENT/$MIGRATION_ID.abort-cleanup-receipt.json"
PENDING="$PARENT/$MIGRATION_ID.abort-cleanup-receipt.pending"
EXPECTED_STACK_ID=${singleQuote(payload.source.stackId)}
EXPECTED_INSTANCE_ID=${singleQuote(payload.source.instanceId)}
EXPECTED_IMAGE=${singleQuote(payload.source.imageUri)}
EXPECTED_CUSTOMER_ID=${singleQuote(payload.target.tenantId)}
EXPECTED_DEPLOYMENT_ID=${singleQuote(payload.target.deploymentId)}
EXPECTED_CHECKPOINT=${singleQuote(checkpointDigest)}
RECEIPT_KIND=${singleQuote(ABORT_CLEANUP_RECEIPT_KIND)}
CONTAINER_ID=$(docker inspect -f '{{.Id}}' redactwall)
[[ "$CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]]
[ "$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID")" = "$EXPECTED_IMAGE" ]
[ "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}|{{.RW}}{{end}}{{end}}' "$CONTAINER_ID")" = '/var/lib/redactwall/runtime|true' ]
running=$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")
[ "$running" = true ] || [ "$running" = false ]
phase=absent
cleanup_phase=none
cleanup_receipt_sha=none
cleanup_root_identity=none
cleanup_journal_sha=none
cleanup_entry_count=0
cleanup_cursor=0
cleanup_current_name=none
cleanup_checkpoint=none
cleanup_pending_publication=0
if [ -e "$ROOT" ] || [ -L "$ROOT" ] || [ -e "$CLEANUP" ] || [ -L "$CLEANUP" ] \
  || [ -e "$RECEIPT" ] || [ -L "$RECEIPT" ] || [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
  [ ! -L "$PARENT" ] && [ -d "$PARENT" ] && [ "$(stat -c '%u:%g:%a' "$PARENT")" = '0:0:700' ]
fi
if [ -e "$PENDING" ] || [ -L "$PENDING" ]; then
  [ ! -L "$PENDING" ] && [ -f "$PENDING" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$PENDING")" = '0:0:600:1' ]
  cleanup_pending_publication=1
fi
if { [ -e "$ROOT" ] || [ -L "$ROOT" ]; } && { [ -e "$CLEANUP" ] || [ -L "$CLEANUP" ]; }; then exit 1; fi
validate_receipt() {
  [ ! -L "$RECEIPT" ] && [ -f "$RECEIPT" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$RECEIPT")" = '0:0:600:1' ]
  jq -e --arg kind "$RECEIPT_KIND" --arg migrationId "$MIGRATION_ID" \
    --arg stackId "$EXPECTED_STACK_ID" --arg instanceId "$EXPECTED_INSTANCE_ID" \
    --arg container "$CONTAINER_ID" --arg image "$EXPECTED_IMAGE" \
    --arg customerId "$EXPECTED_CUSTOMER_ID" --arg deploymentId "$EXPECTED_DEPLOYMENT_ID" \
    --arg checkpoint "$EXPECTED_CHECKPOINT" '
      (keys | sort) == (["checkpointDigest","containerId","currentName","cursor","customerId","deploymentId",
        "entries","entryCount","imageUri","instanceId","journalSetSha256","kind","migrationId","phase",
        "rootIdentity","schemaVersion","sourceStackId"] | sort)
      and .schemaVersion == 1 and .kind == $kind and .migrationId == $migrationId
      and .sourceStackId == $stackId and .instanceId == $instanceId and .containerId == $container
      and .customerId == $customerId and .deploymentId == $deploymentId and .imageUri == $image
      and .checkpointDigest == $checkpoint
      and (.rootIdentity | type == "string" and test("^[0-9]+:[0-9]+:0:0:700$"))
      and (.journalSetSha256 | type == "string" and test("^[a-f0-9]{64}$"))
      and (.entries | type == "array") and (.entryCount | type == "number" and floor == . and . >= 1 and . <= 16)
      and (.entries | length) == .entryCount
      and all(.entries[]; (keys | sort) == ["name","sha256"]
        and (.name | type == "string" and test("^[A-Za-z0-9._-]{1,180}$"))
        and (.sha256 | type == "string" and test("^[a-f0-9]{64}$")))
      and ([.entries[].name] == ([.entries[].name] | sort))
      and ([.entries[].name] | unique | length) == .entryCount
      and (.cursor | type == "number" and floor == . and . >= 0 and . <= .entryCount)
      and (.phase == "prepared" or .phase == "deleting" or .phase == "removing" or .phase == "complete")
      and (if .phase == "deleting" then .cursor < .entryCount and .currentName == .entries[.cursor].name
        elif .phase == "prepared" then .currentName == null
        else .cursor == .entryCount and .currentName == null end)' "$RECEIPT" >/dev/null
  entries_json=$(jq -c '.entries' "$RECEIPT")
  [ "$(printf '%s' "$entries_json" | sha256sum | awk '{print $1}')" = "$(jq -r '.journalSetSha256' "$RECEIPT")" ]
  root_identity=$(jq -r '.rootIdentity' "$RECEIPT")
  entry_count=$(jq -r '.entryCount' "$RECEIPT")
}
verify_entry() {
  local directory=$1 name=$2 expected_sha=$3
  [ ! -L "$directory/$name" ] && [ -f "$directory/$name" ] \
    && [ "$(stat -c '%u:%g:%a:%h' "$directory/$name")" = '0:0:600:1' ]
  [ "$(sha256sum "$directory/$name" | awk '{print $1}')" = "$expected_sha" ]
}
verify_journal_state() {
  local directory=$1 receipt_phase receipt_cursor index name expected_sha actual_count expected_count
  receipt_phase=$(jq -r '.phase' "$RECEIPT")
  receipt_cursor=$(jq -r '.cursor' "$RECEIPT")
  [ ! -L "$directory" ] && [ -d "$directory" ] \
    && [ "$(stat -c '%d:%i:%u:%g:%a' "$directory")" = "$root_identity" ]
  index=0
  while [ "$index" -lt "$entry_count" ]; do
    name=$(printf '%s' "$entries_json" | jq -er --argjson index "$index" '.[$index].name')
    expected_sha=$(printf '%s' "$entries_json" | jq -er --argjson index "$index" '.[$index].sha256')
    if [ "$index" -lt "$receipt_cursor" ]; then
      [ ! -e "$directory/$name" ] && [ ! -L "$directory/$name" ]
    elif [ "$receipt_phase" = deleting ] && [ "$index" -eq "$receipt_cursor" ]; then
      if [ -e "$directory/$name" ] || [ -L "$directory/$name" ]; then verify_entry "$directory" "$name" "$expected_sha"; fi
    else
      verify_entry "$directory" "$name" "$expected_sha"
    fi
    index=$((index + 1))
  done
  actual_count=$(find "$directory" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
  expected_count=$((entry_count - receipt_cursor))
  [ "$actual_count" -eq "$expected_count" ] \
    || { [ "$receipt_phase" = deleting ] && [ "$actual_count" -eq "$((expected_count - 1))" ]; }
}
if [ -e "$RECEIPT" ] || [ -L "$RECEIPT" ]; then
  validate_receipt
  receipt_phase=$(jq -r '.phase' "$RECEIPT")
  receipt_cursor=$(jq -r '.cursor' "$RECEIPT")
  if [ "$receipt_phase" = complete ]; then
    [ ! -e "$ROOT" ] && [ ! -L "$ROOT" ] && [ ! -e "$CLEANUP" ] && [ ! -L "$CLEANUP" ]
    if [ "$cleanup_pending_publication" -eq 1 ]; then phase=cleanup; else phase=cleared; fi
  else
    phase=cleanup
    if [ -e "$ROOT" ] || [ -L "$ROOT" ]; then
      [ "$receipt_phase" = prepared ] && [ "$receipt_cursor" -eq 0 ]
      verify_journal_state "$ROOT"
    elif [ -e "$CLEANUP" ] || [ -L "$CLEANUP" ]; then
      verify_journal_state "$CLEANUP"
    else
      [ "$receipt_phase" = removing ]
    fi
  fi
  cleanup_phase=$receipt_phase
  cleanup_receipt_sha=$(sha256sum "$RECEIPT" | awk '{print $1}')
  cleanup_root_identity=$(jq -r '.rootIdentity' "$RECEIPT")
  cleanup_journal_sha=$(jq -r '.journalSetSha256' "$RECEIPT")
  cleanup_entry_count=$(jq -r '.entryCount' "$RECEIPT")
  cleanup_cursor=$(jq -r '.cursor' "$RECEIPT")
  cleanup_current_name=$(jq -r 'if .currentName == null then "n" else "v:" + .currentName end' "$RECEIPT")
  cleanup_checkpoint=$(jq -r '.checkpointDigest' "$RECEIPT")
elif [ -e "$CLEANUP" ] || [ -L "$CLEANUP" ]; then
  exit 1
elif [ -e "$ROOT" ] || [ -L "$ROOT" ]; then
  [ ! -L "$ROOT" ] && [ -d "$ROOT" ] && [ "$(stat -c '%u:%g:%a' "$ROOT")" = '0:0:700' ]
  INTENT="$ROOT/freeze-intent.json"
  [ ! -L "$INTENT" ] && [ -f "$INTENT" ] && [ "$(stat -c '%u:%g:%a:%h' "$INTENT")" = '0:0:600:1' ]
  jq -e --arg migrationId "$MIGRATION_ID" --arg stackId "$EXPECTED_STACK_ID" \
    --arg image "$EXPECTED_IMAGE" --arg container "$CONTAINER_ID" \
    '.version == 1 and .phase == "freeze_intent" and .migrationId == $migrationId
     and .sourceStackId == $stackId and .imageUri == $image and .containerId == $container
     and (.rootIdentity | type == "string" and test("^[0-9]+:[0-9]+:0:0:700$"))' "$INTENT" >/dev/null
  [ "$(stat -c '%d:%i:%u:%g:%a' "$ROOT")" = "$(jq -er '.rootIdentity' "$INTENT")" ]
  phase=intent
  CHECKPOINT="$ROOT/checkpoint.json"
  if [ -e "$CHECKPOINT" ] || [ -L "$CHECKPOINT" ]; then
    [ ! -L "$CHECKPOINT" ] && [ -f "$CHECKPOINT" ] && [ "$(stat -c '%u:%g:%a:%h' "$CHECKPOINT")" = '0:0:600:1' ]
    jq -e --arg migrationId ${singleQuote(payload.migrationId)} --arg stackId ${singleQuote(payload.source.stackId)} \
      --arg image ${singleQuote(payload.source.imageUri)} --arg container "$CONTAINER_ID" \
      '.version == 1 and .migrationId == $migrationId and .sourceStackId == $stackId
       and .imageUri == $image and .containerId == $container
       and (.backup | type == "string") and (.backup | test("^[A-Za-z0-9._-]{1,180}$"))
       and (.manifest | type == "string") and (.manifest | test("^[A-Za-z0-9._-]{1,180}$"))
       and (.rootIdentity | type == "string") and (.rootIdentity | test("^[0-9]+:[0-9]+:0:0:700$"))
       and (.recoverySetSha256 | type == "string") and (.recoverySetSha256 | test("^[a-f0-9]{64}$"))
       and (.artifactCount | type == "number") and (.artifactCount | floor == . and . >= 4 and . <= 8)
       and (.auditHead | type == "string") and (.auditHead | test("^[a-f0-9]{64}$"))
       and (.auditCount | type == "number") and (.auditCount | floor == . and . >= 0)
       and (.auditSequence | type == "number") and (.auditSequence | floor == . and . >= 0)' "$CHECKPOINT" >/dev/null
    [ "$running" = false ]
    phase=frozen
  fi
fi
printf 'REDACTWALL_LEGACY_SOURCE_CONTAINER_ID=%s\n' "$CONTAINER_ID"
printf 'REDACTWALL_LEGACY_SOURCE_WRITER_STATE=%s\n' "$([ "$running" = true ] && printf running || printf stopped)"
printf 'REDACTWALL_LEGACY_FREEZE_PHASE=%s\n' "$phase"
if [ "$phase" = cleared ] && [ "$running" = true ]; then
  curl --fail --silent --show-error --max-time 3 http://127.0.0.1:4000/readyz >/dev/null
fi
if [ "$phase" = cleanup ] || [ "$phase" = cleared ]; then
  printf 'REDACTWALL_LEGACY_ABORT_RECEIPT_KIND=%s\n' "$RECEIPT_KIND"
  printf 'REDACTWALL_LEGACY_ABORT_RECEIPT_PHASE=%s\n' "$cleanup_phase"
  printf 'REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=%s\n' "$cleanup_receipt_sha"
  printf 'REDACTWALL_LEGACY_ABORT_ROOT_IDENTITY=%s\n' "$cleanup_root_identity"
  printf 'REDACTWALL_LEGACY_ABORT_JOURNAL_SHA256=%s\n' "$cleanup_journal_sha"
  printf 'REDACTWALL_LEGACY_ABORT_ENTRY_COUNT=%s\n' "$cleanup_entry_count"
  printf 'REDACTWALL_LEGACY_ABORT_CURSOR=%s\n' "$cleanup_cursor"
  printf 'REDACTWALL_LEGACY_ABORT_CURRENT_NAME=%s\n' "$cleanup_current_name"
  printf 'REDACTWALL_LEGACY_ABORT_CHECKPOINT_SHA256=%s\n' "$cleanup_checkpoint"
  printf 'REDACTWALL_LEGACY_ABORT_PENDING_PUBLICATION=%s\n' "$cleanup_pending_publication"
fi
if [ "$phase" = frozen ]; then
  printf 'REDACTWALL_LEGACY_FREEZE_BACKUP=%s\n' "$(jq -r '.backup' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_MANIFEST=%s\n' "$(jq -r '.manifest' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_CONTAINER_ID=%s\n' "$CONTAINER_ID"
  printf 'REDACTWALL_LEGACY_FREEZE_ROOT_IDENTITY=%s\n' "$(jq -r '.rootIdentity' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_RECOVERY_SHA256=%s\n' "$(jq -r '.recoverySetSha256' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_ARTIFACT_COUNT=%s\n' "$(jq -r '.artifactCount' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_AUDIT_HEAD=%s\n' "$(jq -r '.auditHead' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_AUDIT_COUNT=%s\n' "$(jq -r '.auditCount' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_AUDIT_SEQUENCE=%s\n' "$(jq -r '.auditSequence' "$CHECKPOINT")"
  printf 'REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=%s\n' "$(sha256sum "$CHECKPOINT" | awk '{print $1}')"
fi`;
}

function legacyFrozenStatusCommand(payload) {
  return `set -euo pipefail
umask 077
exec 9>/run/redactwall-deploy.lock
flock -w 30 9
ROOT=/var/lib/redactwall/runtime/legacy-connected-migration/${singleQuote(payload.migrationId)}
CHECKPOINT="$ROOT/checkpoint.json"
[ ! -L "$CHECKPOINT" ] && [ -f "$CHECKPOINT" ] && [ "$(stat -c '%u:%g:%a:%h' "$CHECKPOINT")" = '0:0:600:1' ]
[ "$(sha256sum "$CHECKPOINT" | awk '{print $1}')" = ${singleQuote(payload.checkpoint.digest)} ]
jq -e --arg migrationId ${singleQuote(payload.migrationId)} --arg stackId ${singleQuote(payload.source.stackId)} \\
  --arg image ${singleQuote(payload.source.imageUri)} --arg container ${singleQuote(payload.checkpoint.containerId)} \\
  --arg rootIdentity ${singleQuote(payload.checkpoint.rootIdentity)} --arg recoverySha ${singleQuote(payload.checkpoint.recoverySetSha256)} \\
  --arg auditHead ${singleQuote(payload.checkpoint.auditHead)} --argjson artifactCount ${payload.checkpoint.artifactCount} \\
  --argjson auditCount ${payload.checkpoint.auditCount} --argjson auditSequence ${payload.checkpoint.auditSequence} \\
  '.version == 1 and .migrationId == $migrationId and .sourceStackId == $stackId and .imageUri == $image
   and .containerId == $container and .rootIdentity == $rootIdentity and .recoverySetSha256 == $recoverySha
   and .artifactCount == $artifactCount and .auditHead == $auditHead
   and .auditCount == $auditCount and .auditSequence == $auditSequence' "$CHECKPOINT" >/dev/null
CONTAINER_ID=$(jq -r '.containerId' "$CHECKPOINT")
[[ "$CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]]
[ "$(docker inspect -f '{{.Id}}' redactwall)" = "$CONTAINER_ID" ]
[ "$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID")" = ${singleQuote(payload.source.imageUri)} ]
[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_ID")" = false ]
[ ! -L "$ROOT" ] && [ -d "$ROOT" ]
root_identity=$(jq -er '.rootIdentity | select(type == "string" and length > 0 and length <= 128)' "$CHECKPOINT")
[ "$(stat -c '%d:%i:%u:%g:%a' "$ROOT")" = "$root_identity" ]
artifact_count=$(jq -er '.artifactCount | select(type == "number" and floor == . and . >= 4 and . <= 8)' "$CHECKPOINT")
expected_recovery_sha=$(jq -er '.recoverySetSha256 | select(type == "string" and test("^[a-f0-9]{64}$"))' "$CHECKPOINT")
backup_name=$(jq -er '.backup | select(type == "string" and test("^[A-Za-z0-9._-]{1,180}$"))' "$CHECKPOINT")
manifest_name=$(jq -er '.manifest | select(type == "string" and test("^[A-Za-z0-9._-]{1,180}$"))' "$CHECKPOINT")
audit_checkpoint_name=$(jq -er '.auditCheckpoint | select(type == "string" and test("^[A-Za-z0-9._-]{1,180}$"))' "$CHECKPOINT")
expected_image=$(jq -er '.imageUri | select(type == "string")' "$CHECKPOINT")
recovery_digest() {
  local root=$1 expected_count=$2 names digests name count
  names=$(mktemp /run/redactwall-legacy-status-names.XXXXXX)
  digests=$(mktemp /run/redactwall-legacy-status-digests.XXXXXX)
  find "$root" -mindepth 1 -maxdepth 1 ! -name checkpoint.json ! -name freeze-intent.json -printf '%f\n' | LC_ALL=C sort > "$names"
  count=$(wc -l < "$names" | tr -d ' ')
  [ "$count" -eq "$expected_count" ]
  while IFS= read -r name; do
    [[ "$name" =~ ^[A-Za-z0-9._-]{1,180}$ ]]
    [ ! -L "$root/$name" ] && [ -f "$root/$name" ] \
      && [ "$(stat -c '%u:%g:%a:%h' "$root/$name")" = '0:0:600:1' ]
    printf '%s  %s\n' "$(sha256sum "$root/$name" | awk '{print $1}')" "$name" >> "$digests"
  done < "$names"
  sha256sum "$digests" | awk '{print $1}'
  rm -- "$names" "$digests"
}
[ "$(find "$ROOT" -mindepth 1 -maxdepth 1 | wc -l)" -eq "$((artifact_count + 2))" ]
[ ! -L "$ROOT/freeze-intent.json" ] && [ -f "$ROOT/freeze-intent.json" ] \
  && [ "$(stat -c '%u:%g:%a:%h' "$ROOT/freeze-intent.json")" = '0:0:600:1' ]
[ "$(sha256sum "$ROOT/freeze-intent.json" | awk '{print $1}')" = "$(jq -r '.intentSha256' "$CHECKPOINT")" ]
[ "$(recovery_digest "$ROOT" "$artifact_count")" = "$expected_recovery_sha" ]
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \\
  --cap-drop ALL --security-opt no-new-privileges --env-file /etc/redactwall/env \\
  -v "$ROOT:/recovery:ro" --entrypoint node "$expected_image" \\
  scripts/backup-store.js verify --file "/recovery/$backup_name" --manifest "/recovery/$manifest_name" >/dev/null
[ "$(jq -er '.head' "$ROOT/$audit_checkpoint_name")" = ${singleQuote(payload.checkpoint.auditHead)} ]
[ "$(jq -er '.count' "$ROOT/$audit_checkpoint_name")" = ${payload.checkpoint.auditCount} ]
[ "$(jq -er '.seq' "$ROOT/$audit_checkpoint_name")" = ${payload.checkpoint.auditSequence} ]
printf 'REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=%s\\n' ${singleQuote(payload.checkpoint.digest)}`;
}

function exactLine(output, name, pattern) {
  const matches = [...String(output || '').matchAll(new RegExp(`^${name}=(${pattern})$`, 'gm'))];
  if (matches.length !== 1) throw new Error(`legacy freeze returned invalid ${name}`);
  return matches[0][1];
}

function parseFreezeCheckpoint(output) {
  if (exactLine(output, 'REDACTWALL_LEGACY_FREEZE_PHASE', 'frozen') !== 'frozen') {
    throw new Error('legacy freeze did not reach the frozen phase');
  }
  const checkpoint = {
    backup: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_BACKUP', '[A-Za-z0-9._-]{1,180}'),
    manifest: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_MANIFEST', '[A-Za-z0-9._-]{1,180}'),
    containerId: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_CONTAINER_ID', '[a-f0-9]{64}'),
    rootIdentity: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_ROOT_IDENTITY', '[0-9]+:[0-9]+:0:0:700'),
    recoverySetSha256: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_RECOVERY_SHA256', '[a-f0-9]{64}'),
    artifactCount: Number(exactLine(output, 'REDACTWALL_LEGACY_FREEZE_ARTIFACT_COUNT', '[0-9]+')),
    auditHead: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_AUDIT_HEAD', '[a-f0-9]{64}'),
    auditCount: Number(exactLine(output, 'REDACTWALL_LEGACY_FREEZE_AUDIT_COUNT', '[0-9]+')),
    auditSequence: Number(exactLine(output, 'REDACTWALL_LEGACY_FREEZE_AUDIT_SEQUENCE', '[0-9]+')),
    digest: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256', '[a-f0-9]{64}'),
  };
  if (!Number.isInteger(checkpoint.artifactCount) || checkpoint.artifactCount < 4 || checkpoint.artifactCount > 8) {
    throw new Error('legacy freeze returned an invalid recovery artifact count');
  }
  if (!Number.isSafeInteger(checkpoint.auditCount) || checkpoint.auditCount < 0
    || !Number.isSafeInteger(checkpoint.auditSequence) || checkpoint.auditSequence < 0) {
    throw new Error('legacy freeze returned invalid authenticated audit coordinates');
  }
  return checkpoint;
}

function validateCleanupReceipt(value, payload, containerId) {
  const cleanup = structuredClone(value);
  const keys = [
    'checkpointDigest', 'containerId', 'currentName', 'cursor', 'customerId', 'deploymentId',
    'entryCount', 'imageUri', 'instanceId', 'journalSetSha256', 'kind', 'migrationId', 'phase',
    'pendingPublication', 'receiptSha256', 'rootIdentity', 'schemaVersion', 'sourceStackId',
  ].sort();
  if (!cleanup || typeof cleanup !== 'object' || Array.isArray(cleanup)
    || Object.keys(cleanup).sort().join(',') !== keys.join(',')
    || cleanup.schemaVersion !== 1 || cleanup.kind !== ABORT_CLEANUP_RECEIPT_KIND
    || !['prepared', 'deleting', 'removing', 'complete'].includes(cleanup.phase)
    || !DIGEST.test(String(cleanup.receiptSha256 || ''))
    || !DIGEST.test(String(cleanup.journalSetSha256 || ''))
    || !/^[0-9]+:[0-9]+:0:0:700$/.test(String(cleanup.rootIdentity || ''))
    || !(cleanup.checkpointDigest === 'none' || DIGEST.test(String(cleanup.checkpointDigest || '')))
    || !Number.isInteger(cleanup.entryCount) || cleanup.entryCount < 1 || cleanup.entryCount > 16
    || !Number.isInteger(cleanup.cursor) || cleanup.cursor < 0 || cleanup.cursor > cleanup.entryCount
    || (cleanup.phase === 'deleting' && (cleanup.cursor >= cleanup.entryCount
      || !/^[A-Za-z0-9._-]{1,180}$/.test(String(cleanup.currentName || ''))))
    || (cleanup.phase !== 'deleting' && cleanup.currentName !== null)
    || (['removing', 'complete'].includes(cleanup.phase) && cleanup.cursor !== cleanup.entryCount)
    || typeof cleanup.pendingPublication !== 'boolean'
    || cleanup.containerId !== containerId) {
    throw new Error('legacy abort cleanup receipt is missing, changed, or ambiguous');
  }
  if (payload && (cleanup.migrationId !== payload.migrationId
    || cleanup.customerId !== payload.target.tenantId || cleanup.deploymentId !== payload.target.deploymentId
    || cleanup.sourceStackId !== payload.source.stackId || cleanup.instanceId !== payload.source.instanceId
    || cleanup.imageUri !== payload.source.imageUri
    || cleanup.containerId !== payload.freezeBaseline?.containerId
    || cleanup.checkpointDigest !== (payload.checkpoint?.digest || 'none'))) {
    throw new Error('legacy abort cleanup receipt is not bound to the exact migration and writer');
  }
  return cleanup;
}

function validateFreezeSourceState(value, payload = null) {
  const state = structuredClone(value);
  if (state && state.cleanup === undefined) state.cleanup = null;
  if (!state || typeof state !== 'object' || Array.isArray(state)
    || !DIGEST.test(String(state.containerId || ''))
    || !['running', 'stopped'].includes(state.writerState)
    || !['absent', 'intent', 'frozen', 'cleanup', 'cleared'].includes(state.freezePhase)
    || (state.freezePhase === 'frozen' && (!state.checkpoint
      || state.writerState !== 'stopped' || state.checkpoint.containerId !== state.containerId))
    || (state.freezePhase !== 'frozen' && state.checkpoint != null)
    || (['cleanup', 'cleared'].includes(state.freezePhase) && !state.cleanup)
    || (!['cleanup', 'cleared'].includes(state.freezePhase) && state.cleanup != null)) {
    throw new Error('legacy source writer/checkpoint state is missing or ambiguous');
  }
  if (state.cleanup) {
    state.cleanup = validateCleanupReceipt(state.cleanup, payload, state.containerId);
    const durablyCleared = state.cleanup.phase === 'complete' && !state.cleanup.pendingPublication;
    if ((state.freezePhase === 'cleared') !== durablyCleared) {
      throw new Error('legacy abort cleanup receipt phase conflicts with the host journal state');
    }
  }
  return state;
}

function parseFreezeProbe(output, payload) {
  const state = {
    containerId: exactLine(output, 'REDACTWALL_LEGACY_SOURCE_CONTAINER_ID', '[a-f0-9]{64}'),
    writerState: exactLine(output, 'REDACTWALL_LEGACY_SOURCE_WRITER_STATE', 'running|stopped'),
    freezePhase: exactLine(output, 'REDACTWALL_LEGACY_FREEZE_PHASE', 'absent|intent|frozen|cleanup|cleared'),
    checkpoint: null,
    cleanup: null,
  };
  if (state.freezePhase === 'frozen') state.checkpoint = parseFreezeCheckpoint(output);
  if (['cleanup', 'cleared'].includes(state.freezePhase)) {
    const currentName = exactLine(output, 'REDACTWALL_LEGACY_ABORT_CURRENT_NAME', 'n|v:[A-Za-z0-9._-]{1,180}');
    state.cleanup = {
      schemaVersion: 1,
      kind: exactLine(output, 'REDACTWALL_LEGACY_ABORT_RECEIPT_KIND', ABORT_CLEANUP_RECEIPT_KIND.replaceAll('.', '\\.')),
      phase: exactLine(output, 'REDACTWALL_LEGACY_ABORT_RECEIPT_PHASE', 'prepared|deleting|removing|complete'),
      migrationId: payload.migrationId,
      customerId: payload.target.tenantId,
      deploymentId: payload.target.deploymentId,
      sourceStackId: payload.source.stackId,
      instanceId: payload.source.instanceId,
      containerId: state.containerId,
      imageUri: payload.source.imageUri,
      checkpointDigest: exactLine(output, 'REDACTWALL_LEGACY_ABORT_CHECKPOINT_SHA256', 'none|[a-f0-9]{64}'),
      rootIdentity: exactLine(output, 'REDACTWALL_LEGACY_ABORT_ROOT_IDENTITY', '[0-9]+:[0-9]+:0:0:700'),
      journalSetSha256: exactLine(output, 'REDACTWALL_LEGACY_ABORT_JOURNAL_SHA256', '[a-f0-9]{64}'),
      entryCount: Number(exactLine(output, 'REDACTWALL_LEGACY_ABORT_ENTRY_COUNT', '[0-9]+')),
      cursor: Number(exactLine(output, 'REDACTWALL_LEGACY_ABORT_CURSOR', '[0-9]+')),
      currentName: currentName === 'n' ? null : currentName.slice(2),
      pendingPublication: exactLine(output,
        'REDACTWALL_LEGACY_ABORT_PENDING_PUBLICATION', '0|1') === '1',
      receiptSha256: exactLine(output, 'REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256', '[a-f0-9]{64}'),
    };
  }
  return validateFreezeSourceState(state, payload);
}

function queryFreezeSourceState(payload, dependencies = {}) {
  if (typeof dependencies.readFreezeSourceState === 'function') {
    return validateFreezeSourceState(dependencies.readFreezeSourceState(payload), payload);
  }
  const sendCommand = dependencies.sendCommand || deployer.sendCommand;
  const timeout = dependencies.timeoutSeconds || 1200;
  const probe = parseFreezeProbe(sendCommand(payload.source.instanceId, payload.source.region,
    legacyFreezeProbeCommand(payload), timeout, 'RedactWall legacy freeze recovery probe').output, payload);
  if (probe.freezePhase === 'frozen') {
    const verified = sendCommand(payload.source.instanceId, payload.source.region,
      legacyFrozenStatusCommand({ ...payload, checkpoint: probe.checkpoint }), timeout,
      'RedactWall legacy frozen checkpoint verification');
    if (exactLine(verified.output, 'REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256', '[a-f0-9]{64}')
      !== probe.checkpoint.digest) throw new Error('legacy frozen checkpoint verification changed during recovery');
  }
  return probe;
}

function targetSnapshot(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || typeof value.registered !== 'boolean'
    || (value.registered && value.state !== 'healthy')
    || (!value.registered && value.state !== 'absent')) {
    throw new Error('legacy target registration and health are missing or not safely recoverable');
  }
  return { registered: value.registered, state: value.state };
}

function freezeBaseline(target, sourceState) {
  if (sourceState.freezePhase !== 'absent' || sourceState.writerState !== 'running') {
    throw new Error('legacy source is not an exact running pre-freeze writer');
  }
  return validateFreezeBaseline({
    containerId: sourceState.containerId, writerState: 'running', target: targetSnapshot(target),
  });
}

function validateFreezeBaseline(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || !DIGEST.test(String(value.containerId || '')) || value.writerState !== 'running') {
    throw new Error('legacy freeze baseline is missing or ambiguous');
  }
  return { containerId: value.containerId, writerState: 'running', target: targetSnapshot(value.target) };
}

function normalizeLeaseReadback(lease, observed, allowReleased = false) {
  if (observed?.exists === false) {
    if (!allowReleased) throw new Error('external maintenance lease disappeared before authorized release');
    return { ...structuredClone(lease), released: true };
  }
  let live = structuredClone(observed);
  if (observed?.tags) {
    live = {
      ...structuredClone(lease), stackId: observed.stackId, stackName: observed.stackName,
      region: lease.region, phase: observed.tags.RedactWallMaintenancePhase,
      permittedOperationId: observed.tags.RedactWallPermittedOperation,
      checkpointSetId: observed.tags.RedactWallMaintenanceSet,
      checkpointLatchSha256: observed.tags.RedactWallMaintenanceLatchSha256,
      operationId: observed.tags.RedactWallMaintenanceOperation,
      sourceStackId: observed.tags.RedactWallSourceStackId,
      sourceFingerprint: observed.tags.RedactWallSourceFingerprint,
      stackStatus: observed.stackStatus,
    };
  }
  if (live.stackId !== lease.stackId || live.stackName !== lease.stackName || live.region !== lease.region
    || live.operationId !== lease.operationId || live.sourceStackId !== lease.sourceStackId
    || live.sourceFingerprint !== lease.sourceFingerprint
    || !['acquired', 'preparing', 'drained', 'release_ready', 'evidence_retained'].includes(live.phase)
    || live.permittedOperationId !== 'none'
    || (live.stackStatus && live.stackStatus !== 'CREATE_COMPLETE')) {
    throw new Error('external maintenance lease identity or phase is missing, changed, or ambiguous');
  }
  return live;
}

function queryFreezeLease(payload, dependencies = {}, allowReleased = false) {
  const observed = typeof dependencies.readLeaseState === 'function'
    ? dependencies.readLeaseState(payload.lease)
    : deployer.stackState(payload.lease.stackId, payload.lease.region);
  return normalizeLeaseReadback(payload.lease, observed, allowReleased);
}

function assertFreezeSource(payload, dependencies) {
  const current = (dependencies.stackDescription || maintenance.stackDescription)(
    payload.source.stackId, payload.source.region,
  );
  if (maintenance.sourceFingerprint(current) !== payload.source.fingerprint) {
    throw new Error('legacy source changed during freeze recovery');
  }
}

function restoreTargetBaseline(payload, current, dependencies) {
  const runAws = dependencies.runAws || deployer.runAws;
  const target = payload.freezeBaseline.target;
  const base = ['--target-group-arn', payload.source.targetGroupArn,
    '--targets', `Id=${payload.source.instanceId}`, '--region', payload.source.region];
  if (target.registered && !current.registered) {
    runAws(['elbv2', 'register-targets', ...base], { errorMessage: 'Could not restore the exact prior target registration' });
  } else if (!target.registered && current.registered) {
    runAws(['elbv2', 'deregister-targets', ...base], { errorMessage: 'Could not restore the exact prior target absence' });
    runAws(['elbv2', 'wait', 'target-deregistered', ...base], {
      errorMessage: 'Prior absent target did not return to exact absence',
    });
  }
  if (target.registered) {
    runAws(['elbv2', 'wait', 'target-in-service', ...base], {
      errorMessage: 'Prior healthy target did not return to service',
    });
  }
  const verified = targetSnapshot((dependencies.targetRegistration || maintenance.targetRegistration)(
    payload.source.targetGroupArn, payload.source.instanceId, payload.source.region,
  ));
  if (JSON.stringify(verified) !== JSON.stringify(target)) {
    throw new Error('legacy target registration did not return to its exact prior health state');
  }
}

function recoveryCommand(dependencies) {
  const fallback = 'node scripts/aws-legacy-connected-migrate.js reconcile'
    + ' --manifest "$REDACTWALL_LEGACY_MANIFEST" --witness "$REDACTWALL_LEGACY_WITNESS"'
    + ' --manifest-key "$REDACTWALL_LEGACY_MANIFEST_KEY" --witness-key "$REDACTWALL_LEGACY_WITNESS_KEY"';
  const command = String(dependencies.recoveryCommand || fallback);
  return command === fallback ? command : fallback;
}

function freezeRecoveryIdentity(payload) {
  const checkpointDigest = DIGEST.test(String(payload.checkpoint?.digest || ''))
    ? payload.checkpoint.digest : 'none';
  return {
    migrationId: payload.migrationId, sourceStackId: payload.source.stackId,
    leaseStackId: payload.lease.stackId, phase: payload.phase, checkpointDigest,
  };
}

function retainedFreezeError(payload, dependencies) {
  const identity = freezeRecoveryIdentity(payload);
  const error = new Error(`legacy freeze evidence retained; checked recovery: ${recoveryCommand(dependencies)}`);
  error.recoveryIdentity = identity;
  error.freezeRecovery = identity;
  return error;
}

function abortCleanupIntent(payload, receiptSha256 = null) {
  return {
    kind: ABORT_CLEANUP_INTENT_KIND,
    migrationId: payload.migrationId,
    customerId: payload.target.tenantId,
    deploymentId: payload.target.deploymentId,
    sourceStackId: payload.source.stackId,
    instanceId: payload.source.instanceId,
    containerId: payload.freezeBaseline.containerId,
    checkpointDigest: payload.checkpoint?.digest || 'none',
    status: receiptSha256 ? 'complete' : 'required',
    receiptSha256,
  };
}

function validateAbortCleanupIntent(value, payload) {
  const intent = structuredClone(value);
  const expected = abortCleanupIntent(payload, intent?.receiptSha256 || null);
  if (!intent || typeof intent !== 'object' || Array.isArray(intent)
    || !['required', 'complete'].includes(intent.status)
    || (intent.status === 'required' && intent.receiptSha256 !== null)
    || (intent.status === 'complete' && !DIGEST.test(String(intent.receiptSha256 || '')))
    || JSON.stringify(canonical(intent)) !== JSON.stringify(canonical(expected))) {
    throw new Error('legacy abort cleanup intent is missing, changed, or not bound to the exact migration');
  }
  return intent;
}

function restoreSourceAndRelease(payload, sourceState, targetState, dependencies) {
  const sendCommand = dependencies.sendCommand || deployer.sendCommand;
  const timeout = dependencies.timeoutSeconds || 1200;
  let state = structuredClone(payload);
  try {
    let cleanupIntent = state.abortCleanup
      ? validateAbortCleanupIntent(state.abortCleanup, state) : null;
    if (cleanupIntent && sourceState.freezePhase === 'absent') {
      throw new Error('legacy abort cleanup receipt disappeared after durable cleanup intent');
    }
    const cleanupNeeded = !['absent', 'cleared'].includes(sourceState.freezePhase)
      || sourceState.writerState === 'stopped' || sourceState.cleanup !== null || cleanupIntent !== null;
    if (cleanupNeeded && !cleanupIntent) {
      cleanupIntent = abortCleanupIntent(state);
      state = { ...state, abortCleanup: cleanupIntent };
      dependencies.persist(structuredClone(state));
    }
    let cleanupReceiptSha256 = sourceState.cleanup?.receiptSha256 || null;
    if (!['absent', 'cleared'].includes(sourceState.freezePhase) || sourceState.writerState === 'stopped') {
      const cleanup = sendCommand(state.source.instanceId, state.source.region,
        legacyAbortCommand(state, dependencies), timeout, 'RedactWall legacy migration recovery abort');
      cleanupReceiptSha256 = exactLine(cleanup.output,
        'REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256', '[a-f0-9]{64}');
    }
    if (cleanupIntent) {
      if (!cleanupReceiptSha256) throw new Error('legacy abort cleanup lacks independent completion evidence');
      if (cleanupIntent.status === 'complete' && cleanupIntent.receiptSha256 !== cleanupReceiptSha256) {
        throw new Error('legacy abort cleanup completion identity changed across restart');
      }
      cleanupIntent = abortCleanupIntent(state, cleanupReceiptSha256);
      state = { ...state, abortCleanup: cleanupIntent };
      dependencies.persist(structuredClone(state));
    }
    restoreTargetBaseline(state, targetState, dependencies);
    const restoredSource = queryFreezeSourceState(state, dependencies);
    if (restoredSource.containerId !== state.freezeBaseline.containerId
      || restoredSource.writerState !== 'running' || restoredSource.checkpoint !== null
      || (cleanupReceiptSha256 && (restoredSource.freezePhase !== 'cleared'
        || restoredSource.cleanup?.phase !== 'complete'
        || restoredSource.cleanup.receiptSha256 !== cleanupReceiptSha256))
      || (!cleanupReceiptSha256 && (restoredSource.freezePhase !== 'absent'
        || restoredSource.cleanup !== null))) {
      throw new Error('legacy writer did not return to its exact prior running identity with a cleared freeze journal');
    }
    const restored = { ...state, phase: 'source_restored', updatedAt: dependencies.now };
    dependencies.persist(structuredClone(restored));
    state = restored;
    let lease = queryFreezeLease(state, dependencies, true);
    if (!lease.released) {
      if (lease.phase !== 'release_ready') {
        lease = (dependencies.transitionMaintenanceLease || maintenance.transitionMaintenanceLease)(
          lease, 'release_ready', {}, 'none', null,
        );
        const releaseReady = { ...state, lease };
        dependencies.persist(structuredClone(releaseReady));
        state = releaseReady;
      }
      try { (dependencies.releaseMaintenanceLease || maintenance.releaseMaintenanceLease)(lease); }
      catch (error) {
        const readback = queryFreezeLease(state, dependencies, true);
        if (!readback.released) throw error;
      }
    }
    const retryable = { ...state, phase: 'retryable', leaseReleased: true, updatedAt: dependencies.now };
    dependencies.persist(structuredClone(retryable));
    return retryable;
  } catch (error) {
    if (!error.freezeRecoveryState) error.freezeRecoveryState = state;
    throw error;
  }
}

function adoptFrozenCheckpoint(payload, sourceState, targetState, dependencies) {
  if (targetState.registered || sourceState.containerId !== payload.freezeBaseline.containerId) {
    throw new Error('stopped checkpoint does not match the drained exact source identity');
  }
  let lease = queryFreezeLease(payload, dependencies);
  if (lease.phase === 'preparing') {
    lease = (dependencies.transitionMaintenanceLease || maintenance.transitionMaintenanceLease)(
      lease, 'drained', {}, 'none', { setId: payload.migrationId, latchSha256: sourceState.checkpoint.digest },
    );
  } else if (lease.phase !== 'drained' || lease.checkpointSetId !== payload.migrationId
    || lease.checkpointLatchSha256 !== sourceState.checkpoint.digest) {
    throw new Error('external maintenance lease is not bound to the exact stopped checkpoint');
  }
  const frozen = { ...structuredClone(payload), phase: 'frozen', lease,
    checkpoint: sourceState.checkpoint, updatedAt: dependencies.now };
  dependencies.persist(structuredClone(frozen));
  return frozen;
}

function reconcileFreezeMigration(payload, now, dependencies = {}) {
  assertRollbackAllowed(payload, dependencies);
  if (!FREEZE_RECOVERY_PHASES.has(payload.phase) || !payload.lease || !ISO_MILLIS.test(String(now || ''))
    || typeof dependencies.persist !== 'function') {
    throw new Error('legacy freeze reconciliation requires authenticated durable recovery state');
  }
  let state = structuredClone(payload);
  const context = { ...dependencies, now };
  try {
    assertFreezeSource(state, dependencies);
    const lease = queryFreezeLease(state, dependencies, true);
    if (state.phase === 'retryable') {
      if (!lease.released) throw new Error('retryable freeze state still has an active external lease');
      return state;
    }
    if (lease.released && state.phase !== 'source_restored') {
      throw new Error('external maintenance lease released before exact source restoration was durable');
    }
    let sourceState = queryFreezeSourceState(state, dependencies);
    let targetState = targetSnapshot((dependencies.targetRegistration || maintenance.targetRegistration)(
      state.source.targetGroupArn, state.source.instanceId, state.source.region,
    ));
    if (!state.freezeBaseline) {
      if (state.phase !== 'freeze_intent') {
        throw new Error('post-intent freeze state lacks its exact pre-deregister baseline');
      }
      state.freezeBaseline = freezeBaseline(targetState, sourceState);
      dependencies.persist(structuredClone(state));
    } else {
      state.freezeBaseline = validateFreezeBaseline(state.freezeBaseline);
    }
    if (sourceState.containerId !== state.freezeBaseline.containerId) {
      throw new Error('legacy source container changed during freeze recovery');
    }
    if (sourceState.freezePhase === 'frozen' && state.recoveryDisposition !== 'restore') {
      return adoptFrozenCheckpoint(state, sourceState, targetState, context);
    }
    if (sourceState.freezePhase === 'absent' && sourceState.writerState === 'stopped') {
      throw new Error('legacy writer stopped without an authenticated freeze intent');
    }
    return restoreSourceAndRelease(state, sourceState, targetState, context);
  } catch (error) {
    if (error?.recoveryIdentity) throw error;
    const recoveryState = error.freezeRecoveryState || state;
    const failed = recoveryState.phase === 'source_restored' ? recoveryState : {
      ...recoveryState, phase: 'freeze_failed', failure: 'evidence_retained', updatedAt: now,
    };
    if (failed.phase !== 'source_restored') {
      try { dependencies.persist(structuredClone(failed)); }
      catch (persistError) { error.freezeFailurePersistenceErrorName = String(persistError?.name || 'Error').slice(0, 64); }
    }
    throw retainedFreezeError(failed, dependencies);
  }
}

function freezeMigration(payload, now, dependencies = {}) {
  assertRollbackAllowed(payload, dependencies);
  if (payload.phase !== 'planned' || !payload.lease || !ISO_MILLIS.test(String(now || ''))) {
    throw new Error('legacy freeze requires one authenticated planned manifest and active external lease');
  }
  const stackDescription = dependencies.stackDescription || maintenance.stackDescription;
  const waitForSsmOnline = dependencies.waitForSsmOnline || deployer.waitForSsmOnline;
  const sendCommand = dependencies.sendCommand || deployer.sendCommand;
  const runAws = dependencies.runAws || deployer.runAws;
  const persist = dependencies.persist;
  const transitionLease = dependencies.transitionMaintenanceLease || maintenance.transitionMaintenanceLease;
  if (typeof persist !== 'function') throw new Error('legacy freeze requires durable state publication');
  let current;
  try { current = stackDescription(payload.source.stackId, payload.source.region); }
  catch (error) {
    const sanitized = new Error('legacy source description query failed before freeze');
    sanitized.queryErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  if (maintenance.sourceFingerprint(current) !== payload.source.fingerprint) {
    throw new Error('legacy source changed after the authenticated migration plan');
  }
  const timeout = dependencies.timeoutSeconds || 1200;
  let state = { ...structuredClone(payload), phase: 'freeze_intent', updatedAt: now };
  try { persist(structuredClone(state)); }
  catch (error) {
    const sanitized = new Error('legacy freeze intent durable publication failed');
    sanitized.persistenceErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  try {
    state.lease = transitionLease(state.lease, 'preparing');
    persist(structuredClone(state));
    waitForSsmOnline(payload.source.instanceId, payload.source.region, timeout);
    sendCommand(payload.source.instanceId, payload.source.region, legacyPreflightCommand(payload), timeout,
      'RedactWall legacy migration preflight');
    const target = targetSnapshot((dependencies.targetRegistration || maintenance.targetRegistration)(
      payload.source.targetGroupArn, payload.source.instanceId, payload.source.region,
    ));
    const sourceState = queryFreezeSourceState(state, dependencies);
    state = { ...state, phase: 'freeze_deregister_intent', freezeBaseline: freezeBaseline(target, sourceState) };
    persist(structuredClone(state));
    if (target.registered) {
      runAws(['elbv2', 'deregister-targets', '--target-group-arn', payload.source.targetGroupArn,
        '--targets', `Id=${payload.source.instanceId}`, '--region', payload.source.region], {
        errorMessage: 'Could not quiesce the legacy target',
      });
      runAws(['elbv2', 'wait', 'target-deregistered', '--target-group-arn', payload.source.targetGroupArn,
        '--targets', `Id=${payload.source.instanceId}`, '--region', payload.source.region], {
        errorMessage: 'Legacy target did not drain before the freeze deadline',
      });
      const drained = targetSnapshot((dependencies.targetRegistration || maintenance.targetRegistration)(
        payload.source.targetGroupArn, payload.source.instanceId, payload.source.region,
      ));
      if (drained.registered) throw new Error('legacy target remained registered after the drain waiter');
    }
    state = { ...state, phase: 'freeze_target_drained' };
    persist(structuredClone(state));
    const invocation = sendCommand(payload.source.instanceId, payload.source.region,
      legacyFreezeCommand(payload), timeout, 'RedactWall stopped-writer legacy migration freeze');
    const checkpoint = parseFreezeCheckpoint(invocation.output);
    if (checkpoint.containerId !== state.freezeBaseline.containerId) {
      throw new Error('legacy stopped checkpoint belongs to a different container identity');
    }
    state.lease = transitionLease(state.lease, 'drained', {}, 'none', {
      setId: state.migrationId, latchSha256: checkpoint.digest,
    });
    const frozen = { ...state, phase: 'frozen', checkpoint };
    persist(structuredClone(frozen));
    return frozen;
  } catch (error) {
    try {
      const reconciled = reconcileFreezeMigration(state, now, { ...dependencies, persist, timeoutSeconds: timeout });
      if (reconciled.phase === 'frozen') return reconciled;
      const sanitized = new Error('legacy freeze operation failed; exact source restoration is durable and retryable');
      sanitized.operationErrorName = String(error?.name || 'Error').slice(0, 64);
      sanitized.freezeRecovery = freezeRecoveryIdentity(reconciled);
      throw sanitized;
    } catch (recoveryError) {
      if (recoveryError === error) throw error;
      throw recoveryError;
    }
  }
}

function deploymentArgsFile(file, expected = null) {
  privatePath.assertPrivatePath(file, { label: 'legacy connected deployment arguments', directory: false });
  const bytes = privatePath.readBoundedRegularFile(file, {
    label: 'legacy connected deployment arguments', maxBytes: 65536,
  });
  if (bytes.length < 2 || bytes.length > 65536) throw new Error('deployment arguments file is invalid');
  if (expected && (bytes.length !== expected.bytes || sha256(bytes) !== expected.sha256)) {
    throw new Error('deployment arguments snapshot changed after the authenticated plan');
  }
  const args = JSON.parse(bytes.toString('utf8'));
  if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) {
    throw new Error('deployment arguments file must contain one JSON string array');
  }
  return deployer.validate(deployer.parseArgs(args));
}

function assertDeploymentSnapshot(payload, values) {
  const expected = JSON.stringify(canonical(payload.target.aws));
  const actual = JSON.stringify(canonical(deploymentAwsContract(values)));
  if (expected !== actual || values['tenant-id'] !== payload.target.tenantId
    || values['deployment-id'] !== payload.target.deploymentId
    || values['secret-version-id'] !== payload.target.connectedSecretVersionId
    || values['data-volume-id'] !== payload.source.dataVolumeId) {
    throw new Error('connected deployment arguments do not match the authenticated migration manifest');
  }
}

function cutoverAttestation(result, expected) {
  if (result.operationId !== expected.operationId || result.stackId !== expected.stackId
    || !/^i-[a-f0-9]{8,17}$/.test(String(result.instanceId || ''))
    || !DIGEST.test(String(result.containerId || '')) || !DIGEST.test(String(result.appliedStateSha256 || ''))
    || !DIGEST.test(String(result.authorityFingerprintSha256 || ''))
    || !ISO_MILLIS.test(String(result.attestedAt || ''))) {
    throw new Error('connected candidate applied attestation is incomplete or mismatched');
  }
  return {
    ...expected, instanceId: result.instanceId, containerId: result.containerId,
    appliedStateSha256: result.appliedStateSha256,
    authorityFingerprintSha256: result.authorityFingerprintSha256, attestedAt: result.attestedAt,
    templateSha256: String(result.templateSha256 || ''), configSha256: String(result.configSha256 || ''),
    protocolSha256: String(result.protocolSha256 || ''),
  };
}

function ensureLeasePhase(lease, phase, permittedOperationId, dependencies = {}) {
  const assertLease = dependencies.assertLeasePhase || maintenance.assertLeasePhase;
  const transitionLease = dependencies.transitionMaintenanceLease || maintenance.transitionMaintenanceLease;
  const desired = { ...lease, phase, permittedOperationId };
  try {
    assertLease(desired, phase);
    return desired;
  } catch (desiredError) {
    try {
      assertLease(lease, lease.phase);
    } catch {
      throw desiredError;
    }
    return transitionLease(lease, phase, {}, permittedOperationId);
  }
}

function cutoverMigration(payload, values, now, dependencies = {}) {
  assertRollbackAllowed(payload, dependencies);
  if (payload.phase !== 'frozen' || !payload.checkpoint || !payload.lease || !ISO_MILLIS.test(String(now || ''))) {
    throw new Error('legacy cutover requires the exact frozen authenticated manifest');
  }
  const baseline = validateFreezeBaseline(payload.freezeBaseline);
  if (payload.checkpoint.containerId !== baseline.containerId) {
    throw new Error('legacy cutover checkpoint does not match the exact pre-freeze writer identity');
  }
  assertDeploymentSnapshot(payload, values);
  const deleteStack = dependencies.deleteApplicationStack || maintenance.deleteApplicationStack;
  const deploy = dependencies.deploy || deployer.deploy;
  const stackDescription = dependencies.stackDescription || maintenance.stackDescription;
  const sendCommand = dependencies.sendCommand || deployer.sendCommand;
  const persist = dependencies.persist;
  const assertLease = dependencies.assertLeasePhase || maintenance.assertLeasePhase;
  if (typeof persist !== 'function') throw new Error('legacy cutover requires durable state publication');
  const operationId = String(dependencies.operationId || deployer.newOperationId());
  if (!deployer.PATTERNS.operationId.test(operationId)) throw new Error('legacy cutover operation id is invalid');
  acquireConditionalAuthorityPermit(payload, operationId, 'legacy.cutover.v1', dependencies);
  const current = stackDescription(payload.source.stackId, payload.source.region);
  if (maintenance.sourceFingerprint(current) !== payload.source.fingerprint) {
    throw new Error('legacy source changed after freeze; cutover deletion is blocked');
  }
  const status = sendCommand(payload.source.instanceId, payload.source.region,
    legacyFrozenStatusCommand(payload), dependencies.timeoutSeconds || 1200,
    'RedactWall legacy stopped-writer checkpoint verification');
  if (exactLine(status.output, 'REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256', '[a-f0-9]{64}')
    !== payload.checkpoint.digest) throw new Error('legacy stopped-writer checkpoint changed before cutover');
  let state = { ...structuredClone(payload), phase: 'cutover_intent', updatedAt: now,
    cutover: { operationId, stackId: null, instanceId: null } };
  persist(state);
  assertLease(state.lease, 'drained');
  try { deleteStack(payload.source.stackId, payload.source.region); }
  catch (error) {
    const sourceState = (dependencies.sourceState || deployer.stackState)(payload.source.stackId, payload.source.region);
    if (sourceState.exists) {
      error.migrationCutover = state;
      throw error;
    }
  }
  state = { ...state, phase: 'source_deleted' };
  persist(state);
  state.lease = ensureLeasePhase(state.lease, 'source_deleted', operationId, dependencies);
  persist(state);
  try {
    const result = deploy(values, dependencies.io || console, {
      operationId, maintenanceLease: state.lease, requireAppliedAttestation: true,
      onOwnership: (ownership) => {
        if (ownership.operationId !== operationId || ownership.stackName !== payload.source.stackName
          || ownership.region !== payload.source.region
          || !deployer.exactStackId(ownership.stackId, payload.source.stackName, payload.source.region)) {
          throw new Error('connected candidate ownership is invalid or ambiguous');
        }
        state = { ...state, phase: 'candidate_created', cutover: {
          operationId, stackId: ownership.stackId, instanceId: null,
        } };
        persist(state);
        state.lease = ensureLeasePhase(state.lease, 'candidate', operationId, dependencies);
        persist(state);
      },
      onAttested: (attested) => {
        if (state.phase !== 'candidate_created') throw new Error('candidate attestation arrived before durable ownership');
        state = { ...state, phase: 'candidate_attested',
          cutover: cutoverAttestation(attested, state.cutover) };
        persist(state);
      },
    });
    if (state.phase !== 'candidate_attested' || result.stackId !== state.cutover.stackId) {
      throw new Error('connected candidate did not durably publish exact ownership and attestation');
    }
    state = { ...state, phase: 'connected_candidate' };
    persist(state);
    return state;
  } catch (error) {
    error.migrationCutover = { ...state, phase: 'cutover_failed', failure: 'evidence_retained' };
    persist(error.migrationCutover);
    throw error;
  }
}

function reconcileCutover(payload, dependencies = {}) {
  const sourceState = dependencies.sourceState || ((state) => deployer.stackState(state.source.stackId, state.source.region));
  const candidateState = dependencies.candidateState || ((state) => {
    const candidate = deployer.stackState(state.cutover?.stackId || state.source.stackName, state.source.region);
    if (!candidate.exists) return candidate;
    return { ...candidate, operationId: candidate.tags?.RedactWallDeploymentOperation };
  });
  const verifyCandidate = dependencies.verifyConnectedStack || verifyConnectedStack;
  if (!['cutover_intent', 'source_deleted', 'candidate_created', 'candidate_attested'].includes(payload.phase)) {
    return structuredClone(payload);
  }
  assertRollbackAllowed(payload, dependencies);
  let state = structuredClone(payload);
  const persist = typeof dependencies.persist === 'function' ? dependencies.persist : () => {};
  const source = sourceState(state);
  if (state.phase === 'cutover_intent') {
    if (source.exists) return state;
    state.phase = 'source_deleted';
    persist(state);
    state.lease = ensureLeasePhase(state.lease, 'source_deleted', state.cutover.operationId, dependencies);
    persist(state);
  } else if (source.exists) {
    throw new Error('cutover journal conflicts with a present legacy source stack');
  }
  const candidate = candidateState(state);
  if (state.phase === 'source_deleted') {
    if (!candidate.exists) return state;
    if (candidate.operationId !== state.cutover.operationId || !candidate.stackId) {
      throw new Error('cutover candidate ownership is missing or ambiguous');
    }
    state.phase = 'candidate_created';
    state.cutover.stackId = candidate.stackId;
    persist(state);
  }
  if (['candidate_created', 'candidate_attested'].includes(state.phase)) {
    state.lease = ensureLeasePhase(state.lease, 'candidate', state.cutover.operationId, dependencies);
    persist(state);
  }
  if (state.phase === 'candidate_created') return state;
  const verification = verifyCandidate(state, dependencies);
  if (verification?.ok === false) return state;
  state.phase = 'connected_candidate';
  persist(state);
  return state;
}

function abortFrozenMigration(payload, now, dependencies = {}) {
  assertRollbackAllowed(payload, dependencies);
  if (payload.phase !== 'frozen' || !payload.checkpoint || !payload.lease || !ISO_MILLIS.test(String(now || ''))) {
    throw new Error('legacy abort requires the exact frozen authenticated manifest');
  }
  const persist = dependencies.persist;
  if (typeof persist !== 'function') throw new Error('legacy abort requires durable state publication');
  const baseline = validateFreezeBaseline(payload.freezeBaseline);
  if (payload.checkpoint.containerId !== baseline.containerId) {
    throw new Error('legacy abort checkpoint does not match the exact pre-freeze writer identity');
  }
  let state = { ...structuredClone(payload), freezeBaseline: baseline, phase: 'abort_intent',
    recoveryDisposition: 'restore', updatedAt: now };
  try { persist(structuredClone(state)); }
  catch (error) {
    const sanitized = new Error('legacy abort intent durable publication failed');
    sanitized.persistenceErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  state = reconcileFreezeMigration(state, now, {
    ...dependencies, persist, timeoutSeconds: dependencies.timeoutSeconds || 1200,
  });
  if (state.phase !== 'retryable') throw new Error('legacy abort did not reach exact retryable restoration state');
  const aborted = { ...state, phase: 'aborted', updatedAt: now };
  try { persist(structuredClone(aborted)); }
  catch (error) {
    const sanitized = new Error('legacy aborted-state durable publication failed after exact retryable restoration');
    sanitized.persistenceErrorName = String(error?.name || 'Error').slice(0, 64);
    sanitized.abortRecovery = freezeRecoveryIdentity(state);
    throw sanitized;
  }
  return aborted;
}

function persistRollbackState(persist, state, operation) {
  try { persist(structuredClone(state)); }
  catch (error) {
    const sanitized = new Error(`${operation} durable publication failed; recovery evidence remains retained`);
    sanitized.persistenceErrorName = String(error?.name || 'Error').slice(0, 64);
    sanitized.rollbackPersistenceState = freezeRecoveryIdentity(state);
    throw sanitized;
  }
}

function candidateOwnership(payload) {
  const ownership = {
    operationId: payload.cutover?.operationId,
    stackId: payload.cutover?.stackId,
    stackName: payload.source?.stackName,
    region: payload.source?.region,
  };
  if (!deployer.PATTERNS.operationId.test(String(ownership.operationId || ''))
    || !deployer.exactStackId(ownership.stackId, ownership.stackName, ownership.region)
    || ownership.stackId === payload.source?.stackId) {
    throw new Error('candidate ownership is missing, changed, or ambiguous');
  }
  return ownership;
}

function cleanupFailedCandidate(payload, now, dependencies = {}) {
  assertRollbackAllowed(payload, dependencies);
  if (!['cutover_failed', 'candidate_cleanup_intent'].includes(payload.phase)
    || !payload.lease || !payload.cutover || !payload.checkpoint
    || !ISO_MILLIS.test(String(now || ''))) {
    throw new Error('candidate cleanup requires the exact authenticated cutover-failed manifest');
  }
  const baseline = validateFreezeBaseline(payload.freezeBaseline);
  if (payload.checkpoint.containerId !== baseline.containerId) {
    throw new Error('candidate cleanup checkpoint does not match the exact pre-freeze writer identity');
  }
  const persist = dependencies.persist;
  if (typeof persist !== 'function') throw new Error('candidate cleanup requires durable state publication');
  const ownership = candidateOwnership(payload);
  const restoreOperationId = String(payload.rollback?.restoreOperationId
    || dependencies.restoreOperationId || deployer.newOperationId());
  if (!deployer.PATTERNS.operationId.test(restoreOperationId)) {
    throw new Error('legacy restore operation id is invalid');
  }
  acquireConditionalAuthorityPermit(payload, restoreOperationId, 'legacy.candidate-cleanup.v1', dependencies);
  let state = payload.phase === 'candidate_cleanup_intent'
    ? { ...structuredClone(payload), freezeBaseline: baseline } : {
    ...structuredClone(payload), freezeBaseline: baseline, phase: 'candidate_cleanup_intent', updatedAt: now,
    rollback: { candidateOwnership: ownership, restoreOperationId, candidateRemovedAt: null },
  };
  if (payload.phase !== 'candidate_cleanup_intent') persistRollbackState(persist, state, 'candidate cleanup intent');
  if (JSON.stringify(canonical(state.rollback?.candidateOwnership)) !== JSON.stringify(canonical(ownership))
    || state.rollback.restoreOperationId !== restoreOperationId) {
    throw new Error('candidate cleanup journal does not match exact immutable ownership');
  }
  const remove = dependencies.removeFailedStackIfOwned || maintenance.removeFailedStackIfOwned;
  try { remove(ownership, payload.source.stackName, payload.source.region); }
  catch (error) {
    const sanitized = new Error('candidate cleanup adapter failed; exact ownership evidence remains retained');
    sanitized.cleanupErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  state = { ...state, phase: 'rollback_ready', updatedAt: now,
    rollback: { ...state.rollback, candidateRemovedAt: now } };
  persistRollbackState(persist, state, 'candidate cleanup completion');
  return state;
}

function validateLegacyRestore(payload, restored, operationId) {
  const expectedTarget = validateFreezeBaseline(payload.freezeBaseline).target;
  if (!restored || typeof restored !== 'object' || Array.isArray(restored)
    || restored.operationId !== operationId
    || !deployer.exactStackId(restored.stackId, payload.source.stackName, payload.source.region)
    || restored.stackId === payload.source.stackId || restored.stackId === payload.cutover.stackId
    || restored.stackName !== payload.source.stackName || restored.region !== payload.source.region
    || !/^i-[a-f0-9]{8,17}$/.test(String(restored.instanceId || ''))
    || !DIGEST.test(String(restored.containerId || ''))
    || restored.imageUri !== payload.source.imageUri || restored.dataVolumeId !== payload.source.dataVolumeId
    || restored.templateSha256 !== payload.source.rollbackTemplate.sha256
    || restored.parametersSha256 !== payload.source.parametersSha256
    || restored.checkpointSha256 !== payload.checkpoint.digest
    || restored.recoverySetSha256 !== payload.checkpoint.recoverySetSha256
    || restored.writerReady !== true
    || JSON.stringify(canonical(restored.targetRegistration)) !== JSON.stringify(canonical(expectedTarget))
    || !ISO_MILLIS.test(String(restored.attestedAt || ''))) {
    throw new Error('legacy recreate/restore adapter did not attest the exact stopped-writer recovery contract');
  }
  return canonical(restored);
}

function restorePrecommitCandidate(payload, now, dependencies = {}) {
  assertRollbackAllowed(payload, dependencies);
  if (!['candidate_created', 'candidate_attested', 'connected_candidate', 'cutover_failed',
    'candidate_cleanup_intent', 'rollback_ready', 'restore_intent',
    'legacy_restore_attested', 'legacy_restore_release_ready'].includes(payload.phase)
    || !payload.cutover?.stackId || !payload.cutover?.operationId || !payload.checkpoint || !payload.lease
    || !ISO_MILLIS.test(String(now || ''))) {
    throw new Error('precommit legacy restore requires one exact candidate and frozen checkpoint');
  }
  const baseline = validateFreezeBaseline(payload.freezeBaseline);
  if (payload.checkpoint.containerId !== baseline.containerId) {
    throw new Error('precommit restore checkpoint does not match the exact pre-freeze writer identity');
  }
  if (typeof dependencies.restoreLegacy !== 'function') {
    throw new Error('RELEASE-BLOCKED: production legacy recreate/restore adapter is not configured');
  }
  const persist = dependencies.persist;
  if (typeof persist !== 'function') throw new Error('precommit legacy restore requires durable state publication');
  const ownership = candidateOwnership(payload);
  const restoreOperationId = String(payload.rollback?.restoreOperationId
    || dependencies.restoreOperationId || deployer.newOperationId());
  if (!deployer.PATTERNS.operationId.test(restoreOperationId)) {
    throw new Error('legacy restore operation id is invalid');
  }
  acquireConditionalAuthorityPermit(payload, restoreOperationId, 'legacy.precommit-restore.v1', dependencies);
  let state = { ...structuredClone(payload), freezeBaseline: baseline };
  if (!['candidate_cleanup_intent', 'rollback_ready', 'restore_intent'].includes(state.phase)) {
    state = { ...state, phase: 'candidate_cleanup_intent', updatedAt: now,
      rollback: { candidateOwnership: ownership, restoreOperationId, candidateRemovedAt: null } };
    persistRollbackState(persist, state, 'precommit candidate cleanup intent');
  }
  if (JSON.stringify(canonical(state.rollback?.candidateOwnership)) !== JSON.stringify(canonical(ownership))
    || state.rollback?.restoreOperationId !== restoreOperationId) {
    throw new Error('legacy restore journal does not match exact candidate ownership');
  }
  if (state.phase === 'candidate_cleanup_intent') {
    const remove = dependencies.removeCandidate
      || ((value) => maintenance.removeFailedStackIfOwned(value, value.stackName, value.region));
    try { remove(ownership); }
    catch (error) {
      const sanitized = new Error('precommit candidate removal failed; exact ownership evidence remains retained');
      sanitized.cleanupErrorName = String(error?.name || 'Error').slice(0, 64);
      throw sanitized;
    }
    state = { ...state, phase: 'rollback_ready', updatedAt: now,
      rollback: { ...state.rollback, candidateRemovedAt: now } };
    persistRollbackState(persist, state, 'precommit candidate cleanup completion');
  }
  if (state.phase === 'rollback_ready') {
    const transitionLease = dependencies.transitionMaintenanceLease || maintenance.transitionMaintenanceLease;
    if (state.lease.phase !== 'restoring') {
      try { state.lease = transitionLease(state.lease, 'restoring', {}, restoreOperationId); }
      catch (error) {
        const sanitized = new Error('precommit restore lease transition failed; rollback evidence remains retained');
        sanitized.leaseErrorName = String(error?.name || 'Error').slice(0, 64);
        throw sanitized;
      }
    }
    state = { ...state, phase: 'restore_intent', updatedAt: now };
    persistRollbackState(persist, state, 'precommit restore intent');
  }
  if (state.phase === 'restore_intent') {
    let observed;
    try {
      observed = dependencies.restoreLegacy(state, { operationId: restoreOperationId,
        rollbackTemplate: state.source.rollbackTemplate, parametersSnapshot: state.source.parametersSnapshot,
        checkpoint: state.checkpoint,
        targetRegistration: validateFreezeBaseline(state.freezeBaseline).target });
    } catch (error) {
      const sanitized = new Error('precommit legacy restore adapter failed; lease and recovery evidence remain retained');
      sanitized.restoreErrorName = String(error?.name || 'Error').slice(0, 64);
      throw sanitized;
    }
    const restored = validateLegacyRestore(state, observed, restoreOperationId);
    state = { ...state, phase: 'legacy_restore_attested', updatedAt: restored.attestedAt,
      restore: restored };
    persistRollbackState(persist, state, 'precommit restore attestation');
  } else if (['legacy_restore_attested', 'legacy_restore_release_ready'].includes(state.phase)) {
    validateLegacyRestore(state, state.restore, restoreOperationId);
  }
  const transitionLease = dependencies.transitionMaintenanceLease || maintenance.transitionMaintenanceLease;
  const releaseLease = dependencies.releaseMaintenanceLease || maintenance.releaseMaintenanceLease;
  if (state.phase === 'legacy_restore_attested') {
    try { state.lease = transitionLease(state.lease, 'release_ready'); }
    catch (error) {
      const sanitized = new Error('precommit restore release-ready transition failed; recovery evidence remains retained');
      sanitized.leaseErrorName = String(error?.name || 'Error').slice(0, 64);
      throw sanitized;
    }
    state = { ...state, phase: 'legacy_restore_release_ready' };
    persistRollbackState(persist, state, 'precommit restore release readiness');
  }
  try { releaseLease(state.lease); }
  catch (error) {
    let leaseState;
    try { leaseState = (dependencies.leaseState || deployer.stackState)(state.lease.stackId, state.lease.region); }
    catch {
      throw new Error('precommit restore lease release is ambiguous; recovery evidence remains retained');
    }
    if (leaseState.exists) {
      const sanitized = new Error('precommit restore lease release failed; recovery evidence remains retained');
      sanitized.releaseErrorName = String(error?.name || 'Error').slice(0, 64);
      throw sanitized;
    }
  }
  state = { ...state, phase: 'legacy_restored', leaseReleased: true };
  persistRollbackState(persist, state, 'precommit restore completion');
  return state;
}

function verifyConnectedStack(payload, dependencies = {}) {
  if (!payload.cutover?.stackId || !payload.cutover?.operationId || !payload.cutover?.instanceId) {
    throw new Error('connected candidate journal lacks exact cutover identity');
  }
  const state = (dependencies.stackState || deployer.stackState)(payload.cutover.stackId, payload.source.region);
  if (!state.exists || state.stackId !== payload.cutover.stackId || state.stackId === payload.source.stackId
    || state.stackName !== payload.source.stackName
    || state.tags?.RedactWallDeploymentOperation !== payload.cutover.operationId
    || state.outputs.TenantId !== payload.target.tenantId
    || state.outputs.DeploymentId !== payload.target.deploymentId
    || state.outputs.LicenseSecretVersionId !== payload.target.connectedSecretVersionId
    || state.outputs.InstanceId !== payload.cutover.instanceId) {
    throw new Error('exact candidate StackId and outputs do not match the migration manifest');
  }
  if (typeof dependencies.verifyAppliedAttestation !== 'function') {
    throw new Error('RELEASE-BLOCKED: connected candidate applied-attestation verifier is not configured');
  }
  const attestation = dependencies.verifyAppliedAttestation(payload, state);
  for (const key of ['containerId', 'appliedStateSha256', 'authorityFingerprintSha256', 'attestedAt']) {
    if (attestation?.[key] !== payload.cutover[key]) {
      throw new Error('connected candidate applied attestation does not match the cutover journal');
    }
  }
  return state;
}

function boundedReceipt(raw, label) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') < 2
    || Buffer.byteLength(raw, 'utf8') > MAX_RECEIPT_BYTES) {
    throw new Error(`${label} raw receipt is missing or exceeds the bounded proof envelope`);
  }
  return raw;
}

function validAcknowledgementMessageId(value) {
  return typeof value === 'string' && value === value.toLowerCase()
    && ACK_MESSAGE_ID_SCHEMA.safeParse(value).success;
}

function validateAuthorityReceipt(receipt, purpose, payload, now) {
  const keys = [
    'appliedAcceptedAt', 'appliedMessageId', 'appliedStateSha256', 'artifactDigest',
    'authorityFingerprintSha256', 'containerId', 'customerAuditHead', 'customerAuditRef', 'customerAuthorityFingerprint',
    'customerId', 'deliveredAcceptedAt', 'deliveredMessageId', 'deploymentId', 'entitlementVersion', 'instanceId',
    'migrationId', 'observedAt', 'operationId', 'ownerAuditHead', 'ownerAuditRef', 'ownerAuthorityFingerprint',
    'purpose', 'registryGeneration', 'registryStateDigest', 'stackId',
  ].sort();
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)
    || Object.keys(receipt).sort().join(',') !== keys.join(',') || receipt.purpose !== purpose
    || receipt.migrationId !== payload.migrationId || receipt.customerId !== payload.target.tenantId
    || receipt.deploymentId !== payload.target.deploymentId || receipt.operationId !== payload.cutover.operationId
    || receipt.stackId !== payload.cutover.stackId || receipt.instanceId !== payload.cutover.instanceId
    || receipt.containerId !== payload.cutover.containerId
    || receipt.appliedStateSha256 !== payload.cutover.appliedStateSha256
    || receipt.authorityFingerprintSha256 !== payload.cutover.authorityFingerprintSha256) {
    throw new Error('verified connected receipt is incomplete or not bound to the exact candidate');
  }
  if (!Number.isInteger(receipt.registryGeneration) || receipt.registryGeneration < 1
    || !Number.isInteger(receipt.entitlementVersion) || receipt.entitlementVersion < 1
    || ![receipt.registryStateDigest, receipt.artifactDigest, receipt.ownerAuditHead, receipt.customerAuditHead,
      receipt.ownerAuthorityFingerprint, receipt.customerAuthorityFingerprint].every((value) => DIGEST.test(String(value || '')))
    || !validAcknowledgementMessageId(receipt.deliveredMessageId)
    || !validAcknowledgementMessageId(receipt.appliedMessageId)
    || receipt.deliveredMessageId === receipt.appliedMessageId
    || !OWNER_AUDIT_REF.test(String(receipt.ownerAuditRef || '')) || !CUSTOMER_AUDIT_REF.test(String(receipt.customerAuditRef || ''))) {
    throw new Error('verified connected receipt lacks durable acknowledgement or audit evidence');
  }
  const times = ['deliveredAcceptedAt', 'appliedAcceptedAt', 'observedAt'].map((key) => {
    if (!ISO_MILLIS.test(String(receipt[key] || ''))) throw new Error('verified connected receipt timestamp is invalid');
    return Date.parse(receipt[key]);
  });
  const attested = Date.parse(payload.cutover.attestedAt);
  const committed = Date.parse(now);
  if (![attested, committed, ...times].every(Number.isFinite)
    || attested > times[0] || times[0] > times[1] || times[1] > times[2] || times[2] > committed
    || committed - times[2] > 5 * 60 * 1000) {
    throw new Error('verified connected receipt is stale or does not show delivered before applied acknowledgement');
  }
  return canonical(receipt);
}

function validateConnectedEvidence(payload, receipts, now, dependencies) {
  if (typeof dependencies.verifyOwnerReceipt !== 'function'
    || typeof dependencies.verifyCustomerReceipt !== 'function') {
    throw new Error('RELEASE-BLOCKED: production proof verifiers are not configured');
  }
  const ownerRaw = boundedReceipt(receipts?.ownerRaw, 'Owner');
  const customerRaw = boundedReceipt(receipts?.customerRaw, 'customer');
  let ownerVerified;
  let customerVerified;
  try { ownerVerified = dependencies.verifyOwnerReceipt(ownerRaw); }
  catch (error) {
    const sanitized = new Error('Owner connected authority receipt verification failed');
    sanitized.verificationErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  try { customerVerified = dependencies.verifyCustomerReceipt(customerRaw); }
  catch (error) {
    const sanitized = new Error('customer connected authority receipt verification failed');
    sanitized.verificationErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  const owner = validateAuthorityReceipt(ownerVerified, RECEIPT_PURPOSES.owner, payload, now);
  const customer = validateAuthorityReceipt(customerVerified, RECEIPT_PURPOSES.customer, payload, now);
  const ownerComparable = { ...owner, purpose: null };
  const customerComparable = { ...customer, purpose: null };
  if (JSON.stringify(canonical(ownerComparable)) !== JSON.stringify(canonical(customerComparable))) {
    throw new Error('Owner and customer connected authority receipts conflict');
  }
  return { ownerRaw, customerRaw, evidence: owner };
}

function commitAdapters(dependencies) {
  if (typeof dependencies.persist !== 'function') {
    throw new Error('RELEASE-BLOCKED: authenticated local commit persistence is not configured');
  }
  if (typeof dependencies.queryPublicationState !== 'function') {
    throw new Error('RELEASE-BLOCKED: exact external publication query adapter is not configured');
  }
  if (typeof dependencies.publishCas !== 'function') {
    throw new Error('RELEASE-BLOCKED: exact external publication CAS adapter is not configured');
  }
}

function commitRecoveryIdentity(state) {
  return {
    migrationId: state.migrationId,
    phase: state.phase,
    commitOperationId: state.authorityCommit?.commitOperationId || 'none',
    expectedPayloadDigest: state.commitProtocol?.request?.expectedPayloadDigest || 'none',
    nextPayloadDigest: state.commitProtocol?.request?.nextPayloadDigest || payloadDigest(state),
  };
}

function persistCommitState(state, dependencies) {
  try { dependencies.persist(structuredClone(state)); }
  catch (error) {
    const sanitized = new Error(`connected authority ${state.phase} durable publication failed`);
    sanitized.persistenceErrorName = String(error?.name || 'Error').slice(0, 64);
    sanitized.commitPersistenceState = commitRecoveryIdentity(state);
    throw sanitized;
  }
}

function commitAuthorityEvidence(payload, verified, now, commitOperationId) {
  return {
    commitOperationId, preparedAt: now, committedAt: now,
    ownerProofDigest: sha256(Buffer.from(verified.ownerRaw, 'utf8')),
    customerProofDigest: sha256(Buffer.from(verified.customerRaw, 'utf8')),
    evidenceDigest: payloadDigest(verified.evidence),
    registryGeneration: verified.evidence.registryGeneration,
    registryStateDigest: verified.evidence.registryStateDigest,
    entitlementVersion: verified.evidence.entitlementVersion,
    artifactDigest: verified.evidence.artifactDigest,
    ownerAuditRef: verified.evidence.ownerAuditRef,
    customerAuditRef: verified.evidence.customerAuditRef,
  };
}

function publicationRequest(payload, authorityCommit, nextPayloadDigest) {
  return canonical({
    schemaVersion: 1, kind: 'legacy.connected-authority-commit.v1',
    commitOperationId: authorityCommit.commitOperationId,
    migrationId: payload.migrationId, customerId: payload.target.tenantId,
    deploymentId: payload.target.deploymentId,
    candidateOperationId: payload.cutover.operationId, stackId: payload.cutover.stackId,
    instanceId: payload.cutover.instanceId, containerId: payload.cutover.containerId,
    appliedStateSha256: payload.cutover.appliedStateSha256,
    authorityFingerprintSha256: payload.cutover.authorityFingerprintSha256,
    attestedAt: payload.cutover.attestedAt,
    expectedPhase: 'connected_candidate', targetPhase: COMMIT_FINAL_PHASE,
    expectedPayloadDigest: payloadDigest(payload), nextPayloadDigest,
    ownerProofDigest: authorityCommit.ownerProofDigest,
    customerProofDigest: authorityCommit.customerProofDigest,
    evidenceDigest: authorityCommit.evidenceDigest,
    registryGeneration: authorityCommit.registryGeneration,
    registryStateDigest: authorityCommit.registryStateDigest,
    entitlementVersion: authorityCommit.entitlementVersion,
    artifactDigest: authorityCommit.artifactDigest,
    ownerAuditRef: authorityCommit.ownerAuditRef,
    customerAuditRef: authorityCommit.customerAuditRef,
  });
}

function preparedCommitState(payload, verified, now, operationId) {
  const authorityCommit = commitAuthorityEvidence(payload, verified, now, operationId);
  const committed = { ...structuredClone(payload), phase: COMMIT_FINAL_PHASE,
    updatedAt: now, authorityCommit };
  const request = publicationRequest(payload, authorityCommit, payloadDigest(committed));
  return { ...structuredClone(payload), phase: COMMIT_PREPARED_PHASE,
    updatedAt: now, authorityCommit, commitProtocol: { request } };
}

function committedFromTombstone(payload) {
  const committed = structuredClone(payload);
  delete committed.commitProtocol;
  committed.phase = COMMIT_FINAL_PHASE;
  committed.updatedAt = committed.authorityCommit.committedAt;
  if (payloadDigest(committed) !== payload.commitProtocol.request.nextPayloadDigest) {
    throw new Error('connected authority commit tombstone does not reconstruct the exact final payload');
  }
  return committed;
}

function exactPublicationReadback(observed, request) {
  const expected = { ...structuredClone(request), state: String(observed?.state || '') };
  if (!['prior', 'committed'].includes(expected.state)
    || !observed || typeof observed !== 'object' || Array.isArray(observed)
    || JSON.stringify(canonical(observed)) !== JSON.stringify(canonical(expected))) {
    throw new Error('authenticated external publication readback is missing, changed, or ambiguous');
  }
  return expected.state;
}

function queryExactPublicationState(request, state, dependencies) {
  const expected = structuredClone(request);
  try {
    return exactPublicationReadback(dependencies.queryPublicationState(structuredClone(expected)), expected);
  }
  catch (error) {
    const sanitized = new Error('authenticated external publication readback is unavailable or ambiguous; rollback stays disabled');
    sanitized.commitUncertain = commitRecoveryIdentity(state);
    sanitized.externalReadbackErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
}

function reconcileConnectedAuthorityCommit(payload, dependencies = {}) {
  if (payload.phase === COMMIT_FINAL_PHASE) return structuredClone(payload);
  if (![COMMIT_PREPARED_PHASE, COMMIT_UNCERTAIN_PHASE].includes(payload.phase)
    || !payload.authorityCommit || !payload.commitProtocol?.request) {
    throw new Error('connected authority commit reconciliation requires an authenticated one-way tombstone');
  }
  commitAdapters(dependencies);
  let state = structuredClone(payload);
  if (state.phase === COMMIT_PREPARED_PHASE) {
    state = { ...state, phase: COMMIT_UNCERTAIN_PHASE };
    persistCommitState(state, dependencies);
  }
  const request = structuredClone(state.commitProtocol.request);
  let external = queryExactPublicationState(request, state, dependencies);
  if (external === 'prior') {
    let casError;
    try { dependencies.publishCas(structuredClone(request)); } catch (error) { casError = error; }
    try { external = queryExactPublicationState(request, state, dependencies); }
    catch (error) {
      error.commitUncertain = commitRecoveryIdentity(state);
      if (casError) error.casResponseWasAmbiguous = true;
      throw error;
    }
    if (external === 'prior') {
      const error = new Error('external publication remains prior; connected authority commit is uncertain and rollback stays disabled');
      error.commitUncertain = commitRecoveryIdentity(state);
      throw error;
    }
  }
  const committed = committedFromTombstone(state);
  persistCommitState(committed, dependencies);
  return committed;
}

function commitConnectedAuthority(payload, receipts, now, dependencies = {}) {
  if (payload.phase !== 'connected_candidate' || !payload.checkpoint || !payload.cutover?.stackId) {
    throw new Error('connected authority can commit only from the exact verified connected candidate');
  }
  const baseline = validateFreezeBaseline(payload.freezeBaseline);
  if (payload.checkpoint.containerId !== baseline.containerId) {
    throw new Error('connected authority candidate does not match the exact pre-freeze writer identity');
  }
  if (!ISO_MILLIS.test(String(now || ''))) throw new Error('connected authority commit timestamp is invalid');
  commitAdapters(dependencies);
  const operationId = String(dependencies.commitOperationId || deployer.newOperationId());
  if (!deployer.PATTERNS.operationId.test(operationId)) throw new Error('connected authority commit operation id is invalid');
  const verified = validateConnectedEvidence(payload, receipts, now, dependencies);
  const prepared = preparedCommitState(payload, verified, now, operationId);
  persistCommitState(prepared, dependencies);
  return reconcileConnectedAuthorityCommit(prepared, dependencies);
}

function rollbackAuthorityQuery(payload) {
  const query = {
    schemaVersion: 1,
    kind: ROLLBACK_AUTHORITY_KIND,
    purpose: ROLLBACK_AUTHORITY_PURPOSE,
    migrationId: String(payload?.migrationId || ''),
    customerId: String(payload?.target?.tenantId || ''),
    deploymentId: String(payload?.target?.deploymentId || ''),
  };
  if (!/^[a-f0-9]{32}$/.test(query.migrationId)
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$/.test(query.customerId)
    || !/^dep_[a-f0-9]{32}$/.test(query.deploymentId)) {
    throw new Error('legacy rollback scope is missing or invalid');
  }
  return query;
}

function exactRollbackAuthorityHighWater(observed, query) {
  if (!observed || typeof observed !== 'object' || Array.isArray(observed)
    || !['prior', 'committed'].includes(observed.state)) {
    throw new Error('one-way authority high-water response is invalid');
  }
  const expected = {
    ...query,
    highWater: observed.state === 'committed' ? 1 : 0,
    state: observed.state,
    commitmentDigest: observed.state === 'committed' ? String(observed.commitmentDigest || '') : null,
  };
  if ((observed.state === 'committed' && !DIGEST.test(expected.commitmentDigest))
    || JSON.stringify(canonical(observed)) !== JSON.stringify(canonical(expected))) {
    throw new Error('one-way authority high-water response is changed or ambiguous');
  }
  return expected;
}

function assertRollbackAllowed(payload, dependencies = {}) {
  if (COMMIT_TOMBSTONE_PHASES.has(payload?.phase) || payload?.authorityCommit) {
    throw new Error('supported legacy rollback and restart are permanently disabled by the one-way connected authority tombstone');
  }
  if (typeof dependencies.verifyOneWayAuthorityHighWater !== 'function') {
    throw new Error('RELEASE-BLOCKED: production independent one-way rollback authority verifier is not configured');
  }
  let observed;
  try {
    const query = rollbackAuthorityQuery(payload);
    observed = exactRollbackAuthorityHighWater(
      dependencies.verifyOneWayAuthorityHighWater(structuredClone(query)), query,
    );
  } catch (error) {
    const sanitized = new Error('independent one-way authority verification is unavailable or ambiguous; rollback stays disabled');
    sanitized.authorityVerificationErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
  if (observed.state !== 'prior' || observed.highWater !== 0) {
    throw new Error('supported legacy rollback and restart are permanently disabled by the external one-way authority high-water');
  }
  return true;
}

// The high-water read above is only a prior observation. When a conditional
// permit adapter is injected, the external authority must additionally grant
// this exact operation after that read, so a connected commit that wins in
// between blocks every cleanup, restore, and cutover side effect.
function acquireConditionalAuthorityPermit(payload, operationId, purpose, dependencies) {
  if (typeof dependencies.beginConditionalAuthorityOperation !== 'function') return null;
  try {
    return dependencies.beginConditionalAuthorityOperation(structuredClone({
      schemaVersion: 1,
      kind: 'legacy.conditional-authority-permit.v1',
      purpose,
      operationId,
      migrationId: String(payload?.migrationId || ''),
      customerId: String(payload?.target?.tenantId || ''),
      deploymentId: String(payload?.target?.deploymentId || ''),
    })) ?? true;
  } catch (error) {
    const sanitized = new Error('conditional one-way authority permit was refused because the connected authority commit won after the prior read; rollback and cutover stay disabled');
    sanitized.authorityPermitErrorName = String(error?.name || 'Error').slice(0, 64);
    throw sanitized;
  }
}

function readKey(file, label = 'legacy migration manifest key') {
  privatePath.assertPrivatePath(file, { label, directory: false });
  const encoded = privatePath.readBoundedRegularFile(file, {
    label, maxBytes: 128,
  }).toString('utf8').trim();
  if (!/^[A-Za-z0-9+/]{43}=$/.test(encoded)) throw new Error(`${label} must be canonical Base64 for 32 bytes`);
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32 || key.toString('base64') !== encoded) throw new Error(`${label} must be canonical Base64 for 32 bytes`);
  return key;
}

function readEnvelope(file, key) {
  privatePath.assertPrivatePath(file, { label: 'legacy migration manifest', directory: false });
  return verifyEnvelope(JSON.parse(privatePath.readBoundedRegularFile(file, {
    label: 'legacy migration manifest', maxBytes: 262144,
  }).toString('utf8')), key);
}

function publishEnvelope(file, payload, key) {
  const target = path.resolve(file);
  const parent = path.dirname(target);
  privatePath.assertPrivatePath(parent, { label: 'legacy migration manifest directory', directory: true });
  const tmp = path.join(parent, `.${path.basename(target)}.${crypto.randomBytes(16).toString('hex')}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify(signEnvelope(payload, key), null, 2)}\n`, 'utf8');
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    privatePath.securePrivatePath(tmp, { label: 'legacy migration manifest staging file', fresh: true });
    privatePath.publishFileDurably(tmp, target, {
      label: 'legacy migration manifest',
      verifyPublished: (published) => privatePath.assertPrivatePath(published, {
        label: 'legacy migration manifest', directory: false,
      }),
    });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(tmp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function publishPrivateBytes(file, bytes, label) {
  const target = path.resolve(file);
  const parent = path.dirname(target);
  privatePath.assertPrivatePath(parent, { label: `${label} directory`, directory: true });
  const tmp = path.join(parent, `.${path.basename(target)}.${crypto.randomBytes(16).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    privatePath.securePrivatePath(tmp, { label: `${label} staging file`, fresh: true });
    privatePath.publishFileDurably(tmp, target, {
      label, verifyPublished: (published) => privatePath.assertPrivatePath(published, { label, directory: false }),
    });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.unlinkSync(tmp); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return { path: path.basename(target), sha256: sha256(bytes), bytes: bytes.length };
}

function readWitness(file, key) {
  privatePath.assertPrivatePath(file, { label: 'legacy migration witness', directory: false });
  return verifyWitness(JSON.parse(privatePath.readBoundedRegularFile(file, {
    label: 'legacy migration witness', maxBytes: 524288,
  }).toString('utf8')), key);
}

function publishWitness(file, witness, key) {
  return publishPrivateBytes(file,
    Buffer.from(`${JSON.stringify(signWitness(witness, key), null, 2)}\n`, 'utf8'),
    'legacy migration witness');
}

function tombstoneFromCommit(payload, prior = null) {
  const phaseOrder = {
    [COMMIT_PREPARED_PHASE]: 1,
    [COMMIT_UNCERTAIN_PHASE]: 2,
    [COMMIT_FINAL_PHASE]: 3,
  };
  if (![COMMIT_PREPARED_PHASE, COMMIT_UNCERTAIN_PHASE, COMMIT_FINAL_PHASE].includes(payload.phase)) return null;
  if (payload.phase === COMMIT_FINAL_PHASE) {
    if (!prior || !Object.hasOwn(phaseOrder, prior.phase) || payloadDigest(payload) !== prior.nextPayloadDigest
      || payload.authorityCommit?.commitOperationId !== prior.commitOperationId
      || payload.authorityCommit?.evidenceDigest !== prior.evidenceDigest) {
      throw new Error('final connected authority state does not match the irreversible witness tombstone');
    }
    return { ...structuredClone(prior), phase: COMMIT_FINAL_PHASE,
      committedAt: payload.authorityCommit.committedAt };
  }
  const request = payload.commitProtocol?.request;
  if (!request || request.migrationId !== payload.migrationId
    || request.commitOperationId !== payload.authorityCommit?.commitOperationId
    || request.evidenceDigest !== payload.authorityCommit?.evidenceDigest
    || !DIGEST.test(String(request.expectedPayloadDigest || ''))
    || !DIGEST.test(String(request.nextPayloadDigest || ''))) {
    throw new Error('connected authority commit tombstone is incomplete or mismatched');
  }
  const tombstone = {
    version: 1, phase: payload.phase, migrationId: payload.migrationId,
    commitOperationId: request.commitOperationId,
    expectedPayloadDigest: request.expectedPayloadDigest,
    nextPayloadDigest: request.nextPayloadDigest,
    evidenceDigest: request.evidenceDigest,
    preparedAt: payload.authorityCommit.preparedAt,
  };
  if (prior && (prior.migrationId !== tombstone.migrationId
    || prior.commitOperationId !== tombstone.commitOperationId
    || prior.expectedPayloadDigest !== tombstone.expectedPayloadDigest
    || prior.nextPayloadDigest !== tombstone.nextPayloadDigest
    || prior.evidenceDigest !== tombstone.evidenceDigest
    || !Object.hasOwn(phaseOrder, prior.phase)
    || phaseOrder[tombstone.phase] < phaseOrder[prior.phase]
    || prior.phase === COMMIT_FINAL_PHASE)) {
    throw new Error('migration witness tombstone permanently blocks rollback, replacement, or replay');
  }
  return tombstone;
}

function validateWitnessTombstone(witness) {
  if (!witness.tombstone) {
    if (COMMIT_TOMBSTONE_PHASES.has(witness.phase) || witness.payload?.authorityCommit) {
      throw new Error('connected authority state lacks its irreversible witness tombstone');
    }
    return;
  }
  const expected = tombstoneFromCommit(witness.payload,
    witness.phase === COMMIT_FINAL_PHASE ? witness.tombstone : null);
  if (JSON.stringify(canonical(expected)) !== JSON.stringify(canonical(witness.tombstone))) {
    throw new Error('migration witness tombstone does not match its authenticated payload');
  }
}

function persistDurableState(files, payload, keys) {
  if (crypto.timingSafeEqual(keys.manifest, keys.witness)) {
    throw new Error('migration manifest and witness keys must be purpose-separated');
  }
  let sequence = 0;
  let priorTombstone = null;
  if (fs.existsSync(files.witness)) {
    const prior = readWitness(files.witness, keys.witness);
    if (prior.migrationId !== payload.migrationId || !Number.isSafeInteger(prior.sequence) || prior.sequence < 1) {
      throw new Error('existing migration witness belongs to another operation');
    }
    sequence = prior.sequence;
    priorTombstone = prior.tombstone || null;
    if (priorTombstone && !COMMIT_TOMBSTONE_PHASES.has(payload.phase)) {
      throw new Error('migration witness tombstone permanently blocks rollback or replay');
    }
  }
  const tombstone = tombstoneFromCommit(payload, priorTombstone);
  const witness = {
    version: 1, sequence: sequence + 1, migrationId: payload.migrationId, phase: payload.phase,
    manifestDigest: payloadDigest(payload), payload: structuredClone(payload),
    tombstone,
  };
  publishWitness(files.witness, witness, keys.witness);
  publishEnvelope(files.manifest, payload, keys.manifest);
  return structuredClone(payload);
}

function readDurableState(files, keys) {
  const witness = readWitness(files.witness, keys.witness);
  if (fs.existsSync(files.manifest)) {
    const manifest = readEnvelope(files.manifest, keys.manifest);
    if (payloadDigest(manifest) === witness.manifestDigest) verifyStateAgainstWitness(manifest, signWitness(witness, keys.witness), keys.witness);
  }
  if (payloadDigest(witness.payload) !== witness.manifestDigest || witness.phase !== witness.payload.phase) {
    throw new Error('migration witness payload is corrupt or inconsistent');
  }
  validateWitnessTombstone(witness);
  return structuredClone(witness.payload);
}

function parseOptions(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    if (!option?.startsWith('--') || argv[index + 1] == null || argv[index + 1].startsWith('--')) {
      throw new Error('legacy migration options must be exact --name value pairs');
    }
    const key = option.slice(2);
    if (Object.hasOwn(values, key)) throw new Error(`duplicate option --${key}`);
    values[key] = argv[index + 1];
  }
  return values;
}

const COMMON_OPTIONS = Object.freeze(['manifest', 'witness', 'manifest-key', 'witness-key']);
const COMMAND_OPTIONS = Object.freeze({
  plan: Object.freeze([...COMMON_OPTIONS, 'stack-name', 'region', 'deploy-args-file',
    'source-template-url', 'tenant-id', 'deployment-id', 'fallback-artifact-sha256',
    'offline-trust-pin-sha256', 'verdict-trust-pin-sha256', 'entitlement-trust-pin-sha256',
    'heartbeat-credential-ref', 'acknowledgement-credential-ref']),
  freeze: Object.freeze([...COMMON_OPTIONS, 'timeout-seconds']),
  abort: Object.freeze([...COMMON_OPTIONS, 'timeout-seconds']),
  cutover: COMMON_OPTIONS,
  reconcile: COMMON_OPTIONS,
  'cleanup-failed-candidate': COMMON_OPTIONS,
  'restore-precommit': COMMON_OPTIONS,
  commit: Object.freeze([...COMMON_OPTIONS, 'owner-receipt-file', 'customer-receipt-file']),
  status: COMMON_OPTIONS,
  'rollback-check': COMMON_OPTIONS,
});

function assertCommandOptions(command, values) {
  const allowed = COMMAND_OPTIONS[command];
  if (!allowed) throw new Error('legacy migration command is invalid');
  const unexpected = Object.keys(values).filter((name) => !allowed.includes(name));
  if (unexpected.length) throw new Error(`legacy migration option --${unexpected.sort()[0]} is not valid for ${command}`);
  return values;
}

function migrationFiles(values) {
  const manifest = path.resolve(String(values.manifest || ''));
  const witness = path.resolve(String(values.witness || ''));
  if (!values.manifest || !values.witness || manifest === witness || path.dirname(manifest) !== path.dirname(witness)) {
    throw new Error('manifest and independent witness must be distinct files in one private operation directory');
  }
  return { manifest, witness, directory: path.dirname(manifest) };
}

function withMigrationOperation(values, callback) {
  const files = migrationFiles(values);
  return privatePath.withPrivateDirectoryMutationLockSync(files.directory,
    () => callback(files), { label: 'legacy connected migration operation directory', timeoutMs: 60_000 });
}

function number(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) throw new Error(`${name} must be an integer`);
  return parsed;
}

function captureLiveTemplate(url, region, directory, dependencies = {}) {
  const runAws = dependencies.runAws || deployer.runAws;
  let parsed;
  try { parsed = new URL(String(url || '')); } catch { throw new Error('source template URL is invalid'); }
  const suffix = region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
  const hostSuffix = `.s3.${region}.${suffix}`;
  if (!parsed.hostname.endsWith(hostSuffix)) throw new Error('source template URL is outside the migration region');
  const bucket = parsed.hostname.slice(0, -hostSuffix.length);
  artifacts.validateBucketName(bucket);
  const identity = JSON.parse(runAws(['sts', 'get-caller-identity', '--output', 'json']));
  const accountId = String(identity.Account || '');
  if (!/^[0-9]{12}$/.test(accountId)) throw new Error('active AWS account identity is unavailable');
  artifacts.verifyArtifactBucket(runAws, { bucket, region, accountId });
  const reference = artifacts.parseTemplateReference(parsed.toString(), { bucket, region });
  const owner = ['--expected-bucket-owner', accountId];
  const head = JSON.parse(runAws(['s3api', 'head-object', '--bucket', bucket, '--key', reference.key,
    '--version-id', reference.versionId, '--checksum-mode', 'ENABLED', ...owner, '--region', region, '--output', 'json']));
  const digest = String(head.Metadata?.sha256 || '');
  const bytes = Number(head.ContentLength);
  artifacts.verifyTemplateReference(runAws, {
    bucket, region, accountId, templateUrl: parsed.toString(), sha256: digest, bytes,
  });
  const target = path.join(directory, `.source-template.${crypto.randomBytes(16).toString('hex')}.tmp`);
  try {
    runAws(['s3api', 'get-object', '--bucket', bucket, '--key', reference.key, '--version-id', reference.versionId,
      '--checksum-mode', 'ENABLED', ...owner, '--region', region, target, '--output', 'json'], {
      errorMessage: 'Could not snapshot the exact source template bytes',
    });
    privatePath.securePrivatePath(target, { label: 'source template snapshot', fresh: true });
    const downloaded = privatePath.readBoundedRegularFile(target, {
      label: 'source template snapshot', maxBytes: 1024 * 1024,
    });
    if (downloaded.length !== bytes || sha256(downloaded) !== digest
      || head.ChecksumSHA256 !== Buffer.from(digest, 'hex').toString('base64')) {
      throw new Error('downloaded source template does not match its versioned S3 identity');
    }
    let semanticSha256 = digest;
    try { semanticSha256 = sha256(JSON.stringify(canonical(JSON.parse(downloaded.toString('utf8'))))); } catch {}
    return { sourceTemplateUrl: parsed.toString(), sourceTemplateSha256: digest,
      sourceTemplateBytes: bytes, sourceTemplateStackSha256: semanticSha256 };
  } finally {
    try { fs.unlinkSync(target); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

function plan(values, dependencies = {}) {
  const files = dependencies.files || migrationFiles(values);
  const keys = dependencies.keys || {
    manifest: readKey(values['manifest-key']),
    witness: readKey(values['witness-key'], 'legacy migration witness key'),
  };
  if (crypto.timingSafeEqual(keys.manifest, keys.witness)) {
    throw new Error('migration manifest and witness keys must be purpose-separated');
  }
  if (fs.existsSync(files.manifest) || fs.existsSync(files.witness)) {
    throw new Error('legacy migration state already exists; use status or an explicit new operation directory');
  }
  const stack = maintenance.stackDescription(values['stack-name'], values.region);
  const deployArgsSource = path.resolve(String(values['deploy-args-file'] || ''));
  const deployValues = deploymentArgsFile(deployArgsSource);
  const deployArgsBytes = privatePath.readBoundedRegularFile(deployArgsSource, {
    label: 'legacy connected deployment arguments', maxBytes: 65536,
  });
  const deployArgsTarget = path.join(files.directory, `${path.basename(files.manifest)}.deploy-args.json`);
  const deployArgsSnapshot = publishPrivateBytes(deployArgsTarget, deployArgsBytes,
    'legacy connected deployment arguments snapshot');
  const sourceParametersBytes = Buffer.from(`${JSON.stringify(canonical({
    stackId: stack.StackId, stackName: stack.StackName, region: values.region,
    parameters: stack.Parameters || [], outputs: stack.Outputs || [], roleArn: String(stack.RoleARN || ''),
    templateSha256: stack.RedactWallTemplateSha256,
  }), null, 2)}\n`, 'utf8');
  const sourceParametersTarget = path.join(files.directory, `${path.basename(files.manifest)}.source-parameters.json`);
  const sourceParametersSnapshot = publishPrivateBytes(sourceParametersTarget, sourceParametersBytes,
    'legacy source parameter snapshot');
  const template = (dependencies.captureLiveTemplate || captureLiveTemplate)(
    values['source-template-url'], values.region, files.directory, dependencies,
  );
  if (template.sourceTemplateStackSha256 !== stack.RedactWallTemplateSha256) {
    throw new Error('versioned source template bytes do not match the live source stack template');
  }
  const payload = createManifestPayload({
    tenantId: values['tenant-id'], deploymentId: values['deployment-id'], region: values.region,
    connectedSecretVersionId: deployValues['secret-version-id'], secretArn: deployValues['secret-arn'],
    fallbackArtifactSha256: values['fallback-artifact-sha256'],
    offlineTrustPinSha256: values['offline-trust-pin-sha256'],
    verdictTrustPinSha256: values['verdict-trust-pin-sha256'],
    entitlementTrustPinSha256: values['entitlement-trust-pin-sha256'],
    heartbeatCredentialRef: values['heartbeat-credential-ref'],
    acknowledgementCredentialRef: values['acknowledgement-credential-ref'],
    ...template, deployValues,
    deployArgsPath: deployArgsSnapshot.path, deployArgsSha256: deployArgsSnapshot.sha256,
    deployArgsBytes: deployArgsSnapshot.bytes,
    sourceParametersPath: sourceParametersSnapshot.path,
    sourceParametersSha256: sourceParametersSnapshot.sha256,
    sourceParametersBytes: sourceParametersSnapshot.bytes,
  }, stack, new Date().toISOString(), crypto.randomBytes(16).toString('hex'));
  payload.lease = maintenance.acquireMaintenanceLease(stack, values.region);
  (dependencies.persistDurableState || persistDurableState)(files, payload, keys);
  return payload;
}

function privateReceipt(file, label) {
  privatePath.assertPrivatePath(file, { label, directory: false });
  return privatePath.readBoundedRegularFile(file, { label, maxBytes: MAX_RECEIPT_BYTES }).toString('utf8');
}

function main(argv = process.argv.slice(2), dependencies = {}) {
  try {
    const command = argv.shift();
    const values = parseOptions(argv);
    assertCommandOptions(command, values);
    return withMigrationOperation(values, (files) => {
      const keys = {
        manifest: readKey(values['manifest-key']),
        witness: readKey(values['witness-key'], 'legacy migration witness key'),
      };
      if (crypto.timingSafeEqual(keys.manifest, keys.witness)) {
        throw new Error('migration manifest and witness keys must be purpose-separated');
      }
      if (command === 'plan') {
        const payload = plan(values, { ...dependencies, files, keys });
        console.log(`REDACTWALL_LEGACY_MIGRATION_ID=${payload.migrationId}`);
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${payload.phase}`);
        return payload;
      }
      const payload = readDurableState(files, keys);
      const persist = (state) => persistDurableState(files, state, keys);
      const now = new Date().toISOString();
      if (command === 'freeze') {
        const frozen = freezeMigration(payload, now, { ...dependencies, persist,
          timeoutSeconds: values['timeout-seconds'] ? number(values['timeout-seconds'], 'timeout seconds') : 1200 });
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${frozen.phase}`);
        console.log(`REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=${frozen.checkpoint.digest}`);
        return frozen;
      }
      if (command === 'cutover') {
        const snapshot = path.join(files.directory, payload.target.deployArgsSnapshot.path);
        const connected = cutoverMigration(payload,
          deploymentArgsFile(snapshot, payload.target.deployArgsSnapshot), now, { ...dependencies, persist });
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${connected.phase}`);
        console.log(`REDACTWALL_CONNECTED_STACK_ID=${connected.cutover.stackId}`);
        return connected;
      }
      if (command === 'reconcile') {
        let reconciled;
        if (COMMIT_TOMBSTONE_PHASES.has(payload.phase)) {
          reconciled = reconcileConnectedAuthorityCommit(payload, { ...dependencies, persist });
        } else if (FREEZE_RECOVERY_PHASES.has(payload.phase)) {
          reconciled = reconcileFreezeMigration(payload, now, { ...dependencies, persist });
        } else {
          reconciled = reconcileCutover(payload, { ...dependencies, persist });
        }
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${reconciled.phase}`);
        if (reconciled.cutover?.stackId) {
          console.log(`REDACTWALL_CONNECTED_STACK_ID=${reconciled.cutover.stackId}`);
        }
        return reconciled;
      }
      if (command === 'abort') {
        const aborted = abortFrozenMigration(payload, now, { ...dependencies, persist,
          timeoutSeconds: values['timeout-seconds'] ? number(values['timeout-seconds'], 'timeout seconds') : 1200 });
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${aborted.phase}`);
        return aborted;
      }
      if (command === 'cleanup-failed-candidate') {
        const cleaned = cleanupFailedCandidate(payload, now, { ...dependencies, persist });
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${cleaned.phase}`);
        return cleaned;
      }
      if (command === 'restore-precommit') {
        const restored = restorePrecommitCandidate(payload, now, { ...dependencies, persist });
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${restored.phase}`);
        return restored;
      }
      if (command === 'commit') {
        verifyConnectedStack(payload, dependencies);
        const receipts = {
          ownerRaw: privateReceipt(values['owner-receipt-file'], 'Owner durable acknowledgement receipt'),
          customerRaw: privateReceipt(values['customer-receipt-file'], 'customer acknowledged-high-water receipt'),
        };
        const committed = commitConnectedAuthority(payload, receipts, now, { ...dependencies, persist });
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${committed.phase}`);
        return committed;
      }
      if (command === 'rollback-check') {
        assertRollbackAllowed(payload, dependencies);
        console.log(`REDACTWALL_LEGACY_ROLLBACK_ALLOWED=${payload.migrationId}`);
        return payload;
      }
      if (command === 'status') {
        console.log(`REDACTWALL_LEGACY_MIGRATION_ID=${payload.migrationId}`);
        console.log(`REDACTWALL_LEGACY_MIGRATION_PHASE=${payload.phase}`);
        return payload;
      }
      throw new Error('usage: aws-legacy-connected-migrate <plan|freeze|abort|cutover|reconcile|cleanup-failed-candidate|restore-precommit|commit|status|rollback-check> --manifest <path> --witness <path> --manifest-key <path> --witness-key <path> ...');
    });
  } catch (error) {
    console.error(`[legacy-connected-migrate] ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  TRUST_PIN_PROGRAM,
  abortFrozenMigration,
  assertCommandOptions,
  assertRollbackAllowed,
  cleanupFailedCandidate,
  commitConnectedAuthority,
  captureLiveTemplate,
  createManifestPayload,
  cutoverMigration,
  freezeMigration,
  legacyAbortCommand,
  legacyFreezeCommand,
  legacyFreezeProbeCommand,
  legacyFrozenStatusCommand,
  legacyPreflightCommand,
  main,
  migrationFiles,
  payloadDigest,
  parseFreezeCheckpoint,
  plan,
  publishEnvelope,
  publishWitness,
  persistDurableState,
  reconcileConnectedAuthorityCommit,
  reconcileCutover,
  reconcileFreezeMigration,
  readEnvelope,
  readDurableState,
  signEnvelope,
  signWitness,
  restorePrecommitCandidate,
  validateConnectedEvidence,
  verifyConnectedStack,
  verifyEnvelope,
  verifyStateAgainstWitness,
  verifyWitness,
};
