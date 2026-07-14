'use strict';

/**
 * Supported customer-silo deployment entrypoint.
 *
 * CloudFormation metadata updates are asynchronous when left to cfn-hup. This
 * command makes the update operator-visible and synchronous: deploy the stack,
 * invoke the host apply-and-attest command through SSM, then wait for the exact
 * image digest and immutable secret version to be proven live.
 */
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const artifacts = require('./aws-artifacts');

const PATTERNS = {
  stackName: /^[A-Za-z][-A-Za-z0-9]{0,127}$/,
  region: /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/,
  vpc: /^vpc-[a-f0-9]{8,17}$/,
  subnet: /^subnet-[a-f0-9]{8,17}$/,
  availabilityZone: /^[a-z]{2}(?:-gov)?-[a-z]+-\d[a-z]$/,
  image: /^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?\/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$/,
  secretArn: /^arn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/,
  secretVersion: /^[A-Za-z0-9-]{32,64}$/,
  tenant: /^[a-z0-9][a-z0-9_-]{1,62}$/,
  deployment: /^dep_[a-f0-9]{32}$/,
  hostname: /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/,
  certificateArn: /^arn:(?:aws|aws-us-gov|aws-cn):acm:[a-z0-9-]+:[0-9]{12}:certificate\/[a-f0-9-]{16,64}$/,
  volume: /^vol-[a-f0-9]{8,17}$/,
  ami: /^ami-[a-f0-9]{8,17}$/,
  instanceType: /^(?:t3\.(?:small|medium|large)|m7i\.large)$/,
  digest: /^[a-f0-9]{64}$/,
  recoveryName: /^[A-Za-z0-9._-]{1,180}$/,
  operationId: /^rw-[a-f0-9]{32}$/,
};

const REQUIRED = [
  'stack-name', 'region', 'vpc-id', 'public-subnet-ids', 'instance-subnet-id',
  'instance-availability-zone', 'image-uri', 'secret-arn', 'secret-version-id',
  'tenant-id', 'deployment-id', 'certificate-arn', 'public-hostname', 'data-volume-id',
  'artifact-bucket', 'ami-id', 'data-stack-name',
];
const ALLOWED = new Set([...REQUIRED, 'source-data-volume-id', 'artifact-prefix', 'instance-type',
  'root-volume-gb', 'timeout-seconds']);
const DEPLOYMENT_LEASE_PHASES = new Set(['source_deleted', 'candidate', 'restoring']);
const OPERATION_AUTHORITY_MAX_BYTES = 16 * 1024;
const OPERATION_AUTHORITY_PHASES = new Set([
  'available', 'deploying', 'lease_creating', 'acquired', 'preparing', 'drained', 'source_deleted',
  'candidate', 'restoring', 'evidence_retained', 'release_ready', 'releasing',
]);

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) throw new Error(`unexpected argument: ${token}`);
    const key = token.slice(2);
    if (!key || Object.prototype.hasOwnProperty.call(values, key)) throw new Error(`duplicate or invalid option: ${token}`);
    if (!ALLOWED.has(key)) throw new Error(`unknown option: ${token}`);
    const value = argv[index + 1];
    if (value == null || value.startsWith('--')) throw new Error(`missing value for ${token}`);
    values[key] = value;
    index += 1;
  }
  for (const key of REQUIRED) {
    if (!values[key]) throw new Error(`missing required option --${key}`);
  }
  values['source-data-volume-id'] ||= '';
  values['artifact-prefix'] ||= artifacts.DEFAULT_PREFIX;
  values['instance-type'] ||= 't3.small';
  values['root-volume-gb'] ||= '20';
  values['timeout-seconds'] ||= '1200';
  return values;
}

function requirePattern(label, value, pattern) {
  if (!pattern.test(String(value || ''))) throw new Error(`${label} is invalid`);
  return value;
}

function validate(values) {
  requirePattern('stack name', values['stack-name'], PATTERNS.stackName);
  requirePattern('region', values.region, PATTERNS.region);
  requirePattern('VPC id', values['vpc-id'], PATTERNS.vpc);
  requirePattern('instance subnet id', values['instance-subnet-id'], PATTERNS.subnet);
  requirePattern('instance availability zone', values['instance-availability-zone'], PATTERNS.availabilityZone);
  const subnets = values['public-subnet-ids'].split(',');
  if (subnets.length < 2 || subnets.some((subnet) => !PATTERNS.subnet.test(subnet))) {
    throw new Error('public subnet ids must contain at least two comma-separated subnet ids');
  }
  requirePattern('image URI', values['image-uri'], PATTERNS.image);
  requirePattern('secret ARN', values['secret-arn'], PATTERNS.secretArn);
  requirePattern('secret version id', values['secret-version-id'], PATTERNS.secretVersion);
  requirePattern('tenant id', values['tenant-id'], PATTERNS.tenant);
  requirePattern('deployment id', values['deployment-id'], PATTERNS.deployment);
  requirePattern('certificate ARN', values['certificate-arn'], PATTERNS.certificateArn);
  requirePattern('public hostname', values['public-hostname'], PATTERNS.hostname);
  requirePattern('data volume id', values['data-volume-id'], PATTERNS.volume);
  requirePattern('data stack name', values['data-stack-name'], PATTERNS.stackName);
  requirePattern('AMI id', values['ami-id'], PATTERNS.ami);
  requirePattern('instance type', values['instance-type'], PATTERNS.instanceType);
  artifacts.validateBucketName(values['artifact-bucket']);
  artifacts.validatePrefix(values['artifact-prefix']);
  if (values['source-data-volume-id']) {
    requirePattern('source data volume id', values['source-data-volume-id'], PATTERNS.volume);
  }
  const imageRegion = values['image-uri'].match(/\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com/)?.[1];
  const secretRegion = values['secret-arn'].split(':')[3];
  const certificateRegion = values['certificate-arn'].split(':')[3];
  if (imageRegion !== values.region || secretRegion !== values.region || certificateRegion !== values.region) {
    throw new Error('image, secret, and ACM certificate must be in --region');
  }
  const timeout = Number(values['timeout-seconds']);
  if (!Number.isInteger(timeout) || timeout < 120 || timeout > 3600) throw new Error('timeout seconds must be an integer from 120 through 3600');
  const rootVolumeGb = Number(values['root-volume-gb']);
  if (!Number.isInteger(rootVolumeGb) || rootVolumeGb < 20 || rootVolumeGb > 500) throw new Error('root volume size must be an integer from 20 through 500');
  return values;
}

function sha256Text(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function desiredConfig(values) {
  return {
    dataStackName: values['data-stack-name'],
    dataVolumeId: values['data-volume-id'],
    imageUri: values['image-uri'],
    deploymentId: values['deployment-id'],
    publicHostname: values['public-hostname'],
    region: values.region,
    secretArn: values['secret-arn'],
    secretVersionId: values['secret-version-id'],
    sourceDataVolumeId: values['source-data-volume-id'],
    tenantId: values['tenant-id'],
  };
}

function desiredConfigSha256(values) {
  return sha256Text(JSON.stringify(desiredConfig(values)));
}

function protocolSha256() {
  const source = fs.readFileSync(path.resolve(__dirname, '..', 'infra', 'aws', 'scripts', 'redactwall-deploy.sh'));
  return crypto.createHash('sha256').update(source).digest('hex');
}

function templateByteLength(staged) {
  const bytes = Buffer.isBuffer(staged?.bytes) ? staged.bytes.length : Number(staged?.bytes);
  if (!Number.isInteger(bytes) || bytes < 1 || bytes > 1024 * 1024) {
    throw new Error('deployment template byte count is invalid');
  }
  return bytes;
}

function templateReferenceFromOutputs(outputs) {
  const reference = {
    templateUrl: String(outputs.DeploymentTemplateUrl || ''),
    sha256: String(outputs.DeploymentTemplateSha256 || ''),
    bytes: Number(outputs.DeploymentTemplateBytes),
    protocolSha256: String(outputs.DeploymentProtocolSha256 || ''),
    configSha256: String(outputs.DesiredConfigSha256 || ''),
  };
  if (!PATTERNS.digest.test(reference.sha256) || !PATTERNS.digest.test(reference.protocolSha256)
    || !PATTERNS.digest.test(reference.configSha256) || !Number.isInteger(reference.bytes)
    || reference.bytes < 1 || reference.bytes > 1024 * 1024) {
    throw new Error('source stack does not publish a complete exact template rollback contract');
  }
  return reference;
}

function verifyRollbackTemplate(values, reference) {
  if (reference.configSha256 !== desiredConfigSha256(values)) {
    throw new Error('source stack desired-config digest does not match its parameters');
  }
  const identity = JSON.parse(runAws(['sts', 'get-caller-identity', '--output', 'json']));
  const accountId = String(identity.Account || '');
  if (!/^[0-9]{12}$/.test(accountId)) throw new Error('active AWS account id is unavailable');
  artifacts.verifyArtifactBucket(runAws, { bucket: values['artifact-bucket'], region: values.region, accountId });
  return { ...artifacts.verifyTemplateReference(runAws, {
    ...reference, bucket: values['artifact-bucket'], region: values.region, accountId,
  }), protocolSha256: reference.protocolSha256, configSha256: reference.configSha256 };
}

function runAws(args, options = {}) {
  const executable = process.env.REDACTWALL_AWS_CLI || 'aws';
  const result = childProcess.spawnSync(executable, args, {
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 4 * 1024 * 1024,
    timeout: options.timeoutMs || 20 * 60 * 1000,
    env: { ...process.env, AWS_PAGER: '' },
  });
  if (result.error || result.status !== 0) {
    const error = new Error(options.errorMessage || `AWS command failed: ${args.slice(0, 2).join(' ')}`);
    error.cause = result.error;
    error.status = result.status;
    error.stderr = String(result.stderr || '');
    error.stdout = String(result.stdout || '');
    throw error;
  }
  return String(result.stdout || '').trim();
}

function stackDetails(stackName, region) {
  const raw = runAws([
    'cloudformation', 'describe-stacks', '--stack-name', stackName,
    '--region', region, '--output', 'json',
  ], { errorMessage: 'Could not read the deployed stack outputs' });
  const parsed = JSON.parse(raw);
  const stacks = parsed?.Stacks || [];
  const stack = stacks.length === 1 ? stacks[0] : null;
  if (!stack) throw new Error('CloudFormation returned no exact stack');
  const outputs = Object.fromEntries((stack.Outputs || []).map((entry) => [entry.OutputKey, entry.OutputValue]));
  const tags = Object.fromEntries((stack.Tags || []).map((entry) => [entry.Key, entry.Value]));
  return { stackId: String(stack.StackId || ''), stackName: String(stack.StackName || ''),
    stackStatus: String(stack.StackStatus || ''), outputs, tags, stack };
}

function stackOutputs(stackName, region) {
  return stackDetails(stackName, region).outputs;
}

function stackNotFound(error, stackName) {
  return String(error?.stderr || '').trim()
    === `An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id ${stackName} does not exist`;
}

function stackState(stackName, region) {
  try { return { exists: true, ...stackDetails(stackName, region) }; }
  catch (error) {
    if (stackNotFound(error, stackName)) return { exists: false, outputs: {} };
    throw error;
  }
}

function assertConnectedDeploymentIdentity(stackExists, outputs, values) {
  if (!stackExists) return;
  if (!PATTERNS.deployment.test(String(outputs.DeploymentId || ''))) {
    throw new Error('existing stack lacks the immutable connected deployment identity; reprovision it through Owner enrollment');
  }
  if (outputs.DeploymentId !== values['deployment-id']) {
    throw new Error('deployment id is immutable for an existing silo');
  }
}

function replacementBlockingPolicy() {
  return JSON.stringify({ Statement: [
    { Effect: 'Allow', Action: 'Update:*', Principal: '*', Resource: '*' },
    { Effect: 'Deny', Action: ['Update:Replace', 'Update:Delete'], Principal: '*', Resource: [
      'LogicalResourceId/AppInstance', 'LogicalResourceId/CustomerDataVolumeAttachment',
    ] },
  ] });
}

function enforceReplacementBlock(stackName, region) {
  runAws(['cloudformation', 'set-stack-policy', '--stack-name', stackName,
    '--stack-policy-body', replacementBlockingPolicy(), '--region', region],
  { errorMessage: 'Could not enforce the application-instance replacement block' });
}

function noStackUpdates(error) {
  return String(error?.stderr || '').trim()
    === 'An error occurred (ValidationError) when calling the UpdateStack operation: No updates are to be performed.';
}

function newOperationId() {
  return `rw-${crypto.randomBytes(16).toString('hex')}`;
}

function maintenanceLeaseName(stackName) {
  const digest = crypto.createHash('sha256').update(String(stackName)).digest('hex').slice(0, 32);
  return `rw-maintenance-${digest}`;
}

function operationAuthorityLocation(values, accountId) {
  const stackName = requirePattern('stack name', values['stack-name'], PATTERNS.stackName);
  const region = requirePattern('region', values.region, PATTERNS.region);
  const bucket = artifacts.validateBucketName(values['artifact-bucket']);
  const prefix = artifacts.validatePrefix(values['artifact-prefix'] || artifacts.DEFAULT_PREFIX);
  if (!/^[0-9]{12}$/.test(String(accountId || ''))) throw new Error('operation authority AWS account id is invalid');
  const scopeDigest = sha256Text(`${region}\0${stackName}`);
  return {
    accountId: String(accountId), bucket, key: `${prefix}/operation-authority/${scopeDigest}.json`,
    prefix, region, stackName,
  };
}

function exactUtcMilliseconds(value) {
  return /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/.test(String(value || ''))
    && new Date(value).toISOString() === value;
}

function authorityCandidateValid(candidate, location) {
  if (candidate == null) return true;
  const keys = [
    'appliedStateSha256', 'attestedAt', 'authorityFingerprintSha256', 'configSha256', 'containerId',
    'imageUri', 'instanceId', 'operationId', 'protocolSha256', 'recoverySetId', 'secretVersionId', 'stackId',
    'stage', 'templateSha256',
  ];
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
    || Object.keys(candidate).sort().join('\0') !== [...keys].sort().join('\0')
    || !['owned', 'attested'].includes(candidate.stage)
    || !PATTERNS.operationId.test(candidate.operationId)
    || !exactStackId(candidate.stackId, location.stackName, location.region)
    || !PATTERNS.digest.test(candidate.configSha256)
    || !PATTERNS.image.test(candidate.imageUri)
    || !PATTERNS.digest.test(candidate.templateSha256)
    || !PATTERNS.digest.test(candidate.protocolSha256)
    || !PATTERNS.secretVersion.test(candidate.secretVersionId)
    || !(candidate.recoverySetId === 'none' || /^[a-f0-9]{32}$/.test(candidate.recoverySetId))) return false;
  if (candidate.stage === 'owned') {
    return candidate.instanceId === 'none' && candidate.containerId === 'none'
      && candidate.appliedStateSha256 === 'none' && candidate.authorityFingerprintSha256 === 'none'
      && candidate.attestedAt === 'none';
  }
  return /^i-[a-f0-9]{8,17}$/.test(candidate.instanceId)
    && /^[a-f0-9]{64}$/.test(candidate.containerId)
    && PATTERNS.digest.test(candidate.appliedStateSha256)
    && PATTERNS.digest.test(candidate.authorityFingerprintSha256)
    && exactUtcMilliseconds(candidate.attestedAt);
}

function authorityTargetRegistrationValid(target) {
  if (target == null) return true;
  return exactObjectKeys(target, ['instanceId', 'observedAt', 'registered', 'state', 'targetGroupArn'])
    && /^i-[a-f0-9]{8,17}$/.test(target.instanceId)
    && exactUtcMilliseconds(target.observedAt)
    && target.registered === true
    && ['healthy', 'unhealthy', 'initial'].includes(target.state)
    && /^arn:(?:aws|aws-us-gov|aws-cn):elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:targetgroup\/[A-Za-z0-9-]{1,32}\/[a-f0-9]{16}$/.test(target.targetGroupArn);
}

function authorityCutoverIntentValid(intent, location, state) {
  if (intent == null) return true;
  const keys = [
    'candidateClientToken', 'candidateStackName', 'configSha256', 'deploymentId', 'imageUri', 'protocolSha256',
    'recoverySetId', 'secretArnSha256', 'secretVersionId', 'sourceStackId', 'stage', 'templateSha256', 'tenantId',
  ];
  if (!exactObjectKeys(intent, keys)
    || !['drain', 'source_delete', 'candidate_create'].includes(intent.stage)
    || !PATTERNS.operationId.test(intent.candidateClientToken)
    || intent.candidateStackName !== location.stackName
    || intent.sourceStackId !== state.sourceStackId
    || !exactStackId(intent.sourceStackId, location.stackName, location.region)) return false;
  const planned = intent.stage === 'candidate_create';
  return planned
    ? PATTERNS.digest.test(intent.configSha256) && PATTERNS.image.test(intent.imageUri)
      && PATTERNS.deployment.test(intent.deploymentId)
      && PATTERNS.digest.test(intent.protocolSha256)
      && (intent.recoverySetId === 'none' || /^[a-f0-9]{32}$/.test(intent.recoverySetId))
      && PATTERNS.digest.test(intent.secretArnSha256) && PATTERNS.secretVersion.test(intent.secretVersionId)
      && PATTERNS.digest.test(intent.templateSha256) && PATTERNS.tenant.test(intent.tenantId)
    : [intent.configSha256, intent.deploymentId, intent.imageUri, intent.protocolSha256, intent.recoverySetId,
      intent.secretArnSha256, intent.secretVersionId, intent.templateSha256, intent.tenantId].every((value) => value === 'none');
}

function validateOperationAuthorityState(state, location) {
  const keys = [
    'candidate', 'checkpointLatchSha256', 'checkpointSetId', 'cutoverIntent', 'generation', 'holderKind',
    'leaseClientToken', 'leaseStackId', 'leaseStackName', 'operationId', 'permittedOperationId', 'phase',
    'previousBodySha256', 'schemaVersion', 'scope', 'sourceFingerprint', 'sourceStackId', 'targetRegistration',
    'updatedAt',
  ];
  const leaseName = maintenanceLeaseName(location.stackName);
  if (!state || typeof state !== 'object' || Array.isArray(state)
    || Object.keys(state).sort().join('\0') !== [...keys].sort().join('\0')
    || state.schemaVersion !== 1 || !Number.isSafeInteger(state.generation) || state.generation < 1
    || !['available', 'deploy', 'maintenance'].includes(state.holderKind)
    || !OPERATION_AUTHORITY_PHASES.has(state.phase)
    || !exactUtcMilliseconds(state.updatedAt)
    || !state.scope || Object.keys(state.scope).sort().join('\0') !== 'region\0stackName'
    || state.scope.region !== location.region || state.scope.stackName !== location.stackName
    || !(state.previousBodySha256 === 'none' || PATTERNS.digest.test(state.previousBodySha256))
    || !(state.sourceFingerprint === 'none' || PATTERNS.digest.test(state.sourceFingerprint))
    || !(state.sourceStackId === 'none' || exactStackId(state.sourceStackId, location.stackName, location.region))
    || !(state.leaseStackId === 'none' || exactStackId(state.leaseStackId, leaseName, location.region))
    || !(state.leaseStackName === 'none' || state.leaseStackName === leaseName)
    || !(state.leaseClientToken === 'none' || PATTERNS.operationId.test(state.leaseClientToken))
    || !(state.permittedOperationId === 'none' || PATTERNS.operationId.test(state.permittedOperationId))
    || !(state.checkpointSetId === 'none' || /^[a-f0-9]{32}$/.test(state.checkpointSetId))
    || !(state.checkpointLatchSha256 === 'none' || PATTERNS.digest.test(state.checkpointLatchSha256))
    || ((state.checkpointSetId === 'none') !== (state.checkpointLatchSha256 === 'none'))
    || !authorityCandidateValid(state.candidate, location)
    || !authorityTargetRegistrationValid(state.targetRegistration)
    || !authorityCutoverIntentValid(state.cutoverIntent, location, state)) {
    throw new Error('external operation authority state is malformed or out of scope');
  }
  if (state.holderKind === 'available') {
    if (state.operationId !== 'none' || state.phase !== 'available' || state.permittedOperationId !== 'none'
      || state.candidate !== null || state.cutoverIntent !== null || state.targetRegistration !== null
      || state.leaseClientToken !== 'none' || state.leaseStackName !== 'none') {
      throw new Error('external operation authority available tombstone is malformed');
    }
  } else if (!PATTERNS.operationId.test(state.operationId)) {
    throw new Error('external operation authority operation id is malformed');
  }
  if (state.holderKind === 'deploy' && (state.leaseClientToken !== 'none' || state.leaseStackName !== 'none'
    || state.cutoverIntent !== null || state.targetRegistration !== null)) {
    throw new Error('external deployment authority contains maintenance-only state');
  }
  if (state.holderKind === 'maintenance') {
    if (state.leaseClientToken !== state.operationId || state.leaseStackName !== leaseName
      || (state.phase === 'lease_creating' ? state.leaseStackId !== 'none' : state.leaseStackId === 'none')) {
      throw new Error('external maintenance lease creation binding is invalid');
    }
  }
  return state;
}

function authorityBytes(state, location) {
  validateOperationAuthorityState(state, location);
  const bytes = Buffer.from(JSON.stringify(canonical(state)), 'utf8');
  if (bytes.length < 1 || bytes.length > OPERATION_AUTHORITY_MAX_BYTES) {
    throw new Error('external operation authority exceeds its bounded schema');
  }
  return bytes;
}

function privateAuthoritySnapshot(bytes) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-operation-authority-'));
  fs.chmodSync(directory, 0o700);
  const file = path.join(directory, 'authority.json');
  const descriptor = fs.openSync(file, 'wx', 0o600);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  return { directory, file };
}

function normalizeEtag(value) {
  const etag = String(value || '');
  if (!/^"[a-fA-F0-9]{32}"$/.test(etag)) throw new Error('external operation authority ETag is invalid');
  return etag;
}

function normalizeVersionId(value) {
  const versionId = String(value || '');
  if (!versionId || versionId.length > 1024 || /[\u0000-\u001f\u007f]/.test(versionId)) {
    throw new Error('external operation authority version id is invalid');
  }
  return versionId;
}

function authorityObjectMissing(error) {
  return /\(NoSuchKey\)|\bNoSuchKey\b/.test(String(error?.stderr || ''));
}

function authorityPreconditionFailed(error) {
  return /\(PreconditionFailed\)|\bPreconditionFailed\b|status code:\s*412\b/.test(String(error?.stderr || ''))
    || error?.code === 'PreconditionFailed';
}

function authorityConditionalConflict(error) {
  return /\(ConditionalRequestConflict\)|\bConditionalRequestConflict\b|status code:\s*409\b/.test(String(error?.stderr || ''));
}

function readS3OperationAuthority(location, versionId = '') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-operation-authority-read-'));
  fs.chmodSync(directory, 0o700);
  const file = path.join(directory, 'authority.json');
  const owner = ['--expected-bucket-owner', location.accountId];
  const version = versionId ? ['--version-id', normalizeVersionId(versionId)] : [];
  try {
    let response;
    try {
      response = JSON.parse(runAws(['s3api', 'get-object', '--bucket', location.bucket, '--key', location.key,
        ...version, '--checksum-mode', 'ENABLED', ...owner, '--region', location.region, '--output', 'json', file], {
        errorMessage: 'Could not read the external operation authority',
      }) || '{}');
    } catch (error) {
      if (!versionId && authorityObjectMissing(error)) return null;
      throw error;
    }
    const stat = fs.lstatSync(file, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n || stat.size < 1n
      || stat.size > BigInt(OPERATION_AUTHORITY_MAX_BYTES)) {
      throw new Error('external operation authority object has an invalid local snapshot');
    }
    const bytes = fs.readFileSync(file);
    const bodySha256 = crypto.createHash('sha256').update(bytes).digest('hex');
    const checksum = crypto.createHash('sha256').update(bytes).digest('base64');
    const etag = normalizeEtag(response.ETag);
    const observedVersionId = normalizeVersionId(response.VersionId);
    if (versionId && observedVersionId !== versionId) throw new Error('external operation authority version readback changed');
    if (response.ChecksumSHA256 !== checksum || response.Metadata?.sha256 !== bodySha256
      || !['AES256', 'aws:kms'].includes(response.ServerSideEncryption)) {
      throw new Error('external operation authority checksum or encryption verification failed');
    }
    let state;
    try { state = JSON.parse(bytes.toString('utf8')); } catch { throw new Error('external operation authority JSON is invalid'); }
    validateOperationAuthorityState(state, location);
    return { bodySha256, etag, location, state, versionId: observedVersionId };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function putS3OperationAuthority(location, state, condition) {
  const bytes = authorityBytes(state, location);
  const bodySha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  const checksum = crypto.createHash('sha256').update(bytes).digest('base64');
  const snapshot = privateAuthoritySnapshot(bytes);
  const conditionArgs = condition.etag
    ? ['--if-match', normalizeEtag(condition.etag)] : ['--if-none-match', '*'];
  try {
    const response = JSON.parse(runAws(['s3api', 'put-object', '--bucket', location.bucket, '--key', location.key,
      '--body', snapshot.file, '--checksum-algorithm', 'SHA256', '--checksum-sha256', checksum,
      '--metadata', `sha256=${bodySha256}`, ...conditionArgs, '--expected-bucket-owner', location.accountId,
      '--region', location.region, '--output', 'json'], {
      errorMessage: 'Could not conditionally publish the external operation authority',
    }) || '{}');
    const versionId = normalizeVersionId(response.VersionId);
    const published = readS3OperationAuthority(location, versionId);
    if (published.etag !== normalizeEtag(response.ETag) || published.bodySha256 !== bodySha256
      || JSON.stringify(canonical(published.state)) !== JSON.stringify(canonical(state))) {
      throw new Error('external operation authority publication readback changed');
    }
    return published;
  } finally {
    fs.rmSync(snapshot.directory, { recursive: true, force: true });
  }
}

function exactObjectKeys(value, keys) {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function isExactOperationAuthorityPolicyDeny(statement, location) {
  if (!exactObjectKeys(statement, ['Action', 'Condition', 'Effect', 'Principal', 'Resource', 'Sid'])) return false;
  const condition = statement.Condition;
  const nullCondition = exactObjectKeys(condition, ['Null']) ? condition.Null : null;
  const expectedResource = `arn:aws:s3:::${location.bucket}/${location.prefix}/operation-authority/*`;
  return statement.Sid === 'DenyUnconditionalOperationAuthorityWrites'
    && statement.Effect === 'Deny' && statement.Principal === '*'
    && statement.Action === 's3:PutObject'
    && statement.Resource === expectedResource
    && exactObjectKeys(nullCondition, ['s3:if-match', 's3:if-none-match'])
    && nullCondition['s3:if-match'] === 'true'
    && nullCondition['s3:if-none-match'] === 'true';
}

function isExactOperationAuthorityDeleteDeny(statement, location) {
  if (!exactObjectKeys(statement, ['Action', 'Effect', 'Principal', 'Resource', 'Sid'])
    || !Array.isArray(statement.Action) || statement.Action.length !== 2) return false;
  const expectedResource = `arn:aws:s3:::${location.bucket}/${location.prefix}/operation-authority/*`;
  return statement.Sid === 'DenyOperationAuthorityDeletion'
    && statement.Effect === 'Deny' && statement.Principal === '*'
    && statement.Action[0] === 's3:DeleteObject'
    && statement.Action[1] === 's3:DeleteObjectVersion'
    && statement.Resource === expectedResource;
}

function verifyOperationAuthorityPreflight(location, dependencies = {}) {
  if (dependencies.skipPreflight === true) return;
  let skeleton;
  try { skeleton = JSON.parse(runAws(['s3api', 'put-object', '--generate-cli-skeleton', 'input'])); }
  catch { throw new Error('RELEASE-BLOCKED: AWS CLI cannot prove conditional S3 PutObject support'); }
  if (!Object.prototype.hasOwnProperty.call(skeleton, 'IfMatch')
    || !Object.prototype.hasOwnProperty.call(skeleton, 'IfNoneMatch')) {
    throw new Error('RELEASE-BLOCKED: AWS CLI lacks conditional S3 PutObject support');
  }
  try {
    artifacts.verifyArtifactBucket(runAws, {
      accountId: location.accountId, bucket: location.bucket, region: location.region,
    });
  } catch (error) {
    throw new Error(`RELEASE-BLOCKED: external operation authority bucket assurance failed: ${error.message}`, {
      cause: error,
    });
  }
  let policy;
  try {
    policy = JSON.parse(JSON.parse(runAws(['s3api', 'get-bucket-policy', '--bucket', location.bucket,
      '--expected-bucket-owner', location.accountId, '--region', location.region, '--output', 'json'])).Policy);
  } catch {
    throw new Error('RELEASE-BLOCKED: artifact bucket conditional-write policy cannot be proved');
  }
  const statements = Array.isArray(policy?.Statement) ? policy.Statement : [policy?.Statement].filter(Boolean);
  const protectedByCondition = statements.some((statement) => isExactOperationAuthorityPolicyDeny(statement, location));
  const protectedFromDeletion = statements.some((statement) => isExactOperationAuthorityDeleteDeny(statement, location));
  if (!protectedByCondition || !protectedFromDeletion) {
    throw new Error('RELEASE-BLOCKED: artifact bucket does not enforce conditional writes and no-delete retention on the operation-authority prefix');
  }
}

function nowUtc(dependencies) {
  const value = dependencies.now ? dependencies.now() : new Date().toISOString();
  if (!exactUtcMilliseconds(value)) throw new Error('external operation authority clock is invalid');
  return value;
}

function initialAuthorityState(location, holderKind, operationId, dependencies = {}) {
  return {
    candidate: null,
    checkpointLatchSha256: 'none',
    checkpointSetId: 'none',
    cutoverIntent: null,
    generation: 1,
    holderKind,
    leaseClientToken: 'none',
    leaseStackId: 'none',
    leaseStackName: 'none',
    operationId,
    permittedOperationId: holderKind === 'deploy' ? operationId : 'none',
    phase: holderKind === 'deploy' ? 'deploying' : 'acquired',
    previousBodySha256: 'none',
    schemaVersion: 1,
    scope: { region: location.region, stackName: location.stackName },
    sourceFingerprint: 'none',
    sourceStackId: 'none',
    targetRegistration: null,
    updatedAt: nowUtc(dependencies),
  };
}

function authorityAdapter(dependencies = {}) {
  if (dependencies.authority) return dependencies.authority;
  return {
    read: (location) => readS3OperationAuthority(location),
    create: (location, state) => putS3OperationAuthority(location, state, {}),
    compareAndSwap: (location, etag, state) => putS3OperationAuthority(location, state, { etag }),
  };
}

function readOperationAuthority(location, dependencies = {}) {
  return authorityAdapter(dependencies).read(location);
}

function exactAuthorityPublication(current, expectedState, location) {
  try {
    return current?.location?.accountId === location.accountId
      && current.location.bucket === location.bucket && current.location.key === location.key
      && current.location.region === location.region && current.location.stackName === location.stackName
      && PATTERNS.digest.test(current.bodySha256 || '')
      && !!normalizeEtag(current.etag) && !!normalizeVersionId(current.versionId)
      && JSON.stringify(canonical(validateOperationAuthorityState(current.state, location)))
        === JSON.stringify(canonical(expectedState));
  } catch {
    return false;
  }
}

function acquireOperationAuthority(location, holderKind, operationId, dependencies = {}, initialChanges = {}) {
  if (!['deploy', 'maintenance'].includes(holderKind) || !PATTERNS.operationId.test(operationId)) {
    throw new Error('external operation authority holder is invalid');
  }
  verifyOperationAuthorityPreflight(location, dependencies);
  const adapter = authorityAdapter(dependencies);
  const observed = Object.prototype.hasOwnProperty.call(dependencies, 'observed')
    ? dependencies.observed : adapter.read(location);
  const generation = observed?.state?.generation;
  if (observed && (observed.state?.holderKind !== 'available' || observed.state?.phase !== 'available')) {
    throw new Error('external operation authority is already held by another supported operation');
  }
  const state = { ...initialAuthorityState(location, holderKind, operationId, dependencies), ...initialChanges };
  if (observed) {
    if (!Number.isSafeInteger(generation) || generation < 1 || !PATTERNS.digest.test(observed.bodySha256 || '')) {
      throw new Error('external operation authority available tombstone is invalid');
    }
    state.generation = generation + 1;
    state.previousBodySha256 = observed.bodySha256;
  }
  try {
    return observed ? adapter.compareAndSwap(location, observed.etag, state) : adapter.create(location, state);
  } catch (error) {
    let reconciled;
    try { reconciled = adapter.read(location); }
    catch (reconciliationError) { error.reconciliationError = reconciliationError; }
    if (exactAuthorityPublication(reconciled, state, location)) return reconciled;
    if (authorityPreconditionFailed(error)) {
      throw new Error('external operation authority stale precondition blocked the supported operation', { cause: error });
    }
    if (authorityConditionalConflict(error)) {
      throw new Error('external operation authority conditional conflict requires checked reconciliation', { cause: error });
    }
    throw error;
  }
}

function acquireDeploymentAuthority(values, operationId, dependencies = {}) {
  const accountId = String(dependencies.accountId || '');
  const location = dependencies.location || operationAuthorityLocation(values, accountId);
  return acquireOperationAuthority(location, 'deploy', operationId, dependencies);
}

function compareAndSwapOperationAuthority(handle, changes, dependencies = {}) {
  if (!handle?.location || !handle?.state || !normalizeEtag(handle.etag)
    || !PATTERNS.digest.test(handle.bodySha256 || '')) {
    throw new Error('external operation authority prior handle is invalid');
  }
  const next = {
    ...handle.state,
    ...changes,
    generation: handle.state.generation + 1,
    previousBodySha256: handle.bodySha256,
    updatedAt: nowUtc(dependencies),
  };
  const adapter = authorityAdapter(dependencies);
  try {
    return adapter.compareAndSwap(handle.location, handle.etag, next);
  } catch (error) {
    let current;
    try { current = adapter.read(handle.location); }
    catch (reconciliationError) { error.reconciliationError = reconciliationError; }
    if (exactAuthorityPublication(current, next, handle.location)) return current;
    if (authorityPreconditionFailed(error)) {
      throw new Error('external operation authority stale CAS', { cause: error });
    }
    if (authorityConditionalConflict(error)) {
      throw new Error('external operation authority CAS outcome is ambiguous and requires checked reconciliation', { cause: error });
    }
    throw error;
  }
}

function assertOperationAuthorityHandle(handle, expected, dependencies = {}) {
  if (!handle?.location || !handle?.state || !PATTERNS.digest.test(handle.bodySha256 || '')) {
    throw new Error('external operation authority proof is missing');
  }
  const current = authorityAdapter(dependencies).read(handle.location);
  if (!current || current.etag !== handle.etag || current.versionId !== handle.versionId
    || current.bodySha256 !== handle.bodySha256
    || JSON.stringify(canonical(current.state)) !== JSON.stringify(canonical(handle.state))) {
    throw new Error('external operation authority proof is stale or changed');
  }
  for (const [key, value] of Object.entries(expected || {})) {
    if (current.state[key] !== value) throw new Error(`external operation authority ${key} binding is invalid`);
  }
  return current;
}

function releaseDeploymentAuthority(handle, dependencies = {}) {
  if (handle?.state?.holderKind !== 'deploy' || handle.state.phase !== 'deploying') {
    throw new Error('external deployment authority is not releasable');
  }
  return compareAndSwapOperationAuthority(handle, {
    candidate: null,
    checkpointLatchSha256: 'none',
    checkpointSetId: 'none',
    cutoverIntent: null,
    holderKind: 'available',
    leaseClientToken: 'none',
    leaseStackId: 'none',
    leaseStackName: 'none',
    operationId: 'none',
    permittedOperationId: 'none',
    phase: 'available',
    sourceFingerprint: 'none',
    sourceStackId: 'none',
    targetRegistration: null,
  }, dependencies);
}

function sanitizedAuthorityReference(handle) {
  return {
    bodySha256: handle.bodySha256,
    etag: handle.etag,
    key: handle.location.key,
    versionId: handle.versionId,
  };
}

function settleDeploymentAuthority(handle, outcome, dependencies = {}, io = console) {
  if (!outcome.owned) return handle;
  if (outcome.failure && outcome.mutationAttempted) {
    outcome.failure.operationAuthority = sanitizedAuthorityReference(handle);
    return handle;
  }
  try {
    return releaseDeploymentAuthority(handle, dependencies);
  } catch (releaseError) {
    if (outcome.result && !outcome.failure) {
      outcome.result.warnings.push('operation_authority_release_pending');
      outcome.result.operationAuthority = sanitizedAuthorityReference(handle);
      (io.warn || io.log)('RedactWall committed with warning: operation_authority_release_pending');
    } else if (outcome.failure) {
      outcome.failure.operationAuthorityReleaseError = releaseError;
    }
    return handle;
  }
}

function assertCreationLease(values, stackExists, proof, deploymentOperationId = '') {
  const leaseName = maintenanceLeaseName(values['stack-name']);
  const lease = stackState(leaseName, values.region);
  if (!proof) {
    if (lease.exists) throw new Error('an external maintenance lease blocks supported deployment, including existing-stack updates');
    return null;
  }
  if (!DEPLOYMENT_LEASE_PHASES.has(String(proof.phase || ''))) {
    throw new Error('external maintenance lease phase is not permitted for deployment');
  }
  if (!lease.exists || lease.stackId !== proof.stackId || lease.stackName !== leaseName
    || lease.stackStatus !== 'CREATE_COMPLETE'
    || lease.tags.RedactWallMaintenanceOperation !== proof.operationId
    || lease.tags.RedactWallSourceStackId !== proof.sourceStackId
    || lease.tags.RedactWallSourceFingerprint !== proof.sourceFingerprint
    || lease.tags.RedactWallMaintenancePhase !== proof.phase
    || lease.tags.RedactWallMaintenanceSet !== proof.checkpointSetId
    || lease.tags.RedactWallMaintenanceLatchSha256 !== proof.checkpointLatchSha256
    || (deploymentOperationId && (proof.permittedOperationId !== deploymentOperationId
      || lease.tags.RedactWallPermittedOperation !== deploymentOperationId))) {
    throw new Error('external maintenance lease identity is missing, stale, or ambiguous');
  }
  if (stackExists && proof.phase === 'source_deleted') {
    throw new Error('external maintenance lease source_deleted proof conflicts with an existing application stack');
  }
  return lease;
}

function exactStackId(stackId, stackName, region) {
  const escapedName = String(stackName).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^arn:(?:aws|aws-us-gov|aws-cn):cloudformation:${region}:[0-9]{12}:stack/${escapedName}/[A-Za-z0-9-]{16,128}$`)
    .test(String(stackId || ''));
}

function assertStackOperationToken(stackId, stackName, region, operationId) {
  if (!exactStackId(stackId, stackName, region) || !PATTERNS.operationId.test(operationId)) {
    throw new Error('CloudFormation operation-token proof identity is invalid');
  }
  const response = JSON.parse(runAws([
    'cloudformation', 'describe-stack-events', '--stack-name', stackId, '--max-items', '256',
    '--query', '{StackEvents:StackEvents[].{StackId:StackId,StackName:StackName,ClientRequestToken:ClientRequestToken,ResourceType:ResourceType,LogicalResourceId:LogicalResourceId,PhysicalResourceId:PhysicalResourceId,ResourceStatus:ResourceStatus}}',
    '--region', region, '--output', 'json',
  ], { errorMessage: 'Could not prove the CloudFormation operation client token' }) || '{}');
  const events = response.StackEvents;
  if (!Array.isArray(events) || events.length < 1 || events.length > 256) {
    throw new Error('CloudFormation operation-token event history is missing or ambiguous');
  }
  const exact = events.some((event) => event?.StackId === stackId
    && event.StackName === stackName
    && event.ClientRequestToken === operationId
    && event.ResourceType === 'AWS::CloudFormation::Stack'
    && event.LogicalResourceId === stackName
    && event.PhysicalResourceId === stackId
    && ['CREATE_IN_PROGRESS', 'CREATE_COMPLETE'].includes(event.ResourceStatus));
  if (!exact) throw new Error('CloudFormation operation client token does not match the exact stack creation');
  return true;
}

function deployVersionedStack(values, template, parameters, exists, options = {}) {
  const action = exists ? 'update-stack' : 'create-stack';
  const operationId = String(options.operationId || newOperationId());
  if (!PATTERNS.operationId.test(operationId)) throw new Error('deployment operation id is invalid');
  const args = [
    'cloudformation', action, '--stack-name', values['stack-name'], '--template-url', template.templateUrl,
    '--parameters', JSON.stringify(parameters.map(([ParameterKey, ParameterValue]) => ({ ParameterKey, ParameterValue }))),
    '--capabilities', 'CAPABILITY_NAMED_IAM', '--client-request-token', operationId,
    '--region', values.region, '--output', 'json',
  ];
  if (!exists) args.push('--tags', `Key=RedactWallDeploymentOperation,Value=${operationId}`);
  let ownership;
  try {
    const response = JSON.parse(runAws(args, { errorMessage: `CloudFormation ${exists ? 'update' : 'creation'} failed` }) || '{}');
    const stackId = String(response.StackId || '');
    if (!exactStackId(stackId, values['stack-name'], values.region)) {
      throw new Error('CloudFormation did not return the exact returned StackId for this operation');
    }
    if (exists && options.expectedStackId && stackId !== options.expectedStackId) {
      throw new Error('CloudFormation update returned a different stack identity');
    }
    ownership = { operationId, stackId, stackName: values['stack-name'], region: values.region };
    if (typeof options.onOwnership === 'function') options.onOwnership(structuredClone(ownership));
  } catch (error) {
    if (exists && noStackUpdates(error)) {
      if (!exactStackId(options.expectedStackId, values['stack-name'], values.region)) {
        throw new Error('unchanged update lacks an exact source stack identity');
      }
      return { changed: false, ownership: {
        operationId, stackId: options.expectedStackId, stackName: values['stack-name'], region: values.region,
      } };
    }
    if (ownership) error.deploymentOwnership = ownership;
    throw error;
  }
  try {
    runAws(['cloudformation', 'wait', exists ? 'stack-update-complete' : 'stack-create-complete',
      '--stack-name', ownership.stackId, '--region', values.region], {
      timeoutMs: 60 * 60 * 1000,
      errorMessage: `CloudFormation ${exists ? 'update' : 'creation'} did not complete successfully`,
    });
    const applied = stackDetails(ownership.stackId, values.region);
    if (applied.stackId !== ownership.stackId) throw new Error('CloudFormation readback changed the exact operation-owned StackId');
    return { changed: true, ownership };
  } catch (error) {
    error.deploymentOwnership = ownership;
    throw error;
  }
}

function certificateCovers(hostname, names) {
  const expected = String(hostname).toLowerCase();
  return names.some((raw) => {
    const name = String(raw || '').toLowerCase();
    if (name === expected) return true;
    if (!name.startsWith('*.')) return false;
    const suffix = name.slice(1);
    return expected.endsWith(suffix) && !expected.slice(0, -suffix.length).includes('.');
  });
}

function validateCertificate(values) {
  const identity = JSON.parse(runAws(['sts', 'get-caller-identity', '--output', 'json']));
  if (!/^[0-9]{12}$/.test(String(identity.Account || ''))
    || values['certificate-arn'].split(':')[4] !== identity.Account) throw new Error('ACM certificate must belong to the active AWS account');
  const raw = runAws(['acm', 'describe-certificate', '--certificate-arn', values['certificate-arn'],
    '--region', values.region, '--output', 'json'], { errorMessage: 'Could not validate the ACM certificate' });
  const certificate = JSON.parse(raw)?.Certificate;
  const names = [certificate?.DomainName, ...(certificate?.SubjectAlternativeNames || [])];
  if (certificate?.Status !== 'ISSUED' || !certificateCovers(values['public-hostname'], names)) {
    throw new Error('ACM certificate must be ISSUED and cover the exact public hostname');
  }
}

function validateVolume(values, expectedInstanceId, expectedDataStackId) {
  const volumeRaw = runAws(['ec2', 'describe-volumes', '--volume-ids', values['data-volume-id'],
    '--region', values.region, '--output', 'json'], { errorMessage: 'Could not validate the retained customer data volume' });
  const volumes = JSON.parse(volumeRaw)?.Volumes || [];
  const volume = volumes.length === 1 ? volumes[0] : null;
  const tags = Object.fromEntries((volume?.Tags || []).map((tag) => [tag.Key, tag.Value]));
  const stackArnPattern = new RegExp(`^arn:(?:aws|aws-us-gov|aws-cn):cloudformation:${values.region}:[0-9]{12}:stack/${values['data-stack-name']}/[a-f0-9-]{16,64}$`);
  if (!volume || volume.VolumeId !== values['data-volume-id'] || volume.Encrypted !== true
    || volume.VolumeType !== 'gp3' || volume.MultiAttachEnabled !== false
    || volume.AvailabilityZone !== values['instance-availability-zone'] || !['available', 'in-use'].includes(volume.State)
    || tags.RedactWallTenant !== values['tenant-id'] || tags.RedactWallPurpose !== 'evidence-store'
    || tags.RedactWallAuthority !== 'retained-external'
    || tags['aws:cloudformation:stack-name'] !== values['data-stack-name']
    || tags['aws:cloudformation:logical-id'] !== 'CustomerDataVolume'
    || !stackArnPattern.test(String(expectedDataStackId || ''))
    || tags['aws:cloudformation:stack-id'] !== expectedDataStackId) {
    throw new Error('retained data volume failed encryption, gp3, tenant, stack, or availability-zone validation');
  }
  const attachments = volume.Attachments || [];
  const attachmentOk = expectedInstanceId
    ? attachments.length === 1 && attachments[0].InstanceId === expectedInstanceId
      && attachments[0].Device === '/dev/sdf' && ['attached', 'attaching'].includes(attachments[0].State)
    : attachments.length === 0 && volume.State === 'available';
  if (!attachmentOk) throw new Error('retained data volume is attached outside the exact current silo instance contract');
  const snapshotId = String(volume.SnapshotId || '');
  if ((!!snapshotId) !== (!!values['source-data-volume-id'])) throw new Error('snapshot-restored data volumes require --source-data-volume-id; fresh volumes require it to be empty');
}

function validateAwsTopology(values, options = {}) {
  const publicSubnets = values['public-subnet-ids'].split(',');
  const requested = [...new Set([values['instance-subnet-id'], ...publicSubnets])];
  const raw = runAws([
    'ec2', 'describe-subnets', '--subnet-ids', ...requested,
    '--region', values.region, '--output', 'json',
  ], { errorMessage: 'Could not validate the selected VPC subnets' });
  const subnets = JSON.parse(raw)?.Subnets || [];
  if (subnets.length !== requested.length) throw new Error('AWS did not return every selected subnet');
  const byId = new Map(subnets.map((subnet) => [subnet.SubnetId, subnet]));
  if (subnets.some((subnet) => subnet.VpcId !== values['vpc-id'])) {
    throw new Error('every selected subnet must belong to --vpc-id');
  }
  if (byId.get(values['instance-subnet-id'])?.AvailabilityZone !== values['instance-availability-zone']) {
    throw new Error('instance availability zone does not match the selected instance subnet');
  }
  const albZones = new Set(publicSubnets.map((subnetId) => byId.get(subnetId)?.AvailabilityZone));
  if (albZones.has(undefined) || albZones.size < 2) {
    throw new Error('public ALB subnets must span at least two availability zones');
  }
  const dataStack = stackState(values['data-stack-name'], values.region);
  if (!dataStack.exists || dataStack.outputs.DataVolumeId !== values['data-volume-id']
    || dataStack.outputs.AvailabilityZone !== values['instance-availability-zone']
    || String(dataStack.outputs.SourceDataVolumeId || '') !== values['source-data-volume-id']
    || dataStack.outputs.TenantId !== values['tenant-id']) throw new Error('durable-data stack outputs do not match this silo');
  validateVolume(values, options.expectedInstanceId || '', dataStack.stackId);
  validateCertificate(values);
}

function sleep(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function waitForCommand(commandId, instanceId, region, timeoutSeconds) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  const terminal = new Set(['Success', 'Cancelled', 'TimedOut', 'Failed', 'Cancelling']);
  let lastStatus = 'Pending';
  while (Date.now() < deadline) {
    try {
      const raw = runAws([
        'ssm', 'get-command-invocation', '--command-id', commandId,
        '--instance-id', instanceId, '--region', region, '--output', 'json',
      ], { timeoutMs: 30_000, errorMessage: 'Could not read the SSM deployment result' });
      const result = JSON.parse(raw);
      lastStatus = String(result.Status || 'Unknown');
      if (terminal.has(lastStatus)) {
        if (lastStatus !== 'Success') {
          const sanitized = `${result.StandardOutputContent || ''}\n${result.StandardErrorContent || ''}`
            .match(/^REDACTWALL_COMMITTED_DEGRADED=([a-z0-9_]{1,80})$/m)?.[1];
          if (sanitized) throw new Error(`Runtime apply-and-attest committed but degraded: ${sanitized}`);
          throw new Error(`Runtime apply-and-attest failed with SSM status ${lastStatus}`);
        }
        return result;
      }
    } catch (error) {
      if (!/\(InvocationDoesNotExist\)/.test(String(error.stderr || ''))) throw error;
    }
    sleep(5000);
  }
  throw new Error(`Runtime apply-and-attest did not finish within ${timeoutSeconds} seconds (last status ${lastStatus})`);
}

function sendCommand(instanceId, region, command, timeoutSeconds, comment) {
  const commandId = runAws([
    'ssm', 'send-command', '--instance-ids', instanceId,
    '--document-name', 'AWS-RunShellScript', '--comment', comment,
    '--parameters', JSON.stringify({ commands: [command], executionTimeout: [String(timeoutSeconds)] }),
    '--region', region, '--query', 'Command.CommandId', '--output', 'text',
  ], { errorMessage: 'Could not start the bounded SSM deployment command' });
  if (!/^[a-f0-9-]{32,64}$/.test(commandId)) throw new Error('SSM did not return a valid command id');
  const invocation = waitForCommand(commandId, instanceId, region, timeoutSeconds);
  return { commandId, output: String(invocation?.StandardOutputContent || ''), error: String(invocation?.StandardErrorContent || '') };
}

function waitForSsmOnline(instanceId, region, timeoutSeconds) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    try {
      const raw = runAws([
        'ssm', 'describe-instance-information',
        '--filters', `Key=InstanceIds,Values=${instanceId}`,
        '--region', region, '--output', 'json',
      ], { timeoutMs: 30_000, errorMessage: 'Could not query SSM managed-instance readiness' });
      const records = JSON.parse(raw)?.InstanceInformationList || [];
      if (records.length === 1 && records[0].InstanceId === instanceId && records[0].PingStatus === 'Online') return;
    } catch {}
    sleep(5000);
  }
  throw new Error(`Instance ${instanceId} did not become SSM Online within ${timeoutSeconds} seconds`);
}

function waitForHostReadiness(instanceId, region, requiredScript, timeoutSeconds) {
  if (!/^\/usr\/local\/sbin\/[a-z0-9-]+$/.test(requiredScript)) throw new Error('required host script is invalid');
  const deadline = Date.now() + timeoutSeconds * 1000;
  waitForSsmOnline(instanceId, region, timeoutSeconds);
  while (Date.now() < deadline) {
    try {
      sendCommand(
        instanceId,
        region,
        `test -x ${requiredScript} && systemctl is-active --quiet redactwall-data-identity.service && systemctl is-active --quiet docker.service`,
        Math.max(30, Math.min(90, Math.floor((deadline - Date.now()) / 1000))),
        'RedactWall host readiness',
      );
      return;
    } catch {}
    sleep(5000);
  }
  throw new Error(`Instance ${instanceId} bootstrap units did not become ready within ${timeoutSeconds} seconds`);
}

function cleanupDeploymentSnapshot(staged, result, failure, io = console, cleanup = artifacts.cleanupSnapshot) {
  if (!staged || !staged.directory) return;
  try {
    cleanup(staged);
  } catch (cleanupError) {
    if (result) {
      result.warnings.push('local_template_snapshot_cleanup_failed');
      (io.warn || io.log)('RedactWall committed with warning: local_template_snapshot_cleanup_failed');
      return;
    }
    if (failure) failure.cleanupError = cleanupError;
  }
}

function parseAppliedWarnings(output) {
  return [...new Set([...String(output || '').matchAll(/^REDACTWALL_APPLIED_WARNING=([a-z0-9_]{1,80})$/gm)]
    .map((match) => match[1]))];
}

function appliedAuthorityDocument(input) {
  const document = {
    appliedAt: String(input.appliedAt || ''),
    appliedStateDigest: String(input.appliedStateDigest || ''),
    configSha256: String(input.configSha256 || ''),
    containerId: String(input.containerId || ''),
    deploymentId: String(input.deploymentId || ''),
    domain: 'redactwall.applied-authority.v1',
    imageUri: String(input.imageUri || ''),
    protocolSha256: String(input.protocolSha256 || ''),
    recoverySetId: String(input.recoverySetId || ''),
    secretArn: String(input.secretArn || ''),
    secretVersionId: String(input.secretVersionId || ''),
    stackId: String(input.stackId || ''),
    templateSha256: String(input.templateSha256 || ''),
    tenantId: String(input.tenantId || ''),
    version: 1,
  };
  if (!exactUtcMilliseconds(document.appliedAt)
    || !PATTERNS.digest.test(document.appliedStateDigest)
    || !PATTERNS.digest.test(document.configSha256)
    || !/^[a-f0-9]{64}$/.test(document.containerId)
    || !PATTERNS.deployment.test(document.deploymentId)
    || !PATTERNS.image.test(document.imageUri)
    || !PATTERNS.digest.test(document.protocolSha256)
    || !(document.recoverySetId === 'none' || /^[a-f0-9]{32}$/.test(document.recoverySetId))
    || !PATTERNS.secretArn.test(document.secretArn)
    || !PATTERNS.secretVersion.test(document.secretVersionId)
    || !/^arn:(?:aws|aws-us-gov|aws-cn):cloudformation:[a-z0-9-]+:[0-9]{12}:stack\/[A-Za-z][-A-Za-z0-9]{0,127}\/[A-Za-z0-9-]{16,128}$/.test(document.stackId)
    || !PATTERNS.digest.test(document.templateSha256)
    || !PATTERNS.tenant.test(document.tenantId)) {
    throw new Error('runtime applied authority document is invalid');
  }
  return canonical(document);
}

function appliedAuthorityFingerprint(input) {
  return sha256Text(JSON.stringify(appliedAuthorityDocument(input)));
}

function parseAppliedAttestation(output, expected = null, required = false) {
  const fields = {
    containerId: ['REDACTWALL_APPLIED_CONTAINER_ID', '[a-f0-9]{64}'],
    appliedStateSha256: ['REDACTWALL_APPLIED_STATE_DIGEST', '[a-f0-9]{64}'],
    authorityFingerprintSha256: ['REDACTWALL_APPLIED_AUTHORITY_FINGERPRINT', '[a-f0-9]{64}'],
    attestedAt: ['REDACTWALL_APPLIED_AT', '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z'],
    recoverySetId: ['REDACTWALL_APPLIED_RECOVERY_SET_ID', 'none|[a-f0-9]{32}'],
  };
  const matchesByKey = Object.fromEntries(Object.entries(fields).map(([key, [name, pattern]]) => [
    key, [...String(output || '').matchAll(new RegExp(`^${name}=(${pattern})$`, 'gm'))],
  ]));
  if (!required && Object.values(matchesByKey).every((matches) => matches.length === 0)) return null;
  const parsed = {};
  for (const [key, [name]] of Object.entries(fields)) {
    const matches = matchesByKey[key];
    if (matches.length !== 1) throw new Error(`runtime attestation returned an invalid ${name}`);
    parsed[key] = matches[0][1];
  }
  if (!exactUtcMilliseconds(parsed.attestedAt)) throw new Error('runtime attestation returned an invalid applied time');
  if (!expected || typeof expected !== 'object') {
    throw new Error('runtime attestation lacks an expected authority contract');
  }
  const authorityInput = {
    ...expected,
    appliedAt: parsed.attestedAt,
    appliedStateDigest: parsed.appliedStateSha256,
    containerId: parsed.containerId,
    recoverySetId: parsed.recoverySetId,
  };
  if (parsed.recoverySetId !== expected.recoverySetId
    || parsed.authorityFingerprintSha256 !== appliedAuthorityFingerprint(authorityInput)) {
    throw new Error('runtime attestation does not match the exact applied authority contract');
  }
  return parsed;
}

function deploy(values, io = console, options = {}) {
  const template = path.resolve(__dirname, '..', 'infra', 'aws', 'customer-silo.yml');
  const identity = JSON.parse(runAws(['sts', 'get-caller-identity', '--output', 'json']));
  const accountId = String(identity.Account || '');
  if (!/^[0-9]{12}$/.test(accountId)) throw new Error('active AWS account id is unavailable');
  artifacts.verifyArtifactBucket(runAws, {
    bucket: values['artifact-bucket'], region: values.region, accountId,
  });
  const deploymentOperationId = String(options.operationId || newOperationId());
  if (!PATTERNS.operationId.test(deploymentOperationId)) throw new Error('deployment operation id is invalid');
  const authorityDependencies = { ...(options.authorityDependencies || {}), accountId };
  const authorityLocation = operationAuthorityLocation(values, accountId);
  let operationAuthority;
  let operationAuthorityOwned = false;
  const configSha256 = desiredConfigSha256(values);
  let staged;
  if (options.template) {
    if (!PATTERNS.digest.test(options.template.protocolSha256 || '')
      || options.template.configSha256 !== configSha256) {
      throw new Error('prior template protocol or desired-config digest does not match the rollback parameters');
    }
    staged = artifacts.verifyTemplateReference(runAws, {
      ...options.template, bucket: values['artifact-bucket'], region: values.region, accountId,
    });
    staged.protocolSha256 = options.template.protocolSha256;
    staged.configSha256 = options.template.configSha256;
  } else {
    staged = artifacts.stageTemplate(runAws, {
      bucket: values['artifact-bucket'], prefix: values['artifact-prefix'], region: values.region,
      accountId, templatePath: template,
    });
    staged.protocolSha256 = protocolSha256();
    staged.configSha256 = configSha256;
  }
  const recovery = options.recovery || {};
  const recoverySetId = String(recovery.setId || '');
  const recoveryBackup = String(recovery.backup || '');
  const recoveryManifest = String(recovery.manifest || '');
  if (!([recoverySetId, recoveryBackup, recoveryManifest].every(Boolean)
      || [recoverySetId, recoveryBackup, recoveryManifest].every((value) => !value))
    || (recoverySetId && (!/^[a-f0-9]{32}$/.test(recoverySetId)
      || !PATTERNS.recoveryName.test(recoveryBackup) || !PATTERNS.recoveryName.test(recoveryManifest)))) {
    throw new Error('maintenance recovery set, backup, and manifest identities must be supplied together');
  }
  let result;
  let failure;
  let mutation;
  let mutationAttempted = false;
  if (options.maintenanceLease) {
    operationAuthority = assertOperationAuthorityHandle(options.maintenanceLease.authority, {
      checkpointLatchSha256: options.maintenanceLease.checkpointLatchSha256,
      checkpointSetId: options.maintenanceLease.checkpointSetId,
      holderKind: 'maintenance',
      leaseStackId: options.maintenanceLease.stackId,
      operationId: options.maintenanceLease.operationId,
      permittedOperationId: deploymentOperationId,
      phase: options.maintenanceLease.phase,
    }, authorityDependencies);
  } else {
    operationAuthority = acquireOperationAuthority(
      authorityLocation, 'deploy', deploymentOperationId, authorityDependencies,
    );
    operationAuthorityOwned = true;
  }
  try {
  const current = stackState(values['stack-name'], values.region);
  const currentOutputs = current.outputs;
  const stackExists = current.exists;
  if (operationAuthorityOwned) {
    operationAuthority = compareAndSwapOperationAuthority(operationAuthority, {
      sourceFingerprint: stackExists ? sha256Text(JSON.stringify(canonical(current.stack))) : 'none',
      sourceStackId: stackExists ? current.stackId : 'none',
    }, authorityDependencies);
  }
  assertCreationLease(values, stackExists, options.maintenanceLease, deploymentOperationId);
  validateAwsTopology(values, { expectedInstanceId: currentOutputs.InstanceId || '' });
  if (stackExists && (!/^vol-[a-f0-9]{8,17}$/.test(String(currentOutputs.DataVolumeId || ''))
    || !PATTERNS.availabilityZone.test(String(currentOutputs.InstanceAvailabilityZone || '')))) {
    throw new Error('existing stack predates the retained-volume contract; use the documented backup/restore migration before updating it');
  }
  if (stackExists && currentOutputs.InstanceAvailabilityZone !== values['instance-availability-zone']) {
    throw new Error('instance availability zone is immutable for a retained customer data volume; use the documented backup/restore migration instead');
  }
  if (stackExists && currentOutputs.DataVolumeId !== values['data-volume-id']) {
    throw new Error('data volume id is immutable for an existing silo; use the documented backup/restore migration instead');
  }
  if (stackExists && (currentOutputs.DataStackName !== values['data-stack-name']
    || String(currentOutputs.SourceDataVolumeId || '') !== values['source-data-volume-id'])) {
    throw new Error('data stack and snapshot lineage are immutable for an existing silo; use the maintenance restore workflow');
  }
  if (stackExists && currentOutputs.TenantId !== values['tenant-id']) {
    throw new Error('tenant id is immutable for an existing silo');
  }
  assertConnectedDeploymentIdentity(stackExists, currentOutputs, values);
  if (stackExists && (currentOutputs.AmiId !== values['ami-id']
    || currentOutputs.InstanceType !== values['instance-type']
    || currentOutputs.RootVolumeGb !== values['root-volume-gb'])) {
    throw new Error('AMI, instance type, and root volume are frozen; use the explicit maintenance replacement workflow');
  }
  const currentInstanceId = String(currentOutputs.InstanceId || '');
  if (stackExists && !/^i-[a-f0-9]{8,17}$/.test(currentInstanceId)) {
    throw new Error('existing stack published an invalid InstanceId');
  }
  if (currentInstanceId) {
    waitForHostReadiness(
      currentInstanceId,
      values.region,
      '/usr/local/sbin/redactwall-validate-release-input',
      Number(values['timeout-seconds']),
    );
    const validationCommand = [
      '/usr/local/sbin/redactwall-validate-release-input',
      '--image-uri', values['image-uri'], '--secret-arn', values['secret-arn'],
      '--secret-version-id', values['secret-version-id'], '--tenant-id', values['tenant-id'],
      '--deployment-id', values['deployment-id'],
    ].join(' ');
    sendCommand(
      currentInstanceId,
      values.region,
      validationCommand,
      Number(values['timeout-seconds']),
      `RedactWall preflight ${values['stack-name']}`,
    );
  }
  if (stackExists) enforceReplacementBlock(values['stack-name'], values.region);
  const parameters = [
    ['VpcId', values['vpc-id']],
    ['PublicSubnetIds', values['public-subnet-ids']],
    ['InstanceSubnetId', values['instance-subnet-id']],
    ['InstanceAvailabilityZone', values['instance-availability-zone']],
    ['DataVolumeId', values['data-volume-id']],
    ['DataStackName', values['data-stack-name']],
    ['SourceDataVolumeId', values['source-data-volume-id']],
    ['AmiId', values['ami-id']],
    ['InstanceType', values['instance-type']],
    ['RootVolumeGb', values['root-volume-gb']],
    ['ImageUri', values['image-uri']],
    ['SecretArn', values['secret-arn']],
    ['LicenseSecretVersionId', values['secret-version-id']],
    ['TenantId', values['tenant-id']],
    ['DeploymentId', values['deployment-id']],
    ['CertificateArn', values['certificate-arn']],
    ['PublicHostname', values['public-hostname']],
    ['DesiredConfigSha256', staged.configSha256],
    ['DeploymentTemplateUrl', staged.templateUrl],
    ['DeploymentTemplateSha256', staged.sha256],
    ['DeploymentTemplateBytes', String(templateByteLength(staged))],
    ['DeploymentProtocolSha256', staged.protocolSha256],
    ['RecoveryBackupName', recoveryBackup],
    ['RecoveryManifestName', recoveryManifest],
    ['RecoverySetId', recoverySetId],
  ];
  if (typeof options.onMutationIntent === 'function') {
    const updatedLease = options.onMutationIntent({
      configSha256: staged.configSha256,
      deploymentId: values['deployment-id'],
      imageUri: values['image-uri'],
      protocolSha256: staged.protocolSha256,
      recoverySetId: recoverySetId || 'none',
      secretArnSha256: sha256Text(values['secret-arn']),
      secretVersionId: values['secret-version-id'],
      templateSha256: staged.sha256,
      tenantId: values['tenant-id'],
    });
    if (!updatedLease?.authority) throw new Error('maintenance candidate-create intent did not return external authority');
    operationAuthority = updatedLease.authority;
  }
  operationAuthority = assertOperationAuthorityHandle(operationAuthority, {
    holderKind: operationAuthorityOwned ? 'deploy' : 'maintenance',
    operationId: operationAuthorityOwned ? deploymentOperationId : options.maintenanceLease.operationId,
    permittedOperationId: deploymentOperationId,
  }, authorityDependencies);
  mutationAttempted = true;
  mutation = deployVersionedStack(values, staged, parameters, stackExists, {
    operationId: deploymentOperationId, expectedStackId: current.stackId,
    onOwnership: typeof options.onOwnership === 'function' ? (ownership) => options.onOwnership({
      ...ownership,
      configSha256: staged.configSha256,
      imageUri: values['image-uri'],
      protocolSha256: staged.protocolSha256,
      recoverySetId: String(options.maintenanceRecoverySetId || recoverySetId || 'none'),
      secretVersionId: values['secret-version-id'],
      templateSha256: staged.sha256,
    }) : undefined,
  });
  enforceReplacementBlock(mutation.ownership.stackId, values.region);

  const outputs = stackOutputs(mutation.ownership.stackId, values.region);
  const instanceId = String(outputs.InstanceId || '');
  if (!/^i-[a-f0-9]{8,17}$/.test(instanceId)) throw new Error('Stack did not publish a valid InstanceId');
  if (outputs.DataVolumeId !== values['data-volume-id']
    || outputs.DataStackName !== values['data-stack-name']
    || String(outputs.SourceDataVolumeId || '') !== values['source-data-volume-id']
    || outputs.DeploymentId !== values['deployment-id']
    || outputs.DesiredConfigSha256 !== staged.configSha256
    || outputs.DeploymentTemplateUrl !== staged.templateUrl
    || outputs.DeploymentTemplateSha256 !== staged.sha256
    || Number(outputs.DeploymentTemplateBytes) !== templateByteLength(staged)
    || outputs.DeploymentProtocolSha256 !== staged.protocolSha256
    || outputs.InstanceAvailabilityZone !== values['instance-availability-zone']) {
    throw new Error('Stack did not publish the expected retained-volume identity');
  }
  waitForHostReadiness(
    instanceId,
    values.region,
    '/usr/local/sbin/redactwall-assert-applied',
    Number(values['timeout-seconds']),
  );
  const command = [
    '/usr/local/sbin/redactwall-apply-and-attest',
    '--image-uri', values['image-uri'],
    '--secret-version-id', values['secret-version-id'],
    '--config-sha256', staged.configSha256,
    '--template-sha256', staged.sha256,
    '--protocol-sha256', staged.protocolSha256,
    '--recovery-set-id', recoverySetId || 'none',
  ].join(' ');
  const invocation = sendCommand(
    instanceId,
    values.region,
    command,
    Number(values['timeout-seconds']),
    `RedactWall attested deploy ${values['stack-name']}`,
  );
  const warnings = parseAppliedWarnings(invocation.output);
  const attestation = parseAppliedAttestation(invocation.output, {
    configSha256: staged.configSha256,
    deploymentId: values['deployment-id'],
    imageUri: values['image-uri'],
    protocolSha256: staged.protocolSha256,
    recoverySetId: recoverySetId || 'none',
    secretArn: values['secret-arn'],
    secretVersionId: values['secret-version-id'],
    stackId: mutation.ownership.stackId,
    templateSha256: staged.sha256,
    tenantId: values['tenant-id'],
  }, true);
  for (const warning of warnings) (io.warn || io.log)(`RedactWall committed with warning: ${warning}`);
  io.log(`RedactWall silo ${values['stack-name']} applied and attested on ${instanceId}.`);
  result = { stackName: values['stack-name'], instanceId, commandId: invocation.commandId,
    operationId: mutation.ownership.operationId, stackId: mutation.ownership.stackId,
    templateSha256: staged.sha256, templateUrl: staged.templateUrl, protocolSha256: staged.protocolSha256,
    configSha256: staged.configSha256, warnings, ...(attestation || {}) };
  if (typeof options.onAttested === 'function') options.onAttested(structuredClone(result));
  } catch (error) {
    if (!error.deploymentOwnership && mutation?.ownership) error.deploymentOwnership = mutation.ownership;
    failure = error;
  } finally {
    cleanupDeploymentSnapshot(staged, result, failure, io);
    operationAuthority = settleDeploymentAuthority(operationAuthority, {
      failure, mutationAttempted, owned: operationAuthorityOwned, result,
    }, authorityDependencies, io);
  }
  if (failure) throw failure;
  return result;
}

function main(argv = process.argv.slice(2)) {
  try {
    deploy(validate(parseArgs(argv)));
  } catch (error) {
    console.error(`[silo-deploy] ${error.message || 'deployment failed'}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  PATTERNS,
  acquireDeploymentAuthority,
  acquireOperationAuthority,
  assertConnectedDeploymentIdentity,
  assertStackOperationToken,
  assertOperationAuthorityHandle,
  deploy,
  main,
  parseArgs,
  parseAppliedWarnings,
  parseAppliedAttestation,
  appliedAuthorityDocument,
  appliedAuthorityFingerprint,
  enforceReplacementBlock,
  replacementBlockingPolicy,
  sendCommand,
  stackNotFound,
  stackDetails,
  stackOutputs,
  stackState,
  validate,
  certificateCovers,
  validateCertificate,
  validateVolume,
  waitForCommand,
  waitForHostReadiness,
  waitForSsmOnline,
  validateAwsTopology,
  desiredConfigSha256,
  compareAndSwapOperationAuthority,
  cleanupDeploymentSnapshot,
  deployVersionedStack,
  exactStackId,
  assertCreationLease,
  maintenanceLeaseName,
  newOperationId,
  operationAuthorityLocation,
  readS3OperationAuthority,
  readOperationAuthority,
  releaseDeploymentAuthority,
  settleDeploymentAuthority,
  templateReferenceFromOutputs,
  templateByteLength,
  verifyRollbackTemplate,
  validateOperationAuthorityState,
  verifyOperationAuthorityPreflight,
  isExactOperationAuthorityPolicyDeny,
  isExactOperationAuthorityDeleteDeny,
  runAws,
};
