'use strict';

const crypto = require('node:crypto');
const deployer = require('./aws-silo-deploy');

const STABLE_SOURCE_STATUSES = new Set([
  'CREATE_COMPLETE',
  'IMPORT_COMPLETE',
  'UPDATE_COMPLETE',
  'UPDATE_ROLLBACK_COMPLETE',
]);

const PARAMETER_MAP = {
  VpcId: 'vpc-id', PublicSubnetIds: 'public-subnet-ids', InstanceSubnetId: 'instance-subnet-id',
  InstanceAvailabilityZone: 'instance-availability-zone', DataVolumeId: 'data-volume-id',
  DataStackName: 'data-stack-name', SourceDataVolumeId: 'source-data-volume-id', AmiId: 'ami-id',
  InstanceType: 'instance-type', RootVolumeGb: 'root-volume-gb', ImageUri: 'image-uri', SecretArn: 'secret-arn',
  LicenseSecretVersionId: 'secret-version-id', TenantId: 'tenant-id', DeploymentId: 'deployment-id',
  CertificateArn: 'certificate-arn', PublicHostname: 'public-hostname',
};

const LEASE_TEMPLATE = JSON.stringify({
  AWSTemplateFormatVersion: '2010-09-09',
  Description: 'Independent RedactWall application-stack maintenance lease',
  Resources: { MaintenanceLeaseHandle: { Type: 'AWS::CloudFormation::WaitConditionHandle' } },
});
const LEASE_TRANSITIONS = Object.freeze({
  acquired: new Set(['preparing', 'release_ready']),
  preparing: new Set(['drained', 'release_ready', 'evidence_retained']),
  drained: new Set(['source_deleted', 'release_ready', 'evidence_retained']),
  source_deleted: new Set(['candidate', 'restoring', 'evidence_retained']),
  candidate: new Set(['release_ready', 'restoring', 'evidence_retained']),
  restoring: new Set(['release_ready', 'evidence_retained']),
  evidence_retained: new Set(['restoring', 'release_ready']),
  release_ready: new Set(['releasing']),
  releasing: new Set(),
});

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function templateDigest(templateBody) {
  if (typeof templateBody === 'string') return sha256(Buffer.from(templateBody, 'utf8'));
  if (!templateBody || typeof templateBody !== 'object') throw new Error('maintenance source template is unavailable');
  return sha256(JSON.stringify(canonical(templateBody)));
}

function stackDescription(stackName, region) {
  const raw = deployer.runAws(['cloudformation', 'describe-stacks', '--stack-name', stackName,
    '--region', region, '--output', 'json'], { errorMessage: 'Could not read the maintenance source stack' });
  const stacks = JSON.parse(raw)?.Stacks || [];
  if (stacks.length !== 1) throw new Error('maintenance source stack is unavailable or ambiguous');
  const templateRaw = deployer.runAws(['cloudformation', 'get-template', '--stack-name', stacks[0].StackId,
    '--template-stage', 'Original', '--region', region, '--output', 'json'], {
    errorMessage: 'Could not bind the exact maintenance source template',
  });
  const response = JSON.parse(templateRaw);
  if (!Object.prototype.hasOwnProperty.call(response, 'TemplateBody')) {
    throw new Error('maintenance source template is unavailable');
  }
  return { ...stacks[0], RedactWallTemplateSha256: templateDigest(response.TemplateBody) };
}

function escaped(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function sortedEntries(entries, keyName, valueName) {
  return (entries || []).map((entry) => [String(entry[keyName] || ''), String(entry[valueName] ?? '')])
    .sort(([left], [right]) => left.localeCompare(right));
}

function sourceStackContract(stack) {
  return JSON.stringify(canonical({
    stackId: String(stack.StackId || ''),
    stackName: String(stack.StackName || ''),
    stackStatus: String(stack.StackStatus || ''),
    stackStatusReason: String(stack.StackStatusReason || ''),
    creationTime: String(stack.CreationTime || ''),
    lastUpdatedTime: String(stack.LastUpdatedTime || ''),
    roleArn: String(stack.RoleARN || ''),
    changeSetId: String(stack.ChangeSetId || ''),
    rootId: String(stack.RootId || ''),
    parentId: String(stack.ParentId || ''),
    description: String(stack.Description || ''),
    enableTerminationProtection: stack.EnableTerminationProtection === true,
    timeoutInMinutes: Number(stack.TimeoutInMinutes || 0),
    capabilities: [...(stack.Capabilities || [])].map(String).sort(),
    notificationArns: [...(stack.NotificationARNs || [])].map(String).sort(),
    tags: sortedEntries(stack.Tags, 'Key', 'Value'),
    rollbackConfiguration: stack.RollbackConfiguration || null,
    driftInformation: stack.DriftInformation || null,
    retainExceptOnCreate: stack.RetainExceptOnCreate === true,
    deletionMode: String(stack.DeletionMode || ''),
    parameters: sortedEntries(stack.Parameters, 'ParameterKey', 'ParameterValue'),
    outputs: sortedEntries(stack.Outputs, 'OutputKey', 'OutputValue'),
    templateSha256: String(stack.RedactWallTemplateSha256 || ''),
  }));
}

function sourceFingerprint(stack) {
  return sha256(sourceStackContract(stack));
}

function assertStableSourceStack(stack, stackName, region) {
  const exactId = new RegExp(`^arn:(?:aws|aws-us-gov|aws-cn):cloudformation:${escaped(region)}:[0-9]{12}:stack/${escaped(stackName)}/[A-Za-z0-9-]{16,128}$`);
  if (String(stack?.StackName || '') !== stackName || !exactId.test(String(stack?.StackId || ''))) {
    throw new Error('maintenance requires the exact source stack identity');
  }
  if (!STABLE_SOURCE_STATUSES.has(String(stack?.StackStatus || ''))) {
    throw new Error('maintenance requires a stable complete source stack status');
  }
  if (!/^[a-f0-9]{64}$/.test(String(stack.RedactWallTemplateSha256 || ''))) {
    throw new Error('maintenance requires the exact source template identity');
  }
  return stack;
}

function assertUnchangedSourceStack(before, after) {
  if (sourceStackContract(before) !== sourceStackContract(after)) {
    throw new Error('maintenance source stack changed after the maintenance checkpoint');
  }
  return after;
}

function valuesFromStack(stack, requested) {
  const values = {
    'stack-name': requested['stack-name'], region: requested.region,
    'artifact-bucket': requested['artifact-bucket'], 'artifact-prefix': requested['artifact-prefix'],
    'timeout-seconds': requested['timeout-seconds'],
  };
  for (const parameter of stack.Parameters || []) {
    const key = PARAMETER_MAP[parameter.ParameterKey];
    if (key) values[key] = String(parameter.ParameterValue ?? '');
  }
  return deployer.validate(values);
}

function outputMap(stack) {
  return Object.fromEntries((stack.Outputs || []).map((entry) => [entry.OutputKey, entry.OutputValue]));
}

function assertMaintenanceDelta(mode, before, after) {
  if (before['tenant-id'] !== after['tenant-id']) throw new Error('maintenance cannot change TenantId');
  if (before['deployment-id'] !== after['deployment-id']) throw new Error('maintenance cannot change DeploymentId');
  const allowed = mode === 'replace-instance'
    ? new Set(['ami-id', 'instance-type', 'root-volume-gb'])
    : new Set(['data-volume-id', 'data-stack-name', 'source-data-volume-id']);
  for (const key of Object.keys(PARAMETER_MAP).map((name) => PARAMETER_MAP[name])) {
    if (!allowed.has(key) && before[key] !== after[key]) throw new Error(`maintenance must preserve ${key}`);
  }
  if (mode === 'replace-instance' && before['data-volume-id'] !== after['data-volume-id']) {
    throw new Error('instance replacement must retain the exact data volume');
  }
  if (mode === 'restore-volume' && (before['data-volume-id'] === after['data-volume-id']
    || after['source-data-volume-id'] !== before['data-volume-id'])) {
    throw new Error('snapshot restore requires a new volume and the exact prior DataVolumeId as lineage source');
  }
}

function deleteApplicationStack(stackId, region) {
  deployer.runAws(['cloudformation', 'delete-stack', '--stack-name', stackId, '--region', region],
    { errorMessage: 'Could not begin the application-stack maintenance deletion' });
  deployer.runAws(['cloudformation', 'wait', 'stack-delete-complete', '--stack-name', stackId, '--region', region],
    { timeoutMs: 60 * 60 * 1000, errorMessage: 'Application stack did not delete and detach before the maintenance deadline' });
}

function candidateDigest(candidate) {
  return candidate ? sha256(JSON.stringify(canonical(candidate))) : 'none';
}

function leaseTags(operationId, sourceStack, fingerprint, phase = 'acquired', permittedOperationId = 'none',
  checkpointSetId = 'none', checkpointLatchSha256 = 'none', authority = null, candidate = null) {
  return {
    RedactWallMaintenanceOperation: operationId,
    RedactWallSourceStackId: String(sourceStack.StackId),
    RedactWallSourceFingerprint: fingerprint,
    RedactWallMaintenancePhase: phase,
    RedactWallPermittedOperation: permittedOperationId,
    RedactWallMaintenanceSet: checkpointSetId,
    RedactWallMaintenanceLatchSha256: checkpointLatchSha256,
    RedactWallAuthorityGeneration: authority ? String(authority.state.generation) : 'none',
    RedactWallAuthorityBodySha256: authority ? authority.bodySha256 : 'none',
    RedactWallCandidateStateSha256: candidateDigest(candidate),
  };
}

function assertLeaseReadback(details, expected) {
  if (details.stackId !== expected.stackId || details.stackName !== expected.stackName
    || details.stackStatus !== 'CREATE_COMPLETE'
    || details.tags.RedactWallMaintenanceOperation !== expected.operationId
    || details.tags.RedactWallSourceStackId !== expected.sourceStackId
    || details.tags.RedactWallSourceFingerprint !== expected.sourceFingerprint
    || details.tags.RedactWallMaintenancePhase !== expected.phase
    || details.tags.RedactWallPermittedOperation !== expected.permittedOperationId
    || details.tags.RedactWallMaintenanceSet !== expected.checkpointSetId
    || details.tags.RedactWallMaintenanceLatchSha256 !== expected.checkpointLatchSha256
    || details.tags.RedactWallAuthorityGeneration !== String(expected.authority?.state?.generation || 'none')
    || details.tags.RedactWallAuthorityBodySha256 !== String(expected.authority?.bodySha256 || 'none')
    || details.tags.RedactWallCandidateStateSha256 !== candidateDigest(expected.authority?.state?.candidate || null)) {
    throw new Error('external maintenance lease readback is missing, changed, or ambiguous');
  }
  return expected;
}

function leaseDescription(stackId, region) {
  const raw = deployer.runAws(['cloudformation', 'describe-stacks', '--stack-name', stackId,
    '--region', region, '--output', 'json'], { errorMessage: 'Could not verify the independent maintenance lease' });
  const stacks = JSON.parse(raw)?.Stacks || [];
  if (stacks.length !== 1) throw new Error('external maintenance lease readback is ambiguous');
  const stack = stacks[0];
  return {
    stackId: String(stack.StackId || ''), stackName: String(stack.StackName || ''),
    stackStatus: String(stack.StackStatus || ''),
    tags: Object.fromEntries((stack.Tags || []).map((entry) => [entry.Key, entry.Value])),
  };
}

function activeAccountId() {
  const identity = JSON.parse(deployer.runAws(['sts', 'get-caller-identity', '--output', 'json']));
  const accountId = String(identity.Account || '');
  if (!/^[0-9]{12}$/.test(accountId)) throw new Error('active AWS account id is unavailable for maintenance authority');
  return accountId;
}

function acquireMaintenanceLease(sourceStack, region, options = {}) {
  const stackName = deployer.maintenanceLeaseName(sourceStack.StackName);
  const fingerprint = sourceFingerprint(sourceStack);
  const accountId = String(options.accountId || activeAccountId());
  const location = options.location || deployer.operationAuthorityLocation(options.values || {}, accountId);
  const authorityDependencies = { ...(options.authorityDependencies || {}), accountId };
  const describeLeaseCreation = options.describeLeaseCreation
    || ((name, valueRegion) => deployer.stackState(name, valueRegion));
  const sourceStackId = String(sourceStack.StackId);
  let authority = deployer.readOperationAuthority(location, authorityDependencies);
  const resumable = authority?.state?.holderKind === 'maintenance'
    && ['lease_creating', 'acquired'].includes(authority.state.phase)
    && authority.state.sourceStackId === sourceStackId
    && authority.state.sourceFingerprint === fingerprint
    && authority.state.leaseStackName === stackName
    && authority.state.leaseClientToken === authority.state.operationId;
  if (authority && !resumable) {
    throw new Error('external operation authority is already held by another or later maintenance operation');
  }
  if (!authority) {
    const operationId = String(options.operationId || deployer.newOperationId());
    authority = deployer.acquireOperationAuthority(location, 'maintenance', operationId, authorityDependencies, {
      leaseClientToken: operationId,
      leaseStackName: stackName,
      phase: 'lease_creating',
      sourceFingerprint: fingerprint,
      sourceStackId,
    });
  }
  const operationId = authority.state.operationId;
  let stackId = authority.state.leaseStackId;
  if (authority.state.phase === 'lease_creating') {
    const tags = leaseTags(operationId, sourceStack, fingerprint, 'lease_creating', 'none', 'none', 'none', authority);
    let response;
    try {
      response = JSON.parse(deployer.runAws([
        'cloudformation', 'create-stack', '--stack-name', stackName, '--template-body', LEASE_TEMPLATE,
        '--client-request-token', operationId,
        '--tags', ...Object.entries(tags).map(([Key, Value]) => `Key=${Key},Value=${Value}`),
        '--region', region, '--output', 'json',
      ], { errorMessage: 'Could not acquire the independent maintenance lease' }) || '{}');
      stackId = String(response.StackId || '');
    } catch (error) {
      let observed;
      try { observed = describeLeaseCreation(stackName, region); }
      catch (reconciliationError) { error.reconciliationError = reconciliationError; }
      if (!observed?.exists) {
        error.maintenanceLease = { authority, operationId, phase: 'lease_creating', region,
          sourceFingerprint: fingerprint, sourceStackId, stackId: 'none', stackName };
        throw error;
      }
      stackId = observed.stackId;
      assertLeaseCreationReadback(observed, { authority, operationId, sourceFingerprint: fingerprint,
        sourceStackId, stackId, stackName });
      (options.verifyLeaseCreation || deployer.assertStackOperationToken)(stackId, stackName, region, operationId);
    }
    if (!deployer.exactStackId(stackId, stackName, region)) {
      const error = new Error('maintenance lease creation did not return one exact StackId');
      error.maintenanceLease = { authority, operationId, phase: 'lease_creating', region,
        sourceFingerprint: fingerprint, sourceStackId, stackId: 'none', stackName };
      throw error;
    }
    authority = deployer.compareAndSwapOperationAuthority(authority, {
      leaseStackId: stackId,
      phase: 'acquired',
    }, authorityDependencies);
  }
  let lease = { operationId, stackId, stackName, region, phase: 'acquired', permittedOperationId: 'none',
    checkpointSetId: 'none', checkpointLatchSha256: 'none', sourceStackId, sourceFingerprint: fingerprint,
    authority, authorityEtag: authority.etag, authorityDependencies };
  try {
    deployer.runAws(['cloudformation', 'wait', 'stack-create-complete', '--stack-name', stackId, '--region', region], {
      timeoutMs: 60 * 60 * 1000, errorMessage: 'Independent maintenance lease did not become active',
    });
    updateLeaseTags(lease, 'acquired', 'none');
    return assertLeaseReadback(leaseDescription(stackId, region), lease);
  } catch (error) {
    error.maintenanceLease = lease;
    throw error;
  }
}

function assertLeaseCreationReadback(details, expected) {
  const tags = details?.tags || {};
  if (!details?.exists || details.stackId !== expected.stackId || details.stackName !== expected.stackName
    || !['CREATE_IN_PROGRESS', 'CREATE_COMPLETE'].includes(details.stackStatus)
    || tags.RedactWallMaintenanceOperation !== expected.operationId
    || tags.RedactWallSourceStackId !== expected.sourceStackId
    || tags.RedactWallSourceFingerprint !== expected.sourceFingerprint
    || tags.RedactWallMaintenancePhase !== 'lease_creating'
    || tags.RedactWallPermittedOperation !== 'none'
    || tags.RedactWallMaintenanceSet !== 'none'
    || tags.RedactWallMaintenanceLatchSha256 !== 'none'
    || tags.RedactWallAuthorityGeneration !== String(expected.authority.state.generation)
    || tags.RedactWallAuthorityBodySha256 !== expected.authority.bodySha256
    || tags.RedactWallCandidateStateSha256 !== 'none') {
    throw new Error('maintenance lease creation readback is missing, changed, or ambiguous');
  }
  return details;
}

function updateLeaseTags(lease, phase, permittedOperationId) {
  const tags = leaseTags(lease.operationId, { StackId: lease.sourceStackId }, lease.sourceFingerprint,
    phase, permittedOperationId, lease.checkpointSetId, lease.checkpointLatchSha256,
    lease.authority, lease.authority?.state?.candidate || null);
  const token = deployer.newOperationId();
  deployer.runAws(['cloudformation', 'update-stack', '--stack-name', lease.stackId,
    '--use-previous-template', '--client-request-token', token,
    '--tags', ...Object.entries(tags).map(([Key, Value]) => `Key=${Key},Value=${Value}`),
    '--region', lease.region, '--output', 'json'], { errorMessage: 'Could not advance the maintenance lease phase' });
  deployer.runAws(['cloudformation', 'wait', 'stack-update-complete', '--stack-name', lease.stackId,
    '--region', lease.region], { timeoutMs: 60 * 60 * 1000,
    errorMessage: 'Maintenance lease phase did not become durable' });
}

function transitionMaintenanceLease(lease, phase, dependencies = {}, permittedOperationId = 'none', checkpoint = null) {
  if (!LEASE_TRANSITIONS[lease?.phase]?.has(phase)) {
    throw new Error(`maintenance lease transition ${lease?.phase || 'unknown'} -> ${phase} is not monotonic`);
  }
  if (permittedOperationId !== 'none' && !deployer.PATTERNS.operationId.test(permittedOperationId)) {
    throw new Error('maintenance lease permitted operation id is invalid');
  }
  const checkpointSetId = checkpoint ? String(checkpoint.setId || '') : String(lease.checkpointSetId || 'none');
  const checkpointLatchSha256 = checkpoint
    ? String(checkpoint.latchSha256 || '') : String(lease.checkpointLatchSha256 || 'none');
  if (!((checkpointSetId === 'none' && checkpointLatchSha256 === 'none')
    || (/^[a-f0-9]{32}$/.test(checkpointSetId) && /^[a-f0-9]{64}$/.test(checkpointLatchSha256)))) {
    throw new Error('maintenance lease checkpoint binding is invalid');
  }
  const update = dependencies.updateLease || updateLeaseTags;
  const describe = dependencies.describeLease || ((value) => leaseDescription(value.stackId, value.region));
  const proposed = { ...lease, phase, permittedOperationId, checkpointSetId, checkpointLatchSha256 };
  let next;
  if (dependencies.compareAndSwapAuthority) {
    next = dependencies.compareAndSwapAuthority(lease, proposed);
  } else {
    if (!lease.authority) throw new Error('RELEASE-BLOCKED: maintenance lease lacks the external CAS authority');
    const authority = deployer.compareAndSwapOperationAuthority(lease.authority, {
      checkpointLatchSha256,
      checkpointSetId,
      permittedOperationId,
      phase,
    }, lease.authorityDependencies || {});
    next = { ...proposed, authority, authorityEtag: authority.etag };
  }
  try {
    update(next, phase, permittedOperationId);
    return assertLeaseReadback(describe(next), next);
  } catch (error) {
    error.maintenanceLease = next;
    error.externalAuthorityAdvanced = true;
    throw error;
  }
}

function assertLeasePhase(lease, phase, dependencies = {}) {
  if (lease?.phase !== phase) throw new Error(`maintenance lease is not in required ${phase} phase`);
  const describe = dependencies.describeLease || ((value) => leaseDescription(value.stackId, value.region));
  return assertLeaseReadback(describe(lease), lease);
}

function normalizeStableTargetRegistration(value) {
  const target = {
    instanceId: String(value?.instanceId || ''),
    observedAt: String(value?.observedAt || ''),
    registered: value?.registered,
    state: String(value?.state || ''),
    targetGroupArn: String(value?.targetGroupArn || ''),
  };
  if (!/^i-[a-f0-9]{8,17}$/.test(target.instanceId)
    || !/^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$/.test(target.observedAt)
    || new Date(target.observedAt).toISOString() !== target.observedAt
    || target.registered !== true || !['healthy', 'unhealthy', 'initial'].includes(target.state)
    || !/^arn:(?:aws|aws-us-gov|aws-cn):elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:targetgroup\/[A-Za-z0-9-]{1,32}\/[a-f0-9]{16}$/.test(target.targetGroupArn)) {
    throw new Error('maintenance target registration intent is invalid');
  }
  return target;
}

function normalizeCutoverIntent(lease, input) {
  const stage = String(input?.stage || '');
  const planned = stage === 'candidate_create';
  const intent = {
    candidateClientToken: String(input?.candidateClientToken || ''),
    candidateStackName: candidateStackName(lease),
    configSha256: planned ? String(input.configSha256 || '') : 'none',
    deploymentId: planned ? String(input.deploymentId || '') : 'none',
    imageUri: planned ? String(input.imageUri || '') : 'none',
    protocolSha256: planned ? String(input.protocolSha256 || '') : 'none',
    recoverySetId: planned ? String(input.recoverySetId || 'none') : 'none',
    secretArnSha256: planned ? String(input.secretArnSha256 || '') : 'none',
    secretVersionId: planned ? String(input.secretVersionId || '') : 'none',
    sourceStackId: String(lease.sourceStackId || ''),
    stage,
    templateSha256: planned ? String(input.templateSha256 || '') : 'none',
    tenantId: planned ? String(input.tenantId || '') : 'none',
  };
  if (!['drain', 'source_delete', 'candidate_create'].includes(stage)
    || !deployer.PATTERNS.operationId.test(intent.candidateClientToken)
    || !deployer.PATTERNS.stackName.test(intent.candidateStackName)) {
    throw new Error('maintenance cutover intent identity is invalid');
  }
  return intent;
}

function recordMaintenanceCutover(lease, input, dependencies = {}) {
  const requiredPhase = input.stage === 'drain' ? 'preparing'
    : input.stage === 'source_delete' ? 'drained' : 'source_deleted';
  if (lease?.phase !== requiredPhase) {
    throw new Error(`maintenance ${input.stage || 'unknown'} intent requires ${requiredPhase}`);
  }
  const cutoverIntent = normalizeCutoverIntent(lease, input);
  const targetRegistration = normalizeStableTargetRegistration(
    input.targetRegistration || lease.authority?.state?.targetRegistration,
  );
  const checkpointSetId = String(input.checkpoint?.setId || lease.checkpointSetId || 'none');
  const checkpointLatchSha256 = String(input.checkpoint?.latchSha256 || lease.checkpointLatchSha256 || 'none');
  if (!/^[a-f0-9]{32}$/.test(checkpointSetId) || !/^[a-f0-9]{64}$/.test(checkpointLatchSha256)) {
    throw new Error('maintenance cutover intent lacks the exact host checkpoint');
  }
  if (!lease.authority) throw new Error('RELEASE-BLOCKED: maintenance cutover lacks the external CAS authority');
  const authority = deployer.compareAndSwapOperationAuthority(lease.authority, {
    checkpointLatchSha256,
    checkpointSetId,
    cutoverIntent,
    permittedOperationId: cutoverIntent.candidateClientToken,
    targetRegistration,
  }, lease.authorityDependencies || dependencies);
  const next = {
    ...lease, authority, authorityEtag: authority.etag, checkpointLatchSha256, checkpointSetId,
    permittedOperationId: cutoverIntent.candidateClientToken,
  };
  const update = dependencies.updateLease || updateLeaseTags;
  const describe = dependencies.describeLease || ((value) => leaseDescription(value.stackId, value.region));
  try {
    update(next, next.phase, next.permittedOperationId);
    return assertLeaseReadback(describe(next), next);
  } catch (error) {
    error.maintenanceLease = next;
    error.externalAuthorityAdvanced = true;
    throw error;
  }
}

function candidateStackName(lease) {
  const match = String(lease?.sourceStackId || '').match(/:stack\/([^/]+)\//);
  return match?.[1] || '';
}

function normalizeCandidateEvidence(lease, input) {
  const stage = input.stage || (input.instanceId ? 'attested' : 'owned');
  const candidate = {
    appliedStateSha256: stage === 'attested' ? String(input.appliedStateSha256 || '') : 'none',
    attestedAt: stage === 'attested' ? String(input.attestedAt || '') : 'none',
    authorityFingerprintSha256: stage === 'attested' ? String(input.authorityFingerprintSha256 || '') : 'none',
    configSha256: String(input.configSha256 || ''),
    containerId: stage === 'attested' ? String(input.containerId || '') : 'none',
    imageUri: String(input.imageUri || ''),
    instanceId: stage === 'attested' ? String(input.instanceId || '') : 'none',
    operationId: String(input.operationId || ''),
    protocolSha256: String(input.protocolSha256 || ''),
    recoverySetId: String(input.recoverySetId || 'none'),
    secretVersionId: String(input.secretVersionId || ''),
    stackId: String(input.stackId || ''),
    stage,
    templateSha256: String(input.templateSha256 || ''),
  };
  const applicationStack = candidateStackName(lease) || String(input.stackName || '');
  if (!['owned', 'attested'].includes(stage)
    || candidate.operationId !== lease.permittedOperationId
    || !deployer.PATTERNS.operationId.test(candidate.operationId)
    || !deployer.exactStackId(candidate.stackId, applicationStack, String(lease.region || 'us-east-1'))
    || !deployer.PATTERNS.digest.test(candidate.configSha256)
    || !deployer.PATTERNS.image.test(candidate.imageUri)
    || !deployer.PATTERNS.digest.test(candidate.templateSha256)
    || !deployer.PATTERNS.digest.test(candidate.protocolSha256)
    || !deployer.PATTERNS.secretVersion.test(candidate.secretVersionId)
    || !(candidate.recoverySetId === 'none' || /^[a-f0-9]{32}$/.test(candidate.recoverySetId))) {
    throw new Error('maintenance candidate authority identity is invalid');
  }
  if (stage === 'attested' && (!/^i-[a-f0-9]{8,17}$/.test(candidate.instanceId)
    || !/^[a-f0-9]{64}$/.test(candidate.containerId)
    || !deployer.PATTERNS.digest.test(candidate.appliedStateSha256)
    || !deployer.PATTERNS.digest.test(candidate.authorityFingerprintSha256)
    || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(candidate.attestedAt)
    || new Date(candidate.attestedAt).toISOString() !== candidate.attestedAt)) {
    throw new Error('maintenance candidate applied attestation is invalid');
  }
  const intent = lease.authority?.state?.cutoverIntent || lease.cutoverIntent;
  if (!intent || intent.stage !== 'candidate_create'
    || intent.candidateClientToken !== candidate.operationId
    || intent.candidateStackName !== applicationStack
    || intent.configSha256 !== candidate.configSha256
    || intent.imageUri !== candidate.imageUri
    || intent.protocolSha256 !== candidate.protocolSha256
    || intent.recoverySetId !== candidate.recoverySetId
    || intent.secretVersionId !== candidate.secretVersionId
    || intent.templateSha256 !== candidate.templateSha256) {
    throw new Error('maintenance candidate does not match the durable create intent');
  }
  return candidate;
}

function recordCandidateAuthority(lease, evidence, dependencies = {}) {
  const candidate = normalizeCandidateEvidence(lease, evidence);
  if (!((lease.phase === 'source_deleted' && candidate.stage === 'owned')
    || (lease.phase === 'candidate' && candidate.stage === 'attested'))) {
    throw new Error('maintenance candidate authority transition is out of order');
  }
  const proposed = { ...lease, phase: 'candidate', candidate };
  let next;
  if (dependencies.compareAndSwapAuthority) {
    next = dependencies.compareAndSwapAuthority(lease, proposed);
  } else {
    if (!lease.authority) throw new Error('RELEASE-BLOCKED: candidate lacks the external CAS authority');
    const authority = deployer.compareAndSwapOperationAuthority(lease.authority, {
      candidate,
      phase: 'candidate',
    }, lease.authorityDependencies || {});
    next = { ...proposed, authority, authorityEtag: authority.etag };
  }
  if (!dependencies.compareAndSwapAuthority || dependencies.updateLease || dependencies.describeLease) {
    const update = dependencies.updateLease || updateLeaseTags;
    const describe = dependencies.describeLease || ((value) => leaseDescription(value.stackId, value.region));
    try {
      update(next, 'candidate', next.permittedOperationId);
      assertLeaseReadback(describe(next), next);
    } catch (error) {
      error.maintenanceLease = next;
      error.externalAuthorityAdvanced = true;
      throw error;
    }
  }
  return next;
}

function candidateRecoveryStatus(value) {
  const authorityState = value?.authority?.state || value?.state || value || {};
  const candidate = authorityState.candidate || value?.candidate || null;
  const scope = authorityState.scope || {};
  const canRelease = candidate?.stage === 'attested'
    && ['candidate', 'release_ready', 'releasing'].includes(authorityState.phase || value?.phase);
  const phase = authorityState.phase || value?.phase;
  const canReconcile = ['preparing', 'drained', 'source_deleted', 'candidate'].includes(phase);
  const recoveryMode = canRelease ? 'reconcile-release' : canReconcile ? 'reconcile' : 'status';
  const recoveryCommand = `node scripts/aws-silo-maintenance.js --mode ${recoveryMode}`
    + ` --stack-name ${scope.stackName || 'UNKNOWN'}`
    + ` --region ${scope.region || value?.region || 'UNKNOWN'}`
    + ` --lease-stack-id ${value?.stackId || authorityState.leaseStackId || 'UNKNOWN'}`
    + ` --maintenance-id ${authorityState.checkpointSetId || value?.checkpointSetId || 'UNKNOWN'}`
    + ` --latch-sha256 ${authorityState.checkpointLatchSha256 || value?.checkpointLatchSha256 || 'UNKNOWN'}`
    + (value?.authority?.location?.bucket
      ? ` --artifact-bucket ${value.authority.location.bucket} --artifact-prefix ${value.authority.location.prefix}` : '');
  return {
    candidate,
    canRelease,
    operationId: authorityState.operationId || value?.operationId || null,
    phase: phase || null,
    recoveryCommand,
  };
}

function exactAvailableAuthoritySuccessor(current, releasing) {
  if (!current) return false;
  if (current.state && releasing.authority?.state) {
    const state = current.state;
    const prior = releasing.authority;
    return state.holderKind === 'available' && state.phase === 'available'
      && state.operationId === 'none' && state.permittedOperationId === 'none'
      && state.candidate === null && state.cutoverIntent === null && state.targetRegistration === null
      && state.checkpointSetId === 'none' && state.checkpointLatchSha256 === 'none'
      && state.leaseClientToken === 'none' && state.leaseStackId === 'none' && state.leaseStackName === 'none'
      && state.sourceFingerprint === 'none' && state.sourceStackId === 'none'
      && state.generation === prior.state.generation + 1
      && state.previousBodySha256 === prior.bodySha256
      && JSON.stringify(state.scope) === JSON.stringify(prior.state.scope)
      && current.location?.key === prior.location?.key && current.location?.bucket === prior.location?.bucket
      && current.location?.region === prior.location?.region && current.location?.accountId === prior.location?.accountId;
  }
  return current.phase === 'available' && current.operationId === 'none'
    && current.permittedOperationId === 'none'
    && current.previousAuthorityEtag === releasing.authorityEtag;
}

function readMaintenanceAuthority(lease, dependencies) {
  if (dependencies.readAuthority) return dependencies.readAuthority(lease);
  if (!lease.authority?.location) return null;
  return deployer.readOperationAuthority(lease.authority.location, lease.authorityDependencies || {});
}

function availableMaintenanceLease(releasing, current) {
  return {
    ...releasing,
    authority: current.state ? current : releasing.authority,
    authorityEtag: current.etag || current.authorityEtag,
    checkpointLatchSha256: 'none',
    checkpointSetId: 'none',
    operationId: 'none',
    permittedOperationId: 'none',
    phase: 'available',
    previousAuthorityEtag: current.previousAuthorityEtag,
  };
}

function releaseMaintenanceLease(lease, dependencies = {}) {
  if (!['release_ready', 'releasing'].includes(lease.phase)) {
    throw new Error('maintenance lease may be released only from release_ready or resumed releasing');
  }
  let releasing = lease;
  if (lease.phase === 'releasing') {
    let current;
    try { current = readMaintenanceAuthority(lease, dependencies); } catch {}
    if (exactAvailableAuthoritySuccessor(current, lease)) return availableMaintenanceLease(lease, current);
  }
  if (lease.phase === 'release_ready') {
    const proposed = { ...lease, phase: 'releasing' };
    if (dependencies.compareAndSwapAuthority) {
      releasing = dependencies.compareAndSwapAuthority(lease, proposed);
    } else {
      if (!lease.authority) throw new Error('RELEASE-BLOCKED: maintenance release lacks the external CAS authority');
      const authority = deployer.compareAndSwapOperationAuthority(lease.authority, { phase: 'releasing' },
        lease.authorityDependencies || {});
      releasing = { ...proposed, authority, authorityEtag: authority.etag };
    }
    const update = dependencies.updateLease || updateLeaseTags;
    const describe = dependencies.describeLease || ((value) => leaseDescription(value.stackId, value.region));
    try {
      update(releasing, 'releasing', releasing.permittedOperationId);
      assertLeaseReadback(describe(releasing), releasing);
    } catch (error) {
      error.maintenanceLease = releasing;
      error.externalAuthorityAdvanced = true;
      throw error;
    }
  } else if (dependencies.assertCurrentAuthority) {
    dependencies.assertCurrentAuthority(releasing);
  } else {
    const authority = deployer.assertOperationAuthorityHandle(releasing.authority, {
      holderKind: 'maintenance', leaseStackId: releasing.stackId,
      operationId: releasing.operationId, phase: 'releasing',
    }, releasing.authorityDependencies || {});
    releasing = { ...releasing, authority, authorityEtag: authority.etag };
  }
  try {
    (dependencies.deleteLease || deleteApplicationStack)(releasing.stackId, releasing.region);
  } catch (error) {
    let absent = false;
    try {
      absent = dependencies.leaseAbsent
        ? dependencies.leaseAbsent(releasing)
        : !deployer.stackState(releasing.stackId, releasing.region).exists;
    } catch (reconciliationError) {
      error.maintenanceLease = releasing;
      error.reconciliationError = reconciliationError;
      throw error;
    }
    if (!absent) {
      error.maintenanceLease = releasing;
      throw error;
    }
  }
  try {
    if (dependencies.compareAndSwapAuthority) {
      return dependencies.compareAndSwapAuthority(releasing, {
        ...releasing, phase: 'available', permittedOperationId: 'none', operationId: 'none',
        previousAuthorityEtag: releasing.authorityEtag,
      });
    }
    const authority = deployer.compareAndSwapOperationAuthority(releasing.authority, {
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
    }, releasing.authorityDependencies || {});
    return { ...releasing, authority, authorityEtag: authority.etag, phase: 'available' };
  } catch (error) {
    let current;
    try { current = readMaintenanceAuthority(releasing, dependencies); }
    catch (reconciliationError) { error.reconciliationError = reconciliationError; }
    if (exactAvailableAuthoritySuccessor(current, releasing)) return availableMaintenanceLease(releasing, current);
    error.maintenanceLease = releasing;
    throw error;
  }
}

function assertCheckpoint(checkpoint, allowPartial = false) {
  if (!checkpoint || !/^[a-f0-9]{32}$/.test(String(checkpoint.setId || ''))
    || !/^[a-f0-9]{64}$/.test(String(checkpoint.latchSha256 || ''))
    || !['preparing', 'drained', 'stopped', 'resumed', 'resumed-partial'].includes(String(checkpoint.phase || ''))) {
    throw new Error('maintenance checkpoint identity is invalid');
  }
  const complete = /^[A-Za-z0-9._-]{1,180}$/.test(String(checkpoint.backup || ''))
    && /^[A-Za-z0-9._-]{1,180}$/.test(String(checkpoint.manifest || ''));
  if (!allowPartial && (checkpoint.phase !== 'stopped' || !complete)) {
    throw new Error('maintenance checkpoint is not a complete stopped recovery point');
  }
  if (!complete && (checkpoint.backup || checkpoint.manifest)) {
    throw new Error('maintenance checkpoint recovery pair is incomplete');
  }
  return checkpoint;
}

function exactOutputValue(output, name, pattern, optional = false) {
  const matches = [...String(output || '').matchAll(new RegExp(`^${name}=(${pattern})$`, 'gm'))];
  if (optional && matches.length === 0) return '';
  if (matches.length !== 1) throw new Error(`maintenance control returned an invalid ${name} field`);
  return matches[0][1];
}

function parseMaintenanceStatus(output, allowPartial = true) {
  return assertCheckpoint({
    phase: exactOutputValue(output, 'REDACTWALL_MAINTENANCE_PHASE', 'preparing|drained|stopped|resumed|resumed-partial'),
    setId: exactOutputValue(output, 'REDACTWALL_MAINTENANCE_SET', '[a-f0-9]{32}'),
    backup: exactOutputValue(output, 'REDACTWALL_MAINTENANCE_BACKUP', '[A-Za-z0-9._-]{1,180}', true),
    manifest: exactOutputValue(output, 'REDACTWALL_MAINTENANCE_MANIFEST', '[A-Za-z0-9._-]{1,180}', true),
    latchSha256: exactOutputValue(output, 'REDACTWALL_MAINTENANCE_LATCH_SHA256', '[a-f0-9]{64}'),
  }, allowPartial);
}

function retainedEvidenceError(message, lease, checkpoint, stackName) {
  const safeStack = /^[A-Za-z][-A-Za-z0-9]{0,127}$/.test(String(stackName || '')) ? stackName : 'UNKNOWN';
  const mode = ['preparing', 'drained', 'source_deleted', 'candidate'].includes(lease?.phase)
    ? 'reconcile' : 'status';
  const command = `node scripts/aws-silo-maintenance.js --mode ${mode} --stack-name ${safeStack}`
    + ` --region ${lease.region} --lease-stack-id ${lease.stackId}`
    + ` --maintenance-id ${checkpoint?.setId || lease.checkpointSetId || 'UNKNOWN'}`
    + ` --latch-sha256 ${checkpoint?.latchSha256 || lease.checkpointLatchSha256 || 'UNKNOWN'}`
    + (lease.authority?.location?.bucket
      ? ` --artifact-bucket ${lease.authority.location.bucket} --artifact-prefix ${lease.authority.location.prefix}` : '');
  const error = new Error(`${String(message || 'maintenance failed').replace(/[\r\n]/g, ' ').slice(0, 160)}; evidence retained; checked recovery: ${command}`);
  error.maintenanceLease = lease;
  error.checkpoint = checkpoint;
  error.recoveryCommand = command;
  return error;
}

function maintenanceStatus(instanceId, region, timeoutSeconds) {
  return parseMaintenanceStatus(deployer.sendCommand(instanceId, region,
    '/usr/local/sbin/redactwall-maintenance-status', timeoutSeconds,
    'RedactWall maintenance status recovery').output, true);
}

function finishAbort(instanceId, targetGroupArn, region, timeoutSeconds, status, commandName) {
  assertCheckpoint(status, true);
  const resumed = deployer.sendCommand(instanceId, region,
    `/usr/local/sbin/${commandName} ${status.setId} ${status.latchSha256}`,
    timeoutSeconds, 'RedactWall maintenance abort resume');
  const resumedStatus = parseMaintenanceStatus(resumed.output, true);
  if (!['resumed', 'resumed-partial'].includes(resumedStatus.phase) || resumedStatus.setId !== status.setId) {
    throw new Error('maintenance abort did not resume the exact operation');
  }
  deployer.runAws(['elbv2', 'register-targets', '--target-group-arn', targetGroupArn,
    '--targets', `Id=${instanceId}`, '--region', region], { errorMessage: 'Could not re-register the source target after maintenance abort' });
  deployer.runAws(['elbv2', 'wait', 'target-in-service', '--target-group-arn', targetGroupArn,
    '--targets', `Id=${instanceId}`, '--region', region], { errorMessage: 'Source target did not recover after maintenance abort' });
  deployer.sendCommand(instanceId, region,
    `/usr/local/sbin/redactwall-maintenance-clear ${status.setId} ${resumedStatus.latchSha256}`,
    timeoutSeconds, 'RedactWall maintenance abort latch clear');
  return resumedStatus;
}

function abortSource(instanceId, targetGroupArn, region, timeoutSeconds, status) {
  return finishAbort(instanceId, targetGroupArn, region, timeoutSeconds, status, 'redactwall-maintenance-abort');
}

function resumeSource(instanceId, targetGroupArn, region, timeoutSeconds, checkpoint) {
  assertCheckpoint(checkpoint);
  return finishAbort(instanceId, targetGroupArn, region, timeoutSeconds, checkpoint, 'redactwall-maintenance-resume');
}

function recoverAndAbort(instanceId, targetGroupArn, region, timeoutSeconds, knownStatus, error) {
  try {
    const status = knownStatus || maintenanceStatus(instanceId, region, timeoutSeconds);
    const resumedStatus = abortSource(instanceId, targetGroupArn, region, timeoutSeconds, status);
    error.sourceRestored = true;
    return { ok: true, status: resumedStatus };
  } catch (abortError) {
    error.abortError = abortError;
    error.sourceRestored = false;
    return { ok: false, error: abortError };
  }
}

function targetRegistration(targetGroupArn, instanceId, region) {
  let raw;
  try {
    raw = deployer.runAws(['elbv2', 'describe-target-health', '--target-group-arn', targetGroupArn,
      '--targets', `Id=${instanceId}`, '--region', region, '--output', 'json'], {
      errorMessage: 'Could not reconcile source target registration after an ambiguous drain',
    });
  } catch (error) {
    if (/\(InvalidTarget\)|\bInvalidTarget\b|not registered/i.test(String(error?.stderr || ''))) {
      return { instanceId, observedAt: new Date().toISOString(), registered: false, state: 'absent', targetGroupArn };
    }
    throw error;
  }
  const records = JSON.parse(raw)?.TargetHealthDescriptions;
  if (!Array.isArray(records) || records.length > 1) {
    throw new Error('source target registration readback is malformed or ambiguous');
  }
  if (records.length === 0) {
    return { instanceId, observedAt: new Date().toISOString(), registered: false, state: 'absent', targetGroupArn };
  }
  const record = records[0];
  if (String(record?.Target?.Id || '') !== instanceId
    || !['initial', 'healthy', 'unhealthy', 'unused', 'draining', 'unavailable']
      .includes(String(record?.TargetHealth?.State || ''))) {
    throw new Error('source target registration readback is malformed or ambiguous');
  }
  return {
    instanceId,
    observedAt: new Date().toISOString(),
    registered: true,
    state: String(record.TargetHealth.State),
    targetGroupArn,
  };
}

function drainAndDeregister(outputs, region, timeoutSeconds, options = {}) {
  const instanceId = String(outputs.InstanceId || '');
  const targetGroupArn = String(outputs.TargetGroupArn || '');
  if (!/^i-[a-f0-9]{8,17}$/.test(instanceId)
    || !/^arn:(?:aws|aws-us-gov|aws-cn):elasticloadbalancing:/.test(targetGroupArn)) {
    throw new Error('maintenance source outputs are incomplete');
  }
  const targetRegistrationBefore = targetRegistration(targetGroupArn, instanceId, region);
  if (!targetRegistrationBefore.registered
    || !['healthy', 'unhealthy', 'initial'].includes(targetRegistrationBefore.state)) {
    const error = new Error('maintenance source target must have one stable registered pre-drain state');
    error.targetRegistrationBefore = targetRegistrationBefore;
    throw error;
  }
  deployer.waitForHostReadiness(instanceId, region, '/usr/local/sbin/redactwall-maintenance-status', timeoutSeconds);
  let prepared;
  let targetDeregisterIssued = false;
  let targetDrainConfirmed = false;
  try {
    prepared = parseMaintenanceStatus(deployer.sendCommand(instanceId, region,
      '/usr/local/sbin/redactwall-maintenance-drain', timeoutSeconds,
      'RedactWall maintenance prepare').output, true);
    if (prepared.phase !== 'preparing') throw new Error('maintenance prepare did not publish the preparing phase');
    if (typeof options.onPrepared === 'function') {
      options.onPrepared(structuredClone(prepared), structuredClone(targetRegistrationBefore));
    }
    targetDeregisterIssued = true;
    deployer.runAws(['elbv2', 'deregister-targets', '--target-group-arn', targetGroupArn,
      '--targets', `Id=${instanceId}`, '--region', region], { errorMessage: 'Could not deregister the old application target' });
    deployer.runAws(['elbv2', 'wait', 'target-deregistered', '--target-group-arn', targetGroupArn,
      '--targets', `Id=${instanceId}`, '--region', region], { errorMessage: 'Old application target did not drain before the deadline' });
    targetDrainConfirmed = true;
    const checkpoint = parseMaintenanceStatus(deployer.sendCommand(instanceId, region,
      `/usr/local/sbin/redactwall-maintenance-checkpoint ${prepared.setId} ${prepared.latchSha256}`,
      timeoutSeconds, 'RedactWall final stopped-writer checkpoint').output, false);
    if (checkpoint.setId !== prepared.setId) throw new Error('maintenance checkpoint changed operation identity');
    return { ...checkpoint, targetRegistrationBefore };
  } catch (error) {
    error.targetRegistrationBefore = targetRegistrationBefore;
    if (targetDeregisterIssued && !targetDrainConfirmed && prepared) {
      try {
        if (!targetRegistration(targetGroupArn, instanceId, region).registered) {
          const checkpoint = parseMaintenanceStatus(deployer.sendCommand(instanceId, region,
            `/usr/local/sbin/redactwall-maintenance-checkpoint ${prepared.setId} ${prepared.latchSha256}`,
            timeoutSeconds, 'RedactWall final stopped-writer checkpoint').output, false);
          if (checkpoint.setId !== prepared.setId) throw new Error('maintenance checkpoint changed operation identity');
          return { ...checkpoint, targetRegistrationBefore };
        }
      } catch (reconciliationError) {
        error.targetReconciliationError = reconciliationError;
      }
    }
    recoverAndAbort(instanceId, targetGroupArn, region, timeoutSeconds, null, error);
    throw error;
  }
}

function removeFailedStackIfOwned(ownership, stackName, region) {
  const named = deployer.stackState(stackName, region);
  if (!ownership) {
    if (named.exists) throw new Error('a same-name candidate is ambiguous and will not be deleted');
    return;
  }
  if (ownership.stackName !== stackName || ownership.region !== region
    || !deployer.exactStackId(ownership.stackId, stackName, region)
    || !deployer.PATTERNS.operationId.test(String(ownership.operationId || ''))) {
    throw new Error('candidate cleanup ownership is invalid');
  }
  const exact = deployer.stackState(ownership.stackId, region);
  if (!exact.exists) {
    if (named.exists) throw new Error('a competing stack now owns the same name; cleanup is ambiguous');
    return;
  }
  if (exact.stackId !== ownership.stackId || (named.exists && named.stackId !== ownership.stackId)) {
    throw new Error('a competing stack now owns the same name; cleanup is ambiguous');
  }
  deleteApplicationStack(ownership.stackId, region);
  if (deployer.stackState(stackName, region).exists) {
    throw new Error('a competing stack appeared after exact candidate cleanup');
  }
}

function releaseVerifiedLease(lease) {
  if (lease.authority?.state?.candidate && lease.authority.state.candidate.stage !== 'attested') {
    throw new Error('maintenance candidate cannot release before exact applied attestation is durable');
  }
  const ready = ['release_ready', 'releasing'].includes(lease.phase)
    ? lease : transitionMaintenanceLease(lease, 'release_ready');
  return releaseMaintenanceLease(ready);
}

function retainMaintenanceEvidence(message, lease, checkpoint, stackName, cause) {
  let retained = lease;
  let transitionError;
  if (lease?.phase !== 'evidence_retained' && LEASE_TRANSITIONS[lease?.phase]?.has('evidence_retained')) {
    try { retained = transitionMaintenanceLease(lease, 'evidence_retained'); }
    catch (error) {
      transitionError = error;
      if (error.maintenanceLease) retained = error.maintenanceLease;
    }
  }
  const result = retainedEvidenceError(message, retained, checkpoint, stackName);
  if (cause) result.cause = cause;
  if (transitionError) result.leaseTransitionError = transitionError;
  return result;
}

function maintain(mode, requested, io = console, options = {}) {
  if (!['replace-instance', 'restore-volume'].includes(mode)) {
    throw new Error('maintenance mode must be replace-instance or restore-volume');
  }
  const sourceStack = assertStableSourceStack(
    stackDescription(requested['stack-name'], requested.region), requested['stack-name'], requested.region,
  );
  const sourceOutputs = outputMap(sourceStack);
  const prior = valuesFromStack(sourceStack, requested);
  const priorTemplate = deployer.verifyRollbackTemplate(prior, deployer.templateReferenceFromOutputs(sourceOutputs));
  assertMaintenanceDelta(mode, prior, requested);
  deployer.validateAwsTopology(requested, {
    expectedInstanceId: mode === 'replace-instance' ? sourceOutputs.InstanceId : '',
  });

  let lease = acquireMaintenanceLease(sourceStack, requested.region, {
    accountId: options.accountId,
    authorityDependencies: options.authorityDependencies,
    location: options.authorityLocation,
    values: requested,
  });
  const candidateOperationId = deployer.newOperationId();
  let checkpoint;
  try {
    const preDrain = assertStableSourceStack(
      stackDescription(sourceStack.StackId, requested.region), requested['stack-name'], requested.region,
    );
    assertUnchangedSourceStack(sourceStack, preDrain);
    lease = transitionMaintenanceLease(lease, 'preparing');
  } catch (error) {
    if (lease.phase === 'acquired') {
      try { lease = releaseVerifiedLease(lease); }
      catch (releaseError) {
        if (releaseError.maintenanceLease) lease = releaseError.maintenanceLease;
        error.leaseReleaseError = releaseError;
      }
    }
    error.maintenanceLease = lease;
    throw error;
  }
  try {
    checkpoint = drainAndDeregister(sourceOutputs, requested.region, Number(requested['timeout-seconds']), {
      onPrepared: (prepared, targetRegistrationBefore) => {
        try {
          lease = recordMaintenanceCutover(lease, {
            candidateClientToken: candidateOperationId,
            checkpoint: prepared,
            stage: 'drain',
            targetRegistration: targetRegistrationBefore,
          });
        } catch (error) {
          if (error.maintenanceLease) lease = error.maintenanceLease;
          throw error;
        }
      },
    });
  } catch (error) {
    if (error.sourceRestored === true) {
      try { lease = releaseVerifiedLease(lease); }
      catch (releaseError) {
        if (releaseError.maintenanceLease) lease = releaseError.maintenanceLease;
        error.leaseReleaseError = releaseError;
      }
      error.maintenanceLease = lease;
      throw error;
    }
    throw retainMaintenanceEvidence(error.message, lease, error.checkpoint, requested['stack-name'], error);
  }
  try {
    lease = transitionMaintenanceLease(lease, 'drained', {}, 'none', checkpoint);
    const beforeDelete = assertStableSourceStack(
      stackDescription(sourceStack.StackId, requested.region), requested['stack-name'], requested.region,
    );
    assertUnchangedSourceStack(sourceStack, beforeDelete);
  } catch (error) {
    throw retainMaintenanceEvidence(error.message, lease, checkpoint, requested['stack-name'], error);
  }
  try {
    lease = recordMaintenanceCutover(lease, {
      candidateClientToken: candidateOperationId,
      checkpoint,
      stage: 'source_delete',
    });
    assertLeasePhase(lease, 'drained');
    deleteApplicationStack(sourceStack.StackId, requested.region);
  } catch (error) {
    const state = deployer.stackState(sourceStack.StackId, requested.region);
    if (!state.exists) {
      io.warn?.('Application stack was confirmed absent after the delete waiter returned an error; continuing cutover.');
    } else {
      if (!state.stackStatus.startsWith('DELETE_')) {
        try {
          const exactSource = assertStableSourceStack(
            stackDescription(sourceStack.StackId, requested.region), requested['stack-name'], requested.region,
          );
          assertUnchangedSourceStack(sourceStack, exactSource);
          abortSource(sourceOutputs.InstanceId, sourceOutputs.TargetGroupArn, requested.region,
            Number(requested['timeout-seconds']), checkpoint);
          lease = releaseVerifiedLease(lease);
          error.sourceRestored = true;
        } catch (abortError) {
          if (abortError.maintenanceLease) lease = abortError.maintenanceLease;
          error.abortError = abortError;
        }
      }
      if (error.sourceRestored === true) throw error;
      throw retainMaintenanceEvidence(error.message, lease, checkpoint, requested['stack-name'], error);
    }
  }
  try {
    lease = transitionMaintenanceLease(lease, 'source_deleted', {}, candidateOperationId);
  } catch (error) {
    throw retainMaintenanceEvidence(error.message, lease, checkpoint, requested['stack-name'], error);
  }
  try {
    const result = deployer.deploy(requested, io, {
      operationId: candidateOperationId, maintenanceLease: lease,
      maintenanceRecoverySetId: checkpoint.setId,
      authorityDependencies: lease.authorityDependencies,
      onMutationIntent: (intent) => {
        try {
          lease = recordMaintenanceCutover(lease, {
            ...intent,
            candidateClientToken: candidateOperationId,
            checkpoint,
            stage: 'candidate_create',
          });
          return lease;
        } catch (error) {
          if (error.maintenanceLease) lease = error.maintenanceLease;
          throw error;
        }
      },
      onOwnership: (ownership) => {
        try { lease = recordCandidateAuthority(lease, { ...ownership, stage: 'owned' }); }
        catch (error) {
          if (error.maintenanceLease) lease = error.maintenanceLease;
          throw error;
        }
      },
      onAttested: (attestation) => {
        try {
          lease = recordCandidateAuthority(lease, {
            ...attestation,
            imageUri: requested['image-uri'],
            recoverySetId: checkpoint.setId,
            secretVersionId: requested['secret-version-id'],
            stage: 'attested',
          });
        } catch (error) {
          if (error.maintenanceLease) lease = error.maintenanceLease;
          throw error;
        }
      },
    });
    const outputs = deployer.stackOutputs(result.stackId, requested.region);
    let leaseReleasePending = false;
    let leaseRecovery = null;
    try { lease = releaseVerifiedLease(lease); }
    catch (releaseError) {
      if (releaseError.maintenanceLease) lease = releaseError.maintenanceLease;
      leaseReleasePending = true;
      leaseRecovery = candidateRecoveryStatus(lease);
      io.warn?.(`Maintenance committed, but the independent lease remains. Checked recovery: ${leaseRecovery.recoveryCommand}`);
    }
    io.log(`Maintenance committed. Update DNS to ${outputs.LoadBalancerDnsName}.`);
    return { ...result, mode, checkpoint, loadBalancerDnsName: outputs.LoadBalancerDnsName,
      maintenanceLease: lease, leaseReleasePending, leaseRecovery };
  } catch (error) {
    let rollback;
    try {
      removeFailedStackIfOwned(error.deploymentOwnership, requested['stack-name'], requested.region);
      const rollbackOperationId = deployer.newOperationId();
      if (lease.phase !== 'restoring') {
        lease = transitionMaintenanceLease(lease, 'restoring', {}, rollbackOperationId);
      }
      rollback = deployer.deploy(prior, io, {
        template: priorTemplate, recovery: checkpoint, maintenanceLease: lease,
        operationId: rollbackOperationId,
      });
      lease = releaseVerifiedLease(lease);
    } catch (rollbackError) {
      if (rollbackError.maintenanceLease) lease = rollbackError.maintenanceLease;
      const combined = retainMaintenanceEvidence(
        `maintenance failed (${error.message}); exact prior-stack rollback also failed (${rollbackError.message})`,
        lease, checkpoint, requested['stack-name'], error,
      );
      combined.rollbackError = rollbackError;
      throw combined;
    }
    error.rollback = { ok: true, checkpoint, instanceId: rollback.instanceId,
      dataVolumeId: prior['data-volume-id'] };
    throw error;
  }
}

function parseStatusArgs(argv) {
  const required = new Set([
    'stack-name', 'region', 'lease-stack-id', 'maintenance-id', 'latch-sha256', 'artifact-bucket',
  ]);
  const allowed = new Set([...required, 'artifact-prefix']);
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (!String(option || '').startsWith('--') || value == null || String(value).startsWith('--')) {
      throw new Error('maintenance status options must be exact --name value pairs');
    }
    const key = option.slice(2);
    if (!allowed.has(key) || Object.prototype.hasOwnProperty.call(values, key)) {
      throw new Error(`unknown or duplicate maintenance status option: ${option}`);
    }
    values[key] = value;
  }
  for (const key of required) {
    if (!values[key]) throw new Error(`missing required maintenance status option --${key}`);
  }
  values['artifact-prefix'] ||= 'redactwall/cloudformation';
  if (!deployer.PATTERNS.stackName.test(values['stack-name']) || !deployer.PATTERNS.region.test(values.region)
    || !/^[a-f0-9]{32}$/.test(values['maintenance-id'])
    || !deployer.PATTERNS.digest.test(values['latch-sha256'])
    || !/^(?=.{3,63}$)(?!.*\.\.)(?!.*\.-)(?!.*-\.)(?![0-9.]+$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(values['artifact-bucket'])
    || !/^[A-Za-z0-9][A-Za-z0-9!_.*'()/-]{0,255}$/.test(values['artifact-prefix'])) {
    throw new Error('maintenance status identity is invalid');
  }
  const leaseName = deployer.maintenanceLeaseName(values['stack-name']);
  if (!deployer.exactStackId(values['lease-stack-id'], leaseName, values.region)) {
    throw new Error('maintenance status lease StackId is invalid');
  }
  return values;
}

function scopedMaintenanceAuthority(values, dependencies = {}) {
  const accountId = String(dependencies.accountId || activeAccountId());
  const location = dependencies.location || deployer.operationAuthorityLocation(values, accountId);
  const authorityDependencies = dependencies.authorityDependencies || { accountId };
  const authority = dependencies.authority || deployer.readOperationAuthority(location, authorityDependencies);
  const state = authority?.state;
  if (!state || state.holderKind !== 'maintenance'
    || state.leaseStackId !== values['lease-stack-id']
    || state.checkpointSetId !== values['maintenance-id']
    || state.checkpointLatchSha256 !== values['latch-sha256']) {
    throw new Error('maintenance reconciliation authority is missing or outside the exact requested scope');
  }
  const lease = {
    authority,
    authorityDependencies,
    authorityEtag: authority.etag,
    checkpointLatchSha256: state.checkpointLatchSha256,
    checkpointSetId: state.checkpointSetId,
    operationId: state.operationId,
    permittedOperationId: state.permittedOperationId,
    phase: state.phase,
    region: values.region,
    sourceFingerprint: state.sourceFingerprint,
    sourceStackId: state.sourceStackId,
    stackId: state.leaseStackId,
    stackName: deployer.maintenanceLeaseName(values['stack-name']),
  };
  const describe = dependencies.describeLease || ((value) => leaseDescription(value.stackId, value.region));
  assertLeaseReadback(describe(lease), lease);
  return lease;
}

function exactCheckpointMatchesAuthority(checkpoint, lease) {
  assertCheckpoint(checkpoint, true);
  if (checkpoint.setId !== lease.checkpointSetId || checkpoint.latchSha256 !== lease.checkpointLatchSha256) {
    throw new Error('maintenance host checkpoint does not match the external cutover authority');
  }
  return checkpoint;
}

function candidateParameterMap(candidate) {
  return Object.fromEntries((candidate?.stack?.Parameters || []).map((entry) => [entry.ParameterKey, entry.ParameterValue]));
}

function assertCandidateMatchesCutover(candidate, intent, region, verifyOperation = deployer.assertStackOperationToken) {
  if (!candidate.exists || !deployer.exactStackId(candidate.stackId, intent.candidateStackName, region)
    || candidate.stackName !== intent.candidateStackName
    || candidate.tags?.RedactWallDeploymentOperation !== intent.candidateClientToken) {
    throw new Error('maintenance candidate does not match the exact create client token and StackId');
  }
  verifyOperation(candidate.stackId, intent.candidateStackName, region, intent.candidateClientToken);
  if (!['CREATE_COMPLETE', 'UPDATE_COMPLETE'].includes(candidate.stackStatus)) {
    return false;
  }
  const parameters = candidateParameterMap(candidate);
  const outputs = candidate.outputs || {};
  if (parameters.ImageUri !== intent.imageUri || parameters.LicenseSecretVersionId !== intent.secretVersionId
    || parameters.TenantId !== intent.tenantId || parameters.DeploymentId !== intent.deploymentId
    || String(parameters.RecoverySetId || 'none') !== intent.recoverySetId
    || sha256(String(parameters.SecretArn || '')) !== intent.secretArnSha256
    || outputs.DesiredConfigSha256 !== intent.configSha256
    || outputs.DeploymentTemplateSha256 !== intent.templateSha256
    || outputs.DeploymentProtocolSha256 !== intent.protocolSha256
    || outputs.LicenseSecretVersionId !== intent.secretVersionId
    || outputs.DeploymentId !== intent.deploymentId
    || !/^i-[a-f0-9]{8,17}$/.test(String(outputs.InstanceId || ''))) {
    throw new Error('maintenance candidate parameters or outputs do not match the durable create intent');
  }
  return true;
}

function reconciliationResult(lease, action, extra = {}, io = console) {
  const state = lease.authority.state;
  const result = {
    action,
    authorityBodySha256: lease.authority.bodySha256,
    authorityGeneration: state.generation,
    candidate: state.candidate,
    checkpointSetId: state.checkpointSetId,
    leaseStackId: state.leaseStackId,
    ok: true,
    operationId: state.operationId,
    phase: state.phase,
    ...extra,
  };
  io.log(JSON.stringify(result));
  return result;
}

function reconcileMaintenanceOperation(values, io = console, dependencies = {}) {
  let lease = scopedMaintenanceAuthority(values, dependencies);
  const stateOf = dependencies.stackState || deployer.stackState;
  const statusOf = dependencies.maintenanceStatus || maintenanceStatus;
  const registrationOf = dependencies.targetRegistration || targetRegistration;
  const send = dependencies.sendCommand || deployer.sendCommand;
  const wait = dependencies.waitForHostReadiness || deployer.waitForHostReadiness;
  const remove = dependencies.deleteApplicationStack || deleteApplicationStack;
  const leaseDependencies = dependencies.leaseDependencies || {};
  let state = lease.authority.state;
  let intent = state.cutoverIntent;
  if (!intent || !state.targetRegistration || intent.candidateClientToken !== state.permittedOperationId) {
    throw new Error('maintenance reconciliation lacks an exact target and cutover intent');
  }
  const source = stateOf(state.sourceStackId, values.region);
  if (state.phase === 'preparing') {
    if (!source.exists || source.stackId !== state.sourceStackId || intent.stage !== 'drain') {
      throw new Error('maintenance preparing reconciliation cannot prove the exact source stack');
    }
    const outputs = source.outputs || {};
    if (outputs.InstanceId !== state.targetRegistration.instanceId
      || outputs.TargetGroupArn !== state.targetRegistration.targetGroupArn) {
      throw new Error('maintenance preparing source outputs changed from the durable target intent');
    }
    const host = exactCheckpointMatchesAuthority(statusOf(outputs.InstanceId, values.region, 300), lease);
    const currentTarget = registrationOf(outputs.TargetGroupArn, outputs.InstanceId, values.region);
    if (currentTarget.registered) {
      return reconciliationResult(lease, 'preparing_source_still_registered', { hostPhase: host.phase }, io);
    }
    const checkpoint = host.phase === 'stopped' ? assertCheckpoint(host) : parseMaintenanceStatus(send(
      outputs.InstanceId, values.region,
      `/usr/local/sbin/redactwall-maintenance-checkpoint ${host.setId} ${host.latchSha256}`,
      300, 'RedactWall checked maintenance checkpoint reconciliation',
    ).output, false);
    if (checkpoint.setId !== host.setId) throw new Error('maintenance checkpoint reconciliation changed operation identity');
    lease = transitionMaintenanceLease(lease, 'drained', leaseDependencies, state.permittedOperationId, checkpoint);
    return reconciliationResult(lease, 'checkpoint_adopted', {}, io);
  }
  if (state.phase === 'drained') {
    if (!source.exists || source.stackId !== state.sourceStackId
      || !['drain', 'source_delete'].includes(intent.stage)) {
      throw new Error('maintenance drained reconciliation cannot prove the exact source stack and intent');
    }
    const outputs = source.outputs || {};
    const checkpoint = exactCheckpointMatchesAuthority(statusOf(
      state.targetRegistration.instanceId, values.region, 300,
    ), lease);
    assertCheckpoint(checkpoint);
    if (registrationOf(state.targetRegistration.targetGroupArn,
      state.targetRegistration.instanceId, values.region).registered) {
      throw new Error('maintenance drained reconciliation found the source target registered');
    }
    if (intent.stage === 'drain') {
      lease = recordMaintenanceCutover(lease, {
        candidateClientToken: intent.candidateClientToken,
        checkpoint,
        stage: 'source_delete',
      }, leaseDependencies);
      state = lease.authority.state;
      intent = state.cutoverIntent;
    }
    if (outputs.InstanceId && outputs.InstanceId !== state.targetRegistration.instanceId) {
      throw new Error('maintenance drained source instance changed from the durable target intent');
    }
    remove(state.sourceStackId, values.region);
    if (stateOf(state.sourceStackId, values.region).exists) {
      throw new Error('maintenance source deletion did not reach exact absence');
    }
    lease = transitionMaintenanceLease(lease, 'source_deleted', leaseDependencies,
      intent.candidateClientToken, checkpoint);
    return reconciliationResult(lease, 'source_deleted_adopted', {}, io);
  }
  if (!['source_deleted', 'candidate'].includes(state.phase)) {
    throw new Error(`maintenance phase ${state.phase} has no checked cutover reconciliation`);
  }
  if (source.exists) throw new Error('maintenance candidate reconciliation found the exact source stack still present');
  if (intent.stage !== 'candidate_create') {
    return reconciliationResult(lease, 'candidate_create_required', {}, io);
  }
  const candidateState = stateOf(intent.candidateStackName, values.region);
  if (!candidateState.exists) return reconciliationResult(lease, 'candidate_create_required', {}, io);
  if (!assertCandidateMatchesCutover(candidateState, intent, values.region, dependencies.verifyCandidateOperation)) {
    return reconciliationResult(lease, 'candidate_create_pending', { candidateStackId: candidateState.stackId }, io);
  }
  if (!state.candidate) {
    lease = recordCandidateAuthority(lease, {
      configSha256: intent.configSha256,
      imageUri: intent.imageUri,
      operationId: intent.candidateClientToken,
      protocolSha256: intent.protocolSha256,
      recoverySetId: intent.recoverySetId,
      secretVersionId: intent.secretVersionId,
      stackId: candidateState.stackId,
      stage: 'owned',
      templateSha256: intent.templateSha256,
    }, leaseDependencies);
    state = lease.authority.state;
  }
  if (state.candidate.stage === 'attested') {
    return reconciliationResult(lease, 'candidate_attested', { candidateStackId: state.candidate.stackId }, io);
  }
  if (dependencies.attestCandidate === false) {
    return reconciliationResult(lease, 'candidate_owned', { candidateStackId: state.candidate.stackId }, io);
  }
  const instanceId = candidateState.outputs.InstanceId;
  wait(instanceId, values.region, '/usr/local/sbin/redactwall-assert-applied', 300);
  const invocation = send(instanceId, values.region, [
    '/usr/local/sbin/redactwall-assert-applied', '--image-uri', intent.imageUri,
    '--secret-version-id', intent.secretVersionId, '--config-sha256', intent.configSha256,
    '--template-sha256', intent.templateSha256, '--protocol-sha256', intent.protocolSha256,
    '--recovery-set-id', intent.recoverySetId,
  ].join(' '), 300, 'RedactWall checked candidate attestation reconciliation');
  const parameters = candidateParameterMap(candidateState);
  const attestation = deployer.parseAppliedAttestation(invocation.output, {
    configSha256: intent.configSha256,
    deploymentId: intent.deploymentId,
    imageUri: intent.imageUri,
    protocolSha256: intent.protocolSha256,
    recoverySetId: intent.recoverySetId,
    secretArn: parameters.SecretArn,
    secretVersionId: intent.secretVersionId,
    stackId: candidateState.stackId,
    templateSha256: intent.templateSha256,
    tenantId: intent.tenantId,
  }, true);
  lease = recordCandidateAuthority(lease, {
    ...state.candidate, ...attestation, instanceId, stage: 'attested',
  }, leaseDependencies);
  return reconciliationResult(lease, 'candidate_attested', { candidateStackId: candidateState.stackId }, io);
}

function checkedMaintenanceStatus(values, io = console) {
  const details = leaseDescription(values['lease-stack-id'], values.region);
  const tags = details.tags;
  const mirrored = {
    operationId: String(tags.RedactWallMaintenanceOperation || ''),
    stackId: values['lease-stack-id'],
    stackName: deployer.maintenanceLeaseName(values['stack-name']),
    region: values.region,
    sourceStackId: String(tags.RedactWallSourceStackId || ''),
    sourceFingerprint: String(tags.RedactWallSourceFingerprint || ''),
    phase: String(tags.RedactWallMaintenancePhase || ''),
    permittedOperationId: String(tags.RedactWallPermittedOperation || ''),
    checkpointSetId: String(tags.RedactWallMaintenanceSet || ''),
    checkpointLatchSha256: String(tags.RedactWallMaintenanceLatchSha256 || ''),
  };
  const accountId = activeAccountId();
  const location = deployer.operationAuthorityLocation(values, accountId);
  const authority = deployer.readS3OperationAuthority(location);
  if (!authority || authority.state.holderKind !== 'maintenance'
    || authority.state.leaseStackId !== values['lease-stack-id']
    || authority.state.operationId !== mirrored.operationId
    || authority.state.sourceStackId !== mirrored.sourceStackId
    || authority.state.sourceFingerprint !== mirrored.sourceFingerprint
    || authority.state.checkpointSetId !== values['maintenance-id']
    || authority.state.checkpointLatchSha256 !== values['latch-sha256']) {
    throw new Error('maintenance status lease binding is invalid or does not match the requested checkpoint');
  }
  const lease = {
    ...mirrored,
    authority,
    authorityEtag: authority.etag,
    checkpointLatchSha256: authority.state.checkpointLatchSha256,
    checkpointSetId: authority.state.checkpointSetId,
    permittedOperationId: authority.state.permittedOperationId,
    phase: authority.state.phase,
  };
  let leaseMirrorMatches = true;
  try { assertLeaseReadback(details, lease); } catch { leaseMirrorMatches = false; }
  const source = deployer.stackState(lease.sourceStackId, values.region);
  let host = null;
  if (source.exists) {
    if (source.stackId !== lease.sourceStackId) throw new Error('maintenance source stack identity changed');
    const outputs = deployer.stackOutputs(lease.sourceStackId, values.region);
    if (!/^i-[a-f0-9]{8,17}$/.test(String(outputs.InstanceId || ''))) {
      throw new Error('maintenance source stack no longer publishes one exact instance');
    }
    host = maintenanceStatus(outputs.InstanceId, values.region, 300);
    if (host.setId !== lease.checkpointSetId || host.latchSha256 !== lease.checkpointLatchSha256) {
      throw new Error('maintenance host checkpoint does not match the external lease');
    }
  }
  let candidatePresent = false;
  if (authority.state.candidate) {
    const candidateState = deployer.stackState(authority.state.candidate.stackId, values.region);
    candidatePresent = candidateState.exists && candidateState.stackId === authority.state.candidate.stackId;
  }
  const recoveryCommand = `node scripts/aws-silo-maintenance.js --mode status --stack-name ${values['stack-name']}`
    + ` --region ${values.region} --lease-stack-id ${lease.stackId}`
    + ` --maintenance-id ${lease.checkpointSetId} --latch-sha256 ${lease.checkpointLatchSha256}`
    + ` --artifact-bucket ${values['artifact-bucket']} --artifact-prefix ${values['artifact-prefix']}`;
  const reconcileReleaseCommand = authority.state.candidate?.stage === 'attested' && candidatePresent
    && ['candidate', 'release_ready', 'releasing'].includes(authority.state.phase)
    ? recoveryCommand.replace('--mode status', '--mode reconcile-release') : null;
  const reconcileCommand = ['preparing', 'drained', 'source_deleted', 'candidate'].includes(authority.state.phase)
    ? recoveryCommand.replace('--mode status', '--mode reconcile') : null;
  const result = {
    ok: true,
    leaseStackId: lease.stackId,
    operationId: lease.operationId,
    phase: lease.phase,
    sourceStackId: lease.sourceStackId,
    sourcePresent: source.exists,
    maintenanceId: lease.checkpointSetId,
    latchSha256: lease.checkpointLatchSha256,
    hostPhase: host?.phase || null,
    authorityBodySha256: authority.bodySha256,
    authorityGeneration: authority.state.generation,
    authorityVersionId: authority.versionId,
    candidate: authority.state.candidate,
    candidatePresent,
    leaseMirrorMatches,
    reconcileCommand,
    reconcileReleaseCommand,
    recoveryCommand,
  };
  io.log(JSON.stringify(result));
  return result;
}

function reconcileMaintenanceRelease(values, io = console) {
  const accountId = activeAccountId();
  const location = deployer.operationAuthorityLocation(values, accountId);
  const authority = deployer.readS3OperationAuthority(location);
  const state = authority?.state;
  if (!state || state.holderKind !== 'maintenance' || state.leaseStackId !== values['lease-stack-id']
    || state.checkpointSetId !== values['maintenance-id']
    || state.checkpointLatchSha256 !== values['latch-sha256']
    || !['candidate', 'release_ready', 'releasing'].includes(state.phase)
    || state.candidate?.stage !== 'attested') {
    throw new Error('maintenance release reconciliation is not authorized by the exact attested candidate state');
  }
  const candidate = deployer.stackState(state.candidate.stackId, values.region);
  const intent = state.cutoverIntent;
  let candidateMatches = false;
  try {
    candidateMatches = !!intent && intent.stage === 'candidate_create'
      && assertCandidateMatchesCutover(candidate, intent, values.region);
  } catch {
    candidateMatches = false;
  }
  if (!candidateMatches || candidate.stackId !== state.candidate.stackId
    || candidate.outputs.InstanceId !== state.candidate.instanceId) {
    throw new Error('maintenance release reconciliation cannot prove the exact attested candidate stack');
  }
  deployer.waitForHostReadiness(state.candidate.instanceId, values.region,
    '/usr/local/sbin/redactwall-assert-applied', 300);
  const invocation = deployer.sendCommand(state.candidate.instanceId, values.region, [
    '/usr/local/sbin/redactwall-assert-applied', '--image-uri', state.candidate.imageUri,
    '--secret-version-id', state.candidate.secretVersionId,
    '--config-sha256', state.candidate.configSha256,
    '--template-sha256', state.candidate.templateSha256,
    '--protocol-sha256', state.candidate.protocolSha256,
    '--recovery-set-id', state.candidate.recoverySetId,
  ].join(' '), 300, 'RedactWall candidate release reconciliation');
  const parameters = candidateParameterMap(candidate);
  const observed = deployer.parseAppliedAttestation(invocation.output, {
    configSha256: state.candidate.configSha256,
    deploymentId: intent.deploymentId,
    imageUri: state.candidate.imageUri,
    protocolSha256: state.candidate.protocolSha256,
    recoverySetId: state.candidate.recoverySetId,
    secretArn: parameters.SecretArn,
    secretVersionId: state.candidate.secretVersionId,
    stackId: state.candidate.stackId,
    templateSha256: state.candidate.templateSha256,
    tenantId: intent.tenantId,
  }, true);
  if (observed.containerId !== state.candidate.containerId
    || observed.appliedStateSha256 !== state.candidate.appliedStateSha256
    || observed.authorityFingerprintSha256 !== state.candidate.authorityFingerprintSha256
    || observed.attestedAt !== state.candidate.attestedAt
    || observed.recoverySetId !== state.candidate.recoverySetId) {
    throw new Error('maintenance release reconciliation observed changed applied authority evidence');
  }
  let lease = {
    authority,
    authorityDependencies: { accountId },
    authorityEtag: authority.etag,
    checkpointLatchSha256: state.checkpointLatchSha256,
    checkpointSetId: state.checkpointSetId,
    operationId: state.operationId,
    permittedOperationId: state.permittedOperationId,
    phase: state.phase,
    region: values.region,
    sourceFingerprint: state.sourceFingerprint,
    sourceStackId: state.sourceStackId,
    stackId: state.leaseStackId,
    stackName: deployer.maintenanceLeaseName(values['stack-name']),
  };
  lease = releaseVerifiedLease(lease);
  const result = {
    authorityBodySha256: lease.authority.bodySha256,
    authorityGeneration: lease.authority.state.generation,
    authorityVersionId: lease.authority.versionId,
    candidateStackId: state.candidate.stackId,
    ok: true,
    phase: lease.phase,
  };
  io.log(JSON.stringify(result));
  return result;
}

function main(argv = process.argv.slice(2)) {
  try {
    if (argv[0] !== '--mode' || !argv[1]) {
      throw new Error('usage: silo:maintenance --mode <replace-instance|restore-volume> <all silo:deploy options>');
    }
    const mode = argv[1];
    if (mode === 'status' || mode === 'reconcile' || mode === 'reconcile-release') {
      const values = parseStatusArgs(argv.slice(2));
      if (mode === 'status') checkedMaintenanceStatus(values);
      else if (mode === 'reconcile') reconcileMaintenanceOperation(values);
      else reconcileMaintenanceRelease(values);
      return;
    }
    const values = deployer.validate(deployer.parseArgs(argv.slice(2)));
    maintain(mode, values);
  } catch (error) {
    const rollback = error.rollback?.ok ? `; prior silo restored on ${error.rollback.dataVolumeId}` : '';
    console.error(`[silo-maintenance] ${error.message}${rollback}`);
    process.exitCode = 1;
  }
}

if (require.main === module) main();

module.exports = {
  abortSource,
  acquireMaintenanceLease,
  assertLeasePhase,
  assertMaintenanceDelta,
  assertStableSourceStack,
  assertUnchangedSourceStack,
  candidateRecoveryStatus,
  checkedMaintenanceStatus,
  deleteApplicationStack,
  drainAndDeregister,
  maintain,
  maintenanceStatus,
  outputMap,
  parseMaintenanceStatus,
  parseStatusArgs,
  recordCandidateAuthority,
  recordMaintenanceCutover,
  reconcileMaintenanceRelease,
  reconcileMaintenanceOperation,
  retainedEvidenceError,
  releaseMaintenanceLease,
  removeFailedStackIfOwned,
  resumeSource,
  sourceFingerprint,
  sourceStackContract,
  stackDescription,
  targetRegistration,
  valuesFromStack,
  transitionMaintenanceLease,
};
