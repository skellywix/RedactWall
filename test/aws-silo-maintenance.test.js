'use strict';

const test = require('node:test');
const assert = require('node:assert');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const maintenance = require('../scripts/aws-silo-maintenance');
const deployer = require('../scripts/aws-silo-deploy');

const root = path.join(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'scripts', 'aws-silo-maintenance.js'), 'utf8');
const template = fs.readFileSync(path.join(root, 'infra', 'aws', 'customer-silo.yml'), 'utf8');

const base = {
  'vpc-id': 'vpc-1', 'public-subnet-ids': 'subnet-a,subnet-b', 'instance-subnet-id': 'subnet-a',
  'instance-availability-zone': 'us-east-1a', 'data-volume-id': 'vol-old', 'data-stack-name': 'data-old',
  'source-data-volume-id': '', 'ami-id': 'ami-old', 'instance-type': 't3.small', 'root-volume-gb': '20',
  'image-uri': 'image', 'secret-arn': 'secret', 'secret-version-id': 'version',
  'tenant-id': 'cu-test', 'deployment-id': 'dep_0123456789abcdef0123456789abcdef',
  'certificate-arn': 'cert', 'public-hostname': 'cu.example',
};

function memoryAuthorityDependencies() {
  let current = null;
  let sequence = 0;
  const publish = (location, state) => {
    sequence += 1;
    current = {
      bodySha256: crypto.createHash('sha256').update(JSON.stringify(state)).digest('hex'),
      etag: `"${sequence.toString(16).padStart(32, '0')}"`,
      location,
      state: structuredClone(state),
      versionId: `version-${sequence}`,
    };
    return structuredClone(current);
  };
  return {
    skipPreflight: true,
    authority: {
      read: () => current == null ? null : structuredClone(current),
      create: (location, state) => {
        if (current != null) throw Object.assign(new Error('precondition failed'), { code: 'PreconditionFailed' });
        return publish(location, state);
      },
      compareAndSwap: (location, etag, state) => {
        if (current?.etag !== etag) throw Object.assign(new Error('precondition failed'), { code: 'PreconditionFailed' });
        return publish(location, state);
      },
    },
  };
}

function leaseAwsResult(args, state) {
  if (args[0] === 'elbv2' && args[1] === 'describe-target-health') {
    const target = String(args[args.indexOf('--targets') + 1] || '').replace(/^Id=/, '');
    return JSON.stringify({ TargetHealthDescriptions: [{
      Target: { Id: target }, TargetHealth: { State: 'healthy' },
    }] });
  }
  if (args[0] !== 'cloudformation') return null;
  if (args[1] === 'create-stack' && String(args[args.indexOf('--stack-name') + 1]).startsWith('rw-maintenance-')) {
    state.stackName = args[args.indexOf('--stack-name') + 1];
    state.stackId = `arn:aws:cloudformation:us-east-1:123456789012:stack/${state.stackName}/12345678-1234-1234-1234-123456789012`;
    state.tags = args.slice(args.indexOf('--tags') + 1, args.indexOf('--region'))
      .map((entry) => entry.match(/^Key=([^,]+),Value=(.+)$/))
      .map((match) => ({ Key: match[1], Value: match[2] }));
    return JSON.stringify({ StackId: state.stackId });
  }
  if (args[1] === 'describe-stacks' && [state.stackId, state.stackName]
    .includes(args[args.indexOf('--stack-name') + 1])) {
    return JSON.stringify({ Stacks: [{ StackId: state.stackId, StackName: state.stackName,
      StackStatus: 'CREATE_COMPLETE', Tags: state.tags }] });
  }
  if (args[1] === 'update-stack' && args[args.indexOf('--stack-name') + 1] === state.stackId) {
    state.tags = args.slice(args.indexOf('--tags') + 1, args.indexOf('--region'))
      .map((entry) => entry.match(/^Key=([^,]+),Value=(.+)$/))
      .map((match) => ({ Key: match[1], Value: match[2] }));
    return JSON.stringify({ StackId: state.stackId });
  }
  if (state.stackId && args[args.indexOf('--stack-name') + 1] === state.stackId
    && ['wait', 'delete-stack'].includes(args[1])) return '{}';
  return null;
}

test('maintenance deltas freeze tenant and unrelated runtime parameters', () => {
  assert.doesNotThrow(() => maintenance.assertMaintenanceDelta('replace-instance', base, { ...base, 'ami-id': 'ami-new' }));
  assert.doesNotThrow(() => maintenance.assertMaintenanceDelta('restore-volume', base, {
    ...base, 'data-volume-id': 'vol-new', 'data-stack-name': 'data-new', 'source-data-volume-id': 'vol-old',
  }));
  assert.throws(() => maintenance.assertMaintenanceDelta('replace-instance', base, { ...base, 'tenant-id': 'other' }), /TenantId/);
  assert.throws(() => maintenance.assertMaintenanceDelta('replace-instance', base, {
    ...base, 'deployment-id': 'dep_fedcba9876543210fedcba9876543210',
  }), /DeploymentId/);
  assert.throws(() => maintenance.assertMaintenanceDelta('restore-volume', base, { ...base, 'data-volume-id': 'vol-new' }), /lineage/);
});

test('maintenance accepts only a stable complete exact source stack and rejects drift before deletion', () => {
  const stack = {
    StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012',
    StackName: 'redactwall-cu-test',
    StackStatus: 'UPDATE_COMPLETE',
    RedactWallTemplateSha256: 'a'.repeat(64),
    Parameters: [{ ParameterKey: 'TenantId', ParameterValue: 'cu-test' }],
    Outputs: [{ OutputKey: 'InstanceId', OutputValue: 'i-0123456789abcdef0' }],
  };
  assert.doesNotThrow(() => maintenance.assertStableSourceStack(stack, 'redactwall-cu-test', 'us-east-1'));
  assert.throws(() => maintenance.assertStableSourceStack({ ...stack, StackStatus: 'UPDATE_IN_PROGRESS' }, 'redactwall-cu-test', 'us-east-1'), /stable complete/);
  assert.throws(() => maintenance.assertStableSourceStack({ ...stack, StackStatus: 'UPDATE_FAILED' }, 'redactwall-cu-test', 'us-east-1'), /stable complete/);
  assert.throws(() => maintenance.assertStableSourceStack({ ...stack, StackId: stack.StackId.replace('us-east-1', 'us-west-2') }, 'redactwall-cu-test', 'us-east-1'), /exact source stack identity/);
  assert.doesNotThrow(() => maintenance.assertUnchangedSourceStack(stack, structuredClone(stack)));
  assert.throws(() => maintenance.assertUnchangedSourceStack(stack, {
    ...stack,
    Outputs: [{ OutputKey: 'InstanceId', OutputValue: 'i-1123456789abcdef0' }],
  }), /changed after the maintenance checkpoint/);
  for (const changed of [
    { LastUpdatedTime: '2026-07-13T20:00:00.000Z' },
    { RoleARN: 'arn:aws:iam::123456789012:role/changed' },
    { RedactWallTemplateSha256: 'b'.repeat(64) },
  ]) {
    assert.throws(() => maintenance.assertUnchangedSourceStack(
      { ...stack, LastUpdatedTime: '2026-07-13T19:00:00.000Z', RoleARN: 'arn:aws:iam::123456789012:role/source', RedactWallTemplateSha256: 'a'.repeat(64) },
      { ...stack, LastUpdatedTime: '2026-07-13T19:00:00.000Z', RoleARN: 'arn:aws:iam::123456789012:role/source', RedactWallTemplateSha256: 'a'.repeat(64), ...changed },
    ), /changed after the maintenance checkpoint/);
  }
});

test('maintenance host lock and durable latch close every stale-checkpoint interleaving', () => {
  const deployment = fs.readFileSync(path.join(root, 'infra', 'aws', 'scripts', 'redactwall-deploy.sh'), 'utf8');
  const controlStart = template.indexOf('/usr/local/sbin/redactwall-maintenance-control:');
  const controlEnd = template.indexOf('/usr/local/sbin/redactwall-maintenance-drain:', controlStart);
  const control = template.slice(controlStart, controlEnd);
  assert.ok(controlStart >= 0 && controlEnd > controlStart, 'the maintenance control script is packaged');
  assert.match(control, /exec 9>"\$DEPLOY_LOCK"[\s\S]*flock -w 30 9/);

  const preparing = control.indexOf('write_latch "preparing"');
  const drained = control.indexOf('write_latch "drained"', preparing);
  const stop = control.indexOf('docker stop -t 30 "$container_id"', drained);
  const stopped = control.indexOf('write_latch "stopped"', stop);
  const backup = control.indexOf('backup-store.js create', stopped);
  const retainedVerify = control.indexOf('scripts/backup-store.js verify --file "/recovery/', backup);
  const finalStopped = control.indexOf('write_latch "stopped" "$maintenance_id" "$backup_name"', retainedVerify);
  assert.ok(preparing >= 0 && preparing < drained && drained < stop && stop < stopped
    && stopped < backup && backup < retainedVerify && retainedVerify < finalStopped,
  'traffic-drained intent and exact stopped writer are durable before the final backup and complete checkpoint');
  assert.doesNotMatch(control.slice(0, control.indexOf('case "$operation" in')), /rm -f -- "\$MAINTENANCE_LATCH"/,
    'failure paths retain the latch and recovery evidence');

  const lock = deployment.indexOf('flock 9');
  const latchRefusal = deployment.indexOf('A maintenance latch is active', lock);
  const firstMutation = deployment.indexOf('DATA_VOLUME_ROOT=', lock);
  assert.ok(lock >= 0 && latchRefusal > lock && latchRefusal < firstMutation,
    'ordinary deploy refuses the latch under the same host lock before mutation');
  assert.match(template, /redactwall-cfn-update:[\s\S]*flock -w 30 9[\s\S]*A maintenance latch is active[\s\S]*cfn-init/,
    'cfn-hup checks the latch while holding the same lock around cfn-init');
  assert.match(template, /REDACTWALL_DEPLOY_LOCK_HELD=1 \/opt\/aws\/bin\/cfn-init/);
  assert.match(deployment, /printenv REDACTWALL_DEPLOY_LOCK_HELD[\s\S]*else[\s\S]*flock 9/,
    'nested cfn-init keeps the parent lock without reacquiring and deadlocking it');
  assert.match(template, /redactwall-maintenance-clear:[\s\S]*exec .*maintenance-control clear/);
  assert.match(template, /redactwall-maintenance-status:[\s\S]*exec .*maintenance-control status/);
  assert.match(template, /redactwall-maintenance-abort:[\s\S]*exec .*maintenance-control abort/);
  assert.match(control, /resume\)[\s\S]*\[ "\$latch_phase" != preparing \]/,
    'resume cannot reinterpret a partially prepared operation as a durable checkpoint');
  assert.match(control, /abort\)[\s\S]*preparing\|drained\|stopped/,
    'abort is phase-aware from the first durable latch through the exact writer stop');
  assert.match(control, /partial_count=.*find "\$retained_root"[\s\S]*\[ "\$partial_count" -le 8 \][\s\S]*stat -c '%u:%g:%a:%h'/,
    'crash-partial recovery artifacts stay bounded and regular under the identity-bound retained root');
  assert.match(control, /resume\)[\s\S]*sha256sum "\$MAINTENANCE_LATCH"[\s\S]*write_latch "resumed"[\s\S]*print_status/);
  assert.match(control, /clear\)[\s\S]*resumed\|resumed-partial[\s\S]*assert_live_state[\s\S]*expected_latch_identity[\s\S]*rm -- "\$MAINTENANCE_LATCH"/);
  assert.match(control, /RETAINED_PARENT=\/var\/lib\/redactwall\/runtime\/maintenance-recovery/,
    'maintenance evidence is retained on the data volume across application-stack deletion');
});

test('maintenance creates an external lease before source drain and keeps it through source deletion', () => {
  const acquire = source.indexOf('acquireMaintenanceLease(');
  const drain = source.indexOf('drainAndDeregister(sourceOutputs', acquire);
  const remove = source.indexOf('deleteApplicationStack(sourceStack.StackId', drain);
  const release = source.indexOf('releaseVerifiedLease(', remove);
  assert.ok(acquire >= 0 && acquire < drain && drain < remove && release > remove);
  assert.match(source, /cloudformation', 'create-stack'[\s\S]*--client-request-token/);
  assert.match(source, /RedactWallMaintenanceOperation/);
  assert.match(source, /deleteApplicationStack\)|deleteApplicationStack\(releasing\.stackId/,
    'lease cleanup is bound to the exact independently returned lease StackId');
  const beforeDelete = source.indexOf('deleteApplicationStack(sourceStack.StackId');
  assert.ok(source.lastIndexOf('assertLeasePhase(lease', beforeDelete) >= 0,
    'the external lease is read back at its exact phase immediately before destructive deletion');
});

test('maintenance acquisition binds the exact returned lease StackId into the external authority', (t) => {
  const original = deployer.runAws;
  const cloudFormation = {};
  t.after(() => { deployer.runAws = original; });
  deployer.runAws = (args) => {
    const result = leaseAwsResult(args, cloudFormation);
    if (result != null) return result;
    throw new Error(`unexpected AWS mock call: ${args.join(' ')}`);
  };
  const sourceStack = {
    StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/11111111-1111-1111-1111-111111111111',
    StackName: 'redactwall-cu-test', StackStatus: 'UPDATE_COMPLETE', RedactWallTemplateSha256: 'a'.repeat(64),
    Parameters: [], Outputs: [], Tags: [],
  };
  const authorityDependencies = memoryAuthorityDependencies();
  const lease = maintenance.acquireMaintenanceLease(sourceStack, 'us-east-1', {
    accountId: '123456789012', authorityDependencies,
    values: {
      'artifact-bucket': 'redactwall-cfn-123456789012-us-east-1',
      'artifact-prefix': 'redactwall/cloudformation', 'stack-name': 'redactwall-cu-test', region: 'us-east-1',
    },
  });
  assert.strictEqual(lease.authority.state.leaseStackId, lease.stackId);
  assert.strictEqual(lease.authority.state.sourceStackId, sourceStack.StackId);
  assert.strictEqual(lease.authority.state.generation, 2);
  const tags = Object.fromEntries(cloudFormation.tags.map((entry) => [entry.Key, entry.Value]));
  assert.strictEqual(tags.RedactWallAuthorityBodySha256, lease.authority.bodySha256);
  assert.strictEqual(tags.RedactWallAuthorityGeneration, '2');
});

test('maintenance lease creation response loss resumes from deterministic external intent after restart', (t) => {
  const original = deployer.runAws;
  const cloudFormation = {};
  let createCalls = 0;
  let loseFirstReconciliation = true;
  t.after(() => { deployer.runAws = original; });
  deployer.runAws = (args) => {
    if (args[0] === 'cloudformation' && args[1] === 'create-stack') {
      createCalls += 1;
      if (createCalls === 1) {
        leaseAwsResult(args, cloudFormation);
        const error = new Error('lease create response lost');
        error.cause = Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });
        throw error;
      }
      const error = new Error('lease already exists after restart');
      error.stderr = 'AlreadyExistsException';
      throw error;
    }
    const result = leaseAwsResult(args, cloudFormation);
    if (result != null) return result;
    throw new Error(`unexpected AWS mock call: ${args.join(' ')}`);
  };
  const sourceStack = {
    StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/11111111-1111-1111-1111-111111111111',
    StackName: 'redactwall-cu-test', StackStatus: 'UPDATE_COMPLETE', RedactWallTemplateSha256: 'a'.repeat(64),
    Parameters: [], Outputs: [], Tags: [],
  };
  const authorityDependencies = memoryAuthorityDependencies();
  let operationTokenProofs = 0;
  const options = {
    accountId: '123456789012', authorityDependencies,
    operationId: `rw-${'f'.repeat(32)}`,
    verifyLeaseCreation: (stackId, stackName, region, token) => {
      assert.strictEqual(stackId, cloudFormation.stackId);
      assert.strictEqual(stackName, cloudFormation.stackName);
      assert.strictEqual(region, 'us-east-1');
      assert.strictEqual(token, `rw-${'f'.repeat(32)}`);
      operationTokenProofs += 1;
    },
    describeLeaseCreation: () => {
      if (loseFirstReconciliation) {
        loseFirstReconciliation = false;
        throw new Error('lease readback response also lost');
      }
      return {
        exists: true,
        stackId: cloudFormation.stackId,
        stackName: cloudFormation.stackName,
        stackStatus: 'CREATE_IN_PROGRESS',
        tags: Object.fromEntries(cloudFormation.tags.map((entry) => [entry.Key, entry.Value])),
      };
    },
    values: {
      'artifact-bucket': 'redactwall-cfn-123456789012-us-east-1',
      'artifact-prefix': 'redactwall/cloudformation', 'stack-name': 'redactwall-cu-test', region: 'us-east-1',
    },
  };
  let interrupted;
  try { maintenance.acquireMaintenanceLease(sourceStack, 'us-east-1', options); }
  catch (error) { interrupted = error; }
  assert.match(interrupted?.message || '', /lease create response lost/);
  assert.strictEqual(interrupted.maintenanceLease.authority.state.phase, 'lease_creating');
  assert.strictEqual(interrupted.maintenanceLease.stackId, 'none');
  const lease = maintenance.acquireMaintenanceLease(sourceStack, 'us-east-1', options);
  assert.strictEqual(lease.operationId, options.operationId);
  assert.strictEqual(lease.stackId, cloudFormation.stackId);
  assert.strictEqual(lease.authority.state.phase, 'acquired');
  assert.strictEqual(lease.authority.state.leaseClientToken, options.operationId);
  assert.strictEqual(lease.authority.state.leaseStackName, cloudFormation.stackName);
  assert.strictEqual(createCalls, 2);
  assert.strictEqual(operationTokenProofs, 1);
});

test('maintenance lease coordinator authenticates every monotonic phase transition', () => {
  const lease = {
    operationId: `rw-${'a'.repeat(32)}`,
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/rw-maintenance-test/12345678-1234-1234-1234-123456789012',
    stackName: 'rw-maintenance-test', region: 'us-east-1', sourceStackId: 'source',
    sourceFingerprint: 'b'.repeat(64), phase: 'acquired', permittedOperationId: 'none',
    checkpointSetId: 'none', checkpointLatchSha256: 'none', authorityEtag: 'etag-1',
  };
  const events = [];
  const transitioned = maintenance.transitionMaintenanceLease(lease, 'preparing', {
    compareAndSwapAuthority: (_prior, next) => ({ ...next, authorityEtag: 'etag-2' }),
    updateLease: (_lease, phase) => events.push(`update:${phase}`),
    describeLease: () => ({
      stackId: lease.stackId,
      stackName: lease.stackName,
      stackStatus: 'CREATE_COMPLETE',
      tags: {
        RedactWallMaintenanceOperation: lease.operationId,
        RedactWallSourceStackId: lease.sourceStackId,
        RedactWallSourceFingerprint: lease.sourceFingerprint,
        RedactWallMaintenancePhase: 'preparing',
        RedactWallPermittedOperation: 'none',
        RedactWallMaintenanceSet: 'none',
        RedactWallMaintenanceLatchSha256: 'none',
        RedactWallAuthorityGeneration: 'none',
        RedactWallAuthorityBodySha256: 'none',
        RedactWallCandidateStateSha256: 'none',
      },
    }),
  });
  assert.strictEqual(transitioned.phase, 'preparing');
  assert.deepStrictEqual(events, ['update:preparing']);
  assert.throws(() => maintenance.transitionMaintenanceLease(transitioned, 'acquired', {
    compareAndSwapAuthority: (_prior, next) => next,
    updateLease() {}, describeLease: () => ({ ...lease, phase: 'acquired' }),
  }), /monotonic/);
});

test('maintenance cutover intent durably binds target health, checkpoint, and candidate client token', () => {
  const stackName = 'redactwall-cu-test';
  const region = 'us-east-1';
  const accountId = '123456789012';
  const operationId = `rw-${'a'.repeat(32)}`;
  const candidateClientToken = `rw-${'b'.repeat(32)}`;
  const sourceStackId = `arn:aws:cloudformation:${region}:${accountId}:stack/${stackName}/11111111-1111-1111-1111-111111111111`;
  const leaseStackName = deployer.maintenanceLeaseName(stackName);
  const leaseStackId = `arn:aws:cloudformation:${region}:${accountId}:stack/${leaseStackName}/22222222-2222-2222-2222-222222222222`;
  const location = {
    accountId, bucket: 'redactwall-cfn-123456789012-us-east-1',
    key: 'redactwall/cloudformation/operation-authority/test.json',
    prefix: 'redactwall/cloudformation', region, stackName,
  };
  const authorityDependencies = memoryAuthorityDependencies();
  let authority = deployer.acquireOperationAuthority(location, 'maintenance', operationId, authorityDependencies, {
    leaseClientToken: operationId,
    leaseStackName,
    phase: 'lease_creating',
    sourceFingerprint: '1'.repeat(64),
    sourceStackId,
  });
  authority = deployer.compareAndSwapOperationAuthority(authority, {
    leaseStackId, phase: 'acquired',
  }, authorityDependencies);
  authority = deployer.compareAndSwapOperationAuthority(authority, { phase: 'preparing' }, authorityDependencies);
  const lease = {
    authority, authorityDependencies, authorityEtag: authority.etag,
    checkpointLatchSha256: 'none', checkpointSetId: 'none', operationId,
    permittedOperationId: 'none', phase: 'preparing', region,
    sourceFingerprint: '1'.repeat(64), sourceStackId, stackId: leaseStackId, stackName: leaseStackName,
  };
  const targetRegistration = {
    instanceId: 'i-0123456789abcdef0', observedAt: '2026-07-13T20:00:00.000Z', registered: true,
    state: 'healthy',
    targetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789',
  };
  const recorded = maintenance.recordMaintenanceCutover(lease, {
    candidateClientToken,
    checkpoint: { setId: '2'.repeat(32), latchSha256: '3'.repeat(64) },
    stage: 'drain', targetRegistration,
  }, {
    updateLease() {},
    describeLease: (value) => ({
      stackId: value.stackId, stackName: value.stackName, stackStatus: 'CREATE_COMPLETE',
      tags: {
        RedactWallAuthorityBodySha256: value.authority.bodySha256,
        RedactWallAuthorityGeneration: String(value.authority.state.generation),
        RedactWallCandidateStateSha256: 'none',
        RedactWallMaintenanceLatchSha256: value.checkpointLatchSha256,
        RedactWallMaintenanceOperation: value.operationId,
        RedactWallMaintenancePhase: value.phase,
        RedactWallMaintenanceSet: value.checkpointSetId,
        RedactWallPermittedOperation: value.permittedOperationId,
        RedactWallSourceFingerprint: value.sourceFingerprint,
        RedactWallSourceStackId: value.sourceStackId,
      },
    }),
  });
  assert.deepStrictEqual(recorded.authority.state.targetRegistration, targetRegistration);
  assert.strictEqual(recorded.authority.state.cutoverIntent.stage, 'drain');
  assert.strictEqual(recorded.authority.state.cutoverIntent.candidateClientToken, candidateClientToken);
  assert.strictEqual(recorded.authority.state.checkpointSetId, '2'.repeat(32));
  assert.throws(() => deployer.validateOperationAuthorityState({
    ...recorded.authority.state,
    targetRegistration: { ...targetRegistration, state: 'draining' },
  }, location), /malformed|out of scope/);
});

test('stale maintenance holders cannot transition or release a newer external CAS state', () => {
  const baseLease = {
    operationId: `rw-${'a'.repeat(32)}`,
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/rw-maintenance-test/12345678-1234-1234-1234-123456789012',
    stackName: 'rw-maintenance-test', region: 'us-east-1', sourceStackId: 'source',
    sourceFingerprint: 'b'.repeat(64), phase: 'acquired', permittedOperationId: 'none',
    checkpointSetId: 'none', checkpointLatchSha256: 'none', authorityEtag: 'etag-1',
  };
  let etag = 'etag-1';
  let state = { phase: 'acquired', operationId: baseLease.operationId };
  let deleted = false;
  const dependencies = {
    compareAndSwapAuthority: (lease, next) => {
      if (lease.authorityEtag !== etag) throw new Error('external authority stale CAS');
      state = { phase: next.phase, operationId: next.operationId };
      etag = `etag-${Number(etag.slice(-1)) + 1}`;
      return { ...next, authorityEtag: etag };
    },
    updateLease() {},
    describeLease: (lease) => ({
      stackId: lease.stackId, stackName: lease.stackName, stackStatus: 'CREATE_COMPLETE',
      tags: {
        RedactWallMaintenanceOperation: lease.operationId,
        RedactWallSourceStackId: lease.sourceStackId,
        RedactWallSourceFingerprint: lease.sourceFingerprint,
        RedactWallMaintenancePhase: lease.phase,
        RedactWallPermittedOperation: lease.permittedOperationId,
        RedactWallMaintenanceSet: lease.checkpointSetId,
        RedactWallMaintenanceLatchSha256: lease.checkpointLatchSha256,
        RedactWallAuthorityGeneration: 'none',
        RedactWallAuthorityBodySha256: 'none',
        RedactWallCandidateStateSha256: 'none',
      },
    }),
    deleteLease: () => { deleted = true; },
  };
  const advanced = maintenance.transitionMaintenanceLease(baseLease, 'preparing', dependencies);
  assert.strictEqual(advanced.authorityEtag, 'etag-2');
  assert.strictEqual(state.phase, 'preparing');
  assert.throws(() => maintenance.transitionMaintenanceLease(baseLease, 'release_ready', dependencies), /stale CAS/);
  assert.throws(() => maintenance.releaseMaintenanceLease({ ...baseLease, phase: 'release_ready' }, dependencies), /stale CAS|external authority/i);
  assert.strictEqual(deleted, false);
  assert.strictEqual(state.phase, 'preparing');
});

test('release resumes after the exact lease was deleted but final authority publication failed', () => {
  const releasing = {
    operationId: `rw-${'a'.repeat(32)}`,
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/rw-maintenance-test/12345678-1234-1234-1234-123456789012',
    stackName: 'rw-maintenance-test', region: 'us-east-1', sourceStackId: 'source',
    sourceFingerprint: 'b'.repeat(64), phase: 'releasing', permittedOperationId: `rw-${'c'.repeat(32)}`,
    checkpointSetId: 'd'.repeat(32), checkpointLatchSha256: 'e'.repeat(64), authorityEtag: 'etag-4',
  };
  let deleted = false;
  let failFinalPublication = true;
  const dependencies = {
    assertCurrentAuthority() {},
    compareAndSwapAuthority: (_prior, next) => {
      if (failFinalPublication) {
        failFinalPublication = false;
        throw new Error('final external CAS response lost');
      }
      return { ...next, authorityEtag: 'etag-5' };
    },
    deleteLease: () => {
      if (deleted) throw new Error('lease stack no longer exists');
      deleted = true;
    },
    leaseAbsent: () => deleted,
  };
  let first;
  try { maintenance.releaseMaintenanceLease(releasing, dependencies); }
  catch (error) { first = error; }
  assert.match(first?.message || '', /final external CAS response lost/);
  assert.strictEqual(first.maintenanceLease.phase, 'releasing');
  assert.strictEqual(deleted, true);
  const resumed = maintenance.releaseMaintenanceLease(first.maintenanceLease, dependencies);
  assert.strictEqual(resumed.phase, 'available');
  assert.strictEqual(resumed.operationId, 'none');
  assert.strictEqual(resumed.authorityEtag, 'etag-5');
});

test('release recognizes the exact available successor after CAS response and readback loss', () => {
  const releasing = {
    operationId: `rw-${'a'.repeat(32)}`,
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/rw-maintenance-test/12345678-1234-1234-1234-123456789012',
    stackName: 'rw-maintenance-test', region: 'us-east-1', sourceStackId: 'source',
    sourceFingerprint: 'b'.repeat(64), phase: 'releasing', permittedOperationId: `rw-${'c'.repeat(32)}`,
    checkpointSetId: 'd'.repeat(32), checkpointLatchSha256: 'e'.repeat(64), authorityEtag: 'etag-4',
  };
  let current = releasing;
  let readbackUnavailable = false;
  const dependencies = {
    assertCurrentAuthority() {},
    readAuthority: () => {
      if (readbackUnavailable) {
        readbackUnavailable = false;
        throw new Error('final CAS readback lost');
      }
      return current;
    },
    compareAndSwapAuthority: (_prior, next) => {
      current = { ...next, authorityEtag: 'etag-5' };
      readbackUnavailable = true;
      throw new Error('final CAS response lost');
    },
    deleteLease() {},
  };
  let interrupted;
  try { maintenance.releaseMaintenanceLease(releasing, dependencies); }
  catch (error) { interrupted = error; }
  assert.match(interrupted?.message || '', /final CAS response lost/);
  assert.strictEqual(interrupted.maintenanceLease.phase, 'releasing');
  const resumed = maintenance.releaseMaintenanceLease(interrupted.maintenanceLease, dependencies);
  assert.strictEqual(resumed.phase, 'available');
  assert.strictEqual(resumed.operationId, 'none');
  assert.strictEqual(resumed.authorityEtag, 'etag-5');
});

test('candidate ownership and attestation survive a crash before final lease release', () => {
  const lease = {
    operationId: `rw-${'a'.repeat(32)}`, phase: 'source_deleted', authorityEtag: 'etag-7',
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/rw-maintenance-test/12345678-1234-1234-1234-123456789012',
    permittedOperationId: `rw-${'b'.repeat(32)}`, checkpointSetId: 'c'.repeat(32),
    checkpointLatchSha256: 'd'.repeat(64),
    region: 'us-east-1',
    sourceStackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/11111111-1111-1111-1111-111111111111',
  };
  const candidate = {
    operationId: lease.permittedOperationId,
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012',
    imageUri: `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`,
    instanceId: 'i-0123456789abcdef0', configSha256: '1'.repeat(64), templateSha256: '2'.repeat(64),
    protocolSha256: '3'.repeat(64), secretVersionId: '12345678-1234-1234-1234-123456789012',
    recoverySetId: lease.checkpointSetId, containerId: '4'.repeat(64),
    appliedStateSha256: '5'.repeat(64), authorityFingerprintSha256: '6'.repeat(64),
    attestedAt: '2026-07-13T20:00:00.000Z', stage: 'attested',
  };
  lease.cutoverIntent = {
    candidateClientToken: candidate.operationId,
    candidateStackName: 'redactwall-cu-test',
    configSha256: candidate.configSha256,
    deploymentId: 'dep_0123456789abcdef0123456789abcdef',
    imageUri: candidate.imageUri,
    protocolSha256: candidate.protocolSha256,
    recoverySetId: candidate.recoverySetId,
    secretArnSha256: crypto.createHash('sha256')
      .update('arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12').digest('hex'),
    secretVersionId: candidate.secretVersionId,
    sourceStackId: lease.sourceStackId,
    stage: 'candidate_create',
    templateSha256: candidate.templateSha256,
    tenantId: 'cu-test',
  };
  let durable;
  const dependencies = {
    compareAndSwapAuthority: (_prior, next) => {
      durable = structuredClone(next);
      return { ...next, authorityEtag: next.candidate.stage === 'owned' ? 'etag-8' : 'etag-9' };
    },
  };
  const owned = maintenance.recordCandidateAuthority(lease, {
    ...candidate, stage: 'owned', instanceId: undefined, containerId: undefined,
    appliedStateSha256: undefined, authorityFingerprintSha256: undefined, attestedAt: undefined,
  }, dependencies);
  assert.strictEqual(owned.authorityEtag, 'etag-8');
  const recorded = maintenance.recordCandidateAuthority(owned, candidate, dependencies);
  assert.strictEqual(recorded.authorityEtag, 'etag-9');
  const afterRestart = maintenance.candidateRecoveryStatus(durable);
  assert.deepStrictEqual(afterRestart.candidate, candidate);
  assert.strictEqual(afterRestart.canRelease, true);
  assert.match(afterRestart.recoveryCommand, /--mode reconcile-release/);
  assert.doesNotMatch(JSON.stringify(afterRestart), /secret:redactwall|bearer|credential/i);
});

test('checked candidate release revalidates exact stack and host authority before resumable cleanup', (t) => {
  const names = ['runAws', 'readS3OperationAuthority', 'stackState', 'assertStackOperationToken', 'waitForHostReadiness',
    'sendCommand', 'compareAndSwapOperationAuthority'];
  const originals = Object.fromEntries(names.map((name) => [name, deployer[name]]));
  t.after(() => Object.assign(deployer, originals));
  const stackName = 'redactwall-cu-test';
  const leaseName = deployer.maintenanceLeaseName(stackName);
  const leaseStackId = `arn:aws:cloudformation:us-east-1:123456789012:stack/${leaseName}/12345678-1234-1234-1234-123456789012`;
  const candidateStackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/22222222-2222-2222-2222-222222222222';
  const sourceStackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/11111111-1111-1111-1111-111111111111';
  const secretArn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12';
  const deploymentId = 'dep_0123456789abcdef0123456789abcdef';
  const candidate = {
    appliedStateSha256: '5'.repeat(64), attestedAt: '2026-07-13T20:00:00.000Z',
    authorityFingerprintSha256: '6'.repeat(64), configSha256: '1'.repeat(64), containerId: '4'.repeat(64),
    imageUri: `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`,
    instanceId: 'i-0123456789abcdef0', operationId: `rw-${'b'.repeat(32)}`, protocolSha256: '3'.repeat(64),
    recoverySetId: 'c'.repeat(32), secretVersionId: '12345678-1234-1234-1234-123456789012',
    stackId: candidateStackId, stage: 'attested', templateSha256: '2'.repeat(64),
  };
  const cutoverIntent = {
    candidateClientToken: candidate.operationId,
    candidateStackName: stackName,
    configSha256: candidate.configSha256,
    deploymentId,
    imageUri: candidate.imageUri,
    protocolSha256: candidate.protocolSha256,
    recoverySetId: candidate.recoverySetId,
    secretArnSha256: crypto.createHash('sha256').update(secretArn).digest('hex'),
    secretVersionId: candidate.secretVersionId,
    sourceStackId,
    stage: 'candidate_create',
    templateSha256: candidate.templateSha256,
    tenantId: 'cu-test',
  };
  candidate.authorityFingerprintSha256 = deployer.appliedAuthorityFingerprint({
    appliedAt: candidate.attestedAt,
    appliedStateDigest: candidate.appliedStateSha256,
    configSha256: candidate.configSha256,
    containerId: candidate.containerId,
    deploymentId,
    imageUri: candidate.imageUri,
    protocolSha256: candidate.protocolSha256,
    recoverySetId: candidate.recoverySetId,
    secretArn,
    secretVersionId: candidate.secretVersionId,
    stackId: candidate.stackId,
    templateSha256: candidate.templateSha256,
    tenantId: cutoverIntent.tenantId,
  });
  const location = {
    accountId: '123456789012', bucket: 'redactwall-cfn-123456789012-us-east-1',
    key: `redactwall/cloudformation/operation-authority/${'f'.repeat(64)}.json`,
    prefix: 'redactwall/cloudformation', region: 'us-east-1', stackName,
  };
  let authority = {
    bodySha256: '7'.repeat(64), etag: `"${'8'.repeat(32)}"`, location,
    state: {
      candidate, checkpointLatchSha256: 'd'.repeat(64), checkpointSetId: candidate.recoverySetId,
      cutoverIntent,
      generation: 7, holderKind: 'maintenance', leaseStackId, operationId: `rw-${'a'.repeat(32)}`,
      leaseClientToken: `rw-${'a'.repeat(32)}`, leaseStackName: leaseName,
      permittedOperationId: candidate.operationId, phase: 'candidate', previousBodySha256: '9'.repeat(64),
      schemaVersion: 1, scope: { region: 'us-east-1', stackName }, sourceFingerprint: 'e'.repeat(64),
      sourceStackId,
      targetRegistration: {
        instanceId: 'i-1123456789abcdef0', observedAt: '2026-07-13T19:00:00.000Z', registered: true,
        state: 'healthy',
        targetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789',
      },
      updatedAt: '2026-07-13T20:00:00.000Z',
    },
    versionId: 'authority-version-7',
  };
  const cloudFormation = { stackId: leaseStackId, stackName: leaseName, tags: [] };
  const events = [];
  deployer.runAws = (args) => {
    events.push(args.join(' '));
    if (args[0] === 'sts') return '{"Account":"123456789012"}';
    const result = leaseAwsResult(args, cloudFormation);
    if (result != null) return result;
    throw new Error(`unexpected AWS mock call: ${args.join(' ')}`);
  };
  deployer.readS3OperationAuthority = () => structuredClone(authority);
  let exactCandidate = false;
  deployer.stackState = (id) => id === candidateStackId ? {
    exists: true, stackId: candidateStackId, stackName, stackStatus: 'CREATE_COMPLETE',
    outputs: {
      DesiredConfigSha256: candidate.configSha256, DeploymentProtocolSha256: candidate.protocolSha256,
      DeploymentTemplateSha256: exactCandidate ? candidate.templateSha256 : '0'.repeat(64),
      DeploymentId: deploymentId,
      InstanceId: candidate.instanceId,
      LicenseSecretVersionId: candidate.secretVersionId,
    },
    stack: { Parameters: [
      ['ImageUri', candidate.imageUri], ['LicenseSecretVersionId', candidate.secretVersionId],
      ['TenantId', cutoverIntent.tenantId], ['DeploymentId', deploymentId],
      ['RecoverySetId', candidate.recoverySetId], ['SecretArn', secretArn],
    ].map(([ParameterKey, ParameterValue]) => ({ ParameterKey, ParameterValue })) },
    tags: { RedactWallDeploymentOperation: candidate.operationId },
  } : { exists: false, outputs: {} };
  deployer.assertStackOperationToken = (id, name, region, token) => {
    assert.strictEqual(id, candidateStackId);
    assert.strictEqual(name, stackName);
    assert.strictEqual(region, 'us-east-1');
    assert.strictEqual(token, candidate.operationId);
    return true;
  };
  deployer.waitForHostReadiness = (...args) => events.push(`host:${args.join(':')}`);
  let hostAuthorityValid = false;
  let hostFieldOverride = null;
  deployer.sendCommand = (_instance, _region, command) => {
    events.push(command);
    if (!hostAuthorityValid) throw new Error('host applied authority changed');
    const fields = {
      REDACTWALL_APPLIED_CONTAINER_ID: candidate.containerId,
      REDACTWALL_APPLIED_STATE_DIGEST: candidate.appliedStateSha256,
      REDACTWALL_APPLIED_AUTHORITY_FINGERPRINT: candidate.authorityFingerprintSha256,
      REDACTWALL_APPLIED_AT: candidate.attestedAt,
      REDACTWALL_APPLIED_RECOVERY_SET_ID: candidate.recoverySetId,
      ...(hostFieldOverride || {}),
    };
    return { output: Object.entries(fields).map(([key, value]) => `${key}=${value}`).join('\n') };
  };
  deployer.compareAndSwapOperationAuthority = (prior, changes) => {
    assert.strictEqual(prior.etag, authority.etag);
    const generation = authority.state.generation + 1;
    authority = {
      ...authority,
      bodySha256: String(generation).repeat(64).slice(0, 64),
      etag: `"${String(generation).repeat(32).slice(0, 32)}"`,
      state: { ...authority.state, ...changes, generation, previousBodySha256: authority.bodySha256 },
      versionId: `authority-version-${generation}`,
    };
    return structuredClone(authority);
  };
  const values = maintenance.parseStatusArgs([
    '--stack-name', stackName, '--region', 'us-east-1', '--lease-stack-id', leaseStackId,
    '--maintenance-id', candidate.recoverySetId, '--latch-sha256', 'd'.repeat(64),
    '--artifact-bucket', location.bucket, '--artifact-prefix', location.prefix,
  ]);
  assert.throws(() => maintenance.reconcileMaintenanceRelease(values, { log() {} }), /cannot prove the exact/);
  assert.strictEqual(events.some((event) => event.includes('cloudformation delete-stack')), false);
  exactCandidate = true;
  assert.throws(() => maintenance.reconcileMaintenanceRelease(values, { log() {} }), /host applied authority changed/);
  assert.strictEqual(events.some((event) => event.includes('cloudformation delete-stack')), false);
  hostAuthorityValid = true;
  for (const [name, value] of Object.entries({
    REDACTWALL_APPLIED_CONTAINER_ID: '0'.repeat(64),
    REDACTWALL_APPLIED_STATE_DIGEST: '1'.repeat(64),
    REDACTWALL_APPLIED_AUTHORITY_FINGERPRINT: '2'.repeat(64),
    REDACTWALL_APPLIED_AT: '2026-07-13T20:00:00.001Z',
    REDACTWALL_APPLIED_RECOVERY_SET_ID: '3'.repeat(32),
  })) {
    hostFieldOverride = { [name]: value };
    assert.throws(() => maintenance.reconcileMaintenanceRelease(values, { log() {} }),
      /runtime attestation|changed applied authority evidence/);
    assert.strictEqual(events.some((event) => event.includes('cloudformation delete-stack')), false);
  }
  hostFieldOverride = null;
  const result = maintenance.reconcileMaintenanceRelease(values, { log() {} });
  assert.strictEqual(result.phase, 'available');
  assert.strictEqual(result.candidateStackId, candidateStackId);
  assert.ok(events.some((event) => event.startsWith('host:')));
  assert.ok(events.some((event) => event.includes('/usr/local/sbin/redactwall-assert-applied --image-uri')));
  assert.strictEqual(events.filter((event) => event.includes('cloudformation delete-stack')).length, 1);
});

test('partial maintenance recovery has a schema-valid exact resumed-partial phase', () => {
  const status = maintenance.parseMaintenanceStatus(
    `REDACTWALL_MAINTENANCE_PHASE=resumed-partial\nREDACTWALL_MAINTENANCE_SET=${'b'.repeat(32)}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${'c'.repeat(64)}\n`, true);
  assert.strictEqual(status.phase, 'resumed-partial');
  const controlStart = template.indexOf('/usr/local/sbin/redactwall-maintenance-control:');
  const controlEnd = template.indexOf('/usr/local/sbin/redactwall-maintenance-drain:', controlStart);
  const control = template.slice(controlStart, controlEnd);
  assert.match(control, /resumed-partial/);
  assert.match(control, /partial_set_sha256|partialSetSha256/);
  assert.match(control, /write_latch "resumed-partial"/);
  assert.match(control, /clear\)[\s\S]*resumed\|resumed-partial/);
});

test('extracted maintenance shell resumes one exact partial set and rejects an oversized partial set', (t) => {
  const wslExecutable = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'wsl.exe');
  const wsl = process.platform === 'win32'
    && childProcess.spawnSync(wslExecutable, ['-e', 'bash', '-lc', 'command -v jq'], {
      encoding: 'utf8', timeout: 10_000,
    }).status === 0;
  if (process.platform === 'win32' && !wsl) return t.skip('bounded Linux shell fixture requires WSL with jq');
  const bash = wsl ? wslExecutable : 'bash';
  const bashArgs = (args) => wsl ? ['-e', 'bash', ...args] : args;
  const runBash = (args, options = {}) => childProcess.spawnSync(bash, bashArgs(args), options);
  const probe = runBash(['--version'], { encoding: 'utf8', timeout: 10_000 });
  if (probe.error || probe.status !== 0) return t.skip('bash is unavailable');
  const jqProbe = runBash(['-lc', 'command -v jq'], { encoding: 'utf8', timeout: 10_000 });
  if (jqProbe.status !== 0) return t.skip('jq is unavailable');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-maintenance-shell-'));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const quote = (value) => `'${String(value).replace(/'/g, `'"'"'`)}'`;
  const windowsToBash = (value) => runBash(['-lc', `${wsl ? 'wslpath -a' : 'cygpath -u'} ${quote(value)}`], {
    encoding: 'utf8', timeout: 10_000,
  }).stdout.trim() || value.replaceAll('\\', '/');
  const tempBash = windowsToBash(temp);
  const bashPath = (value) => {
    const relative = path.relative(temp, value);
    return !relative.startsWith('..') && !path.isAbsolute(relative)
      ? `${tempBash}/${relative.replaceAll('\\', '/')}`.replace(/\/$/, '') : windowsToBash(value);
  };
  const stateDir = path.join(temp, 'state');
  const retainedParent = path.join(temp, 'runtime', 'maintenance-recovery');
  const bin = path.join(temp, 'bin');
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(retainedParent, { recursive: true, mode: 0o700 });
  fs.mkdirSync(bin, { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(temp, 'run'), { recursive: true, mode: 0o700 });
  fs.chmodSync(stateDir, 0o700);
  fs.chmodSync(retainedParent, 0o700);
  fs.chmodSync(bin, 0o700);
  fs.chmodSync(path.join(temp, 'run'), 0o700);
  const identity = runBash(['-lc', 'printf "%s:%s" "$(id -u)" "$(id -g)"'], {
    encoding: 'utf8', timeout: 10_000,
  }).stdout.trim();
  const [uid, gid] = identity.split(':');
  const dockerState = path.join(temp, 'docker-running');
  fs.writeFileSync(dockerState, 'false\n', { mode: 0o600 });
  const containerId = 'c'.repeat(64);
  const image = `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`;
  const dockerMock = `#!/bin/bash\nset -euo pipefail\ncase "$*" in\n  *'{{.Id}}'*) printf '%s\\n' "$MOCK_CONTAINER_ID" ;;\n  *'{{.Config.Image}}'*) printf '%s\\n' "$MOCK_IMAGE" ;;\n  *'{{.State.Running}}'*) cat "$MOCK_DOCKER_STATE" ;;\n  start*) printf 'true\\n' > "$MOCK_DOCKER_STATE"; printf '%s\\n' "$MOCK_CONTAINER_ID" ;;\n  *) exit 1 ;;\nesac\n`;
  fs.writeFileSync(path.join(bin, 'docker'), dockerMock, { mode: 0o700 });
  fs.writeFileSync(path.join(bin, 'flock'), '#!/bin/bash\nexit 0\n', { mode: 0o700 });
  fs.writeFileSync(path.join(bin, 'assert-applied'), '#!/bin/bash\nexit 0\n', { mode: 0o700 });
  for (const name of ['docker', 'flock', 'assert-applied']) fs.chmodSync(path.join(bin, name), 0o700);

  const lines = template.split(/\r?\n/);
  const marker = lines.findIndex((line) => line.includes('/usr/local/sbin/redactwall-maintenance-control:'));
  const content = lines.findIndex((line, index) => index > marker && line.trim() === 'content: |');
  const mode = lines.findIndex((line, index) => index > content && line.trim().startsWith('mode:'));
  let script = lines.slice(content + 1, mode).map((line) => line.startsWith('                ')
    ? line.slice(16) : line).join('\n');
  script = script
    .replace(/^DEPLOY_LOCK=.*$/m, `DEPLOY_LOCK=${quote(`${tempBash}/deploy.lock`)}`)
    .replace(/^MAINTENANCE_LATCH=.*$/m, `MAINTENANCE_LATCH=${quote(`${tempBash}/state/maintenance-latch.json`)}`)
    .replace(/^APPLIED_STATE=.*$/m, `APPLIED_STATE=${quote(`${tempBash}/state/applied-deployment.json`)}`)
    .replace(/^MAINTENANCE_CONTEXT=.*$/m, `MAINTENANCE_CONTEXT=${quote(`${tempBash}/state/maintenance-context.json`)}`)
    .replace(/^DEPLOY_STATE_DIR=.*$/m, `DEPLOY_STATE_DIR=${quote(`${tempBash}/state`)}`)
    .replace(/^RETAINED_PARENT=.*$/m, `RETAINED_PARENT=${quote(`${tempBash}/runtime/maintenance-recovery`)}`)
    .replaceAll('/run/redactwall-maintenance-', `${tempBash}/run/redactwall-maintenance-`)
    .replaceAll('/usr/local/sbin/redactwall-assert-applied', `${tempBash}/bin/assert-applied`)
    .replaceAll('0:0:', `${uid}:${gid}:`)
    // Git for Windows sync may block on unrelated host volumes. Durability is
    // statically required in the extracted source; this scenario tests state semantics and process liveness.
    .replace(/^\s*sync -f .*$/gm, ':');
  if (wsl) {
    script = script.replaceAll(`${uid}:${gid}:700`, `${uid}:${gid}:777`)
      .replaceAll(`${uid}:${gid}:600`, `${uid}:${gid}:777`);
  }
  const scriptFile = path.join(temp, 'maintenance-control.sh');
  fs.writeFileSync(scriptFile, script, { mode: 0o700 });
  fs.chmodSync(scriptFile, 0o700);

  const context = {
    version: 1,
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012',
    stackName: 'redactwall-cu-test', region: 'us-east-1', tenantId: 'cu-test',
    deploymentId: 'dep_0123456789abcdef0123456789abcdef', dataVolumeId: 'vol-0123456789abcdef0',
    recoverySetId: '',
  };
  const applied = {
    version: 1, committedAt: '2026-07-13T20:00:00.000Z', containerId, dataFilesystemUuid: 'uuid',
    dataVolumeId: context.dataVolumeId, desiredConfigSha256: '1'.repeat(64), imageUri: image,
    licenseSha256: '2'.repeat(64), protocolSha256: '3'.repeat(64), recoveryPath: null,
    secretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12',
    secretVersionId: '12345678-1234-1234-1234-123456789012', templateSha256: '4'.repeat(64), warnings: [],
  };
  const contextFile = path.join(stateDir, 'maintenance-context.json');
  const stateFile = path.join(stateDir, 'applied-deployment.json');
  fs.writeFileSync(contextFile, JSON.stringify(context), { mode: 0o600 });
  fs.writeFileSync(stateFile, JSON.stringify(applied), { mode: 0o600 });
  fs.chmodSync(contextFile, 0o600);
  fs.chmodSync(stateFile, 0o600);
  const stat = (format, file) => runBash(['-lc', `umask 077; stat -c ${quote(format)} ${quote(bashPath(file))}`], {
    encoding: 'utf8', timeout: 10_000,
  }).stdout.trim();
  const stateIdentity = stat('%d:%i:%s:%Y:%h', stateFile);
  const stateSha = crypto.createHash('sha256').update(fs.readFileSync(stateFile)).digest('hex');
  const setId = 'b'.repeat(32);
  const retainedRoot = path.join(retainedParent, setId);
  fs.mkdirSync(retainedRoot, { mode: 0o700 });
  fs.chmodSync(retainedRoot, 0o700);
  fs.writeFileSync(path.join(retainedRoot, 'partial.bin'), 'partial-evidence', { mode: 0o600 });
  fs.chmodSync(path.join(retainedRoot, 'partial.bin'), 0o600);
  const latchFile = path.join(stateDir, 'maintenance-latch.json');
  const writeStoppedLatch = () => {
    const latch = {
      version: 1, phase: 'stopped', maintenanceId: setId, stackId: context.stackId,
      tenantId: context.tenantId, deploymentId: context.deploymentId, dataVolumeId: context.dataVolumeId,
      appliedStateIdentity: stateIdentity, appliedStateSha256: stateSha, containerId, imageUri: image,
      recoverySetId: setId, recoveryRootIdentity: stat('%d:%i:%u:%g:%a', retainedRoot), recoveryBackup: null, recoveryManifest: null,
      recoverySetSha256: null, recoveryArtifactCount: 0, partialSetSha256: null, partialArtifactCount: 0,
      createdAt: '2026-07-13T20:00:00.000Z', updatedAt: '2026-07-13T20:00:00.000Z',
    };
    fs.writeFileSync(latchFile, JSON.stringify(latch), { mode: 0o600 });
    fs.chmodSync(latchFile, 0o600);
  };
  const run = (operation, digest) => {
    const linuxPath = `${bashPath(bin)}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`;
    const options = {
      encoding: 'utf8', timeout: 15_000, windowsHide: true,
      env: { ...process.env, PATH: `${bashPath(bin)}:${process.env.PATH}`,
        MOCK_CONTAINER_ID: containerId, MOCK_IMAGE: image, MOCK_DOCKER_STATE: bashPath(dockerState) },
    };
    if (!wsl) return runBash([bashPath(scriptFile), operation, setId, digest], options);
    const command = [
      `PATH=${quote(linuxPath)}`,
      `MOCK_CONTAINER_ID=${quote(containerId)}`,
      `MOCK_IMAGE=${quote(image)}`,
      `MOCK_DOCKER_STATE=${quote(bashPath(dockerState))}`,
      'exec bash', quote(bashPath(scriptFile)), quote(operation), quote(setId), quote(digest),
    ].join(' ');
    return runBash(['-lc', command], { encoding: 'utf8', timeout: 15_000, windowsHide: true });
  };
  const digest = () => crypto.createHash('sha256').update(fs.readFileSync(latchFile)).digest('hex');
  writeStoppedLatch();
  const resumed = run('abort', digest());
  assert.notStrictEqual(resumed.error?.code, 'ETIMEDOUT', 'the extracted shell must finish without a leaked child');
  assert.strictEqual(resumed.status, 0, resumed.stderr || resumed.stdout
    || JSON.stringify({ error: resumed.error?.message, signal: resumed.signal }));
  const resumedLatch = JSON.parse(fs.readFileSync(latchFile, 'utf8'));
  assert.strictEqual(resumedLatch.phase, 'resumed-partial');
  assert.strictEqual(resumedLatch.partialArtifactCount, 1);
  assert.match(resumedLatch.partialSetSha256, /^[a-f0-9]{64}$/);
  const cleared = run('clear', digest());
  assert.notStrictEqual(cleared.error?.code, 'ETIMEDOUT', 'clear must finish without a leaked child');
  assert.strictEqual(cleared.status, 0, cleared.stderr || cleared.stdout);
  assert.strictEqual(fs.existsSync(latchFile), false);

  fs.writeFileSync(dockerState, 'false\n', { mode: 0o600 });
  for (let index = 1; index < 9; index += 1) {
    const file = path.join(retainedRoot, `partial-${index}.bin`);
    fs.writeFileSync(file, `evidence-${index}`, { mode: 0o600 });
    fs.chmodSync(file, 0o600);
  }
  writeStoppedLatch();
  const rejected = run('abort', digest());
  assert.notStrictEqual(rejected.error?.code, 'ETIMEDOUT', 'bounded rejection must finish without a leaked child');
  assert.notStrictEqual(rejected.status, 0, 'an oversized partial set must fail closed');
  assert.strictEqual(JSON.parse(fs.readFileSync(latchFile, 'utf8')).phase, 'stopped');
  const processPattern = bashPath(scriptFile).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace('maintenance-control', '[m]aintenance-control');
  const leaked = runBash(['-lc', `pgrep -f -- ${quote(processPattern)}`], {
    encoding: 'utf8', timeout: 10_000,
  });
  assert.strictEqual(leaked.status, 1, `extracted maintenance shell leaked a child: ${leaked.stdout || leaked.stderr}`);
});

test('retained post-drain evidence reports one sanitized checked recovery command', () => {
  const error = maintenance.retainedEvidenceError('source stack drifted', {
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/rw-maintenance-test/12345678-1234-1234-1234-123456789012',
    operationId: `rw-${'a'.repeat(32)}`, phase: 'drained', region: 'us-east-1',
  }, { setId: 'b'.repeat(32), latchSha256: 'c'.repeat(64) }, 'redactwall-cu-test');
  assert.match(error.message, /evidence retained/);
  assert.match(error.message, /--mode reconcile[\s\S]*--lease-stack-id[\s\S]*--maintenance-id[\s\S]*--latch-sha256/);
  assert.doesNotMatch(error.message, /token|secret|credential|\\Users\\/i);
});

test('maintenance exposes a checked phase reconciler for durable cutover windows', () => {
  assert.strictEqual(typeof maintenance.reconcileMaintenanceOperation, 'function');
});

test('checked reconciliation adopts exact preparing and drained crash windows before source deletion', () => {
  const accountId = '123456789012';
  const region = 'us-east-1';
  const stackName = 'redactwall-cu-test';
  const leaseStackName = deployer.maintenanceLeaseName(stackName);
  const sourceStackId = `arn:aws:cloudformation:${region}:${accountId}:stack/${stackName}/11111111-1111-1111-1111-111111111111`;
  const leaseStackId = `arn:aws:cloudformation:${region}:${accountId}:stack/${leaseStackName}/22222222-2222-2222-2222-222222222222`;
  const operationId = `rw-${'a'.repeat(32)}`;
  const candidateClientToken = `rw-${'b'.repeat(32)}`;
  const checkpoint = {
    backup: 'maintenance.backup', latchSha256: '7'.repeat(64), manifest: 'maintenance.manifest',
    phase: 'stopped', setId: '6'.repeat(32),
  };
  const target = {
    instanceId: 'i-0123456789abcdef0', observedAt: '2026-07-13T20:00:00.000Z', registered: true,
    state: 'healthy',
    targetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789',
  };
  const intent = {
    candidateClientToken,
    candidateStackName: stackName,
    configSha256: 'none',
    deploymentId: 'none',
    imageUri: 'none',
    protocolSha256: 'none',
    recoverySetId: 'none',
    secretArnSha256: 'none',
    secretVersionId: 'none',
    sourceStackId,
    stage: 'drain',
    templateSha256: 'none',
    tenantId: 'none',
  };
  const location = {
    accountId, bucket: 'redactwall-cfn-123456789012-us-east-1',
    key: 'redactwall/cloudformation/operation-authority/reconcile-phases.json',
    prefix: 'redactwall/cloudformation', region, stackName,
  };
  const authorityDependencies = memoryAuthorityDependencies();
  let authority = deployer.acquireOperationAuthority(location, 'maintenance', operationId, authorityDependencies, {
    leaseClientToken: operationId,
    leaseStackName,
    phase: 'lease_creating',
    sourceFingerprint: '8'.repeat(64),
    sourceStackId,
  });
  authority = deployer.compareAndSwapOperationAuthority(authority, {
    checkpointLatchSha256: checkpoint.latchSha256,
    checkpointSetId: checkpoint.setId,
    cutoverIntent: intent,
    leaseStackId,
    permittedOperationId: candidateClientToken,
    phase: 'preparing',
    targetRegistration: target,
  }, authorityDependencies);
  const describeLease = (lease) => ({
    stackId: leaseStackId,
    stackName: leaseStackName,
    stackStatus: 'CREATE_COMPLETE',
    tags: {
      RedactWallAuthorityBodySha256: lease.authority.bodySha256,
      RedactWallAuthorityGeneration: String(lease.authority.state.generation),
      RedactWallCandidateStateSha256: 'none',
      RedactWallMaintenanceLatchSha256: lease.checkpointLatchSha256,
      RedactWallMaintenanceOperation: lease.operationId,
      RedactWallMaintenancePhase: lease.phase,
      RedactWallMaintenanceSet: lease.checkpointSetId,
      RedactWallPermittedOperation: lease.permittedOperationId,
      RedactWallSourceFingerprint: lease.sourceFingerprint,
      RedactWallSourceStackId: lease.sourceStackId,
    },
  });
  const values = {
    'artifact-bucket': location.bucket,
    'artifact-prefix': location.prefix,
    'latch-sha256': checkpoint.latchSha256,
    'lease-stack-id': leaseStackId,
    'maintenance-id': checkpoint.setId,
    'stack-name': stackName,
    region,
  };
  let sourceExists = true;
  let checkpointDrift = true;
  let deleteCalls = 0;
  const dependencies = {
    accountId,
    authorityDependencies,
    describeLease,
    leaseDependencies: { describeLease, updateLease() {} },
    location,
    maintenanceStatus: () => ({
      ...checkpoint,
      latchSha256: checkpointDrift ? '9'.repeat(64) : checkpoint.latchSha256,
    }),
    stackState: (id) => id === sourceStackId
      ? { exists: sourceExists, outputs: { InstanceId: target.instanceId, TargetGroupArn: target.targetGroupArn },
        stackId: sourceStackId }
      : { exists: false, outputs: {} },
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    deleteApplicationStack: (id) => {
      assert.strictEqual(id, sourceStackId);
      assert.strictEqual(deployer.readOperationAuthority(location, authorityDependencies)
        .state.cutoverIntent.stage, 'source_delete');
      deleteCalls += 1;
      sourceExists = false;
    },
  };
  assert.throws(() => maintenance.reconcileMaintenanceOperation(values, { log() {} }, dependencies),
    /checkpoint does not match/);
  assert.strictEqual(deleteCalls, 0);
  checkpointDrift = false;
  const prepared = maintenance.reconcileMaintenanceOperation(values, { log() {} }, dependencies);
  assert.strictEqual(prepared.action, 'checkpoint_adopted');
  assert.strictEqual(prepared.phase, 'drained');
  assert.strictEqual(deleteCalls, 0);
  const deleted = maintenance.reconcileMaintenanceOperation(values, { log() {} }, dependencies);
  assert.strictEqual(deleted.action, 'source_deleted_adopted');
  assert.strictEqual(deleted.phase, 'source_deleted');
  assert.strictEqual(deleteCalls, 1);
});

test('checked reconciliation adopts only an exact unrecorded candidate client token and StackId', () => {
  const accountId = '123456789012';
  const region = 'us-east-1';
  const stackName = 'redactwall-cu-test';
  const leaseStackName = deployer.maintenanceLeaseName(stackName);
  const sourceStackId = `arn:aws:cloudformation:${region}:${accountId}:stack/${stackName}/11111111-1111-1111-1111-111111111111`;
  const leaseStackId = `arn:aws:cloudformation:${region}:${accountId}:stack/${leaseStackName}/22222222-2222-2222-2222-222222222222`;
  const candidateStackId = `arn:aws:cloudformation:${region}:${accountId}:stack/${stackName}/33333333-3333-3333-3333-333333333333`;
  const operationId = `rw-${'a'.repeat(32)}`;
  const candidateClientToken = `rw-${'b'.repeat(32)}`;
  const secretArn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12';
  const intent = {
    candidateClientToken,
    candidateStackName: stackName,
    configSha256: '1'.repeat(64),
    deploymentId: 'dep_0123456789abcdef0123456789abcdef',
    imageUri: `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'2'.repeat(64)}`,
    protocolSha256: '3'.repeat(64),
    recoverySetId: '4'.repeat(32),
    secretArnSha256: crypto.createHash('sha256').update(secretArn).digest('hex'),
    secretVersionId: '12345678-1234-1234-1234-123456789012',
    sourceStackId,
    stage: 'candidate_create',
    templateSha256: '5'.repeat(64),
    tenantId: 'cu-test',
  };
  const target = {
    instanceId: 'i-0123456789abcdef0', observedAt: '2026-07-13T20:00:00.000Z', registered: true,
    state: 'healthy',
    targetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789',
  };
  const location = {
    accountId, bucket: 'redactwall-cfn-123456789012-us-east-1',
    key: 'redactwall/cloudformation/operation-authority/reconcile.json',
    prefix: 'redactwall/cloudformation', region, stackName,
  };
  const authorityDependencies = memoryAuthorityDependencies();
  let authority = deployer.acquireOperationAuthority(location, 'maintenance', operationId, authorityDependencies, {
    leaseClientToken: operationId,
    leaseStackName,
    phase: 'lease_creating',
    sourceFingerprint: '6'.repeat(64),
    sourceStackId,
  });
  authority = deployer.compareAndSwapOperationAuthority(authority, {
    checkpointLatchSha256: '7'.repeat(64),
    checkpointSetId: intent.recoverySetId,
    cutoverIntent: intent,
    leaseStackId,
    permittedOperationId: candidateClientToken,
    phase: 'source_deleted',
    targetRegistration: target,
  }, authorityDependencies);
  const candidate = {
    exists: true,
    outputs: {
      DeploymentId: intent.deploymentId,
      DeploymentProtocolSha256: intent.protocolSha256,
      DeploymentTemplateSha256: intent.templateSha256,
      DesiredConfigSha256: intent.configSha256,
      InstanceId: 'i-1123456789abcdef0',
      LicenseSecretVersionId: intent.secretVersionId,
    },
    stack: { Parameters: [
      ['ImageUri', intent.imageUri], ['LicenseSecretVersionId', intent.secretVersionId],
      ['TenantId', intent.tenantId], ['DeploymentId', intent.deploymentId],
      ['RecoverySetId', intent.recoverySetId], ['SecretArn', secretArn],
    ].map(([ParameterKey, ParameterValue]) => ({ ParameterKey, ParameterValue })) },
    stackId: candidateStackId,
    stackName,
    stackStatus: 'CREATE_COMPLETE',
    tags: { RedactWallDeploymentOperation: candidateClientToken },
  };
  const describeLease = (value) => {
    const recordedCandidate = value.authority.state.candidate;
    const digest = recordedCandidate ? crypto.createHash('sha256').update(JSON.stringify(
      Object.fromEntries(Object.keys(recordedCandidate).sort().map((key) => [key, recordedCandidate[key]])),
    )).digest('hex') : 'none';
    return {
      stackId: leaseStackId, stackName: leaseStackName, stackStatus: 'CREATE_COMPLETE',
      tags: {
        RedactWallAuthorityBodySha256: value.authority.bodySha256,
        RedactWallAuthorityGeneration: String(value.authority.state.generation),
        RedactWallCandidateStateSha256: digest,
        RedactWallMaintenanceLatchSha256: value.checkpointLatchSha256,
        RedactWallMaintenanceOperation: value.operationId,
        RedactWallMaintenancePhase: value.phase,
        RedactWallMaintenanceSet: value.checkpointSetId,
        RedactWallPermittedOperation: value.permittedOperationId,
        RedactWallSourceFingerprint: value.sourceFingerprint,
        RedactWallSourceStackId: value.sourceStackId,
      },
    };
  };
  const values = {
    'artifact-bucket': location.bucket,
    'artifact-prefix': location.prefix,
    'latch-sha256': '7'.repeat(64),
    'lease-stack-id': leaseStackId,
    'maintenance-id': intent.recoverySetId,
    'stack-name': stackName,
    region,
  };
  const dependencies = {
    accountId,
    attestCandidate: false,
    authority,
    authorityDependencies,
    describeLease,
    leaseDependencies: { describeLease, updateLease() {} },
    location,
    stackState: (id) => id === sourceStackId ? { exists: false } : structuredClone(candidate),
    verifyCandidateOperation: (id, name, candidateRegion, token) => {
      assert.strictEqual(id, candidateStackId);
      assert.strictEqual(name, stackName);
      assert.strictEqual(candidateRegion, region);
      assert.strictEqual(token, candidateClientToken);
      return true;
    },
  };
  const lines = [];
  const result = maintenance.reconcileMaintenanceOperation(values, { log: (line) => lines.push(line) }, dependencies);
  assert.strictEqual(result.action, 'candidate_owned');
  assert.strictEqual(result.candidate.stackId, candidateStackId);
  assert.strictEqual(result.candidate.operationId, candidateClientToken);
  const wrong = structuredClone(candidate);
  wrong.tags.RedactWallDeploymentOperation = `rw-${'f'.repeat(32)}`;
  assert.throws(() => maintenance.reconcileMaintenanceOperation(values, { log() {} }, {
    ...dependencies,
    authority,
    stackState: (id) => id === sourceStackId ? { exists: false } : wrong,
  }), /client token and StackId/);
  assert.throws(() => maintenance.reconcileMaintenanceOperation(values, { log() {} }, {
    ...dependencies,
    authority,
    verifyCandidateOperation: () => { throw new Error('actual create client token changed'); },
  }), /actual create client token changed/);
});

test('maintenance quiesces ALB traffic before stopping the exact writer and taking the final backup', () => {
  const deregister = source.indexOf("'elbv2', 'deregister-targets'");
  const drained = source.indexOf("'elbv2', 'wait', 'target-deregistered'", deregister);
  const checkpoint = source.indexOf('/usr/local/sbin/redactwall-maintenance-checkpoint', drained);
  assert.ok(deregister >= 0 && deregister < drained && drained < checkpoint);
  const controlStart = template.indexOf('/usr/local/sbin/redactwall-maintenance-control:');
  const controlEnd = template.indexOf('/usr/local/sbin/redactwall-maintenance-drain:', controlStart);
  const control = template.slice(controlStart, controlEnd);
  const stop = control.indexOf('docker stop -t 30 "$container_id"');
  const finalBackup = control.indexOf('backup-store.js create', stop);
  assert.ok(stop >= 0 && stop < finalBackup,
    'the final authenticated recovery point is created only after the only writer is stopped');
});

test('candidate rollback deletes only the exact operation-owned StackId and preserves a same-name competitor', () => {
  assert.match(source, /removeFailedStackIfOwned\(ownership/);
  assert.doesNotMatch(source, /removeFailedStackIfPresent\(requested\['stack-name'\]/);
  assert.match(source, /ownership\.stackId/);
  assert.match(source, /same-name candidate is ambiguous|competing stack/i);
});

test('candidate cleanup refuses a same-name competitor without issuing delete-stack', (t) => {
  const originals = { stackState: deployer.stackState, runAws: deployer.runAws };
  t.after(() => Object.assign(deployer, originals));
  const owned = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/11111111-1111-1111-1111-111111111111';
  const competitor = owned.replace(/1/g, '2');
  const calls = [];
  deployer.stackState = (name) => {
    if (name === 'redactwall-cu-test') return { exists: true, stackId: competitor };
    if (name === owned) return { exists: true, stackId: owned };
    return { exists: false };
  };
  deployer.runAws = (args) => { calls.push(args); return '{}'; };
  assert.throws(() => maintenance.removeFailedStackIfOwned({
    operationId: `rw-${'a'.repeat(32)}`, stackId: owned,
    stackName: 'redactwall-cu-test', region: 'us-east-1',
  }, 'redactwall-cu-test', 'us-east-1'), /competing stack/);
  assert.strictEqual(calls.some((args) => args[1] === 'delete-stack'), false);
});

test('maintenance abort restarts the exact writer and clears only after target recovery', (t) => {
  const originals = {};
  for (const name of ['waitForHostReadiness', 'sendCommand', 'runAws']) originals[name] = deployer[name];
  t.after(() => Object.assign(deployer, originals));
  const events = [];
  const setId = 'b'.repeat(32);
  const preparedHash = 'c'.repeat(64);
  const resumedHash = 'd'.repeat(64);
  deployer.waitForHostReadiness = () => events.push('host-ready');
  deployer.sendCommand = (_instance, _region, command) => {
    events.push(command);
    if (command === '/usr/local/sbin/redactwall-maintenance-drain') {
      return { output: `REDACTWALL_MAINTENANCE_PHASE=preparing\nREDACTWALL_MAINTENANCE_SET=${setId}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${preparedHash}\n` };
    }
    if (command === '/usr/local/sbin/redactwall-maintenance-status') {
      return { output: `REDACTWALL_MAINTENANCE_PHASE=preparing\nREDACTWALL_MAINTENANCE_SET=${setId}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${preparedHash}\n` };
    }
    if (command === `/usr/local/sbin/redactwall-maintenance-abort ${setId} ${preparedHash}`) {
      return { output: `REDACTWALL_MAINTENANCE_PHASE=resumed\nREDACTWALL_MAINTENANCE_SET=${setId}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${resumedHash}\n` };
    }
    if (command === `/usr/local/sbin/redactwall-maintenance-clear ${setId} ${resumedHash}`) return { output: '' };
    throw new Error(`unexpected command: ${command}`);
  };
  deployer.runAws = (args) => {
    const event = args.join(' ');
    events.push(event);
    if (args[0] === 'elbv2' && args[1] === 'describe-target-health') {
      return JSON.stringify({ TargetHealthDescriptions: [{
        Target: { Id: 'i-0123456789abcdef0' }, TargetHealth: { State: 'healthy' },
      }] });
    }
    if (args[0] === 'elbv2' && args[1] === 'wait' && args[2] === 'target-deregistered') {
      throw new Error('target drain failed');
    }
    return '{}';
  };
  assert.throws(() => maintenance.drainAndDeregister({
    InstanceId: 'i-0123456789abcdef0',
    TargetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789',
  }, 'us-east-1', 1200), /target drain failed/);
  const resume = events.indexOf(`/usr/local/sbin/redactwall-maintenance-abort ${setId} ${preparedHash}`);
  const register = events.findIndex((event) => event.includes('elbv2 register-targets'));
  const inService = events.findIndex((event) => event.includes('elbv2 wait target-in-service'));
  const clear = events.indexOf(`/usr/local/sbin/redactwall-maintenance-clear ${setId} ${resumedHash}`);
  assert.ok(resume >= 0 && resume < register && register < inService && inService < clear);
});

test('target registration distinguishes exact absence from an unreadable target', (t) => {
  const original = deployer.runAws;
  t.after(() => { deployer.runAws = original; });
  const targetGroupArn = 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789';
  const instanceId = 'i-0123456789abcdef0';
  deployer.runAws = () => {
    const error = new Error('Could not reconcile source target registration after an ambiguous drain');
    error.stderr = 'An error occurred (InvalidTarget) when calling DescribeTargetHealth: not registered';
    throw error;
  };
  const absent = maintenance.targetRegistration(targetGroupArn, instanceId, 'us-east-1');
  assert.deepStrictEqual({ ...absent, observedAt: undefined }, {
    instanceId, observedAt: undefined, registered: false, state: 'absent', targetGroupArn,
  });
  deployer.runAws = () => {
    const error = new Error('Could not reconcile source target registration after an ambiguous drain');
    error.stderr = 'An error occurred (AccessDeniedException) when calling DescribeTargetHealth';
    throw error;
  };
  assert.throws(() => maintenance.targetRegistration(targetGroupArn, instanceId, 'us-east-1'), /Could not reconcile/);
});

test('checkpoint failure injection recovers by authenticated phase from preparing through stopped', async (t) => {
  for (const phase of ['preparing', 'drained', 'stopped']) {
    await t.test(phase, (inner) => {
      const originals = {};
      for (const name of ['waitForHostReadiness', 'sendCommand', 'runAws']) originals[name] = deployer[name];
      inner.after(() => Object.assign(deployer, originals));
      const setId = 'b'.repeat(32);
      const hash = 'c'.repeat(64);
      const resumed = 'd'.repeat(64);
      const events = [];
      deployer.waitForHostReadiness = () => {};
      deployer.runAws = (args) => {
        events.push(args.join(' '));
        if (args[0] === 'elbv2' && args[1] === 'describe-target-health') {
          return JSON.stringify({ TargetHealthDescriptions: [{
            Target: { Id: 'i-0123456789abcdef0' }, TargetHealth: { State: 'healthy' },
          }] });
        }
        return '{}';
      };
      deployer.sendCommand = (_instance, _region, command) => {
        events.push(command);
        if (command === '/usr/local/sbin/redactwall-maintenance-drain') {
          return { output: `REDACTWALL_MAINTENANCE_PHASE=preparing\nREDACTWALL_MAINTENANCE_SET=${setId}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${hash}\n` };
        }
        if (command.startsWith('/usr/local/sbin/redactwall-maintenance-checkpoint')) throw new Error('checkpoint failed');
        if (command === '/usr/local/sbin/redactwall-maintenance-status') {
          return { output: `REDACTWALL_MAINTENANCE_PHASE=${phase}\nREDACTWALL_MAINTENANCE_SET=${setId}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${hash}\n` };
        }
        if (command === `/usr/local/sbin/redactwall-maintenance-abort ${setId} ${hash}`) {
          return { output: `REDACTWALL_MAINTENANCE_PHASE=resumed\nREDACTWALL_MAINTENANCE_SET=${setId}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${resumed}\n` };
        }
        if (command === `/usr/local/sbin/redactwall-maintenance-clear ${setId} ${resumed}`) return { output: '' };
        throw new Error(`unexpected command: ${command}`);
      };
      assert.throws(() => maintenance.drainAndDeregister({
        InstanceId: 'i-0123456789abcdef0',
        TargetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789',
      }, 'us-east-1', 1200), /checkpoint failed/);
      assert.ok(events.includes(`/usr/local/sbin/redactwall-maintenance-abort ${setId} ${hash}`));
      assert.ok(events.some((event) => event.includes('elbv2 wait target-in-service')));
    });
  }
});

test('maintenance drains and deletes before replacement creation, with exact prior-stack rollback', () => {
  const capturePriorTemplate = source.indexOf('deployer.verifyRollbackTemplate(');
  const drain = source.indexOf('drainAndDeregister(sourceOutputs');
  const remove = source.indexOf('deleteApplicationStack(sourceStack.StackId', drain);
  const create = source.indexOf('deployer.deploy(requested', remove);
  const rollbackDelete = source.indexOf('removeFailedStackIfOwned', create);
  const rollbackCreate = source.indexOf('deployer.deploy(prior', rollbackDelete);
  assert.ok(capturePriorTemplate >= 0 && capturePriorTemplate < drain && drain < remove && remove < create
    && create < rollbackDelete && rollbackDelete < rollbackCreate);
  assert.match(source, /cloudformation', 'wait', 'stack-delete-complete'/);
  assert.match(source, /elbv2', 'wait', 'target-deregistered'/);
  assert.match(source, /maintenance abort resume/);
  assert.match(source, /elbv2', 'register-targets'/);
  assert.match(source, /parseMaintenanceStatus[\s\S]*REDACTWALL_MAINTENANCE_SET/);
  assert.match(source, /REDACTWALL_MAINTENANCE_BACKUP[\s\S]*REDACTWALL_MAINTENANCE_MANIFEST/);
  assert.match(template, /redactwall-maintenance-control:[\s\S]*docker stop[\s\S]*backup-store\.js create[\s\S]*backup-store\.js verify[\s\S]*docker run --rm --network none[\s\S]*backup-store\.js verify[\s\S]*redactwall-maintenance-drain:/);
  const recovery = template.indexOf("RECOVERY_BACKUP_NAME='${RecoveryBackupName}'");
  const verify = template.indexOf('scripts/backup-store.js verify', recovery);
  const restore = template.indexOf('scripts/backup-store.js restore', verify);
  const audit = template.indexOf('verifyAuditChain()', restore);
  const initialize = template.indexOf('/opt/aws/bin/cfn-init -v', audit);
  assert.ok(recovery >= 0 && recovery < verify && verify < restore && restore < audit && audit < initialize,
    'rollback authenticates and restores the retained set before the prior writer can initialize');
  assert.strictEqual(source.indexOf('resumeSource(', create), -1,
    'a failed candidate or rollback is never resumed or re-registered after the old stack was deleted');
});

test('maintenance rollback uses the captured versioned template and retained recovery identities', (t) => {
  const requested = deployer.validate({
    'stack-name': 'redactwall-cu-test', region: 'us-east-1',
    'vpc-id': 'vpc-0123456789abcdef0',
    'public-subnet-ids': 'subnet-0123456789abcdef0,subnet-1123456789abcdef0',
    'instance-subnet-id': 'subnet-0123456789abcdef0', 'instance-availability-zone': 'us-east-1a',
    'data-volume-id': 'vol-0123456789abcdef0', 'data-stack-name': 'redactwall-cu-test-data',
    'source-data-volume-id': '', 'ami-id': 'ami-1123456789abcdef0', 'instance-type': 't3.small',
    'root-volume-gb': '20',
    'image-uri': `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`,
    'secret-arn': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12',
    'secret-version-id': '12345678-1234-1234-1234-123456789012',
    'tenant-id': 'cu-test', 'deployment-id': 'dep_0123456789abcdef0123456789abcdef',
    'certificate-arn': 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
    'public-hostname': 'cu-test.redactwall.example',
    'artifact-bucket': 'redactwall-cfn-123456789012-us-east-1',
    'artifact-prefix': 'redactwall/cloudformation', 'timeout-seconds': '1200',
  });
  const prior = { ...requested, 'ami-id': 'ami-0123456789abcdef0' };
  const parameterNames = {
    'vpc-id': 'VpcId', 'public-subnet-ids': 'PublicSubnetIds', 'instance-subnet-id': 'InstanceSubnetId',
    'instance-availability-zone': 'InstanceAvailabilityZone', 'data-volume-id': 'DataVolumeId',
    'data-stack-name': 'DataStackName', 'source-data-volume-id': 'SourceDataVolumeId', 'ami-id': 'AmiId',
    'instance-type': 'InstanceType', 'root-volume-gb': 'RootVolumeGb', 'image-uri': 'ImageUri',
    'secret-arn': 'SecretArn', 'secret-version-id': 'LicenseSecretVersionId',
    'tenant-id': 'TenantId', 'deployment-id': 'DeploymentId', 'certificate-arn': 'CertificateArn',
    'public-hostname': 'PublicHostname',
  };
  const stack = {
    StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012',
    StackName: 'redactwall-cu-test',
    StackStatus: 'UPDATE_COMPLETE',
    Parameters: Object.entries(parameterNames).map(([key, ParameterKey]) => ({ ParameterKey, ParameterValue: prior[key] })),
    Outputs: [
      { OutputKey: 'InstanceId', OutputValue: 'i-0123456789abcdef0' },
      { OutputKey: 'TargetGroupArn', OutputValue: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789' },
      { OutputKey: 'DeploymentTemplateUrl', OutputValue: 'https://versioned.example/template?versionId=prior' },
    ],
  };
  const originals = {};
  for (const name of ['runAws', 'verifyRollbackTemplate', 'templateReferenceFromOutputs', 'validateAwsTopology',
    'waitForHostReadiness', 'sendCommand', 'stackState', 'deploy']) originals[name] = deployer[name];
  t.after(() => Object.assign(deployer, originals));
  const events = [];
  const leaseState = {};
  const priorTemplate = { templateUrl: 'https://versioned.example/template?versionId=prior', sha256: 'a'.repeat(64) };
  deployer.runAws = (args) => {
    events.push(args.join(' '));
    const leaseResult = leaseAwsResult(args, leaseState);
    if (leaseResult != null) return leaseResult;
    if (args[0] === 'cloudformation' && args[1] === 'describe-stacks') return JSON.stringify({ Stacks: [stack] });
    if (args[0] === 'cloudformation' && args[1] === 'get-template') {
      return JSON.stringify({ TemplateBody: { Resources: { Source: { Type: 'AWS::EC2::Instance' } } } });
    }
    return '{}';
  };
  deployer.templateReferenceFromOutputs = (outputs) => { events.push('capture-template'); return outputs; };
  deployer.verifyRollbackTemplate = (values, reference) => {
    events.push('verify-template');
    assert.strictEqual(values['ami-id'], prior['ami-id']);
    assert.strictEqual(reference.DeploymentTemplateUrl, priorTemplate.templateUrl);
    return priorTemplate;
  };
  deployer.validateAwsTopology = () => events.push('validate-topology');
  deployer.waitForHostReadiness = () => events.push('wait-drain');
  deployer.sendCommand = (_instance, _region, command) => {
    events.push(command);
    if (command === '/usr/local/sbin/redactwall-maintenance-drain') {
      return { output: `REDACTWALL_MAINTENANCE_PHASE=preparing\nREDACTWALL_MAINTENANCE_SET=${'b'.repeat(32)}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${'c'.repeat(64)}\n` };
    }
    if (command.startsWith('/usr/local/sbin/redactwall-maintenance-checkpoint')) {
      return { output: `REDACTWALL_MAINTENANCE_PHASE=stopped\nREDACTWALL_MAINTENANCE_SET=${'b'.repeat(32)}\nREDACTWALL_MAINTENANCE_BACKUP=backup.dump\nREDACTWALL_MAINTENANCE_MANIFEST=backup.manifest.json\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${'d'.repeat(64)}\n` };
    }
    throw new Error(`unexpected command ${command}`);
  };
  deployer.stackState = () => ({ exists: false });
  let deployCalls = 0;
  deployer.deploy = (values, _io, options) => {
    deployCalls += 1;
    events.push(deployCalls === 1 ? 'candidate-deploy' : 'rollback-deploy');
    if (deployCalls === 1) throw new Error('candidate failed');
    assert.strictEqual(values['ami-id'], prior['ami-id']);
    assert.strictEqual(options.template, priorTemplate);
    const { targetRegistrationBefore, ...recovery } = options.recovery;
    assert.deepStrictEqual(recovery, {
      phase: 'stopped',
      setId: 'b'.repeat(32), backup: 'backup.dump', manifest: 'backup.manifest.json',
      latchSha256: 'd'.repeat(64),
    });
    assert.deepStrictEqual({ ...targetRegistrationBefore, observedAt: undefined }, {
      instanceId: 'i-0123456789abcdef0',
      targetGroupArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789',
      registered: true, state: 'healthy', observedAt: undefined,
    });
    assert.match(targetRegistrationBefore.observedAt, /^\d{4}-\d{2}-\d{2}T/);
    return { instanceId: 'i-1123456789abcdef0' };
  };
  let thrown;
  try { maintenance.maintain('replace-instance', requested, { log() {}, warn() {} }, {
    accountId: '123456789012', authorityDependencies: memoryAuthorityDependencies(),
  }); }
  catch (error) { thrown = error; }
  assert.match(thrown?.message || '', /candidate failed/);
  assert.strictEqual(thrown?.rollback?.ok, true,
    thrown?.rollbackError?.stack || thrown?.leaseTransitionError?.stack || thrown?.stack);
  assert.ok(events.indexOf('verify-template') < events.indexOf('/usr/local/sbin/redactwall-maintenance-drain'));
  assert.ok(events.indexOf('candidate-deploy') < events.indexOf('rollback-deploy'));
});

test('maintenance retains the latch and checkpoint when the exact stack drifts after drain', (t) => {
  const requested = deployer.validate({
    'stack-name': 'redactwall-cu-test', region: 'us-east-1',
    'vpc-id': 'vpc-0123456789abcdef0',
    'public-subnet-ids': 'subnet-0123456789abcdef0,subnet-1123456789abcdef0',
    'instance-subnet-id': 'subnet-0123456789abcdef0', 'instance-availability-zone': 'us-east-1a',
    'data-volume-id': 'vol-0123456789abcdef0', 'data-stack-name': 'redactwall-cu-test-data',
    'source-data-volume-id': '', 'ami-id': 'ami-1123456789abcdef0', 'instance-type': 't3.small',
    'root-volume-gb': '20',
    'image-uri': `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`,
    'secret-arn': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12',
    'secret-version-id': '12345678-1234-1234-1234-123456789012',
    'tenant-id': 'cu-test', 'deployment-id': 'dep_0123456789abcdef0123456789abcdef',
    'certificate-arn': 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
    'public-hostname': 'cu-test.redactwall.example',
    'artifact-bucket': 'redactwall-cfn-123456789012-us-east-1',
    'artifact-prefix': 'redactwall/cloudformation', 'timeout-seconds': '1200',
  });
  const parameterNames = {
    VpcId: 'vpc-id', PublicSubnetIds: 'public-subnet-ids', InstanceSubnetId: 'instance-subnet-id',
    InstanceAvailabilityZone: 'instance-availability-zone', DataVolumeId: 'data-volume-id',
    DataStackName: 'data-stack-name', SourceDataVolumeId: 'source-data-volume-id', AmiId: 'ami-id',
    InstanceType: 'instance-type', RootVolumeGb: 'root-volume-gb', ImageUri: 'image-uri',
    SecretArn: 'secret-arn', LicenseSecretVersionId: 'secret-version-id', TenantId: 'tenant-id',
    DeploymentId: 'deployment-id', CertificateArn: 'certificate-arn', PublicHostname: 'public-hostname',
  };
  const stack = {
    StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012',
    StackName: 'redactwall-cu-test', StackStatus: 'UPDATE_COMPLETE',
    Parameters: Object.entries(parameterNames).map(([ParameterKey, key]) => ({ ParameterKey, ParameterValue: requested[key] })),
    Outputs: [
      { OutputKey: 'InstanceId', OutputValue: 'i-0123456789abcdef0' },
      { OutputKey: 'TargetGroupArn', OutputValue: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abcdef0123456789' },
      { OutputKey: 'DeploymentTemplateUrl', OutputValue: 'https://versioned.example/template?versionId=prior' },
    ],
  };
  const originals = {};
  for (const name of ['runAws', 'verifyRollbackTemplate', 'templateReferenceFromOutputs', 'validateAwsTopology',
    'waitForHostReadiness', 'sendCommand', 'deploy']) originals[name] = deployer[name];
  t.after(() => Object.assign(deployer, originals));
  const events = [];
  let describeCount = 0;
  const leaseState = {};
  deployer.runAws = (args) => {
    events.push(args.join(' '));
    const leaseResult = leaseAwsResult(args, leaseState);
    if (leaseResult != null) return leaseResult;
    if (args[0] === 'cloudformation' && args[1] === 'describe-stacks') {
      describeCount += 1;
      const current = describeCount < 3 ? stack : {
        ...stack,
        Outputs: stack.Outputs.map((entry) => entry.OutputKey === 'InstanceId'
          ? { ...entry, OutputValue: 'i-1123456789abcdef0' } : entry),
      };
      return JSON.stringify({ Stacks: [current] });
    }
    if (args[0] === 'cloudformation' && args[1] === 'get-template') {
      return JSON.stringify({ TemplateBody: { Resources: { Source: { Type: 'AWS::EC2::Instance' } } } });
    }
    return '{}';
  };
  deployer.templateReferenceFromOutputs = (outputs) => outputs;
  deployer.verifyRollbackTemplate = () => ({ templateUrl: 'https://versioned.example/template?versionId=prior', sha256: 'd'.repeat(64) });
  deployer.validateAwsTopology = () => {};
  deployer.waitForHostReadiness = () => {};
  deployer.sendCommand = (_instance, _region, command) => {
    events.push(command);
    if (command === '/usr/local/sbin/redactwall-maintenance-drain') {
      return { output: `REDACTWALL_MAINTENANCE_PHASE=preparing\nREDACTWALL_MAINTENANCE_SET=${'b'.repeat(32)}\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${'c'.repeat(64)}\n` };
    }
    if (command.startsWith('/usr/local/sbin/redactwall-maintenance-checkpoint')) {
      return { output: `REDACTWALL_MAINTENANCE_PHASE=stopped\nREDACTWALL_MAINTENANCE_SET=${'b'.repeat(32)}\nREDACTWALL_MAINTENANCE_BACKUP=backup.dump\nREDACTWALL_MAINTENANCE_MANIFEST=backup.manifest.json\nREDACTWALL_MAINTENANCE_LATCH_SHA256=${'d'.repeat(64)}\n` };
    }
    throw new Error(`unexpected command ${command}`);
  };
  deployer.deploy = () => { throw new Error('deploy must not run after source drift'); };

  assert.throws(() => maintenance.maintain('replace-instance', requested, { log() {}, warn() {} }, {
    accountId: '123456789012', authorityDependencies: memoryAuthorityDependencies(),
  }),
    /changed after the maintenance checkpoint/);
  assert.strictEqual(events.some((event) => event.includes('cloudformation delete-stack')), false);
  assert.strictEqual(events.some((event) => event.includes('redactwall-maintenance-clear')), false);
  assert.strictEqual(events.some((event) => event.includes('redactwall-maintenance-resume')), false);
});

test('ordinary deploy installs a stack policy that blocks create-before-detach replacement', () => {
  const policy = JSON.parse(deployer.replacementBlockingPolicy());
  const deny = policy.Statement.find((statement) => statement.Effect === 'Deny');
  assert.ok(deny.Action.includes('Update:Replace'));
  assert.ok(deny.Resource.includes('LogicalResourceId/AppInstance'));
  assert.ok(deny.Resource.includes('LogicalResourceId/CustomerDataVolumeAttachment'));
});

test('maintenance CLI requires the explicit --mode contract', () => {
  assert.match(source, /argv\[0\] !== '--mode'/);
  assert.match(source, /argv\.slice\(2\)/);
});
