'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const legacy = require('../scripts/aws-legacy-connected-migrate');

function bashExecutable() {
  const candidates = process.platform === 'win32'
    ? ['C:\\Program Files\\Git\\bin\\bash.exe', 'bash.exe']
    : ['bash'];
  return candidates.find((candidate) => {
    const probe = childProcess.spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    return !probe.error && probe.status === 0;
  }) || null;
}

const source = {
  StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/12345678-1234-1234-1234-123456789012',
  StackName: 'redactwall-legacy', StackStatus: 'UPDATE_COMPLETE',
  LastUpdatedTime: '2026-07-13T19:00:00.000Z', RoleARN: 'arn:aws:iam::123456789012:role/redactwall',
  RedactWallTemplateSha256: '1'.repeat(64),
  Parameters: [
    { ParameterKey: 'TenantId', ParameterValue: 'cu-test' },
    { ParameterKey: 'SecretArn', ParameterValue: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-legacy-Ab12' },
    { ParameterKey: 'LicenseSecretVersionId', ParameterValue: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' },
  ],
  Outputs: [
    { OutputKey: 'TenantId', OutputValue: 'cu-test' },
    { OutputKey: 'InstanceId', OutputValue: 'i-0123456789abcdef0' },
    { OutputKey: 'TargetGroupArn', OutputValue: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/redactwall/abc123' },
    { OutputKey: 'DataVolumeId', OutputValue: 'vol-0123456789abcdef0' },
    { OutputKey: 'ImageUri', OutputValue: `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}` },
  ],
};

const input = {
  tenantId: 'cu-test', deploymentId: 'dep_0123456789abcdef0123456789abcdef',
  region: 'us-east-1', connectedSecretVersionId: '12345678-1234-1234-1234-123456789012',
  fallbackArtifactSha256: '2'.repeat(64), offlineTrustPinSha256: '3'.repeat(64),
  verdictTrustPinSha256: '4'.repeat(64), entitlementTrustPinSha256: '5'.repeat(64),
  heartbeatCredentialRef: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12#REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN',
  acknowledgementCredentialRef: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12#REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN',
  sourceTemplateUrl: 'https://redactwall-cfn-123456789012-us-east-1.s3.us-east-1.amazonaws.com/redactwall/legacy.yml?versionId=exact-version',
  sourceTemplateSha256: '6'.repeat(64), sourceTemplateBytes: 60000,
  secretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12',
  deployArgsPath: 'migration.deploy-args.json', deployArgsSha256: '8'.repeat(64), deployArgsBytes: 2048,
  sourceParametersPath: 'migration.source-parameters.json', sourceParametersSha256: '9'.repeat(64),
  sourceParametersBytes: 1024,
};

const deployValues = {
  'stack-name': 'redactwall-legacy', region: 'us-east-1',
  'vpc-id': 'vpc-0123456789abcdef0',
  'public-subnet-ids': 'subnet-0123456789abcdef0,subnet-1123456789abcdef0',
  'instance-subnet-id': 'subnet-0123456789abcdef0',
  'instance-availability-zone': 'us-east-1a',
  'image-uri': `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`,
  'secret-arn': input.secretArn, 'secret-version-id': input.connectedSecretVersionId,
  'tenant-id': input.tenantId, 'deployment-id': input.deploymentId,
  'certificate-arn': 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
  'public-hostname': 'cu-test.redactwall.example', 'data-volume-id': 'vol-0123456789abcdef0',
  'data-stack-name': 'redactwall-legacy-data', 'source-data-volume-id': '',
  'artifact-bucket': 'redactwall-cfn-123456789012-us-east-1',
  'artifact-prefix': 'redactwall/cloudformation', 'ami-id': 'ami-0123456789abcdef0',
  'instance-type': 't3.small', 'root-volume-gb': '20', 'timeout-seconds': '1200',
};
input.deployValues = deployValues;

function freezeCheckpoint() {
  return {
    backup: 'legacy.dump', manifest: 'legacy.manifest.json', containerId: 'c'.repeat(64),
    rootIdentity: '1:2:0:0:700', recoverySetSha256: 'd'.repeat(64), artifactCount: 4,
    auditHead: 'e'.repeat(64), auditCount: 12, auditSequence: 12,
    digest: '7'.repeat(64),
  };
}

function freezeOutput() {
  const checkpoint = freezeCheckpoint();
  return `REDACTWALL_LEGACY_FREEZE_PHASE=frozen\nREDACTWALL_LEGACY_FREEZE_BACKUP=${checkpoint.backup}\nREDACTWALL_LEGACY_FREEZE_MANIFEST=${checkpoint.manifest}\nREDACTWALL_LEGACY_FREEZE_CONTAINER_ID=${checkpoint.containerId}\nREDACTWALL_LEGACY_FREEZE_ROOT_IDENTITY=${checkpoint.rootIdentity}\nREDACTWALL_LEGACY_FREEZE_RECOVERY_SHA256=${checkpoint.recoverySetSha256}\nREDACTWALL_LEGACY_FREEZE_ARTIFACT_COUNT=${checkpoint.artifactCount}\nREDACTWALL_LEGACY_FREEZE_AUDIT_HEAD=${checkpoint.auditHead}\nREDACTWALL_LEGACY_FREEZE_AUDIT_COUNT=${checkpoint.auditCount}\nREDACTWALL_LEGACY_FREEZE_AUDIT_SEQUENCE=${checkpoint.auditSequence}\nREDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=${checkpoint.digest}\n`;
}

function transitionLease(lease, phase, _dependencies = {}, permittedOperationId = 'none') {
  return { ...lease, phase, permittedOperationId };
}

function freezePlanned() {
  return {
    ...legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32)),
    lease: {
      stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/rw-maintenance-test/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      stackName: 'rw-maintenance-test', region: input.region,
      operationId: `rw-${'a'.repeat(32)}`, sourceStackId: source.StackId,
      sourceFingerprint: '9'.repeat(64), phase: 'acquired', permittedOperationId: 'none',
      checkpointSetId: 'none', checkpointLatchSha256: 'none',
    },
  };
}

function exactFreezeBaseline(target = { registered: true, state: 'healthy' }) {
  return { containerId: 'c'.repeat(64), writerState: 'running', target: structuredClone(target) };
}

function oneWayAuthority(state = 'prior') {
  return {
    verifyOneWayAuthorityHighWater: (query) => ({
      schemaVersion: 1,
      kind: 'legacy.connected-authority-high-water.v1',
      purpose: 'legacy.rollback-one-way-authority.v1',
      migrationId: query.migrationId,
      customerId: query.customerId,
      deploymentId: query.deploymentId,
      highWater: state === 'committed' ? 1 : 0,
      state,
      commitmentDigest: state === 'committed' ? 'f'.repeat(64) : null,
    }),
  };
}

function commitWinsBeforeConditionalPermit() {
  let beginCalls = 0;
  return {
    ...oneWayAuthority(),
    beginConditionalAuthorityOperation: () => {
      beginCalls += 1;
      throw new Error('connected authority commit won the external compare-and-swap');
    },
    completeConditionalAuthorityOperation: () => {
      throw new Error('a permit that was never acquired cannot complete');
    },
    beginCalls: () => beginCalls,
  };
}

function completedCleanupState(payload, writerState = 'running', receiptSha256 = 'b'.repeat(64)) {
  const baseline = payload.freezeBaseline || exactFreezeBaseline();
  return {
    containerId: baseline.containerId,
    writerState,
    freezePhase: 'cleared',
    checkpoint: null,
    cleanup: {
      schemaVersion: 1,
      kind: 'legacy.abort-cleanup-receipt.v1',
      phase: 'complete',
      migrationId: payload.migrationId,
      customerId: payload.target.tenantId,
      deploymentId: payload.target.deploymentId,
      sourceStackId: payload.source.stackId,
      instanceId: payload.source.instanceId,
      containerId: baseline.containerId,
      imageUri: payload.source.imageUri,
      checkpointDigest: payload.checkpoint?.digest || 'none',
      rootIdentity: payload.checkpoint?.rootIdentity || '1:2:0:0:700',
      journalSetSha256: 'a'.repeat(64),
      entryCount: payload.checkpoint ? 6 : 1,
      cursor: payload.checkpoint ? 6 : 1,
      currentName: null,
      pendingPublication: false,
      receiptSha256,
    },
  };
}

function requiredCleanupIntent(payload) {
  return {
    kind: 'legacy.abort-cleanup-intent.v1',
    migrationId: payload.migrationId,
    customerId: payload.target.tenantId,
    deploymentId: payload.target.deploymentId,
    sourceStackId: payload.source.stackId,
    instanceId: payload.source.instanceId,
    containerId: payload.freezeBaseline.containerId,
    checkpointDigest: payload.checkpoint?.digest || 'none',
    status: 'required',
    receiptSha256: null,
  };
}

test('legacy plan is valid before DeploymentId exists and binds every connected authority input', () => {
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  assert.strictEqual(payload.phase, 'planned');
  assert.strictEqual(payload.source.deploymentIdPresent, false);
  assert.strictEqual(payload.source.secretArn,
    'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-legacy-Ab12');
  assert.strictEqual(payload.source.secretVersionId, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
  assert.strictEqual(payload.target.deploymentId, input.deploymentId);
  assert.strictEqual(payload.target.connectedSecretVersionId, input.connectedSecretVersionId);
  assert.strictEqual(payload.target.fallbackArtifactSha256, input.fallbackArtifactSha256);
  assert.deepStrictEqual(payload.target.trustPins, {
    offline: input.offlineTrustPinSha256, onlineVerdict: input.verdictTrustPinSha256,
    entitlement: input.entitlementTrustPinSha256,
  });
  assert.deepStrictEqual(payload.target.credentialRefs, {
    heartbeat: input.heartbeatCredentialRef, acknowledgement: input.acknowledgementCredentialRef,
  });
});

test('legacy migration manifest is authenticated and tamper-evident', () => {
  const key = crypto.randomBytes(32);
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  const envelope = legacy.signEnvelope(payload, key);
  assert.deepStrictEqual(legacy.verifyEnvelope(envelope, key), payload);
  const tampered = structuredClone(envelope);
  tampered.payload.target.deploymentId = 'dep_fedcba9876543210fedcba9876543210';
  assert.throws(() => legacy.verifyEnvelope(tampered, key), /authentication/);
});

test('pre-DeploymentId freeze is self-contained, context-free, and stops before final backup', () => {
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  const shell = legacy.legacyFreezeCommand(payload);
  assert.doesNotMatch(shell, /maintenance-context|DeploymentId|connected deployment/i);
  assert.match(shell, /exec 9>\/run\/redactwall-deploy\.lock[\s\S]*flock -w 30/);
  assert.match(shell, /RUNTIME=\/var\/lib\/redactwall\/runtime[\s\S]*stat -c '%u:%g:%a'[\s\S]*1000:1000:700/);
  assert.match(shell, /PARENT=\$RUNTIME\/legacy-connected-migration[\s\S]*0:0:700/);
  assert.doesNotMatch(shell, /install -d[\s\S]*legacy-connected-migration/);
  assert.match(shell, /docker inspect[\s\S]*docker stop -t 30[\s\S]*backup-store\.js create[\s\S]*backup-store\.js verify/);
  assert.match(shell, /recoverySetSha256[\s\S]*artifactCount/);
  assert.match(shell, /auditCheckpointFile[\s\S]*backup-store\.js verify[\s\S]*audit_head=.*\.head/);
  assert.match(shell, /auditHead[\s\S]*auditCount[\s\S]*auditSequence/);
  assert.match(shell, /REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=/);
});

test('legacy migration host commands are syntactically valid when bash is available', (t) => {
  const bash = bashExecutable();
  if (!bash) return t.skip('bash is unavailable');
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  const frozen = { ...payload, phase: 'frozen', checkpoint: freezeCheckpoint() };
  for (const shell of [legacy.legacyPreflightCommand(payload), legacy.legacyFreezeCommand(payload),
    legacy.legacyAbortCommand({ ...payload, freezeBaseline: exactFreezeBaseline() }, oneWayAuthority()),
    legacy.legacyFreezeProbeCommand(payload),
    legacy.legacyFrozenStatusCommand(frozen)]) {
    const result = childProcess.spawnSync(bash, ['-n', '-s'], {
      input: shell, encoding: 'utf8', timeout: 30_000,
    });
    assert.strictEqual(result.status, 0, result.stderr || result.stdout || 'bash syntax check failed');
  }
});

test('machine preflight derives purpose-bound SPKI fingerprints inside the no-network target image', () => {
  const identities = Object.fromEntries(['offline', 'onlineVerdict', 'entitlement'].map((name) => {
    const pair = crypto.generateKeyPairSync('ed25519');
    const der = pair.publicKey.export({ type: 'spki', format: 'der' });
    return [name, {
      publicKey: der.toString('base64'),
      privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
      fingerprint: crypto.createHash('sha256').update(der).digest('hex'),
    }];
  }));
  const secret = {
    REDACTWALL_LICENSE_PUBLIC_KEY_B64: identities.offline.publicKey,
    REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64: identities.onlineVerdict.publicKey,
    REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64: identities.entitlement.publicKey,
  };
  const result = childProcess.spawnSync(process.execPath, ['-e', legacy.TRUST_PIN_PROGRAM], {
    input: JSON.stringify(secret), encoding: 'utf8', timeout: 10_000,
  });
  assert.strictEqual(result.status, 0, result.stderr);
  const fingerprints = JSON.parse(result.stdout);
  assert.deepStrictEqual(fingerprints, {
    offline: identities.offline.fingerprint,
    onlineVerdict: identities.onlineVerdict.fingerprint,
    entitlement: identities.entitlement.fingerprint,
  });

  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  payload.target.trustPins = fingerprints;
  const shell = legacy.legacyPreflightCommand(payload);
  assert.match(shell, /--secret-id[\s\S]*--version-id[\s\S]*--query SecretString/);
  assert.match(shell, /docker run --rm -i --network none --read-only/);
  for (const [purpose, digest] of Object.entries(fingerprints)) {
    assert.ok(shell.includes(`jq -er '.${purpose}')\" = '${digest}'`), `${purpose} is bound to its planned fingerprint`);
  }
  assert.doesNotMatch(shell, new RegExp(identities.offline.publicKey.slice(0, 24)));

  const swapped = childProcess.spawnSync(process.execPath, ['-e', legacy.TRUST_PIN_PROGRAM], {
    input: JSON.stringify({ ...secret,
      REDACTWALL_LICENSE_PUBLIC_KEY_B64: identities.onlineVerdict.publicKey,
      REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64: identities.offline.publicKey,
    }), encoding: 'utf8', timeout: 10_000,
  });
  assert.strictEqual(swapped.status, 0, swapped.stderr);
  const swappedPins = JSON.parse(swapped.stdout);
  assert.strictEqual(swappedPins.offline, fingerprints.onlineVerdict);
  assert.notStrictEqual(swappedPins.offline, fingerprints.offline,
    'a purpose substitution cannot satisfy the exact planned offline comparison');

  const privateMaterial = childProcess.spawnSync(process.execPath, ['-e', legacy.TRUST_PIN_PROGRAM], {
    input: JSON.stringify({ ...secret, REDACTWALL_LICENSE_PUBLIC_KEY_B64: identities.offline.privateKey }),
    encoding: 'utf8', timeout: 10_000,
  });
  assert.notStrictEqual(privateMaterial.status, 0);
  assert.match(privateMaterial.stderr, /private key material/);
  assert.doesNotMatch(privateMaterial.stderr, new RegExp(identities.offline.privateKey.slice(0, 24)));
});

test('executable freeze drains ALB before the stopped-writer checkpoint and records exact evidence', () => {
  const planned = freezePlanned();
  const events = [];
  const targets = [{ registered: true, state: 'healthy' }, { registered: false, state: 'absent' }];
  const frozen = legacy.freezeMigration(planned, '2026-07-13T20:05:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    waitForSsmOnline: () => events.push('ssm-online'),
    runAws: (args) => { events.push(args.slice(0, 3).join(' ')); return '{}'; },
    persist: () => {}, transitionMaintenanceLease: transitionLease,
    targetRegistration: () => targets.shift(),
    readFreezeSourceState: () => ({ containerId: 'c'.repeat(64), writerState: 'running',
      freezePhase: 'absent', checkpoint: null }),
    sendCommand: (_instance, _region, command) => {
      if (command.includes('backup-store.js create')) {
        events.push('freeze');
        return { output: freezeOutput() };
      }
      events.push('preflight');
      return { output: '' };
    },
  });
  assert.strictEqual(frozen.phase, 'frozen');
  assert.deepStrictEqual(frozen.checkpoint, freezeCheckpoint());
  assert.ok(events.indexOf('elbv2 deregister-targets --target-group-arn')
    < events.indexOf('elbv2 wait target-deregistered'));
  assert.ok(events.indexOf('elbv2 wait target-deregistered') < events.indexOf('freeze'));
});

test('freeze failure restarts the exact legacy writer before traffic is re-registered', () => {
  const planned = freezePlanned();
  const events = [];
  const targets = [
    { registered: true, state: 'healthy' }, { registered: false, state: 'absent' },
    { registered: false, state: 'absent' }, { registered: true, state: 'healthy' },
  ];
  const sources = [
    { containerId: 'c'.repeat(64), writerState: 'running', freezePhase: 'absent', checkpoint: null },
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'intent', checkpoint: null },
    completedCleanupState(planned),
  ];
  let sends = 0;
  assert.throws(() => legacy.freezeMigration(planned, '2026-07-13T20:05:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source), waitForSsmOnline() {},
    runAws: (args) => { events.push(args.slice(0, 3).join(' ')); return '{}'; }, persist: () => {},
    transitionMaintenanceLease: transitionLease, releaseMaintenanceLease: () => events.push('lease-release'),
    readLeaseState: (lease) => structuredClone(lease),
    targetRegistration: () => targets.shift(),
    readFreezeSourceState: () => sources.shift(),
    sendCommand: (_instance, _region, command) => {
      sends += 1;
      if (sends === 2) throw new Error('freeze failed');
      events.push(command.includes('docker start') ? 'abort' : 'preflight');
      return { output: command.includes('abort-cleanup-receipt.json')
        ? `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` : '' };
    },
  }), (error) => {
    assert.match(error.message, /legacy freeze operation failed.*retryable/i);
    assert.doesNotMatch(error.message, /freeze failed/);
    return true;
  });
  assert.ok(events.indexOf('abort') < events.indexOf('elbv2 register-targets --target-group-arn'));
  assert.ok(events.indexOf('elbv2 register-targets --target-group-arn')
    < events.indexOf('elbv2 wait target-in-service'));
});

test('P1 freeze snapshots exact prior target state and never registers a provably absent target', () => {
  const persisted = [];
  const awsCalls = [];
  const frozen = legacy.freezeMigration(freezePlanned(), '2026-07-13T20:05:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source), waitForSsmOnline() {},
    transitionMaintenanceLease: transitionLease,
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    readFreezeSourceState: () => ({ containerId: 'c'.repeat(64), writerState: 'running',
      freezePhase: 'absent', checkpoint: null }),
    runAws: (args) => { awsCalls.push(args.join(' ')); return '{}'; },
    persist: (state) => persisted.push(structuredClone(state)),
    sendCommand: (_instance, _region, command) => command.includes('backup-store.js create')
      ? { output: freezeOutput() } : { output: '' },
  });
  assert.strictEqual(frozen.phase, 'frozen');
  const intent = persisted.find((state) => state.phase === 'freeze_deregister_intent');
  assert.deepStrictEqual(intent.freezeBaseline, {
    containerId: 'c'.repeat(64), writerState: 'running',
    target: { registered: false, state: 'absent' },
  });
  assert.ok(persisted.indexOf(intent) < persisted.findIndex((state) => state.phase === 'freeze_target_drained'));
  assert.doesNotMatch(awsCalls.join('\n'), /deregister-targets|register-targets/);
});

test('P1 freeze sanitizes pre-intent query and intent-publication failures before any external mutation', () => {
  let externalCalls = 0;
  assert.throws(() => legacy.freezeMigration(freezePlanned(), '2026-07-13T20:05:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => { throw new Error('raw AWS output C:\\private\\source.json'); },
    persist: () => { externalCalls += 1; },
  }), (error) => {
    assert.match(error.message, /legacy source description query failed before freeze/i);
    assert.doesNotMatch(error.message, /raw AWS output|private|source\.json/i);
    return true;
  });
  assert.strictEqual(externalCalls, 0);
  assert.throws(() => legacy.freezeMigration(freezePlanned(), '2026-07-13T20:05:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    persist: () => { throw new Error('raw witness path C:\\private\\witness.json'); },
    waitForSsmOnline: () => { externalCalls += 1; },
  }), (error) => {
    assert.match(error.message, /legacy freeze intent durable publication failed/i);
    assert.doesNotMatch(error.message, /raw witness path|private|witness\.json/i);
    return true;
  });
  assert.strictEqual(externalCalls, 0);
});

test('P1 freeze response loss adopts an exact stopped checkpoint instead of restarting the writer', () => {
  const states = [
    { containerId: 'c'.repeat(64), writerState: 'running', freezePhase: 'absent', checkpoint: null },
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'frozen',
      checkpoint: freezeCheckpoint() },
  ];
  const targets = [
    { registered: true, state: 'healthy' },
    { registered: false, state: 'absent' },
    { registered: false, state: 'absent' },
  ];
  const events = [];
  const frozen = legacy.freezeMigration(freezePlanned(), '2026-07-13T20:05:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source), waitForSsmOnline() {},
    transitionMaintenanceLease: transitionLease,
    readLeaseState: (lease) => structuredClone(lease),
    targetRegistration: () => targets.shift(),
    readFreezeSourceState: () => states.shift(),
    persist: (state) => events.push(`persist:${state.phase}`),
    runAws: (args) => { events.push(args[1]); return '{}'; },
    sendCommand: (_instance, _region, command) => {
      if (command.includes('backup-store.js create')) throw new Error('freeze response lost');
      if (command.includes('docker start')) events.push('abort');
      return { output: '' };
    },
    releaseMaintenanceLease: () => events.push('release'),
  });
  assert.strictEqual(frozen.phase, 'frozen');
  assert.deepStrictEqual(frozen.checkpoint, freezeCheckpoint());
  assert.doesNotMatch(events.join('\n'), /(^|\n)(abort|register-targets|release)($|\n)/);
  assert.ok(events.includes('persist:frozen'));
});

test('P1 freeze compensation durably restores exact writer and prior target before lease release', () => {
  const sourceStates = [
    { containerId: 'c'.repeat(64), writerState: 'running', freezePhase: 'absent', checkpoint: null },
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'intent', checkpoint: null },
    completedCleanupState(freezePlanned()),
  ];
  const targetStates = [
    { registered: true, state: 'healthy' },
    { registered: false, state: 'absent' },
    { registered: false, state: 'absent' },
    { registered: true, state: 'healthy' },
  ];
  const events = [];
  let thrown;
  try {
    legacy.freezeMigration(freezePlanned(), '2026-07-13T20:05:00.000Z', {
      ...oneWayAuthority(),
      stackDescription: () => structuredClone(source), waitForSsmOnline() {},
      transitionMaintenanceLease: transitionLease,
      readLeaseState: (lease) => structuredClone(lease),
      targetRegistration: () => targetStates.shift(),
      readFreezeSourceState: () => sourceStates.shift(),
      persist: (state) => events.push(`persist:${state.phase}`),
      runAws: (args) => { events.push(args[1]); return '{}'; },
      sendCommand: (_instance, _region, command) => {
        if (command.includes('backup-store.js create')) throw new Error('freeze transport lost');
        if (command.includes('docker start')) events.push('abort');
        return { output: command.includes('abort-cleanup-receipt.json')
          ? `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` : '' };
      },
      releaseMaintenanceLease: () => events.push('release'),
    });
  } catch (error) { thrown = error; }
  assert.match(thrown?.message || '', /legacy freeze operation failed.*retryable/i);
  assert.doesNotMatch(thrown?.message || '', /freeze transport lost/);
  assert.strictEqual(thrown.freezeRecovery.phase, 'retryable');
  assert.ok(events.indexOf('persist:source_restored') < events.indexOf('release'));
  assert.ok(events.indexOf('release') < events.indexOf('persist:retryable'));
  assert.ok(events.indexOf('abort') < events.indexOf('register-targets'));
  assert.ok(events.indexOf('wait') < events.indexOf('persist:source_restored'));
});

test('P1 freeze ambiguity retains authenticated evidence and a sanitized checked command', () => {
  const planned = freezePlanned();
  const failed = { ...planned, phase: 'freeze_failed', freezeBaseline: {
    containerId: 'c'.repeat(64), writerState: 'running',
    target: { registered: true, state: 'healthy' },
  } };
  const persisted = [];
  assert.throws(() => legacy.reconcileFreezeMigration(failed, '2026-07-13T20:06:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    readLeaseState: (lease) => structuredClone(lease),
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    readFreezeSourceState: () => { throw new Error('raw remote response secret'); },
    persist: (state) => persisted.push(structuredClone(state)),
    recoveryCommand: 'node scripts/aws-legacy-connected-migrate.js reconcile --manifest "$REDACTWALL_LEGACY_MANIFEST"; echo raw-secret',
    releaseMaintenanceLease: () => { throw new Error('must retain lease'); },
  }), (error) => {
    assert.match(error.message, /evidence retained.*checked recovery/i);
    assert.match(error.message, /aws-legacy-connected-migrate\.js reconcile/);
    assert.doesNotMatch(error.message, /raw remote response secret/);
    assert.doesNotMatch(error.message, /raw-secret|; echo/);
    assert.doesNotMatch(error.message, /C:\\|\/Users\/|manifest\.json/);
    assert.strictEqual(error.recoveryIdentity.migrationId, failed.migrationId);
    assert.strictEqual(error.recoveryIdentity.leaseStackId, failed.lease.stackId);
    return true;
  });
  assert.strictEqual(persisted.at(-1).phase, 'freeze_failed');
});

test('P1 freeze restart reconciliation covers intent, deregister, writer-stop, and failed windows', () => {
  const cases = [
    { name: 'intent before baseline', phase: 'freeze_intent', baseline: false,
      targetNow: { registered: true, state: 'healthy' }, sourceNow: 'running', expectAbort: false,
      expectRegister: false },
    { name: 'deregister intent before deregister', phase: 'freeze_deregister_intent', baseline: true,
      targetNow: { registered: true, state: 'healthy' }, sourceNow: 'running', expectAbort: false,
      expectRegister: false },
    { name: 'deregister response loss', phase: 'freeze_deregister_intent', baseline: true,
      targetNow: { registered: false, state: 'absent' }, sourceNow: 'running', expectAbort: false,
      expectRegister: true },
    { name: 'writer stopped with intent', phase: 'freeze_target_drained', baseline: true,
      targetNow: { registered: false, state: 'absent' }, sourceNow: 'stopped', expectAbort: true,
      expectRegister: true },
    { name: 'failed journal with stopped writer', phase: 'freeze_failed', baseline: true,
      targetNow: { registered: false, state: 'absent' }, sourceNow: 'stopped', expectAbort: true,
      expectRegister: true },
  ];
  for (const scenario of cases) {
    const planned = freezePlanned();
    planned.lease.phase = 'preparing';
    const state = { ...planned, phase: scenario.phase };
    if (scenario.baseline) {
      state.freezeBaseline = { containerId: 'c'.repeat(64), writerState: 'running',
        target: { registered: true, state: 'healthy' } };
    }
    const events = [];
    let sourceCalls = 0;
    let targetCalls = 0;
    const result = legacy.reconcileFreezeMigration(state, '2026-07-13T20:06:00.000Z', {
      ...oneWayAuthority(),
      stackDescription: () => structuredClone(source),
      readLeaseState: (lease) => structuredClone(lease),
      transitionMaintenanceLease: transitionLease,
      releaseMaintenanceLease: () => events.push('release'),
      readFreezeSourceState: () => {
        sourceCalls += 1;
        const stopped = scenario.sourceNow === 'stopped' && sourceCalls === 1;
        if (scenario.expectAbort && sourceCalls > 1) return completedCleanupState(state);
        return { containerId: 'c'.repeat(64), writerState: stopped ? 'stopped' : 'running',
          freezePhase: stopped ? 'intent' : 'absent', checkpoint: null };
      },
      targetRegistration: () => {
        targetCalls += 1;
        if (targetCalls === 1) return structuredClone(scenario.targetNow);
        return { registered: true, state: 'healthy' };
      },
      sendCommand: (_instance, _region, command) => {
        if (command.includes('docker start')) events.push('abort');
        return { output: command.includes('abort-cleanup-receipt.json')
          ? `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` : '' };
      },
      runAws: (args) => { events.push(args[1]); return '{}'; },
      persist: (next) => events.push(`persist:${next.phase}`),
    });
    assert.strictEqual(result.phase, 'retryable', scenario.name);
    assert.strictEqual(events.includes('abort'), scenario.expectAbort, scenario.name);
    assert.strictEqual(events.includes('register-targets'), scenario.expectRegister, scenario.name);
    assert.ok(events.indexOf('persist:source_restored') < events.indexOf('release'), scenario.name);
    assert.ok(events.indexOf('release') < events.indexOf('persist:retryable'), scenario.name);
  }
});

test('P1 freeze rejects post-intent state without its pre-deregister baseline and retains the lease', () => {
  const state = { ...freezePlanned(), phase: 'freeze_deregister_intent' };
  state.lease.phase = 'preparing';
  let releases = 0;
  assert.throws(() => legacy.reconcileFreezeMigration(state, '2026-07-13T20:06:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    readLeaseState: (lease) => structuredClone(lease),
    readFreezeSourceState: () => ({ containerId: 'c'.repeat(64), writerState: 'running',
      freezePhase: 'absent', checkpoint: null }),
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    releaseMaintenanceLease: () => { releases += 1; },
    persist() {},
  }), (error) => {
    assert.match(error.message, /evidence retained/i);
    assert.strictEqual(error.freezeRecovery.phase, 'freeze_failed');
    return true;
  });
  assert.strictEqual(releases, 0);
});

test('P1 freeze rejects a lease released before durable restoration', () => {
  const state = { ...freezePlanned(), phase: 'freeze_target_drained', freezeBaseline: {
    containerId: 'c'.repeat(64), writerState: 'running',
    target: { registered: true, state: 'healthy' },
  } };
  let sourceQueries = 0;
  assert.throws(() => legacy.reconcileFreezeMigration(state, '2026-07-13T20:06:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    readLeaseState: () => ({ exists: false }),
    readFreezeSourceState: () => { sourceQueries += 1; },
    persist() {},
  }), (error) => {
    assert.match(error.message, /evidence retained/i);
    assert.strictEqual(error.freezeRecovery.phase, 'freeze_failed');
    return true;
  });
  assert.strictEqual(sourceQueries, 0);
});

test('P1 freeze resumes between lease release and retryable persistence without registering a prior-absent target', () => {
  const state = { ...freezePlanned(), phase: 'source_restored', freezeBaseline: {
    containerId: 'c'.repeat(64), writerState: 'running',
    target: { registered: false, state: 'absent' },
  } };
  state.lease.phase = 'release_ready';
  let released = false;
  let durable = structuredClone(state);
  const awsCalls = [];
  const base = {
    stackDescription: () => structuredClone(source),
    readFreezeSourceState: () => ({ containerId: 'c'.repeat(64), writerState: 'running',
      freezePhase: 'absent', checkpoint: null }),
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    runAws: (args) => { awsCalls.push(args[1]); return '{}'; },
    transitionMaintenanceLease: transitionLease,
  };
  assert.throws(() => legacy.reconcileFreezeMigration(state, '2026-07-13T20:06:00.000Z', {
    ...oneWayAuthority(),
    ...base,
    readLeaseState: (lease) => released ? { exists: false } : structuredClone(lease),
    releaseMaintenanceLease: () => { released = true; },
    persist: (next) => {
      if (next.phase === 'retryable') throw new Error('retryable manifest publication failed');
      durable = structuredClone(next);
    },
  }), (error) => {
    assert.match(error.message, /evidence retained/i);
    assert.strictEqual(error.freezeRecovery.phase, 'source_restored');
    return true;
  });
  assert.strictEqual(released, true);
  assert.strictEqual(durable.phase, 'source_restored');
  const reconciled = legacy.reconcileFreezeMigration(durable, '2026-07-13T20:07:00.000Z', {
    ...oneWayAuthority(),
    ...base,
    readLeaseState: () => ({ exists: false }),
    persist: (next) => { durable = structuredClone(next); },
  });
  assert.strictEqual(reconciled.phase, 'retryable');
  assert.doesNotMatch(awsCalls.join('\n'), /register-targets/);
});

test('cutover revalidates the stopped checkpoint and exact source fingerprint before deletion', () => {
  const planned = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  const frozen = { ...planned, phase: 'frozen', lease: { stackId: 'lease', operationId: 'operation' },
    freezeBaseline: exactFreezeBaseline(), checkpoint: freezeCheckpoint() };
  const values = deployValues;
  const events = [];
  const connected = legacy.cutoverMigration(frozen, values, '2026-07-13T20:10:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    sendCommand: () => {
      events.push('checkpoint');
      return { output: `REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=${'7'.repeat(64)}\n` };
    },
    deleteApplicationStack: () => events.push('delete'),
    persist: () => {}, assertLeasePhase: () => {}, transitionMaintenanceLease: transitionLease,
    deploy: (_values, _io, options) => {
      events.push('deploy');
      const stackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/11111111-1111-1111-1111-111111111111';
      options.onOwnership({ operationId: options.operationId, stackId,
        stackName: source.StackName, region: input.region });
      const result = { operationId: options.operationId, stackId, instanceId: 'i-0123456789abcdef0',
        containerId: 'f'.repeat(64), appliedStateSha256: '1'.repeat(64),
        authorityFingerprintSha256: '2'.repeat(64), attestedAt: '2026-07-13T20:09:59.000Z' };
      options.onAttested(result);
      return result;
    },
    io: { log() {}, warn() {} },
  });
  assert.deepStrictEqual(events, ['checkpoint', 'delete', 'deploy']);
  assert.strictEqual(connected.phase, 'connected_candidate');
  const statusShell = legacy.legacyFrozenStatusCommand(frozen);
  assert.match(statusShell, /recoverySetSha256[\s\S]*recovery_digest[\s\S]*backup-store\.js verify/,
    'cutover rehashes and verifies the retained recovery set before source deletion');
  assert.throws(() => legacy.cutoverMigration(frozen, values, '2026-07-13T20:10:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => ({ ...source, LastUpdatedTime: '2026-07-13T20:09:59.000Z' }),
    persist: () => {},
    deleteApplicationStack: () => { throw new Error('must not delete drifted source'); },
  }), /source changed/);
});

test('pre-cutover abort restores traffic before releasing the external lease', () => {
  const frozen = { ...freezePlanned(), phase: 'frozen', freezeBaseline: exactFreezeBaseline(),
    checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  const events = [];
  const targets = [{ registered: false, state: 'absent' }, { registered: true, state: 'healthy' }];
  const sources = [
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'frozen', checkpoint: freezeCheckpoint() },
    completedCleanupState(frozen),
  ];
  const aborted = legacy.abortFrozenMigration(frozen, '2026-07-13T20:10:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    sendCommand: () => {
      events.push('writer');
      return { output: `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` };
    },
    runAws: (args) => { events.push(args[1] === 'register-targets' ? 'register' : 'healthy'); return '{}'; },
    targetRegistration: () => targets.shift(),
    readFreezeSourceState: () => sources.shift(), readLeaseState: (lease) => structuredClone(lease),
    persist: () => {}, transitionMaintenanceLease: transitionLease,
    releaseMaintenanceLease: () => events.push('release'),
  });
  assert.deepStrictEqual(events, ['writer', 'register', 'healthy', 'release']);
  assert.strictEqual(aborted.phase, 'aborted');
});

test('P1 abort removes the exact freeze journal before writer restart and rejects a stranded intent', () => {
  const frozen = { ...freezePlanned(), phase: 'frozen', freezeBaseline: exactFreezeBaseline(),
    checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  const shell = legacy.legacyAbortCommand(frozen, oneWayAuthority());
  const durableReceipt = shell.indexOf('publish_receipt prepared 0 none');
  const retireJournal = shell.indexOf('mv -T "$ROOT" "$CLEANUP"');
  const deletionIntent = shell.indexOf('publish_receipt deleting "$cursor"');
  const removeEntry = shell.indexOf('rm -- "$CLEANUP/$current_name"');
  const removingReceipt = shell.indexOf('publish_receipt removing "$entry_count"');
  const removeCleanupDirectory = shell.indexOf('rmdir -- "$CLEANUP"');
  const completionReceipt = shell.indexOf('publish_receipt complete "$entry_count"');
  const restart = shell.indexOf('docker start "$CONTAINER_ID"');
  assert.ok(durableReceipt >= 0 && retireJournal > durableReceipt
    && deletionIntent > retireJournal && removeEntry > deletionIntent
    && removingReceipt >= 0 && removeCleanupDirectory > removingReceipt
    && completionReceipt > removeCleanupDirectory && restart > completionReceipt,
    'exact journal cleanup must precede writer restart');
  assert.match(shell, /rootIdentity[\s\S]*journalSetSha256[\s\S]*entries[\s\S]*stat -c '%d:%i:%u:%g:%a'/);
  assert.match(shell, /phase == "deleting"[\s\S]*cursor[\s\S]*currentName/,
    'a crash after each deletion is resumed only from the exact durable deletion intent');
  assert.match(shell, /REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=\%s/);

  let released = false;
  const sources = [
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'frozen', checkpoint: freezeCheckpoint() },
    { containerId: 'c'.repeat(64), writerState: 'running', freezePhase: 'intent', checkpoint: null },
  ];
  assert.throws(() => legacy.abortFrozenMigration(frozen, '2026-07-13T20:10:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    sendCommand: () => ({ output: `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` }),
    runAws: () => '{}', targetRegistration: () => ({ registered: true, state: 'healthy' }),
    readFreezeSourceState: () => sources.shift(), readLeaseState: (lease) => structuredClone(lease),
    persist() {}, transitionMaintenanceLease: transitionLease,
    releaseMaintenanceLease: () => { released = true; },
  }), /evidence retained|journal cleanup|freeze state/i);
  assert.strictEqual(released, false, 'intent-only host state must retain the lease');
});

test('P1 abort adopts exact cleared host state after cleanup response loss on restart', () => {
  const frozen = { ...freezePlanned(), phase: 'abort_intent', recoveryDisposition: 'restore',
    freezeBaseline: exactFreezeBaseline({ registered: false, state: 'absent' }), checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  let durable = structuredClone(frozen);
  let released = false;
  let sends = 0;
  const base = {
    ...oneWayAuthority(), stackDescription: () => structuredClone(source),
    readLeaseState: (lease) => released ? { exists: false } : structuredClone(lease),
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    runAws: () => { throw new Error('prior-absent target must not be registered'); },
    transitionMaintenanceLease: transitionLease,
    releaseMaintenanceLease: () => { released = true; },
    persist: (state) => { durable = structuredClone(state); },
  };
  assert.throws(() => legacy.reconcileFreezeMigration(frozen, '2026-07-13T20:10:01.000Z', {
    ...base,
    readFreezeSourceState: () => ({ containerId: 'c'.repeat(64), writerState: 'stopped',
      freezePhase: 'frozen', checkpoint: freezeCheckpoint() }),
    sendCommand: () => {
      sends += 1;
      throw new Error('cleanup completed but SSM response was lost');
    },
  }), /evidence retained/i);
  assert.strictEqual(durable.phase, 'freeze_failed');
  assert.strictEqual(released, false);

  const reconciled = legacy.reconcileFreezeMigration(durable, '2026-07-13T20:10:02.000Z', {
    ...base,
    readFreezeSourceState: () => completedCleanupState(frozen),
    sendCommand: () => { sends += 1; throw new Error('cleared state must not rerun host cleanup'); },
  });
  assert.strictEqual(reconciled.phase, 'retryable');
  assert.strictEqual(released, true);
  assert.strictEqual(sends, 1);
});

test('P1 abort cleanup uses an external durable receipt and resumes every destructive crash window', () => {
  const frozen = { ...freezePlanned(), phase: 'freeze_failed', recoveryDisposition: 'restore',
    freezeBaseline: exactFreezeBaseline({ registered: false, state: 'absent' }), checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  const shell = legacy.legacyAbortCommand(frozen, oneWayAuthority());
  const receiptPublish = shell.indexOf('publish_receipt prepared 0');
  const journalMove = shell.indexOf('mv -T "$ROOT" "$CLEANUP"');
  const deletionIntent = shell.indexOf('publish_receipt deleting "$cursor"');
  const removeEntry = shell.indexOf('rm -- "$CLEANUP/$current_name"');
  const rmdirIntent = shell.indexOf('publish_receipt removing "$entry_count"');
  const removeDirectory = shell.indexOf('rmdir -- "$CLEANUP"');
  const completeReceipt = shell.indexOf('publish_receipt complete "$entry_count"');
  const restart = shell.indexOf('docker start "$CONTAINER_ID"');
  assert.ok(receiptPublish >= 0 && journalMove > receiptPublish
    && deletionIntent > journalMove && removeEntry > deletionIntent
    && rmdirIntent >= 0 && removeDirectory > rmdirIntent
    && completeReceipt > removeDirectory && restart > completeReceipt,
  'each destructive cleanup boundary must be preceded by an exact durable receipt phase');
  assert.match(shell, /abort-cleanup-receipt\.json/);
  assert.match(shell, /journalSetSha256[\s\S]*entries[\s\S]*receiptSha256|journal_set_sha256/);
  assert.match(shell, /REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=\%s/);

  const probe = legacy.legacyFreezeProbeCommand(frozen);
  assert.match(probe, /abort-cleanup-receipt\.json/);
  assert.match(probe, /freezePhase|phase=cleared|phase=cleanup/);
  assert.match(probe, /REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256/);
  assert.match(probe, /phase" = cleared[\s\S]*running" = true[\s\S]*curl[\s\S]*readyz/,
    'a crash after container start cannot release the lease before the exact writer is ready');

  const receiptSha256 = 'b'.repeat(64);
  const sourceStates = [
    completedCleanupState(frozen, 'stopped', receiptSha256),
    completedCleanupState(frozen, 'running', receiptSha256),
  ];
  let released = false;
  const reconciled = legacy.reconcileFreezeMigration(frozen, '2026-07-13T20:10:02.000Z', {
    ...oneWayAuthority(), stackDescription: () => structuredClone(source),
    readFreezeSourceState: () => sourceStates.shift(),
    sendCommand: () => ({ output: `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${receiptSha256}\n` }),
    readLeaseState: (lease) => released ? { exists: false } : structuredClone(lease),
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    runAws: () => { throw new Error('prior-absent target must not be registered'); },
    transitionMaintenanceLease: transitionLease,
    releaseMaintenanceLease: () => { released = true; },
    persist() {},
  });
  assert.strictEqual(reconciled.phase, 'retryable');
  assert.strictEqual(released, true);
});

test('P1 abort cleanup rejects missing, malformed, or cross-scope completion without releasing the lease', () => {
  const frozen = { ...freezePlanned(), phase: 'freeze_failed', recoveryDisposition: 'restore',
    freezeBaseline: exactFreezeBaseline({ registered: false, state: 'absent' }), checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  const completed = completedCleanupState(frozen);
  const absent = { containerId: 'c'.repeat(64), writerState: 'running',
    freezePhase: 'absent', checkpoint: null };
  const cases = [
    ['durable cleanup intent without receipt', { ...structuredClone(frozen),
      abortCleanup: requiredCleanupIntent(frozen) }, absent],
    ['cleared state without receipt', frozen, { ...structuredClone(completed), cleanup: null }],
    ['cross-customer receipt', frozen, { ...structuredClone(completed), cleanup: {
      ...completed.cleanup, customerId: 'cu-other',
    } }],
    ['cross-deployment receipt', frozen, { ...structuredClone(completed), cleanup: {
      ...completed.cleanup, deploymentId: 'dep_fedcba9876543210fedcba9876543210',
    } }],
    ['changed checkpoint receipt', frozen, { ...structuredClone(completed), cleanup: {
      ...completed.cleanup, checkpointDigest: '9'.repeat(64),
    } }],
    ['malformed receipt identity', frozen, { ...structuredClone(completed), cleanup: {
      ...completed.cleanup, receiptSha256: 'not-a-digest',
    } }],
  ];
  for (const [name, state, sourceState] of cases) {
    let sends = 0;
    let releases = 0;
    const persisted = [];
    assert.throws(() => legacy.reconcileFreezeMigration(state, '2026-07-13T20:10:03.000Z', {
      ...oneWayAuthority(), stackDescription: () => structuredClone(source),
      readFreezeSourceState: () => structuredClone(sourceState),
      readLeaseState: (lease) => structuredClone(lease),
      targetRegistration: () => ({ registered: false, state: 'absent' }),
      sendCommand: () => { sends += 1; return { output: '' }; },
      releaseMaintenanceLease: () => { releases += 1; },
      persist: (next) => persisted.push(structuredClone(next)),
    }), /evidence retained|cleanup receipt|cleanup intent|source writer/i, name);
    assert.strictEqual(sends, 0, `${name} must fail before host mutation`);
    assert.strictEqual(releases, 0, `${name} must retain the external lease`);
    assert.strictEqual(persisted.at(-1).phase, 'freeze_failed', name);
  }
});

test('P1 abort cleanup resumes a crash during atomic receipt publication before lease release', () => {
  const frozen = { ...freezePlanned(), phase: 'freeze_failed', recoveryDisposition: 'restore',
    freezeBaseline: exactFreezeBaseline({ registered: false, state: 'absent' }), checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  const pending = completedCleanupState(frozen);
  pending.freezePhase = 'cleanup';
  pending.cleanup.pendingPublication = true;
  const sourceStates = [pending, completedCleanupState(frozen)];
  let sends = 0;
  let released = false;
  const result = legacy.reconcileFreezeMigration(frozen, '2026-07-13T20:10:04.000Z', {
    ...oneWayAuthority(), stackDescription: () => structuredClone(source),
    readFreezeSourceState: () => sourceStates.shift(),
    readLeaseState: (lease) => released ? { exists: false } : structuredClone(lease),
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    sendCommand: () => {
      sends += 1;
      return { output: `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` };
    },
    runAws: () => { throw new Error('prior-absent target must not be registered'); },
    transitionMaintenanceLease: transitionLease,
    releaseMaintenanceLease: () => { released = true; },
    persist() {},
  });
  assert.strictEqual(result.phase, 'retryable');
  assert.strictEqual(sends, 1);
  assert.strictEqual(released, true);
});

test('P1 pre-cutover abort preserves a prior-absent target instead of registering it', () => {
  const frozen = { ...freezePlanned(), phase: 'frozen',
    freezeBaseline: exactFreezeBaseline({ registered: false, state: 'absent' }), checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  const events = [];
  const sources = [
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'frozen', checkpoint: freezeCheckpoint() },
    completedCleanupState(frozen),
  ];
  const aborted = legacy.abortFrozenMigration(frozen, '2026-07-13T20:10:00.000Z', {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    sendCommand: () => {
      events.push('writer');
      return { output: `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` };
    },
    runAws: (args) => { events.push(args[1]); return '{}'; },
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    readFreezeSourceState: () => sources.shift(), readLeaseState: (lease) => structuredClone(lease),
    persist: (state) => events.push(`persist:${state.phase}`), transitionMaintenanceLease: transitionLease,
    releaseMaintenanceLease: () => events.push('release'),
  });
  assert.strictEqual(aborted.phase, 'aborted');
  assert.doesNotMatch(events.join('\n'), /register-targets|target-in-service/);
  assert.ok(events.indexOf('persist:source_restored') < events.indexOf('release'));
  assert.ok(events.indexOf('release') < events.indexOf('persist:retryable'));
});

test('P1 abort intent and final-persist crashes resume from durable exact restoration state', () => {
  const makeFrozen = () => {
    const frozen = { ...freezePlanned(), phase: 'frozen',
      freezeBaseline: exactFreezeBaseline({ registered: false, state: 'absent' }),
      checkpoint: freezeCheckpoint() };
    frozen.lease.phase = 'drained';
    return frozen;
  };
  let durable = makeFrozen();
  let externalCalls = 0;
  assert.throws(() => legacy.abortFrozenMigration(durable, '2026-07-13T20:10:00.000Z', {
    ...oneWayAuthority(),
    persist: (state) => {
      durable = structuredClone(state);
      if (state.phase === 'abort_intent') throw new Error('raw abort manifest path C:\\private\\abort.json');
    },
    sendCommand: () => { externalCalls += 1; },
  }), (error) => {
    assert.match(error.message, /legacy abort intent durable publication failed/i);
    assert.doesNotMatch(error.message, /private|abort\.json|raw abort/i);
    return true;
  });
  assert.strictEqual(durable.phase, 'abort_intent');
  assert.strictEqual(externalCalls, 0);
  let released = false;
  const sources = [
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'frozen', checkpoint: freezeCheckpoint() },
    completedCleanupState(durable),
  ];
  const dependencies = {
    ...oneWayAuthority(),
    stackDescription: () => structuredClone(source),
    readLeaseState: (lease) => released ? { exists: false } : structuredClone(lease),
    readFreezeSourceState: () => sources.shift(),
    targetRegistration: () => ({ registered: false, state: 'absent' }),
    sendCommand: () => {
      externalCalls += 1;
      return { output: `REDACTWALL_LEGACY_ABORT_RECEIPT_SHA256=${'b'.repeat(64)}\n` };
    },
    runAws: () => { throw new Error('must not register a prior-absent target'); },
    transitionMaintenanceLease: transitionLease,
    releaseMaintenanceLease: () => { released = true; },
    persist: (state) => { durable = structuredClone(state); },
  };
  const retryable = legacy.reconcileFreezeMigration(durable, '2026-07-13T20:11:00.000Z', dependencies);
  assert.strictEqual(retryable.phase, 'retryable');
  assert.strictEqual(released, true);
  assert.strictEqual(externalCalls, 1);

  const frozen = makeFrozen();
  durable = structuredClone(frozen);
  released = false;
  const finalSources = [
    { containerId: 'c'.repeat(64), writerState: 'stopped', freezePhase: 'frozen', checkpoint: freezeCheckpoint() },
    completedCleanupState(frozen),
  ];
  assert.throws(() => legacy.abortFrozenMigration(frozen, '2026-07-13T20:12:00.000Z', {
    ...dependencies,
    readFreezeSourceState: () => finalSources.shift(),
    persist: (state) => {
      if (state.phase === 'aborted') throw new Error('raw final path C:\\private\\aborted.json');
      durable = structuredClone(state);
    },
  }), (error) => {
    assert.match(error.message, /aborted-state durable publication failed.*retryable restoration/i);
    assert.doesNotMatch(error.message, /private|aborted\.json|raw final/i);
    assert.strictEqual(error.abortRecovery.phase, 'retryable');
    return true;
  });
  assert.strictEqual(durable.phase, 'retryable');
  assert.doesNotThrow(() => legacy.reconcileFreezeMigration(durable, '2026-07-13T20:13:00.000Z', {
    ...oneWayAuthority(), stackDescription: () => structuredClone(source),
    readLeaseState: () => ({ exists: false }), persist() {},
  }));
});

test('failed candidate cleanup delegates only exact immutable deployment ownership', () => {
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  const failed = { ...payload, phase: 'cutover_failed', lease: { stackId: 'lease', operationId: 'operation' },
    freezeBaseline: exactFreezeBaseline(), checkpoint: freezeCheckpoint(),
    cutover: { operationId: `rw-${'8'.repeat(32)}`,
      stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/11111111-1111-1111-1111-111111111111' } };
  const calls = [];
  const cleaned = legacy.cleanupFailedCandidate(failed, '2026-07-13T20:11:00.000Z', {
    ...oneWayAuthority(),
    removeFailedStackIfOwned: (...args) => calls.push(args),
    persist() {}, restoreOperationId: `rw-${'f'.repeat(32)}`,
  });
  assert.strictEqual(cleaned.phase, 'rollback_ready');
  assert.deepStrictEqual(calls, [[
    { operationId: failed.cutover.operationId, stackId: failed.cutover.stackId,
      stackName: source.StackName, region: input.region },
    source.StackName,
    input.region,
  ]]);
  assert.throws(() => legacy.cleanupFailedCandidate(failed, '2026-07-13T20:11:00.000Z', {
    ...oneWayAuthority(), persist() {},
    removeFailedStackIfOwned: () => { throw new Error('raw AWS ownership output C:\\private\\cleanup.json'); },
  }), (error) => {
    assert.match(error.message, /candidate cleanup adapter failed.*evidence remains retained/i);
    assert.doesNotMatch(error.message, /raw AWS|private|cleanup\.json/i);
    return true;
  });
  let ambiguousRemovals = 0;
  assert.throws(() => legacy.cleanupFailedCandidate({ ...failed, cutover: {
    operationId: null, stackId: null,
  } }, '2026-07-13T20:11:00.000Z', {
    ...oneWayAuthority(), persist() {}, removeFailedStackIfOwned: () => { ambiguousRemovals += 1; },
  }), /candidate ownership.*ambiguous/i);
  assert.strictEqual(ambiguousRemovals, 0);
  let unsafeRemovals = 0;
  assert.throws(() => legacy.cleanupFailedCandidate({ ...failed, freezeBaseline: null },
    '2026-07-13T20:11:00.000Z', {
      ...oneWayAuthority(), persist() {}, removeFailedStackIfOwned: () => { unsafeRemovals += 1; },
    }), /freeze baseline/i);
  assert.strictEqual(unsafeRemovals, 0);
});

test('legacy scalar acknowledgement claims cannot commit connected authority', () => {
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  const frozen = { ...payload, phase: 'frozen', freezeBaseline: exactFreezeBaseline(), checkpoint: freezeCheckpoint() };
  const candidate = { ...frozen, phase: 'connected_candidate', cutover: {
    operationId: `rw-${'8'.repeat(32)}`, stackId: 'connected-stack', instanceId: 'connected-instance',
  } };
  const scalarEvidence = {
    registryGeneration: 9, entitlementVersion: 4,
    deliveredMessageId: '01234567-89ab-4cde-8fab-0123456789ab', deliveredAcceptedAt: '2026-07-13T21:00:00.000Z',
    appliedMessageId: '11234567-89ab-4cde-8fab-0123456789ab', appliedAcceptedAt: '2026-07-13T21:00:01.000Z',
    ownerAuditRef: 'owner_audit_0123456789abcdef', customerAuditRef: 'customer_audit_0123456789abcdef',
  };
  assert.throws(() => legacy.commitConnectedAuthority(candidate, scalarEvidence,
    '2026-07-13T21:00:02.000Z'), /RELEASE-BLOCKED|production proof verifiers/i);
  assert.throws(() => legacy.commitConnectedAuthority(frozen, scalarEvidence,
    '2026-07-13T21:00:02.000Z'), /exact verified connected candidate/);
  assert.doesNotThrow(() => legacy.assertRollbackAllowed(frozen, oneWayAuthority()));
});

test('plan binds exact source customer, complete deploy snapshot, and all AWS target material', () => {
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  assert.strictEqual(payload.source.tenantId, input.tenantId);
  assert.deepStrictEqual(payload.target.aws, {
    stackName: deployValues['stack-name'], region: deployValues.region,
    vpcId: deployValues['vpc-id'], publicSubnetIds: deployValues['public-subnet-ids'],
    instanceSubnetId: deployValues['instance-subnet-id'], availabilityZone: deployValues['instance-availability-zone'],
    imageUri: deployValues['image-uri'], secretArn: deployValues['secret-arn'],
    secretVersionId: deployValues['secret-version-id'], dataVolumeId: deployValues['data-volume-id'],
    dataStackName: deployValues['data-stack-name'], sourceDataVolumeId: '', amiId: deployValues['ami-id'],
    instanceType: 't3.small', rootVolumeGb: '20', certificateArn: deployValues['certificate-arn'],
    publicHostname: deployValues['public-hostname'], artifactBucket: deployValues['artifact-bucket'],
    artifactPrefix: deployValues['artifact-prefix'],
  });
  assert.deepStrictEqual(payload.target.deployArgsSnapshot, {
    path: input.deployArgsPath, sha256: input.deployArgsSha256, bytes: input.deployArgsBytes,
  });
  assert.throws(() => legacy.createManifestPayload({ ...input, tenantId: 'cu-other', deployValues: {
    ...deployValues, 'tenant-id': 'cu-other',
  } }, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32)), /source customer/i);
  for (const [field, value] of [
    ['secret-arn', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/other-Ab12'],
    ['secret-version-id', '87654321-4321-4321-4321-210987654321'],
    ['deployment-id', 'dep_fedcba9876543210fedcba9876543210'],
    ['data-volume-id', 'vol-1123456789abcdef0'],
  ]) {
    assert.throws(() => legacy.createManifestPayload({ ...input, deployValues: {
      ...deployValues, [field]: value,
    } }, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32)), /deployment snapshot.*target|target.*deployment snapshot/i);
  }
});

test('cutover intent is durable before delete and exact returned ownership is durable before wait', () => {
  const base = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  const frozen = { ...base, phase: 'frozen', lease: {
    stackId: 'lease', operationId: `rw-${'a'.repeat(32)}`, phase: 'drained',
  }, freezeBaseline: exactFreezeBaseline(), checkpoint: freezeCheckpoint() };
  const events = [];
  const stackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/11111111-1111-1111-1111-111111111111';
  const connected = legacy.cutoverMigration(frozen, deployValues, '2026-07-13T20:10:00.000Z', {
    ...oneWayAuthority(),
    operationId: `rw-${'e'.repeat(32)}`,
    persist: (state) => events.push(`persist:${state.phase}:${state.cutover?.stackId || 'none'}`),
    assertLeasePhase: () => events.push('lease-readback'),
    transitionMaintenanceLease: transitionLease,
    stackDescription: () => structuredClone(source),
    sendCommand: () => ({ output: `REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=${'7'.repeat(64)}\n` }),
    deleteApplicationStack: () => events.push('delete'),
    deploy: (_values, _io, options) => {
      options.onOwnership({ operationId: options.operationId, stackId, stackName: source.StackName, region: input.region });
      events.push('wait-and-attest');
      const result = { operationId: options.operationId, stackId, instanceId: 'i-0123456789abcdef0',
        containerId: 'f'.repeat(64), appliedStateSha256: '1'.repeat(64),
        authorityFingerprintSha256: '2'.repeat(64), attestedAt: '2026-07-13T20:09:59.000Z' };
      options.onAttested(result);
      return result;
    }, io: { log() {}, warn() {} },
  });
  assert.deepStrictEqual(events.slice(0, 4), [
    'persist:cutover_intent:none', 'lease-readback', 'delete', 'persist:source_deleted:none',
  ]);
  assert.ok(events.indexOf(`persist:candidate_created:${stackId}`) < events.indexOf('wait-and-attest'));
  assert.ok(events.indexOf('wait-and-attest') < events.indexOf(`persist:candidate_attested:${stackId}`));
  assert.strictEqual(connected.phase, 'connected_candidate');
  assert.strictEqual(connected.cutover.operationId, `rw-${'e'.repeat(32)}`);
});

test('cutover crash reconciliation is fail-closed at every durable window', () => {
  const phases = ['cutover_intent', 'source_deleted', 'candidate_created', 'candidate_attested'];
  for (const phase of phases) {
    const state = { version: 1, migrationId: 'b'.repeat(32), phase,
      source: { stackId: source.StackId, stackName: source.StackName, region: input.region },
      target: { tenantId: input.tenantId, deploymentId: input.deploymentId },
      lease: { stackId: 'lease', operationId: `rw-${'a'.repeat(32)}`, phase: 'source_deleted' },
      checkpoint: { digest: '7'.repeat(64) }, cutover: {
        operationId: `rw-${'e'.repeat(32)}`,
        stackId: ['candidate_created', 'candidate_attested'].includes(phase)
          ? 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/11111111-1111-1111-1111-111111111111' : null,
    } };
    const reconciled = legacy.reconcileCutover(state, {
      ...oneWayAuthority(),
      sourceState: () => ({ exists: phase === 'cutover_intent' }),
      candidateState: () => ({ exists: phase !== 'cutover_intent' && phase !== 'source_deleted',
        stackId: state.cutover.stackId, operationId: state.cutover.operationId }),
      assertLeasePhase: () => {},
      verifyConnectedStack: () => ({ ok: phase === 'candidate_attested' }),
    });
    assert.notStrictEqual(reconciled.phase, 'connected_authority_committed');
    if (phase === 'candidate_attested') assert.strictEqual(reconciled.phase, 'connected_candidate');
  }
});

test('cutover reconciliation durably recovers source deletion and exact candidate ownership', () => {
  const candidateStackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/22222222-2222-2222-2222-222222222222';
  const operationId = `rw-${'e'.repeat(32)}`;
  const initial = {
    version: 1, migrationId: 'b'.repeat(32), phase: 'cutover_intent',
    source: { stackId: source.StackId, stackName: source.StackName, region: input.region },
    target: { tenantId: input.tenantId, deploymentId: input.deploymentId },
    lease: { stackId: 'lease', operationId: `rw-${'a'.repeat(32)}`, phase: 'drained',
      permittedOperationId: 'none' },
    checkpoint: { digest: '7'.repeat(64) },
    cutover: { operationId, stackId: null },
  };
  let externalPhase = 'drained';
  let externalPermittedOperation = 'none';
  const persisted = [];
  const reconciled = legacy.reconcileCutover(initial, {
    ...oneWayAuthority(),
    sourceState: () => ({ exists: false }),
    candidateState: () => ({ exists: true, stackId: candidateStackId, operationId }),
    assertLeasePhase: (lease, phase) => {
      if (phase !== externalPhase || lease.permittedOperationId !== externalPermittedOperation) {
        throw new Error('stale lease projection');
      }
    },
    transitionMaintenanceLease: (lease, phase, _dependencies, permittedOperationId) => {
      externalPhase = phase;
      externalPermittedOperation = permittedOperationId;
      return { ...lease, phase, permittedOperationId };
    },
    persist: (state) => persisted.push(structuredClone(state)),
  });
  assert.strictEqual(reconciled.phase, 'candidate_created');
  assert.strictEqual(reconciled.cutover.stackId, candidateStackId);
  assert.strictEqual(reconciled.lease.phase, 'candidate');
  assert.strictEqual(reconciled.lease.permittedOperationId, operationId);
  assert.ok(persisted.some((state) => state.phase === 'source_deleted' && state.lease.phase === 'source_deleted'));
  assert.ok(persisted.some((state) => state.phase === 'candidate_created' && state.lease.phase === 'candidate'));
});

test('P1 cutover reconciliation verifies the independent one-way high-water before every side effect', () => {
  const candidate = proofCandidate();
  const state = { ...structuredClone(candidate), phase: 'cutover_intent' };
  state.cutover.stackId = null;
  const variants = [
    ['missing', {}],
    ['throwing', { verifyOneWayAuthorityHighWater: () => { throw new Error('raw vendor state'); } }],
    ['malformed', { verifyOneWayAuthorityHighWater: () => ({ state: 'prior' }) }],
    ['cross-scope', { verifyOneWayAuthorityHighWater: (query) => ({
      schemaVersion: 1, kind: 'legacy.connected-authority-high-water.v1',
      purpose: 'legacy.rollback-one-way-authority.v1', migrationId: query.migrationId,
      customerId: 'cu-other', deploymentId: query.deploymentId,
      highWater: 0, state: 'prior', commitmentDigest: null,
    }) }],
    ['committed', oneWayAuthority('committed')],
  ];
  for (const [name, authority] of variants) {
    const calls = [];
    assert.throws(() => legacy.reconcileCutover(state, {
      ...authority,
      sourceState: () => { calls.push('source'); return { exists: false }; },
      candidateState: () => { calls.push('candidate'); return { exists: false }; },
      persist: () => calls.push('persist'),
      transitionMaintenanceLease: () => { calls.push('lease'); return state.lease; },
    }), /one-way|rollback|release-blocked|disabled|unavailable|ambiguous/i, name);
    assert.deepStrictEqual(calls, [], `${name} authority must fail before source, persistence, or lease access`);
  }
});

function proofCandidate() {
  const payload = legacy.createManifestPayload(input, source, '2026-07-13T20:00:00.000Z', 'b'.repeat(32));
  return { ...payload, phase: 'connected_candidate', checkpoint: freezeCheckpoint(),
    freezeBaseline: exactFreezeBaseline(), lease: {
    stackId: 'lease-stack', stackName: 'lease-name', region: input.region,
    operationId: `rw-${'a'.repeat(32)}`, sourceStackId: source.StackId,
    sourceFingerprint: '9'.repeat(64), phase: 'candidate', permittedOperationId: `rw-${'e'.repeat(32)}`,
    checkpointSetId: 'b'.repeat(32), checkpointLatchSha256: '7'.repeat(64),
  }, cutover: {
    operationId: `rw-${'e'.repeat(32)}`,
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/11111111-1111-1111-1111-111111111111',
    instanceId: 'i-0123456789abcdef0', containerId: 'f'.repeat(64),
    appliedStateSha256: '1'.repeat(64), authorityFingerprintSha256: '2'.repeat(64),
    attestedAt: '2026-07-13T20:10:00.000Z',
  } };
}

function authorityReceipt(candidate, purpose) {
  return {
    purpose, migrationId: candidate.migrationId, customerId: candidate.target.tenantId,
    deploymentId: candidate.target.deploymentId, operationId: candidate.cutover.operationId,
    stackId: candidate.cutover.stackId, instanceId: candidate.cutover.instanceId,
    containerId: candidate.cutover.containerId, appliedStateSha256: candidate.cutover.appliedStateSha256,
    authorityFingerprintSha256: candidate.cutover.authorityFingerprintSha256,
    registryGeneration: 9, registryStateDigest: '3'.repeat(64), entitlementVersion: 4,
    artifactDigest: '4'.repeat(64), deliveredMessageId: '01234567-89ab-4cde-8fab-0123456789ab',
    deliveredAcceptedAt: '2026-07-13T20:10:01.000Z', appliedMessageId: '11234567-89ab-4cde-8fab-0123456789ab',
    appliedAcceptedAt: '2026-07-13T20:10:02.000Z', ownerAuditRef: `owner_audit_${'a'.repeat(64)}`,
    ownerAuditHead: '5'.repeat(64), customerAuditRef: `customer_audit_${'b'.repeat(64)}`,
    customerAuditHead: '6'.repeat(64), ownerAuthorityFingerprint: '7'.repeat(64),
    customerAuthorityFingerprint: '8'.repeat(64), observedAt: '2026-07-13T20:10:03.000Z',
  };
}

function externalPublicationState(request, state) {
  return { ...structuredClone(request), state };
}

function connectedProof(candidate) {
  const owner = authorityReceipt(candidate, 'owner.durable-ack-acceptance.v1');
  const customer = authorityReceipt(candidate, 'customer.acknowledged-high-water.v1');
  return {
    receipts: { ownerRaw: JSON.stringify({ signed: owner }),
      customerRaw: JSON.stringify({ authenticated: customer }) },
    verifyOwnerReceipt: () => owner,
    verifyCustomerReceipt: () => customer,
  };
}

test('acknowledgement receipts use exact acknowledgement.v1 UUID messageIds and reject legacy aliases', () => {
  const candidate = proofCandidate();
  const uuidReceipt = (purpose) => {
    const receipt = authorityReceipt(candidate, purpose);
    return receipt;
  };
  const owner = uuidReceipt('owner.durable-ack-acceptance.v1');
  const customer = uuidReceipt('customer.acknowledged-high-water.v1');
  assert.doesNotThrow(() => legacy.validateConnectedEvidence(candidate, {
    ownerRaw: JSON.stringify(owner), customerRaw: JSON.stringify(customer),
  }, '2026-07-13T20:10:04.000Z', {
    verifyOwnerReceipt: () => owner, verifyCustomerReceipt: () => customer,
  }));

  for (const [name, invalid] of [
    ['legacy alias', { deliveredMessageId: 'ack_delivered_0123456789abcdef' }],
    ['noncanonical uppercase', { deliveredMessageId: owner.deliveredMessageId.toUpperCase() }],
    ['same stage message', { appliedMessageId: owner.deliveredMessageId }],
  ]) {
    const ownerInvalid = { ...owner, ...invalid };
    const customerInvalid = { ...customer, ...invalid };
    assert.throws(() => legacy.validateConnectedEvidence(candidate, {
      ownerRaw: JSON.stringify(ownerInvalid), customerRaw: JSON.stringify(customerInvalid),
    }, '2026-07-13T20:10:04.000Z', {
      verifyOwnerReceipt: () => ownerInvalid, verifyCustomerReceipt: () => customerInvalid,
    }), /acknowledgement|receipt|evidence/i, name);
  }
});

test('authority receipts require purpose-specific full-length audit references', () => {
  const candidate = proofCandidate();
  const owner = authorityReceipt(candidate, 'owner.durable-ack-acceptance.v1');
  const customer = authorityReceipt(candidate, 'customer.acknowledged-high-water.v1');
  owner.ownerAuditRef = `owner_audit_${'a'.repeat(64)}`;
  owner.customerAuditRef = `customer_audit_${'b'.repeat(64)}`;
  customer.ownerAuditRef = owner.ownerAuditRef;
  customer.customerAuditRef = owner.customerAuditRef;
  const verify = (ownerReceipt, customerReceipt) => legacy.validateConnectedEvidence(candidate, {
    ownerRaw: JSON.stringify(ownerReceipt), customerRaw: JSON.stringify(customerReceipt),
  }, '2026-07-13T20:10:04.000Z', {
    verifyOwnerReceipt: () => ownerReceipt, verifyCustomerReceipt: () => customerReceipt,
  });
  assert.doesNotThrow(() => verify(owner, customer));

  for (const [name, ownerAuditRef, customerAuditRef] of [
    ['short owner', `owner_audit_${'a'.repeat(63)}`, owner.customerAuditRef],
    ['long owner', `owner_audit_${'a'.repeat(65)}`, owner.customerAuditRef],
    ['uppercase owner', `owner_audit_${'A'.repeat(64)}`, owner.customerAuditRef],
    ['swapped owner prefix', `customer_audit_${'a'.repeat(64)}`, owner.customerAuditRef],
    ['short customer', owner.ownerAuditRef, `customer_audit_${'b'.repeat(63)}`],
    ['long customer', owner.ownerAuditRef, `customer_audit_${'b'.repeat(65)}`],
    ['uppercase customer', owner.ownerAuditRef, `customer_audit_${'B'.repeat(64)}`],
    ['swapped customer prefix', owner.ownerAuditRef, `owner_audit_${'b'.repeat(64)}`],
  ]) {
    const changedOwner = { ...owner, ownerAuditRef, customerAuditRef };
    const changedCustomer = { ...customer, ownerAuditRef, customerAuditRef };
    assert.throws(() => verify(changedOwner, changedCustomer), /audit evidence|receipt/i, name);
  }
});

test('P1 authority commit durably tombstones before CAS and finalizes only after exact external readback', () => {
  const candidate = proofCandidate();
  const proof = connectedProof(candidate);
  const phases = [];
  const durable = [];
  const requests = [];
  let external = 'prior';
  const dependencies = {
    ...proof,
    commitOperationId: `rw-${'d'.repeat(32)}`,
    persist: (state) => {
      phases.push(`persist:${state.phase}`);
      durable.push(structuredClone(state));
    },
    queryPublicationState: (request) => {
      phases.push(`query:${external}`);
      requests.push(structuredClone(request));
      return externalPublicationState(request, external);
    },
    publishCas: () => {
      phases.push('cas');
      external = 'committed';
      return true;
    },
  };
  const committed = legacy.commitConnectedAuthority(candidate, proof.receipts,
    '2026-07-13T20:10:04.000Z', dependencies);
  assert.deepStrictEqual(phases, [
    'persist:connected_authority_commit_prepared',
    'persist:connected_authority_commit_uncertain',
    'query:prior', 'cas', 'query:committed',
    'persist:connected_authority_committed',
  ]);
  assert.strictEqual(committed.phase, 'connected_authority_committed');
  assert.strictEqual(requests[0].migrationId, candidate.migrationId);
  assert.strictEqual(requests[0].customerId, candidate.target.tenantId);
  assert.strictEqual(requests[0].deploymentId, candidate.target.deploymentId);
  assert.strictEqual(requests[0].stackId, candidate.cutover.stackId);
  assert.strictEqual(requests[0].instanceId, candidate.cutover.instanceId);
  assert.strictEqual(requests[0].containerId, candidate.cutover.containerId);
  assert.strictEqual(requests[0].appliedStateSha256, candidate.cutover.appliedStateSha256);
  assert.strictEqual(requests[0].authorityFingerprintSha256, candidate.cutover.authorityFingerprintSha256);
  assert.match(requests[0].expectedPayloadDigest, /^[a-f0-9]{64}$/);
  assert.match(requests[0].nextPayloadDigest, /^[a-f0-9]{64}$/);
  assert.match(requests[0].evidenceDigest, /^[a-f0-9]{64}$/);
  for (const blocked of durable.slice(0, 2)) {
    assert.throws(() => legacy.assertRollbackAllowed(blocked), /permanently disabled|one-way/i);
    assert.throws(() => legacy.legacyAbortCommand(blocked), /permanently disabled|one-way/i);
    assert.throws(() => legacy.abortFrozenMigration(blocked, '2026-07-13T20:11:00.000Z'), /permanently disabled|one-way/i);
    assert.throws(() => legacy.cleanupFailedCandidate(blocked, '2026-07-13T20:11:00.000Z'), /permanently disabled|one-way/i);
    assert.throws(() => legacy.restorePrecommitCandidate(blocked, '2026-07-13T20:11:00.000Z'), /permanently disabled|one-way/i);
  }
});

test('P1 authority commit reconciles CAS response loss and final witness failure across restart', () => {
  const candidate = proofCandidate();
  const proof = connectedProof(candidate);
  let external = 'prior';
  let durable = candidate;
  let failFinalWitness = true;
  let casCalls = 0;
  const dependencies = {
    ...proof,
    commitOperationId: `rw-${'d'.repeat(32)}`,
    persist: (state) => {
      if (state.phase === 'connected_authority_committed' && failFinalWitness) {
        throw new Error('witness publication failed');
      }
      durable = structuredClone(state);
    },
    queryPublicationState: (request) => externalPublicationState(request, external),
    publishCas: () => {
      casCalls += 1;
      external = 'committed';
      throw new Error('CAS response lost');
    },
  };
  assert.throws(() => legacy.commitConnectedAuthority(candidate, proof.receipts,
    '2026-07-13T20:10:04.000Z', dependencies), (error) => {
    assert.match(error.message, /connected authority connected_authority_committed durable publication failed/i);
    assert.doesNotMatch(error.message, /witness publication failed/);
    return true;
  });
  assert.strictEqual(external, 'committed');
  assert.strictEqual(durable.phase, 'connected_authority_commit_uncertain');
  assert.throws(() => legacy.assertRollbackAllowed(durable), /permanently disabled|one-way/i);
  failFinalWitness = false;
  const reconciled = legacy.reconcileConnectedAuthorityCommit(durable, dependencies);
  assert.strictEqual(reconciled.phase, 'connected_authority_committed');
  assert.strictEqual(casCalls, 1, 'restart readback must not issue a second CAS after exact committed proof');
});

test('P1 authority commit survives final manifest failure and never trusts CAS false without readback', () => {
  const candidate = proofCandidate();
  const proof = connectedProof(candidate);
  let external = 'prior';
  let durable = candidate;
  let failManifest = true;
  const dependencies = {
    ...proof,
    commitOperationId: `rw-${'d'.repeat(32)}`,
    persist: (state) => {
      durable = structuredClone(state);
      if (state.phase === 'connected_authority_committed' && failManifest) {
        throw new Error('manifest publication failed after witness');
      }
    },
    queryPublicationState: (request) => externalPublicationState(request, external),
    publishCas: () => false,
  };
  assert.throws(() => legacy.commitConnectedAuthority(candidate, proof.receipts,
    '2026-07-13T20:10:04.000Z', dependencies), /external publication remains prior|uncertain/i);
  assert.strictEqual(durable.phase, 'connected_authority_commit_uncertain');
  assert.throws(() => legacy.assertRollbackAllowed(durable), /permanently disabled|one-way/i);
  dependencies.publishCas = () => { external = 'committed'; return true; };
  assert.throws(() => legacy.reconcileConnectedAuthorityCommit(durable, dependencies), (error) => {
    assert.match(error.message, /connected authority connected_authority_committed durable publication failed/i);
    assert.doesNotMatch(error.message, /manifest publication failed/);
    return true;
  });
  assert.strictEqual(durable.phase, 'connected_authority_committed',
    'witness-first publication makes committed state authoritative despite manifest failure');
  failManifest = false;
  assert.strictEqual(legacy.reconcileConnectedAuthorityCommit(durable, dependencies).phase,
    'connected_authority_committed');
});

test('P1 authority commit requires exact external query and CAS adapters before the tombstone boundary', () => {
  const candidate = proofCandidate();
  const proof = connectedProof(candidate);
  let persisted = 0;
  assert.throws(() => legacy.commitConnectedAuthority(candidate, proof.receipts,
    '2026-07-13T20:10:04.000Z', { ...proof, persist: () => { persisted += 1; }, publishCas: () => true }),
  /RELEASE-BLOCKED.*query|query.*RELEASE-BLOCKED/i);
  assert.strictEqual(persisted, 0);
  assert.throws(() => legacy.commitConnectedAuthority(candidate, proof.receipts,
    '2026-07-13T20:10:04.000Z', { ...proof, persist: () => { persisted += 1; },
      queryPublicationState: () => ({ state: 'prior' }) }), /RELEASE-BLOCKED.*CAS|CAS.*RELEASE-BLOCKED/i);
  assert.strictEqual(persisted, 0);
});

test('P1 authority commit never calls external query or CAS when prepared or uncertain durability fails', () => {
  const cases = [
    { name: 'prepared witness', phase: 'connected_authority_commit_prepared', durableBeforeThrow: false,
      expectedDurable: 'connected_candidate' },
    { name: 'prepared manifest', phase: 'connected_authority_commit_prepared', durableBeforeThrow: true,
      expectedDurable: 'connected_authority_commit_prepared' },
    { name: 'uncertain witness', phase: 'connected_authority_commit_uncertain', durableBeforeThrow: false,
      expectedDurable: 'connected_authority_commit_prepared' },
    { name: 'uncertain manifest', phase: 'connected_authority_commit_uncertain', durableBeforeThrow: true,
      expectedDurable: 'connected_authority_commit_uncertain' },
  ];
  for (const scenario of cases) {
    const candidate = proofCandidate();
    const proof = connectedProof(candidate);
    let durable = structuredClone(candidate);
    let queryCalls = 0;
    let casCalls = 0;
    assert.throws(() => legacy.commitConnectedAuthority(candidate, proof.receipts,
      '2026-07-13T20:10:04.000Z', {
        ...proof,
        commitOperationId: `rw-${'d'.repeat(32)}`,
        persist: (state) => {
          if (state.phase === scenario.phase) {
            if (scenario.durableBeforeThrow) durable = structuredClone(state);
            throw new Error(`${scenario.name} publication failed`);
          }
          durable = structuredClone(state);
        },
        queryPublicationState: (request) => {
          queryCalls += 1;
          return externalPublicationState(request, 'prior');
        },
        publishCas: () => { casCalls += 1; return true; },
      }), (error) => {
        assert.match(error.message, new RegExp(`connected authority ${scenario.phase} durable publication failed`, 'i'));
        assert.doesNotMatch(error.message, new RegExp(`${scenario.name} publication failed`, 'i'));
        return true;
      }, scenario.name);
    assert.strictEqual(queryCalls, 0, scenario.name);
    assert.strictEqual(casCalls, 0, scenario.name);
    assert.strictEqual(durable.phase, scenario.expectedDurable, scenario.name);
    if (durable.phase === 'connected_candidate') {
      assert.doesNotThrow(() => legacy.assertRollbackAllowed(durable, oneWayAuthority()), scenario.name);
      continue;
    }
    assert.throws(() => legacy.assertRollbackAllowed(durable), /permanently disabled|one-way/i,
      scenario.name);
    let external = 'prior';
    const reconciled = legacy.reconcileConnectedAuthorityCommit(durable, {
      persist: (state) => { durable = structuredClone(state); },
      queryPublicationState: (request) => externalPublicationState(request, external),
      publishCas: () => { casCalls += 1; external = 'committed'; return true; },
    });
    assert.strictEqual(reconciled.phase, 'connected_authority_committed', scenario.name);
    assert.strictEqual(casCalls, 1, scenario.name);
  }
});

test('P1 authority commit rejects changed or failed exact readback without leaking adapter output', () => {
  for (const mode of ['changed', 'mutated-request', 'throw']) {
    const candidate = proofCandidate();
    const proof = connectedProof(candidate);
    let durable = structuredClone(candidate);
    let casCalls = 0;
    assert.throws(() => legacy.commitConnectedAuthority(candidate, proof.receipts,
      '2026-07-13T20:10:04.000Z', {
        ...proof,
        commitOperationId: `rw-${'d'.repeat(32)}`,
        persist: (state) => { durable = structuredClone(state); },
        queryPublicationState: (request) => {
          if (mode === 'throw') throw new Error('raw-adapter-secret C:\\private\\manifest.json');
          if (mode === 'mutated-request') {
            request.stackId = `${request.stackId}-adapter-mutated`;
            return externalPublicationState(request, 'prior');
          }
          return { ...externalPublicationState(request, 'prior'), stackId: `${request.stackId}-changed`,
            rawDiagnostic: 'raw-adapter-secret' };
        },
        publishCas: () => { casCalls += 1; return true; },
      }), (error) => {
        assert.match(error.message, /readback.*unavailable|ambiguous/i);
        assert.doesNotMatch(error.message, /raw-adapter-secret|private|manifest\.json|changed/);
        assert.strictEqual(error.commitUncertain.phase, 'connected_authority_commit_uncertain');
        return true;
      });
    assert.strictEqual(durable.phase, 'connected_authority_commit_uncertain', mode);
    assert.strictEqual(casCalls, 0, mode);
    assert.throws(() => legacy.assertRollbackAllowed(durable), /permanently disabled|one-way/i, mode);
  }
});

test('authority commit accepts only two production-verified bound raw receipts and CAS publication', () => {
  const candidate = proofCandidate();
  const owner = authorityReceipt(candidate, 'owner.durable-ack-acceptance.v1');
  const customer = authorityReceipt(candidate, 'customer.acknowledged-high-water.v1');
  const ownerRaw = JSON.stringify({ signed: owner });
  const customerRaw = JSON.stringify({ authenticated: customer });
  let external = 'prior';
  const verifiers = {
    verifyOwnerReceipt: (raw) => {
      if (raw !== ownerRaw) throw new Error('owner signature invalid');
      return owner;
    },
    verifyCustomerReceipt: (raw) => {
      if (raw !== customerRaw) throw new Error('customer authentication invalid');
      return customer;
    },
    commitOperationId: `rw-${'d'.repeat(32)}`,
    persist: () => {},
    queryPublicationState: (request) => externalPublicationState(request, external),
    publishCas: () => { external = 'committed'; return true; },
  };
  assert.throws(() => legacy.commitConnectedAuthority(candidate, { ownerRaw, customerRaw },
    '2026-07-13T20:10:04.000Z'), /RELEASE-BLOCKED|production proof verifiers/i);
  const committed = legacy.commitConnectedAuthority(candidate, { ownerRaw, customerRaw },
    '2026-07-13T20:10:04.000Z', verifiers);
  assert.strictEqual(committed.phase, 'connected_authority_committed');
  assert.match(committed.authorityCommit.ownerProofDigest, /^[a-f0-9]{64}$/);
  assert.match(committed.authorityCommit.customerProofDigest, /^[a-f0-9]{64}$/);
  external = 'prior';
  assert.throws(() => legacy.commitConnectedAuthority(candidate, { ownerRaw, customerRaw },
    '2026-07-13T20:10:04.000Z', { ...verifiers, publishCas: () => false }), /publication remains prior/i);
});

test('wrong, fabricated, delivered-only, stale, or mismatched authority receipts never commit', () => {
  const candidate = proofCandidate();
  const baseOwner = authorityReceipt(candidate, 'owner.durable-ack-acceptance.v1');
  const baseCustomer = authorityReceipt(candidate, 'customer.acknowledged-high-water.v1');
  const cases = [
    ['wrong customer', { ...baseOwner, customerId: 'cu-other' }, baseCustomer],
    ['wrong stack', { ...baseOwner, stackId: `${baseOwner.stackId}-other` }, baseCustomer],
    ['wrong instance', baseOwner, { ...baseCustomer, instanceId: 'i-1123456789abcdef0' }],
    ['delivered only', { ...baseOwner, appliedMessageId: undefined, appliedAcceptedAt: undefined }, baseCustomer],
    ['stale', { ...baseOwner, observedAt: '2026-07-13T19:00:00.000Z' }, baseCustomer],
  ];
  for (const [name, owner, customer] of cases) {
    const adapters = {
      persist: () => {}, queryPublicationState: (request) => externalPublicationState(request, 'prior'),
      publishCas: () => true, commitOperationId: `rw-${'d'.repeat(32)}`,
    };
    assert.throws(() => legacy.commitConnectedAuthority(candidate,
      { ownerRaw: JSON.stringify(owner), customerRaw: JSON.stringify(customer) },
      '2026-07-13T20:10:04.000Z', {
        ...adapters, verifyOwnerReceipt: () => owner, verifyCustomerReceipt: () => customer,
      }), undefined, name);
  }
  assert.throws(() => legacy.commitConnectedAuthority(candidate,
    { ownerRaw: JSON.stringify(baseOwner), customerRaw: JSON.stringify(baseCustomer) },
    '2026-07-13T20:10:04.000Z', {
      verifyOwnerReceipt: () => { throw new Error('fabricated receipt C:\\private\\owner-receipt.json'); },
      verifyCustomerReceipt: () => baseCustomer,
      persist: () => {}, queryPublicationState: (request) => externalPublicationState(request, 'prior'),
      publishCas: () => true, commitOperationId: `rw-${'d'.repeat(32)}`,
    }), (error) => {
    assert.match(error.message, /Owner connected authority receipt verification failed/i);
    assert.doesNotMatch(error.message, /fabricated|receipt.*\{|[A-Za-z]:\\/i);
    return true;
  });
});

test('independent witness rejects replay of an older valid frozen manifest', () => {
  const key = crypto.randomBytes(32);
  const frozen = { ...proofCandidate(), phase: 'frozen', cutover: null, authorityCommit: null };
  const current = proofCandidate();
  const witness = legacy.signWitness({ sequence: 5, migrationId: current.migrationId,
    phase: current.phase, manifestDigest: legacy.payloadDigest(current), payload: current }, key);
  assert.throws(() => legacy.verifyStateAgainstWitness(frozen, witness, key), /replay|witness/i);
  assert.deepStrictEqual(legacy.verifyStateAgainstWitness(current, witness, key), current);
});

test('P1 external one-way high-water blocks a restored valid precommit witness after authority commit', () => {
  const candidate = proofCandidate();
  const restoredFrozen = { ...structuredClone(candidate), phase: 'frozen', cutover: null,
    authorityCommit: null };
  restoredFrozen.lease.phase = 'drained';
  restoredFrozen.lease.permittedOperationId = 'none';
  const committedAuthority = oneWayAuthority('committed');
  let sideEffects = 0;

  assert.throws(() => legacy.assertRollbackAllowed(restoredFrozen, committedAuthority),
    /permanently disabled|one-way/i);
  assert.throws(() => legacy.legacyAbortCommand(restoredFrozen, committedAuthority),
    /permanently disabled|one-way/i);
  assert.throws(() => legacy.abortFrozenMigration(restoredFrozen, '2026-07-13T20:20:00.000Z', {
    ...committedAuthority, persist: () => { sideEffects += 1; },
    sendCommand: () => { sideEffects += 1; },
  }), /permanently disabled|one-way/i);
  const restoredFailed = { ...structuredClone(candidate), phase: 'cutover_failed' };
  assert.throws(() => legacy.cleanupFailedCandidate(restoredFailed, '2026-07-13T20:20:00.000Z', {
    ...committedAuthority, persist: () => { sideEffects += 1; },
    removeFailedStackIfOwned: () => { sideEffects += 1; },
  }), /permanently disabled|one-way/i);
  assert.throws(() => legacy.restorePrecommitCandidate(candidate, '2026-07-13T20:20:00.000Z', {
    ...committedAuthority, persist: () => { sideEffects += 1; },
    restoreLegacy: () => { sideEffects += 1; },
  }), /permanently disabled|one-way/i);
  const restoredFreezeFailure = { ...structuredClone(restoredFrozen), phase: 'freeze_failed' };
  assert.throws(() => legacy.reconcileFreezeMigration(restoredFreezeFailure,
    '2026-07-13T20:20:00.000Z', { ...committedAuthority, persist: () => { sideEffects += 1; } }),
  /permanently disabled|one-way/i);
  assert.throws(() => legacy.freezeMigration(freezePlanned(), '2026-07-13T20:20:00.000Z', {
    ...committedAuthority, persist: () => { sideEffects += 1; },
  }), /permanently disabled|one-way/i);
  assert.throws(() => legacy.cutoverMigration(restoredFrozen, deployValues,
    '2026-07-13T20:20:00.000Z', {
      ...committedAuthority,
      persist: () => { sideEffects += 1; },
      stackDescription: () => { sideEffects += 1; return structuredClone(source); },
      sendCommand: () => { sideEffects += 1; return { output: '' }; },
      deleteApplicationStack: () => { sideEffects += 1; },
    }), /permanently disabled|one-way/i);
  assert.strictEqual(sideEffects, 0);

  assert.throws(() => legacy.assertRollbackAllowed(restoredFrozen, {
    verifyOneWayAuthorityHighWater: () => { throw new Error('raw external secret'); },
  }), (error) => {
    assert.match(error.message, /unavailable|ambiguous|rollback stays disabled/i);
    assert.doesNotMatch(error.message, /raw external secret/i);
    return true;
  });
});

test('P1 external commit winning after the prior read blocks every candidate cleanup, restore, and cutover effect', () => {
  const candidate = proofCandidate();
  const failed = { ...structuredClone(candidate), phase: 'cutover_failed' };
  const cleanupAuthority = commitWinsBeforeConditionalPermit();
  let cleanupEffects = 0;
  assert.throws(() => legacy.cleanupFailedCandidate(failed, '2026-07-13T20:20:00.000Z', {
    ...cleanupAuthority, restoreOperationId: `rw-${'f'.repeat(32)}`,
    persist() {}, removeFailedStackIfOwned: () => { cleanupEffects += 1; },
  }), /conditional|permit|commit.*won|one-way/i);
  assert.strictEqual(cleanupAuthority.beginCalls(), 1);
  assert.strictEqual(cleanupEffects, 0);

  const restoreAuthority = commitWinsBeforeConditionalPermit();
  let restoreEffects = 0;
  assert.throws(() => legacy.restorePrecommitCandidate(candidate, '2026-07-13T20:20:00.000Z', {
    ...restoreAuthority, restoreOperationId: `rw-${'f'.repeat(32)}`, persist() {},
    removeCandidate: () => { restoreEffects += 1; },
    transitionMaintenanceLease: (lease, phase) => { restoreEffects += 1; return { ...lease, phase }; },
    restoreLegacy: () => { restoreEffects += 1; return {}; },
    releaseMaintenanceLease: () => { restoreEffects += 1; },
  }), /conditional|permit|commit.*won|one-way/i);
  assert.strictEqual(restoreAuthority.beginCalls(), 1);
  assert.strictEqual(restoreEffects, 0);

  const cutoverAuthority = commitWinsBeforeConditionalPermit();
  let cutoverEffects = 0;
  const frozen = { ...freezePlanned(), phase: 'frozen', freezeBaseline: exactFreezeBaseline(),
    checkpoint: freezeCheckpoint() };
  frozen.lease.phase = 'drained';
  assert.throws(() => legacy.cutoverMigration(frozen, deployValues, '2026-07-13T20:20:00.000Z', {
    ...cutoverAuthority, operationId: `rw-${'e'.repeat(32)}`, persist() {},
    stackDescription: () => structuredClone(source), assertLeasePhase() {},
    sendCommand: () => ({ output: `REDACTWALL_LEGACY_FREEZE_CHECKPOINT_SHA256=${'7'.repeat(64)}\n` }),
    deleteApplicationStack: () => { cutoverEffects += 1; },
    deploy: () => { cutoverEffects += 1; return {}; },
  }), /conditional|permit|commit.*won|one-way/i);
  assert.strictEqual(cutoverAuthority.beginCalls(), 1);
  assert.strictEqual(cutoverEffects, 0);
});

test('connected candidate can be exactly cleaned and legacy recovery restored before proof commit', () => {
  const candidate = proofCandidate();
  const events = [];
  const restoreOperationId = `rw-${'f'.repeat(32)}`;
  const restoredStackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/22222222-2222-2222-2222-222222222222';
  const restored = legacy.restorePrecommitCandidate(candidate, '2026-07-13T20:20:00.000Z', {
    ...oneWayAuthority(), restoreOperationId,
    persist: (state) => events.push(`persist:${state.phase}`),
    removeCandidate: (ownership) => events.push(`remove:${ownership.stackId}`),
    transitionMaintenanceLease: (lease, phase, _dependencies, permittedOperationId = 'none') => {
      events.push(`lease:${phase}`);
      return { ...lease, phase, permittedOperationId };
    },
    releaseMaintenanceLease: () => events.push('lease:released'),
    restoreLegacy: (state, expected) => {
      events.push(`restore:${expected.operationId}`);
      assert.deepStrictEqual(expected.targetRegistration, state.freezeBaseline.target);
      return {
        operationId: expected.operationId, stackId: restoredStackId,
        stackName: source.StackName, region: input.region, instanceId: 'i-1123456789abcdef0',
        containerId: 'a'.repeat(64), imageUri: state.source.imageUri,
        dataVolumeId: state.source.dataVolumeId, templateSha256: state.source.rollbackTemplate.sha256,
        parametersSha256: state.source.parametersSha256, checkpointSha256: state.checkpoint.digest,
        recoverySetSha256: state.checkpoint.recoverySetSha256,
        writerReady: true, targetRegistration: structuredClone(state.freezeBaseline.target),
        attestedAt: '2026-07-13T20:20:01.000Z',
      };
    },
  });
  assert.deepStrictEqual(events, [
    'persist:candidate_cleanup_intent', `remove:${candidate.cutover.stackId}`, 'persist:rollback_ready',
    'lease:restoring', 'persist:restore_intent', `restore:${restoreOperationId}`,
    'persist:legacy_restore_attested', 'lease:release_ready',
    'persist:legacy_restore_release_ready', 'lease:released', 'persist:legacy_restored',
  ]);
  assert.strictEqual(restored.phase, 'legacy_restored');
  assert.strictEqual(restored.restore.stackId, restoredStackId);
  assert.strictEqual(restored.leaseReleased, true);
});

test('P1 precommit restore rejects an attestation that changes the exact prior target state', () => {
  const candidate = proofCandidate();
  candidate.phase = 'restore_intent';
  candidate.freezeBaseline = exactFreezeBaseline({ registered: false, state: 'absent' });
  candidate.lease.phase = 'restoring';
  const restoreOperationId = `rw-${'f'.repeat(32)}`;
  candidate.rollback = {
    candidateOwnership: { operationId: candidate.cutover.operationId, stackId: candidate.cutover.stackId,
      stackName: candidate.source.stackName, region: candidate.source.region },
    restoreOperationId, candidateRemovedAt: '2026-07-13T20:19:00.000Z',
  };
  assert.throws(() => legacy.restorePrecommitCandidate(candidate, '2026-07-13T20:20:00.000Z', {
    ...oneWayAuthority(), restoreOperationId, persist() {},
    restoreLegacy: (state, expected) => {
      assert.deepStrictEqual(expected.targetRegistration, { registered: false, state: 'absent' });
      return {
        operationId: expected.operationId,
        stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-legacy/22222222-2222-2222-2222-222222222222',
        stackName: source.StackName, region: input.region, instanceId: 'i-1123456789abcdef0',
        containerId: 'a'.repeat(64), imageUri: state.source.imageUri,
        dataVolumeId: state.source.dataVolumeId, templateSha256: state.source.rollbackTemplate.sha256,
        parametersSha256: state.source.parametersSha256, checkpointSha256: state.checkpoint.digest,
        recoverySetSha256: state.checkpoint.recoverySetSha256, writerReady: true,
        targetRegistration: { registered: true, state: 'healthy' },
        attestedAt: '2026-07-13T20:20:01.000Z',
      };
    },
  }), /exact stopped-writer recovery contract/i);
  assert.throws(() => legacy.restorePrecommitCandidate(candidate, '2026-07-13T20:20:00.000Z', {
    ...oneWayAuthority(), restoreOperationId, persist() {},
    restoreLegacy: () => { throw new Error('raw AWS restore output C:\\private\\restore.json'); },
  }), (error) => {
    assert.match(error.message, /restore adapter failed.*evidence remain retained/i);
    assert.doesNotMatch(error.message, /raw AWS|private|restore\.json/i);
    return true;
  });
});

test('connected verification resolves exact cutover StackId and rejects same-name replacement', () => {
  const candidate = proofCandidate();
  const exact = {
    exists: true, stackId: candidate.cutover.stackId, stackName: source.StackName,
    tags: { RedactWallDeploymentOperation: candidate.cutover.operationId },
    outputs: { TenantId: input.tenantId, DeploymentId: input.deploymentId,
      LicenseSecretVersionId: input.connectedSecretVersionId, InstanceId: candidate.cutover.instanceId },
  };
  assert.doesNotThrow(() => legacy.verifyConnectedStack(candidate, {
    stackState: (id) => { assert.strictEqual(id, candidate.cutover.stackId); return exact; },
    verifyAppliedAttestation: () => candidate.cutover,
  }));
  assert.throws(() => legacy.verifyConnectedStack(candidate, {
    stackState: () => ({ ...exact, stackId: `${candidate.cutover.stackId}-replacement` }),
    verifyAppliedAttestation: () => candidate.cutover,
  }), /exact candidate|StackId/i);
});

test('production restore and authority verification remain release-blocked without injected adapters', () => {
  const candidate = proofCandidate();
  assert.throws(() => legacy.restorePrecommitCandidate(candidate, '2026-07-13T20:20:00.000Z'),
    /RELEASE-BLOCKED.*one-way rollback authority verifier/i);
  assert.throws(() => legacy.restorePrecommitCandidate(candidate, '2026-07-13T20:20:00.000Z',
    oneWayAuthority()),
    /RELEASE-BLOCKED.*restore adapter/i);
  const exact = {
    exists: true, stackId: candidate.cutover.stackId, stackName: source.StackName,
    tags: { RedactWallDeploymentOperation: candidate.cutover.operationId },
    outputs: { TenantId: input.tenantId, DeploymentId: input.deploymentId,
      LicenseSecretVersionId: input.connectedSecretVersionId, InstanceId: candidate.cutover.instanceId },
  };
  assert.throws(() => legacy.verifyConnectedStack(candidate, { stackState: () => exact }),
    /RELEASE-BLOCKED.*attestation verifier/i);
});

test('CLI rejects scalar authority claims and unknown plan inputs', () => {
  const common = { manifest: 'manifest.json', witness: 'witness.json',
    'manifest-key': 'manifest.key', 'witness-key': 'witness.key' };
  assert.throws(() => legacy.assertCommandOptions('commit', {
    ...common, 'owner-receipt-file': 'owner.receipt', 'customer-receipt-file': 'customer.receipt',
    'registry-generation': '9',
  }), /registry-generation.*not valid/i);
  assert.throws(() => legacy.assertCommandOptions('commit', {
    ...common, 'owner-receipt-file': 'owner.receipt', 'customer-receipt-file': 'customer.receipt',
    'applied-ack-id': 'ack_applied_0123456789abcdef',
  }), /applied-ack-id.*not valid/i);
  assert.throws(() => legacy.assertCommandOptions('plan', { ...common, 'secret-json': 'raw-secret.json' }),
    /secret-json.*not valid/i);
});

test('live source template capture is version-bound, private, complete, and checksum-verified', () => {
  const sourceCode = legacy.captureLiveTemplate.toString();
  assert.match(sourceCode, /verifyArtifactBucket/);
  assert.match(sourceCode, /head-object[\s\S]*--version-id[\s\S]*--checksum-mode/);
  assert.match(sourceCode, /--expected-bucket-owner/);
  assert.match(sourceCode, /get-object[\s\S]*reference\.versionId/);
  assert.match(sourceCode, /securePrivatePath[\s\S]*readBoundedRegularFile/);
  assert.match(sourceCode, /downloaded\.length !== bytes[\s\S]*sha256\(downloaded\) !== digest[\s\S]*ChecksumSHA256/);
});
