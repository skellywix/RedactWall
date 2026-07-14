'use strict';

const test = require('node:test');
const assert = require('node:assert');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const deployer = require('../scripts/aws-silo-deploy');

const validArgs = [
  '--stack-name', 'redactwall-cu-test',
  '--region', 'us-east-1',
  '--vpc-id', 'vpc-0123456789abcdef0',
  '--public-subnet-ids', 'subnet-0123456789abcdef0,subnet-1123456789abcdef0',
  '--instance-subnet-id', 'subnet-0123456789abcdef0',
  '--instance-availability-zone', 'us-east-1a',
  '--data-volume-id', 'vol-0123456789abcdef0',
  '--data-stack-name', 'redactwall-cu-test-data',
  '--ami-id', 'ami-0123456789abcdef0',
  '--artifact-bucket', 'redactwall-cfn-123456789012-us-east-1',
  '--image-uri', `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`,
  '--secret-arn', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12',
  '--secret-version-id', '12345678-1234-1234-1234-123456789012',
  '--tenant-id', 'cu-test',
  '--deployment-id', 'dep_0123456789abcdef0123456789abcdef',
  '--certificate-arn', 'arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012',
  '--public-hostname', 'cu-test.redactwall.example',
];

function memoryAuthorityDependencies() {
  let current = null;
  let sequence = 0;
  const publish = (location, state) => {
    sequence += 1;
    const bodySha256 = crypto.createHash('sha256').update(JSON.stringify(state)).digest('hex');
    current = {
      bodySha256,
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

test('silo deploy parser accepts one complete bounded deployment contract', () => {
  const parsed = deployer.validate(deployer.parseArgs(validArgs));
  assert.strictEqual(parsed['deployment-id'], 'dep_0123456789abcdef0123456789abcdef');
  assert.strictEqual(parsed['timeout-seconds'], '1200');
  assert.strictEqual(parsed['artifact-prefix'], 'redactwall/cloudformation');
  assert.strictEqual(parsed['instance-type'], 't3.small');
});

test('silo deploy parser rejects shell injection, legacy licensing controls, and invalid deployment ids before AWS access', () => {
  for (const [option, value] of [
    ['--image-uri', "x'; touch /tmp/pwned; echo 'x"],
    ['--secret-version-id', 'x$(whoami)'],
    ['--public-hostname', 'safe.example;whoami'],
    ['--deployment-id', 'deployment_legacy_001'],
  ]) {
    const candidate = [...validArgs];
    candidate[candidate.indexOf(option) + 1] = value;
    assert.throws(() => deployer.validate(deployer.parseArgs(candidate)));
  }
  assert.throws(() => deployer.parseArgs([...validArgs, '--seat-limit', '25']), /unknown option/);
  assert.throws(() => deployer.parseArgs([...validArgs, '--license-mode', 'offline']), /unknown option/);
  assert.throws(() => deployer.parseArgs([...validArgs, '--unknown-option', 'value']), /unknown option/);
  const wrongRegion = [...validArgs];
  wrongRegion[wrongRegion.indexOf('--image-uri') + 1] = `123456789012.dkr.ecr.us-west-2.amazonaws.com/redactwall@sha256:${'a'.repeat(64)}`;
  assert.throws(() => deployer.validate(deployer.parseArgs(wrongRegion)), /must be in --region/);
});

test('existing stacks must publish and preserve the exact connected deployment identity', () => {
  const values = deployer.validate(deployer.parseArgs(validArgs));
  assert.throws(
    () => deployer.assertConnectedDeploymentIdentity(true, {}, values),
    /lacks the immutable connected deployment identity/,
  );
  assert.throws(
    () => deployer.assertConnectedDeploymentIdentity(true, {
      DeploymentId: 'dep_fedcba9876543210fedcba9876543210',
    }, values),
    /deployment id is immutable/,
  );
  assert.doesNotThrow(() => deployer.assertConnectedDeploymentIdentity(true, {
    DeploymentId: values['deployment-id'],
  }, values));
});

test('silo deploy waits for SSM apply-and-attest after CloudFormation', (t) => {
  const original = childProcess.spawnSync;
  const calls = [];
  let staged = null;
  const values = deployer.validate(deployer.parseArgs(validArgs));
  const stackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012';
  const configSha256 = deployer.desiredConfigSha256(values);
  const protocolSha256 = crypto.createHash('sha256').update(fs.readFileSync(
    require('node:path').join(__dirname, '..', 'infra', 'aws', 'scripts', 'redactwall-deploy.sh'),
  )).digest('hex');
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = (_executable, args) => {
    calls.push(args);
    if (args[0] === 'cloudformation' && args[1] === 'update-stack') {
      return { status: 0, stdout: JSON.stringify({
        StackId: stackId,
      }), stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'get-bucket-location') return { status: 0, stdout: '{"LocationConstraint":null}', stderr: '' };
    if (args[0] === 's3api' && args[1] === 'get-public-access-block') return { status: 0, stdout: JSON.stringify({ PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true } }), stderr: '' };
    if (args[0] === 's3api' && args[1] === 'get-bucket-versioning') return { status: 0, stdout: '{"Status":"Enabled"}', stderr: '' };
    if (args[0] === 's3api' && args[1] === 'get-bucket-ownership-controls') return { status: 0, stdout: '{"OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}}', stderr: '' };
    if (args[0] === 's3api' && args[1] === 'get-bucket-encryption') return { status: 0, stdout: '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}}', stderr: '' };
    if (args[0] === 's3api' && args[1] === 'get-bucket-policy') return { status: 0, stdout: JSON.stringify({ Policy: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: ['arn:aws:s3:::redactwall-cfn-123456789012-us-east-1', 'arn:aws:s3:::redactwall-cfn-123456789012-us-east-1/*'], Condition: { Bool: { 'aws:SecureTransport': 'false' } } }] }) }), stderr: '' };
    if (args[0] === 's3api' && args[1] === 'put-object') {
      const body = fs.readFileSync(args[args.indexOf('--body') + 1]);
      const key = args[args.indexOf('--key') + 1];
      staged = { body, checksum: args[args.indexOf('--checksum-sha256') + 1], metadata: args[args.indexOf('--metadata') + 1], key,
        version: 'version/with+symbols=',
        templateUrl: `https://redactwall-cfn-123456789012-us-east-1.s3.us-east-1.amazonaws.com/${key}?versionId=version%2Fwith%2Bsymbols%3D` };
      return { status: 0, stdout: '{"VersionId":"version/with+symbols="}', stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'head-object') return { status: 0, stdout: JSON.stringify({
      ContentLength: staged.body.length, Metadata: { sha256: staged.metadata.split('=')[1] },
      ChecksumSHA256: staged.checksum, ServerSideEncryption: 'AES256',
    }), stderr: '' };
    if (args[0] === 'sts' && args[1] === 'get-caller-identity') return { status: 0, stdout: '{"Account":"123456789012"}', stderr: '' };
    if (args[0] === 'acm' && args[1] === 'describe-certificate') return { status: 0, stdout: JSON.stringify({ Certificate: { Status: 'ISSUED', DomainName: '*.redactwall.example', SubjectAlternativeNames: ['*.redactwall.example'] } }), stderr: '' };
    if (args[0] === 'ec2' && args[1] === 'describe-subnets') {
      return { status: 0, stdout: JSON.stringify({ Subnets: [
        { SubnetId: 'subnet-0123456789abcdef0', VpcId: 'vpc-0123456789abcdef0', AvailabilityZone: 'us-east-1a' },
        { SubnetId: 'subnet-1123456789abcdef0', VpcId: 'vpc-0123456789abcdef0', AvailabilityZone: 'us-east-1b' },
      ] }), stderr: '' };
    }
    if (args[0] === 'ec2' && args[1] === 'describe-volumes') {
      return { status: 0, stdout: JSON.stringify({ Volumes: [{
        VolumeId: 'vol-0123456789abcdef0', Encrypted: true,
        VolumeType: 'gp3', MultiAttachEnabled: false,
        AvailabilityZone: 'us-east-1a', State: 'in-use', SnapshotId: '', Attachments: [
          { InstanceId: 'i-0123456789abcdef0', Device: '/dev/sdf', State: 'attached' },
        ], Tags: [
          { Key: 'RedactWallTenant', Value: 'cu-test' }, { Key: 'RedactWallPurpose', Value: 'evidence-store' },
          { Key: 'RedactWallAuthority', Value: 'retained-external' },
          { Key: 'aws:cloudformation:stack-name', Value: 'redactwall-cu-test-data' },
          { Key: 'aws:cloudformation:logical-id', Value: 'CustomerDataVolume' },
          { Key: 'aws:cloudformation:stack-id', Value: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test-data/12345678-1234-1234-1234-123456789012' },
        ],
      }] }), stderr: '' };
    }
    if (args[0] === 'cloudformation' && args[1] === 'describe-stacks') {
      const stackName = args[args.indexOf('--stack-name') + 1];
      if (String(stackName).startsWith('rw-maintenance-')) {
        return { status: 255, stdout: '', stderr: `An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id ${stackName} does not exist` };
      }
      if (stackName === 'redactwall-cu-test-data') return { status: 0, stdout: JSON.stringify({ Stacks: [{
        StackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test-data/12345678-1234-1234-1234-123456789012', Outputs: [
        { OutputKey: 'DataVolumeId', OutputValue: 'vol-0123456789abcdef0' },
        { OutputKey: 'AvailabilityZone', OutputValue: 'us-east-1a' }, { OutputKey: 'TenantId', OutputValue: 'cu-test' },
        { OutputKey: 'SourceDataVolumeId', OutputValue: '' },
      ] }] }), stderr: '' };
      return { status: 0, stdout: JSON.stringify({ Stacks: [{
        StackId: stackId, Outputs: [
        { OutputKey: 'InstanceId', OutputValue: 'i-0123456789abcdef0' },
        { OutputKey: 'DataVolumeId', OutputValue: 'vol-0123456789abcdef0' },
        { OutputKey: 'DataStackName', OutputValue: 'redactwall-cu-test-data' },
        { OutputKey: 'SourceDataVolumeId', OutputValue: '' },
        { OutputKey: 'InstanceAvailabilityZone', OutputValue: 'us-east-1a' },
        { OutputKey: 'TenantId', OutputValue: 'cu-test' },
        { OutputKey: 'DeploymentId', OutputValue: 'dep_0123456789abcdef0123456789abcdef' },
        { OutputKey: 'AmiId', OutputValue: 'ami-0123456789abcdef0' },
        { OutputKey: 'InstanceType', OutputValue: 't3.small' }, { OutputKey: 'RootVolumeGb', OutputValue: '20' },
        { OutputKey: 'DesiredConfigSha256', OutputValue: configSha256 },
        { OutputKey: 'DeploymentTemplateUrl', OutputValue: staged.templateUrl },
        { OutputKey: 'DeploymentTemplateSha256', OutputValue: staged.metadata.split('=')[1] },
        { OutputKey: 'DeploymentTemplateBytes', OutputValue: String(staged.body.length) },
        { OutputKey: 'DeploymentProtocolSha256', OutputValue: protocolSha256 },
      ] }] }), stderr: '' };
    }
    if (args[0] === 'ssm' && args[1] === 'send-command') {
      return { status: 0, stdout: '12345678-1234-1234-1234-123456789012\n', stderr: '' };
    }
    if (args[0] === 'ssm' && args[1] === 'describe-instance-information') {
      return { status: 0, stdout: JSON.stringify({ InstanceInformationList: [{ InstanceId: 'i-0123456789abcdef0', PingStatus: 'Online' }] }), stderr: '' };
    }
    if (args[0] === 'ssm' && args[1] === 'get-command-invocation') {
      const attestedAt = '2026-07-13T20:00:00.000Z';
      const containerId = '4'.repeat(64);
      const appliedStateDigest = '5'.repeat(64);
      const recoverySetId = 'none';
      const authorityFingerprint = deployer.appliedAuthorityFingerprint({
        appliedAt: attestedAt,
        appliedStateDigest,
        configSha256,
        containerId,
        deploymentId: values['deployment-id'],
        imageUri: values['image-uri'],
        protocolSha256,
        recoverySetId,
        secretArn: values['secret-arn'],
        secretVersionId: values['secret-version-id'],
        stackId,
        templateSha256: staged.metadata.split('=')[1],
        tenantId: values['tenant-id'],
      });
      return { status: 0, stdout: JSON.stringify({ Status: 'Success', StandardOutputContent: [
        'REDACTWALL_APPLIED_WARNING=evidence_scheduler_setup_failed',
        `REDACTWALL_APPLIED_CONTAINER_ID=${containerId}`,
        `REDACTWALL_APPLIED_STATE_DIGEST=${appliedStateDigest}`,
        `REDACTWALL_APPLIED_AUTHORITY_FINGERPRINT=${authorityFingerprint}`,
        `REDACTWALL_APPLIED_AT=${attestedAt}`,
        `REDACTWALL_APPLIED_RECOVERY_SET_ID=${recoverySetId}`,
      ].join('\n') }), stderr: '' };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  const lines = [];
  const result = deployer.deploy(values, { log: (line) => lines.push(line) }, {
    authorityDependencies: memoryAuthorityDependencies(),
  });
  const deployIndex = calls.findIndex((args) => args[0] === 'cloudformation' && args[1] === 'update-stack');
  const validateTemplate = calls.find((args) => args[0] === 'cloudformation' && args[1] === 'validate-template');
  assert.ok(validateTemplate.includes('--template-url'));
  assert.ok(!validateTemplate.includes('--template-body'));
  assert.strictEqual(calls[deployIndex][calls[deployIndex].indexOf('--template-url') + 1], staged.templateUrl);
  assert.strictEqual(validateTemplate[validateTemplate.indexOf('--template-url') + 1], staged.templateUrl);
  assert.strictEqual(calls.filter((args) => args[0] === 's3api' && args[1] === 'put-object').length, 1);
  assert.strictEqual(calls.some((args) => args[0] === 'cloudformation' && args[1] === 'deploy'), false);
  assert.ok(calls.filter((args) => args[0] === 's3api').every((args) => args.includes('--expected-bucket-owner')));
  assert.ok(staged.body.length > 51_200, 'test exercises the oversized customer template');
  assert.strictEqual(crypto.createHash('sha256').update(staged.body).digest('hex'), staged.metadata.split('=')[1]);
  assert.ok(!staged.body.includes(Buffer.from('12345678-1234-1234-1234-123456789012')),
    'immutable secret version input never enters the staged template object');
  const sendIndexes = calls.map((args, index) => ({ args, index }))
    .filter(({ args }) => args[0] === 'ssm' && args[1] === 'send-command')
    .map(({ index }) => index);
  const validateIndex = sendIndexes.find((index) => /redactwall-validate-release-input[\s\S]*--image-uri/.test(calls[index].join(' ')));
  const applyIndex = sendIndexes.find((index) => /redactwall-apply-and-attest[\s\S]*--image-uri/.test(calls[index].join(' ')));
  assert.ok(validateIndex >= 0 && validateIndex < deployIndex && deployIndex < applyIndex);
  assert.doesNotMatch(calls[applyIndex].join(' '), /(?:^|\s)cfn-init(?:\s|$)|\/opt\/aws\/bin\/cfn-init/,
    'SSM may invoke only the lock-and-latch enforcing apply wrapper');
  assert.match(calls[validateIndex].join(' '), /--deployment-id dep_0123456789abcdef0123456789abcdef/);
  assert.doesNotMatch(calls[validateIndex].join(' '), /--seat-limit|--license-mode/);
  const stackMutation = calls[deployIndex].join(' ');
  assert.match(stackMutation, /DeploymentId/);
  assert.doesNotMatch(stackMutation, /SeatLimit|LicenseMode/);
  assert.match(calls[applyIndex].join(' '), new RegExp(`${configSha256}[\\s\\S]*${staged.metadata.split('=')[1]}[\\s\\S]*${protocolSha256}`));
  assert.ok(sendIndexes.some((index) => /redactwall-data-identity\.service/.test(calls[index].join(' '))),
    'initial and replacement hosts wait for data-volume and Docker unit readiness');
  assert.deepStrictEqual(result.warnings, ['evidence_scheduler_setup_failed']);
  assert.match(lines.join('\n'), /committed with warning: evidence_scheduler_setup_failed/);
  assert.match(lines.join('\n'), /applied and attested/);
});

test('new stack creation binds one immutable operation id to the exact returned StackId', (t) => {
  const original = childProcess.spawnSync;
  const calls = [];
  const stackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012';
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = (_executable, args) => {
    calls.push(args);
    if (args[0] === 'cloudformation' && args[1] === 'create-stack') {
      return { status: 0, stdout: JSON.stringify({ StackId: stackId }), stderr: '' };
    }
    if (args[0] === 'cloudformation' && args[1] === 'describe-stacks') {
      return { status: 0, stdout: JSON.stringify({ Stacks: [{
        StackId: stackId, StackName: 'redactwall-cu-test', StackStatus: 'CREATE_COMPLETE', Outputs: [],
      }] }), stderr: '' };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  const values = { 'stack-name': 'redactwall-cu-test', region: 'us-east-1' };
  const operationId = `rw-${'a'.repeat(32)}`;
  const result = deployer.deployVersionedStack(
    values,
    { templateUrl: 'https://versioned.example/template' },
    [],
    false,
    { operationId },
  );
  const create = calls.find((args) => args[0] === 'cloudformation' && args[1] === 'create-stack');
  const waiter = calls.find((args) => args[0] === 'cloudformation' && args[1] === 'wait');
  assert.strictEqual(create[create.indexOf('--client-request-token') + 1], operationId);
  assert.strictEqual(waiter[waiter.indexOf('--stack-name') + 1], stackId);
  assert.deepStrictEqual(result.ownership, {
    operationId, stackId, stackName: 'redactwall-cu-test', region: 'us-east-1',
  });
});

test('ambiguous create response never grants candidate cleanup ownership', (t) => {
  const original = childProcess.spawnSync;
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = () => ({ status: 0, stdout: '{}', stderr: '' });
  assert.throws(() => deployer.deployVersionedStack(
    { 'stack-name': 'redactwall-cu-test', region: 'us-east-1' },
    { templateUrl: 'https://versioned.example/template' }, [], false,
    { operationId: `rw-${'b'.repeat(32)}` },
  ), /exact returned StackId/);
});

test('an ambiguous CloudFormation mutation retains the shared operation authority', () => {
  const values = deployer.validate(deployer.parseArgs(validArgs));
  const accountId = '123456789012';
  const heldDependencies = { ...memoryAuthorityDependencies(), accountId };
  const held = deployer.acquireDeploymentAuthority(values, `rw-${'7'.repeat(32)}`, heldDependencies);
  const failure = new Error('CloudFormation response was ambiguous');
  const retained = deployer.settleDeploymentAuthority(held, {
    failure, mutationAttempted: true, owned: true, result: null,
  }, heldDependencies, { log() {}, warn() {} });
  assert.strictEqual(retained.state.holderKind, 'deploy');
  assert.strictEqual(retained.state.phase, 'deploying');
  assert.deepStrictEqual(failure.operationAuthority, {
    bodySha256: retained.bodySha256, etag: retained.etag,
    key: retained.location.key, versionId: retained.versionId,
  });
  assert.doesNotMatch(JSON.stringify(failure.operationAuthority), /secret|credential|token/i);
  assert.throws(() => deployer.acquireDeploymentAuthority(
    values, `rw-${'8'.repeat(32)}`, heldDependencies,
  ), /already held/);

  const safeDependencies = { ...memoryAuthorityDependencies(), accountId };
  const safe = deployer.acquireDeploymentAuthority(values, `rw-${'9'.repeat(32)}`, safeDependencies);
  const preMutationFailure = new Error('preflight failed');
  const released = deployer.settleDeploymentAuthority(safe, {
    failure: preMutationFailure, mutationAttempted: false, owned: true, result: null,
  }, safeDependencies, { log() {}, warn() {} });
  assert.strictEqual(released.state.holderKind, 'available');
  assert.strictEqual(released.state.phase, 'available');
});

test('the production S3 adapter uses exact conditional create and CAS with verified readback', (t) => {
  const original = childProcess.spawnSync;
  const calls = [];
  let stored = null;
  let sequence = 0;
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = (_executable, args) => {
    calls.push([...args]);
    if (args[0] === 's3api' && args[1] === 'get-bucket-location') {
      return { status: 0, stdout: '{"LocationConstraint":null}', stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'get-public-access-block') {
      return { status: 0, stdout: JSON.stringify({ PublicAccessBlockConfiguration: {
        BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true,
      } }), stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'get-bucket-versioning') {
      return { status: 0, stdout: '{"Status":"Enabled"}', stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'get-bucket-ownership-controls') {
      return { status: 0, stdout: '{"OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}}', stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'get-bucket-encryption') {
      return { status: 0, stdout: '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}}', stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'put-object' && args.includes('--generate-cli-skeleton')) {
      return { status: 0, stdout: JSON.stringify({ IfMatch: '', IfNoneMatch: '' }), stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'get-bucket-policy') {
      const bucket = args[args.indexOf('--bucket') + 1];
      return { status: 0, stdout: JSON.stringify({ Policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Deny', Principal: '*', Action: 's3:*',
            Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          },
          {
            Sid: 'DenyUnconditionalOperationAuthorityWrites',
            Effect: 'Deny', Principal: '*', Action: 's3:PutObject',
            Resource: `arn:aws:s3:::${bucket}/redactwall/cloudformation/operation-authority/*`,
            Condition: { Null: { 's3:if-match': 'true', 's3:if-none-match': 'true' } },
          },
          {
            Sid: 'DenyOperationAuthorityDeletion',
            Effect: 'Deny', Principal: '*',
            Action: ['s3:DeleteObject', 's3:DeleteObjectVersion'],
            Resource: `arn:aws:s3:::${bucket}/redactwall/cloudformation/operation-authority/*`,
          },
        ],
      }) }), stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'get-object') {
      if (!stored) return { status: 255, stdout: '', stderr: 'An error occurred (NoSuchKey) when calling GetObject' };
      fs.writeFileSync(args.at(-1), stored.bytes);
      return { status: 0, stdout: JSON.stringify({
        ChecksumSHA256: stored.checksum, ETag: stored.etag,
        Metadata: { sha256: stored.bodySha256 }, ServerSideEncryption: 'AES256', VersionId: stored.versionId,
      }), stderr: '' };
    }
    if (args[0] === 's3api' && args[1] === 'put-object') {
      const bytes = fs.readFileSync(args[args.indexOf('--body') + 1]);
      sequence += 1;
      stored = {
        bodySha256: crypto.createHash('sha256').update(bytes).digest('hex'),
        bytes,
        checksum: crypto.createHash('sha256').update(bytes).digest('base64'),
        etag: `"${sequence.toString(16).repeat(32).slice(0, 32)}"`,
        versionId: `authority-version-${sequence}`,
      };
      return { status: 0, stdout: JSON.stringify({ ETag: stored.etag, VersionId: stored.versionId }), stderr: '' };
    }
    throw new Error(`unexpected AWS mock call: ${args.join(' ')}`);
  };

  const values = deployer.validate(deployer.parseArgs(validArgs));
  const dependencies = { accountId: '123456789012', now: () => '2026-07-13T20:00:00.000Z' };
  const acquired = deployer.acquireDeploymentAuthority(values, `rw-${'a'.repeat(32)}`, dependencies);
  const released = deployer.releaseDeploymentAuthority(acquired, dependencies);
  const writes = calls.filter((args) => args[0] === 's3api' && args[1] === 'put-object'
    && !args.includes('--generate-cli-skeleton'));
  assert.strictEqual(writes.length, 2);
  assert.deepStrictEqual(writes[0].slice(writes[0].indexOf('--if-none-match'),
    writes[0].indexOf('--if-none-match') + 2), ['--if-none-match', '*']);
  assert.deepStrictEqual(writes[1].slice(writes[1].indexOf('--if-match'),
    writes[1].indexOf('--if-match') + 2), ['--if-match', acquired.etag]);
  assert.ok(writes.every((args) => args.includes('--expected-bucket-owner')));
  assert.strictEqual(released.state.holderKind, 'available');
  assert.strictEqual(released.state.generation, acquired.state.generation + 1);
  assert.strictEqual(released.state.previousBodySha256, acquired.bodySha256);
  assert.doesNotMatch(stored.bytes.toString('utf8'), /secret:redactwall|bearer|credential/i);
});

test('conditional authority publication reconciles exact create and CAS response loss', () => {
  const values = deployer.validate(deployer.parseArgs(validArgs));
  const accountId = '123456789012';
  const createDependencies = { ...memoryAuthorityDependencies(), accountId };
  const publishCreate = createDependencies.authority.create;
  createDependencies.authority.create = (...args) => {
    publishCreate(...args);
    const error = new Error('conditional create response lost');
    error.cause = Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });
    throw error;
  };
  const created = deployer.acquireDeploymentAuthority(values, `rw-${'e'.repeat(32)}`, createDependencies);
  assert.strictEqual(created.state.holderKind, 'deploy');
  assert.strictEqual(created.state.generation, 1);

  const casDependencies = { ...memoryAuthorityDependencies(), accountId };
  const acquired = deployer.acquireDeploymentAuthority(values, `rw-${'f'.repeat(32)}`, casDependencies);
  const publishCas = casDependencies.authority.compareAndSwap;
  casDependencies.authority.compareAndSwap = (...args) => {
    publishCas(...args);
    const error = new Error('conditional CAS response lost');
    error.cause = Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });
    throw error;
  };
  const released = deployer.releaseDeploymentAuthority(acquired, casDependencies);
  assert.strictEqual(released.state.holderKind, 'available');
  assert.strictEqual(released.state.generation, 2);
  assert.strictEqual(released.state.previousBodySha256, acquired.bodySha256);
});

test('operation-authority preflight is release-blocked without conditional CLI support', (t) => {
  const original = childProcess.spawnSync;
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = () => ({ status: 0, stdout: '{}', stderr: '' });
  const values = deployer.validate(deployer.parseArgs(validArgs));
  assert.throws(() => deployer.acquireDeploymentAuthority(values, `rw-${'c'.repeat(32)}`, {
    accountId: '123456789012',
  }), /RELEASE-BLOCKED: AWS CLI lacks conditional S3 PutObject support/);
});

test('operation-authority preflight requires both exact conditional-write and no-delete policies', (t) => {
  const original = childProcess.spawnSync;
  let policyMode = 'conditional-only';
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = (_executable, args) => {
    if (args.includes('--generate-cli-skeleton')) {
      return { status: 0, stdout: JSON.stringify({ IfMatch: '', IfNoneMatch: '' }), stderr: '' };
    }
    const command = args[1];
    if (command === 'get-bucket-location') return { status: 0, stdout: '{"LocationConstraint":null}', stderr: '' };
    if (command === 'get-public-access-block') return { status: 0, stdout: JSON.stringify({
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true,
      },
    }), stderr: '' };
    if (command === 'get-bucket-versioning') return { status: 0, stdout: '{"Status":"Enabled"}', stderr: '' };
    if (command === 'get-bucket-ownership-controls') {
      return { status: 0, stdout: '{"OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]}}', stderr: '' };
    }
    if (command === 'get-bucket-encryption') {
      return { status: 0, stdout: '{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}}', stderr: '' };
    }
    if (command === 'get-bucket-policy') {
      const bucket = args[args.indexOf('--bucket') + 1];
      const authorityResource = `arn:aws:s3:::${bucket}/redactwall/cloudformation/operation-authority/*`;
      const authorityStatement = policyMode === 'conditional-only' ? {
        Sid: 'DenyUnconditionalOperationAuthorityWrites', Effect: 'Deny', Principal: '*', Action: 's3:PutObject',
        Resource: authorityResource,
        Condition: { Null: { 's3:if-match': 'true', 's3:if-none-match': 'true' } },
      } : {
        Sid: 'DenyOperationAuthorityDeletion', Effect: 'Deny', Principal: '*',
        Action: ['s3:DeleteObject', 's3:DeleteObjectVersion'], Resource: authorityResource,
      };
      return { status: 0, stdout: JSON.stringify({ Policy: JSON.stringify({
        Version: '2012-10-17', Statement: [{
          Effect: 'Deny', Principal: '*', Action: 's3:*',
          Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
          Condition: { Bool: { 'aws:SecureTransport': 'false' } },
        }, authorityStatement],
      }) }), stderr: '' };
    }
    throw new Error(`unexpected AWS mock call: ${args.join(' ')}`);
  };
  const values = deployer.validate(deployer.parseArgs(validArgs));
  assert.throws(() => deployer.acquireDeploymentAuthority(values, `rw-${'d'.repeat(32)}`, {
    accountId: '123456789012',
  }), /RELEASE-BLOCKED: artifact bucket does not enforce conditional writes and no-delete retention/);
  policyMode = 'delete-only';
  assert.throws(() => deployer.acquireDeploymentAuthority(values, `rw-${'e'.repeat(32)}`, {
    accountId: '123456789012',
  }), /RELEASE-BLOCKED: artifact bucket does not enforce conditional writes and no-delete retention/);
});

test('operation-authority policy accepts only the exact unconditional-write deny shape', () => {
  const location = {
    bucket: 'redactwall-cfn-123456789012-us-east-1',
    prefix: 'redactwall/cloudformation',
  };
  const exact = {
    Sid: 'DenyUnconditionalOperationAuthorityWrites',
    Effect: 'Deny', Principal: '*', Action: 's3:PutObject',
    Resource: `arn:aws:s3:::${location.bucket}/${location.prefix}/operation-authority/*`,
    Condition: { Null: { 's3:if-match': 'true', 's3:if-none-match': 'true' } },
  };
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny(exact, location), true);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({ ...exact, Action: 's3:*' }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({
    ...exact,
    Resource: `arn:aws:s3:::${location.bucket}/${location.prefix}/operation-authority/one.json`,
  }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({
    ...exact, Condition: { ...exact.Condition, Bool: { 'aws:SecureTransport': 'true' } },
  }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({
    ...exact, Condition: { Null: { ...exact.Condition.Null, 'aws:PrincipalArn': 'true' } },
  }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({
    ...exact, Condition: { StringEquals: exact.Condition.Null },
  }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({ ...exact, Sid: 'SimilarDeny' }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({ ...exact, Principal: { AWS: '*' } }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({ ...exact, Action: ['s3:PutObject'] }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny({
    ...exact, Condition: { Null: { 's3:if-match': 'TRUE', 's3:if-none-match': 'true' } },
  }, location), false);
  const { Sid: _sid, ...missingSid } = exact;
  assert.strictEqual(deployer.isExactOperationAuthorityPolicyDeny(missingSid, location), false);

  const noDelete = {
    Sid: 'DenyOperationAuthorityDeletion',
    Effect: 'Deny',
    Principal: '*',
    Action: ['s3:DeleteObject', 's3:DeleteObjectVersion'],
    Resource: `arn:aws:s3:::${location.bucket}/${location.prefix}/operation-authority/*`,
  };
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny(noDelete, location), true);
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny({
    ...noDelete, Action: ['s3:DeleteObjectVersion', 's3:DeleteObject'],
  }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny({
    ...noDelete, Action: ['s3:DeleteObject'],
  }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny({ ...noDelete, Effect: 'Allow' }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny({
    ...noDelete, Resource: `arn:aws:s3:::${location.bucket}/${location.prefix}/operation-authority/one.json`,
  }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny({ ...noDelete, Principal: { AWS: '*' } }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny({ ...noDelete, Sid: 'SimilarDeny' }, location), false);
  assert.strictEqual(deployer.isExactOperationAuthorityDeleteDeny({
    ...noDelete, Condition: { Null: { 's3:if-match': 'true' } },
  }, location), false);
});

test('external maintenance lease blocks competing supported recreation and accepts only exact proof', (t) => {
  const original = childProcess.spawnSync;
  const values = { 'stack-name': 'redactwall-cu-test', region: 'us-east-1' };
  const leaseName = deployer.maintenanceLeaseName(values['stack-name']);
  const leaseId = `arn:aws:cloudformation:us-east-1:123456789012:stack/${leaseName}/12345678-1234-1234-1234-123456789012`;
  const proof = {
    operationId: `rw-${'a'.repeat(32)}`, stackId: leaseId, sourceStackId: 'source-stack',
    sourceFingerprint: 'b'.repeat(64), phase: 'source_deleted',
    checkpointSetId: 'c'.repeat(32), checkpointLatchSha256: 'd'.repeat(64),
  };
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = () => ({ status: 0, stderr: '', stdout: JSON.stringify({ Stacks: [{
    StackId: leaseId, StackName: leaseName, StackStatus: 'CREATE_COMPLETE', Tags: [
      { Key: 'RedactWallMaintenanceOperation', Value: proof.operationId },
      { Key: 'RedactWallSourceStackId', Value: proof.sourceStackId },
      { Key: 'RedactWallSourceFingerprint', Value: proof.sourceFingerprint },
      { Key: 'RedactWallMaintenancePhase', Value: proof.phase },
      { Key: 'RedactWallPermittedOperation', Value: `rw-${'e'.repeat(32)}` },
      { Key: 'RedactWallMaintenanceSet', Value: proof.checkpointSetId },
      { Key: 'RedactWallMaintenanceLatchSha256', Value: proof.checkpointLatchSha256 },
    ],
  }] }) });
  const permittedOperationId = `rw-${'e'.repeat(32)}`;
  const exactProof = { ...proof, permittedOperationId };
  assert.throws(() => deployer.assertCreationLease(values, false, null), /blocks supported deployment/);
  assert.doesNotThrow(() => deployer.assertCreationLease(values, false, exactProof, permittedOperationId));
  assert.throws(() => deployer.assertCreationLease(values, true, null), /blocks supported deployment/,
    'existing-stack updates must not bypass the deterministic external lease');
  assert.throws(() => deployer.assertCreationLease(values, false, { ...proof, phase: 'acquired' }),
    /phase is not permitted/);
  assert.throws(() => deployer.assertCreationLease(values, false, { ...proof, sourceFingerprint: 'c'.repeat(64) }),
    /missing, stale, or ambiguous/);
  assert.throws(() => deployer.assertCreationLease(values, false, {
    ...exactProof, checkpointSetId: 'f'.repeat(32),
  }, permittedOperationId), /missing, stale, or ambiguous/);
  assert.throws(() => deployer.assertCreationLease(values, false, {
    ...exactProof, checkpointLatchSha256: 'f'.repeat(64),
  }, permittedOperationId), /missing, stale, or ambiguous/);
});

test('supported deploy cannot mutate after a stale no-lease observation loses the external CAS', () => {
  const values = deployer.validate(deployer.parseArgs(validArgs));
  const operationId = `rw-${'1'.repeat(32)}`;
  let current = null;
  let etag = null;
  let generation = 0;
  const authority = {
    read: () => current == null ? null : { state: structuredClone(current), etag },
    create: (_location, state) => {
      if (current != null) throw Object.assign(new Error('precondition failed'), { code: 'PreconditionFailed' });
      current = structuredClone(state);
      generation += 1;
      etag = `etag-${generation}`;
      return { state: structuredClone(current), etag };
    },
    compareAndSwap: (_location, expectedEtag, state) => {
      if (expectedEtag !== etag) throw Object.assign(new Error('precondition failed'), { code: 'PreconditionFailed' });
      current = structuredClone(state);
      generation += 1;
      etag = `etag-${generation}`;
      return { state: structuredClone(current), etag };
    },
  };

  const observed = authority.read();
  authority.create(null, { holderKind: 'maintenance', operationId: `rw-${'2'.repeat(32)}`, phase: 'acquired' });
  let mutated = false;
  assert.throws(() => deployer.acquireDeploymentAuthority(values, operationId, {
    authority, observed, skipPreflight: true,
    location: {
      accountId: '123456789012', bucket: values['artifact-bucket'], key: 'authority.json',
      prefix: values['artifact-prefix'], region: values.region, stackName: values['stack-name'],
    },
    mutate: () => { mutated = true; },
  }), /external operation authority|precondition|stale/i);
  assert.strictEqual(mutated, false);
  assert.strictEqual(current.holderKind, 'maintenance');
});

test('candidate create durably exposes exact ownership before any waiter and tags the operation', (t) => {
  const original = childProcess.spawnSync;
  const calls = [];
  const events = [];
  const stackId = 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012';
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = (_executable, args) => {
    calls.push(args);
    if (args[1] === 'create-stack') return { status: 0, stdout: JSON.stringify({ StackId: stackId }), stderr: '' };
    if (args[1] === 'wait') events.push('wait');
    if (args[1] === 'describe-stacks') return { status: 0, stdout: JSON.stringify({ Stacks: [{
      StackId: stackId, StackName: 'redactwall-cu-test', StackStatus: 'CREATE_COMPLETE', Outputs: [],
    }] }), stderr: '' };
    return { status: 0, stdout: '{}', stderr: '' };
  };
  const operationId = `rw-${'d'.repeat(32)}`;
  deployer.deployVersionedStack({ 'stack-name': 'redactwall-cu-test', region: 'us-east-1' },
    { templateUrl: 'https://versioned.example/template' }, [], false, {
      operationId,
      onOwnership: (ownership) => {
        events.push('ownership');
        assert.strictEqual(ownership.stackId, stackId);
      },
    });
  assert.deepStrictEqual(events.slice(0, 2), ['ownership', 'wait']);
  const create = calls.find((args) => args[1] === 'create-stack');
  assert.match(create.join(' '), new RegExp(`RedactWallDeploymentOperation[\\s\\S]*${operationId}`));
});

test('candidate recovery proves the actual CloudFormation create client token from exact stack events', (t) => {
  const original = childProcess.spawnSync;
  t.after(() => { childProcess.spawnSync = original; });
  const stackName = 'redactwall-cu-test';
  const region = 'us-east-1';
  const stackId = `arn:aws:cloudformation:${region}:123456789012:stack/${stackName}/12345678-1234-1234-1234-123456789012`;
  const operationId = `rw-${'a'.repeat(32)}`;
  let event = {
    ClientRequestToken: operationId,
    LogicalResourceId: stackName,
    PhysicalResourceId: stackId,
    ResourceStatus: 'CREATE_IN_PROGRESS',
    ResourceType: 'AWS::CloudFormation::Stack',
    StackId: stackId,
    StackName: stackName,
  };
  childProcess.spawnSync = (_executable, args) => {
    assert.deepStrictEqual(args.slice(0, 4), [
      'cloudformation', 'describe-stack-events', '--stack-name', stackId,
    ]);
    assert.ok(args.includes('--max-items'));
    return { status: 0, stderr: '', stdout: JSON.stringify({ StackEvents: [event] }) };
  };
  assert.strictEqual(deployer.assertStackOperationToken(stackId, stackName, region, operationId), true);
  event = { ...event, ClientRequestToken: `rw-${'b'.repeat(32)}` };
  assert.throws(() => deployer.assertStackOperationToken(stackId, stackName, region, operationId),
    /client token does not match/);
  event = { ...event, ClientRequestToken: operationId, PhysicalResourceId: `${stackId}-replacement` };
  assert.throws(() => deployer.assertStackOperationToken(stackId, stackName, region, operationId),
    /client token does not match/);
});

test('post-commit local snapshot cleanup failure is a sanitized warning', () => {
  const result = { warnings: [] };
  const lines = [];
  assert.doesNotThrow(() => deployer.cleanupDeploymentSnapshot(
    { directory: 'private-staging-path' }, result, null, { warn: (line) => lines.push(line) },
    () => { throw new Error('C:\\private\\operator\\path'); },
  ));
  assert.deepStrictEqual(result.warnings, ['local_template_snapshot_cleanup_failed']);
  assert.deepStrictEqual(lines, ['RedactWall committed with warning: local_template_snapshot_cleanup_failed']);
  assert.doesNotMatch(lines.join('\n'), /private|operator/i);
});

test('structured applied warnings are bounded and deduplicated', () => {
  assert.deepStrictEqual(deployer.parseAppliedWarnings([
    'REDACTWALL_APPLIED_WARNING=committed_cleanup_pending',
    'REDACTWALL_APPLIED_WARNING=evidence_scheduler_setup_failed',
    'REDACTWALL_APPLIED_WARNING=committed_cleanup_pending',
    'REDACTWALL_APPLIED_WARNING=INVALID',
  ].join('\n')), ['committed_cleanup_pending', 'evidence_scheduler_setup_failed']);
});

test('applied attestation binds every runtime authority field and rejects per-field drift', () => {
  const expected = {
    appliedAt: '2026-07-13T20:00:00.000Z',
    appliedStateDigest: '1'.repeat(64),
    configSha256: '2'.repeat(64),
    containerId: '3'.repeat(64),
    deploymentId: 'dep_0123456789abcdef0123456789abcdef',
    imageUri: `123456789012.dkr.ecr.us-east-1.amazonaws.com/redactwall@sha256:${'4'.repeat(64)}`,
    protocolSha256: '5'.repeat(64),
    recoverySetId: '6'.repeat(32),
    secretArn: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:redactwall/cu-test-Ab12',
    secretVersionId: '12345678-1234-1234-1234-123456789012',
    stackId: 'arn:aws:cloudformation:us-east-1:123456789012:stack/redactwall-cu-test/12345678-1234-1234-1234-123456789012',
    templateSha256: '7'.repeat(64),
    tenantId: 'cu-test',
  };
  const fingerprint = deployer.appliedAuthorityFingerprint(expected);
  const lines = [
    `REDACTWALL_APPLIED_CONTAINER_ID=${expected.containerId}`,
    `REDACTWALL_APPLIED_STATE_DIGEST=${expected.appliedStateDigest}`,
    `REDACTWALL_APPLIED_AUTHORITY_FINGERPRINT=${fingerprint}`,
    `REDACTWALL_APPLIED_AT=${expected.appliedAt}`,
    `REDACTWALL_APPLIED_RECOVERY_SET_ID=${expected.recoverySetId}`,
  ];
  assert.deepStrictEqual(deployer.parseAppliedAttestation(lines.join('\n'), expected, true), {
    appliedStateSha256: expected.appliedStateDigest,
    attestedAt: expected.appliedAt,
    authorityFingerprintSha256: fingerprint,
    containerId: expected.containerId,
    recoverySetId: expected.recoverySetId,
  });
  for (let index = 0; index < lines.length; index += 1) {
    const changed = [...lines];
    changed[index] = changed[index].replace(/[a-f0-9](?=[^=]*$)/, 'f');
    assert.throws(() => deployer.parseAppliedAttestation(changed.join('\n'), expected, true),
      /attestation|authority|recovery|runtime/i);
  }
  assert.throws(() => deployer.parseAppliedAttestation([...lines, lines[0]].join('\n'), expected, true),
    /invalid REDACTWALL_APPLIED_CONTAINER_ID/);
  assert.strictEqual(deployer.parseAppliedAttestation('', expected, false), null);
  assert.throws(() => deployer.parseAppliedAttestation(lines[0], expected, false),
    /invalid REDACTWALL_APPLIED_STATE_DIGEST/);
});

test('stack absence is exact and access errors fail closed', () => {
  assert.strictEqual(deployer.stackNotFound({ stderr: 'An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id redactwall-cu-test does not exist' }, 'redactwall-cu-test'), true);
  assert.strictEqual(deployer.stackNotFound({ stderr: 'An error occurred (AccessDenied) when calling the DescribeStacks operation: denied' }, 'redactwall-cu-test'), false);
});

test('certificate matching permits one-label wildcards only', () => {
  assert.strictEqual(deployer.certificateCovers('cu.redactwall.example', ['*.redactwall.example']), true);
  assert.strictEqual(deployer.certificateCovers('deep.cu.redactwall.example', ['*.redactwall.example']), false);
});

test('SSM reports a post-commit persistence failure as committed but degraded', (t) => {
  const original = childProcess.spawnSync;
  t.after(() => { childProcess.spawnSync = original; });
  childProcess.spawnSync = () => ({ status: 0, stderr: '', stdout: JSON.stringify({
    Status: 'Failed',
    StandardErrorContent: 'REDACTWALL_COMMITTED_DEGRADED=evidence_scheduler_warning_persistence_failed\n',
  }) });
  assert.throws(
    () => deployer.waitForCommand('12345678-1234-1234-1234-123456789012', 'i-0123456789abcdef0', 'us-east-1', 120),
    /committed but degraded: evidence_scheduler_warning_persistence_failed/,
  );
});
