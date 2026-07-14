'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const artifacts = require('../scripts/aws-artifacts');
const bucket = require('../scripts/aws-artifact-bucket');

test('artifact bucket policy denies every non-TLS S3 action', () => {
  const name = 'redactwall-cfn-123456789012-us-east-1';
  const policy = JSON.parse(bucket.bucketPolicy(name));
  assert.strictEqual(artifacts.tlsOnlyPolicy(policy, name), true);
  assert.throws(() => artifacts.validateBucketName('Invalid_Bucket'), /invalid/);
  assert.throws(() => artifacts.validateBucketName('redactwall.cfn.bucket'), /invalid/);
  assert.throws(() => artifacts.validatePrefix('../private'), /invalid/);
  assert.throws(() => bucket.parseArgs(['region', 'us-east-1']), /usage/);
});

test('artifact bucket policy enforces conditional operation-authority writes on the exact prefix', () => {
  const name = 'redactwall-cfn-123456789012-us-east-1';
  const prefix = 'redactwall/custom-prefix';
  const policy = JSON.parse(bucket.bucketPolicy(name, prefix));
  const statement = policy.Statement.find(({ Sid }) => Sid === 'DenyUnconditionalOperationAuthorityWrites');
  assert.deepStrictEqual(statement, {
    Sid: 'DenyUnconditionalOperationAuthorityWrites',
    Effect: 'Deny',
    Principal: '*',
    Action: 's3:PutObject',
    Resource: `arn:aws:s3:::${name}/${prefix}/operation-authority/*`,
    Condition: { Null: { 's3:if-match': 'true', 's3:if-none-match': 'true' } },
  });
  const deletion = policy.Statement.find(({ Sid }) => Sid === 'DenyOperationAuthorityDeletion');
  assert.deepStrictEqual(deletion, {
    Sid: 'DenyOperationAuthorityDeletion',
    Effect: 'Deny',
    Principal: '*',
    Action: ['s3:DeleteObject', 's3:DeleteObjectVersion'],
    Resource: `arn:aws:s3:::${name}/${prefix}/operation-authority/*`,
  });
  assert.deepStrictEqual(bucket.parseArgs([
    '--region', 'us-east-1', '--prefix', prefix,
  ]), { region: 'us-east-1', prefix });
  assert.throws(
    () => bucket.parseArgs(['--region', 'us-east-1', '--prefix', '../authority']),
    /prefix is invalid/,
  );
});

test('artifact policy evaluation rejects narrowed TLS denies and ambiguous writer grants', () => {
  const name = 'redactwall-cfn-123456789012-us-east-1';
  const accountId = '123456789012';
  const secure = JSON.parse(bucket.bucketPolicy(name));
  const tlsStatement = secure.Statement[0];
  const narrowedTlsPolicies = [
    { Version: '2012-10-17', Statement: [{ ...tlsStatement, Condition: { ...tlsStatement.Condition, StringEquals: { 'aws:SourceVpc': 'vpc-safe' } } }] },
    { Version: '2012-10-17', Statement: [{ ...tlsStatement, Condition: { Bool: { 'aws:SecureTransport': 'false', 'aws:PrincipalIsAWSService': 'false' } } }] },
    { Version: '2012-10-17', Statement: [{ ...tlsStatement, Condition: { BoolIfExists: { 'aws:SecureTransport': 'false' } } }] },
    { Version: '2012-10-17', Statement: [{ ...tlsStatement, Principal: { AWS: '*' } }] },
    { Version: '2012-10-17', Statement: [{ ...tlsStatement, Resource: `arn:aws:s3:::${name}/*` }] },
    { Version: '2012-10-17', Statement: [{ ...tlsStatement, Ambiguous: true }] },
    { Statement: tlsStatement },
    { Version: '2008-10-17', Statement: [tlsStatement] },
    { Version: '2012-10-17', Unknown: true, Statement: [tlsStatement] },
  ];
  for (const policy of narrowedTlsPolicies) {
    assert.strictEqual(artifacts.tlsOnlyPolicy(policy, name), false, JSON.stringify(policy));
  }

  const maliciousAllows = [
    { Principal: '*', Action: 's3:Put*' },
    { Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 's3:*Object' },
    { Principal: '*', Action: '*' },
    { Principal: { Service: 'cloudformation.amazonaws.com' }, Action: 's3:PutObject' },
    { Principal: { Federated: 'accounts.google.com' }, Action: 's3:PutObject' },
    { Principal: { CanonicalUser: 'unknown' }, Action: 's3:PutObject' },
    { Principal: { AWS: ['arn:aws:iam::123456789012:root', 'arn:aws:iam::999999999999:root'] }, Action: 's3:PutObject' },
    { Principal: { AWS: 'arn:aws:iam::123456789012:root', Service: 'lambda.amazonaws.com' }, Action: 's3:PutObject' },
    { Principal: { AWS: 'arn:aws:iam::123456789012:root' }, NotAction: 's3:GetObject' },
    { NotPrincipal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 's3:PutObject' },
    { Principal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 's3:PutObject', NotResource: `arn:aws:s3:::${name}/safe/*` },
    { Principal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 's3:PutObject', Condition: { StringEquals: { 'aws:PrincipalAccount': accountId } } },
    { Principal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: { value: 's3:PutObject' } },
  ];
  for (const candidate of maliciousAllows) {
    const statement = { Effect: 'Allow', Resource: `arn:aws:s3:::${name}/*`, ...candidate };
    if (candidate.NotAction) delete statement.Action;
    if (candidate.NotResource) delete statement.Resource;
    const policy = { Version: '2012-10-17', Statement: [...secure.Statement, statement] };
    assert.strictEqual(artifacts.writerPolicyClosed(policy, accountId), false, JSON.stringify(candidate));
  }
  assert.strictEqual(artifacts.writerPolicyClosed({ Statement: secure.Statement[0] }, accountId), false,
    'a non-array Statement is rejected as an ambiguous policy shape');
  assert.strictEqual(artifacts.writerPolicyClosed({ Statement: [...secure.Statement, null] }, accountId), false);
  assert.strictEqual(artifacts.writerPolicyClosed(secure, accountId), true);
});

test('artifact bucket verifier requires region, public block, versioning, ownership, encryption, and TLS', () => {
  const name = 'redactwall-cfn-123456789012-us-east-1';
  const responses = {
    'get-bucket-location': { LocationConstraint: null },
    'get-public-access-block': { PublicAccessBlockConfiguration: {
      BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true,
    } },
    'get-bucket-versioning': { Status: 'Enabled' },
    'get-bucket-ownership-controls': { OwnershipControls: { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] } },
    'get-bucket-encryption': { ServerSideEncryptionConfiguration: { Rules: [{
      ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' },
    }] } },
    'get-bucket-policy': { Policy: bucket.bucketPolicy(name) },
  };
  const runAws = (args) => JSON.stringify(responses[args[1]]);
  assert.deepStrictEqual(artifacts.verifyArtifactBucket(runAws, {
    bucket: name, region: 'us-east-1', accountId: '123456789012',
  }), { algorithm: 'AES256' });
  responses['get-bucket-versioning'] = {};
  assert.throws(() => artifacts.verifyArtifactBucket(runAws, {
    bucket: name, region: 'us-east-1', accountId: '123456789012',
  }), /versioning/);
  responses['get-bucket-versioning'] = { Status: 'Enabled' };
  responses['get-bucket-policy'] = { Policy: JSON.stringify({ Version: '2012-10-17', Statement: [
    ...JSON.parse(bucket.bucketPolicy(name)).Statement,
    { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 's3:PutObject', Resource: `arn:aws:s3:::${name}/*` },
  ] }) };
  assert.throws(() => artifacts.verifyArtifactBucket(runAws, {
    bucket: name, region: 'us-east-1', accountId: '123456789012',
  }), /cross-account/);
});

test('CloudFormation template staging is content-addressed and hash-verified through TemplateURL', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-artifact-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const template = path.join(root, 'customer-silo.yml');
  const bytes = Buffer.from('AWSTemplateFormatVersion: 2010-09-09\nResources: {}\n');
  fs.writeFileSync(template, bytes, { mode: 0o600 });
  const digest = crypto.createHash('sha256').update(bytes).digest();
  const calls = [];
  const runAws = (args) => {
    calls.push(args);
    if (args[0] === 's3api' && args[1] === 'put-object') {
      assert.deepStrictEqual(fs.readFileSync(args[args.indexOf('--body') + 1]), bytes);
      return '{"VersionId":"version/with+symbols="}';
    }
    if (args[0] === 's3api' && args[1] === 'head-object') return JSON.stringify({
      ContentLength: bytes.length,
      Metadata: { sha256: digest.toString('hex') },
      ChecksumSHA256: digest.toString('base64'),
      ServerSideEncryption: 'AES256',
    });
    if (args[0] === 'cloudformation' && args[1] === 'validate-template') return '{}';
    throw new Error(`unexpected command: ${args.join(' ')}`);
  };
  const staged = artifacts.stageTemplate(runAws, {
    bucket: 'redactwall-cfn-123456789012-us-east-1',
    prefix: 'redactwall/cloudformation',
    region: 'us-east-1',
    accountId: '123456789012',
    templatePath: template,
  });
  t.after(() => artifacts.cleanupSnapshot(staged));
  assert.strictEqual(staged.sha256, digest.toString('hex'));
  assert.match(staged.key, new RegExp(`${digest.toString('hex')}\\.yml$`));
  assert.match(staged.templateUrl, /\?versionId=version%2Fwith%2Bsymbols%3D$/);
  assert.throws(() => artifacts.parseTemplateReference(`${staged.templateUrl}&versionId=second`, {
    bucket: staged.bucket, region: 'us-east-1',
  }), /invalid/);
  assert.throws(() => artifacts.parseTemplateReference(`${staged.templateUrl}#replacement`, {
    bucket: staged.bucket, region: 'us-east-1',
  }), /invalid/);
  assert.ok(calls.find((args) => args[1] === 'head-object').includes('--version-id'));
  assert.ok(calls.filter((args) => args[0] === 's3api').every((args) => args.includes('--expected-bucket-owner')));
  const validation = calls.find((args) => args[0] === 'cloudformation' && args[1] === 'validate-template');
  assert.ok(validation.includes('--template-url'));
  assert.strictEqual(validation.includes('--template-body'), false);
});
