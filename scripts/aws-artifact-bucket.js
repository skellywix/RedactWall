'use strict';

const childProcess = require('node:child_process');
const artifacts = require('./aws-artifacts');

const REGION_PATTERN = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;

function runAws(args, options = {}) {
  const result = childProcess.spawnSync(process.env.REDACTWALL_AWS_CLI || 'aws', args, {
    encoding: 'utf8', windowsHide: true, maxBuffer: 1024 * 1024,
    timeout: options.timeoutMs || 120_000, env: { ...process.env, AWS_PAGER: '' },
  });
  if (result.error || result.status !== 0) {
    const error = new Error(options.errorMessage || `AWS command failed: ${args.slice(0, 2).join(' ')}`);
    error.status = result.status; error.stderr = String(result.stderr || ''); error.cause = result.error;
    throw error;
  }
  return String(result.stdout || '').trim();
}

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const token = String(argv[index] || '');
    if (!token.startsWith('--')) throw new Error('usage: silo:artifacts:init --region <region> [--bucket <name>] [--prefix <prefix>]');
    const key = token.slice(2);
    const value = argv[index + 1];
    if (!['region', 'bucket', 'prefix'].includes(key) || value == null || Object.hasOwn(values, key)) throw new Error('usage: silo:artifacts:init --region <region> [--bucket <name>] [--prefix <prefix>]');
    values[key] = value;
  }
  if (!REGION_PATTERN.test(values.region || '')) throw new Error('region is invalid');
  if (values.bucket) artifacts.validateBucketName(values.bucket);
  if (values.prefix) artifacts.validatePrefix(values.prefix);
  return values;
}

function bucketPolicy(bucket, prefix = artifacts.DEFAULT_PREFIX) {
  artifacts.validateBucketName(bucket);
  const authorityPrefix = artifacts.validatePrefix(prefix);
  return JSON.stringify({ Version: '2012-10-17', Statement: [
    {
      Sid: 'DenyInsecureTransport', Effect: 'Deny', Principal: '*', Action: 's3:*',
      Resource: [`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
    {
      Sid: 'DenyUnconditionalOperationAuthorityWrites',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:PutObject',
      Resource: `arn:aws:s3:::${bucket}/${authorityPrefix}/operation-authority/*`,
      Condition: { Null: { 's3:if-match': 'true', 's3:if-none-match': 'true' } },
    },
    {
      Sid: 'DenyOperationAuthorityDeletion',
      Effect: 'Deny',
      Principal: '*',
      Action: ['s3:DeleteObject', 's3:DeleteObjectVersion'],
      Resource: `arn:aws:s3:::${bucket}/${authorityPrefix}/operation-authority/*`,
    },
  ] });
}

function configureBucket(bucket, region, accountId, prefix = artifacts.DEFAULT_PREFIX) {
  const owner = ['--expected-bucket-owner', accountId];
  runAws(['s3api', 'put-public-access-block', '--bucket', bucket, '--region', region,
    ...owner,
    '--public-access-block-configuration', 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true']);
  runAws(['s3api', 'put-bucket-encryption', '--bucket', bucket, '--region', region,
    ...owner,
    '--server-side-encryption-configuration', '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":false}}']);
  runAws(['s3api', 'put-bucket-versioning', '--bucket', bucket, '--region', region,
    ...owner,
    '--versioning-configuration', 'Status=Enabled']);
  runAws(['s3api', 'put-bucket-ownership-controls', '--bucket', bucket, '--region', region,
    ...owner,
    '--ownership-controls', 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]']);
  runAws(['s3api', 'put-bucket-policy', '--bucket', bucket, '--region', region, ...owner,
    '--policy', bucketPolicy(bucket, prefix)]);
  runAws(['s3api', 'put-bucket-tagging', '--bucket', bucket, '--region', region,
    ...owner,
    '--tagging', 'TagSet=[{Key=RedactWallPurpose,Value=cloudformation-artifacts}]']);
  return artifacts.verifyArtifactBucket(runAws, { bucket, region, accountId });
}

function initialize(values, io = console) {
  const identity = JSON.parse(runAws(['sts', 'get-caller-identity', '--output', 'json']));
  const accountId = String(identity.Account || '');
  if (!/^[0-9]{12}$/.test(accountId)) throw new Error('AWS account id is unavailable');
  let bucket = values.bucket;
  if (!bucket) {
    bucket = `redactwall-cfn-${accountId}-${values.region}`;
    artifacts.validateBucketName(bucket);
  }
  let exists = true;
  try { runAws(['s3api', 'get-bucket-location', '--bucket', bucket, '--expected-bucket-owner', accountId, '--region', values.region, '--output', 'json']); }
  catch (error) {
    if (!/\((?:NoSuchBucket|NotFound)\)/.test(error.stderr || '')) throw error;
    exists = false;
  }
  if (!exists) {
    const args = ['s3api', 'create-bucket', '--bucket', bucket, '--region', values.region];
    if (values.region !== 'us-east-1') args.push('--create-bucket-configuration', `LocationConstraint=${values.region}`);
    runAws(args, { errorMessage: 'Could not create the dedicated CloudFormation artifact bucket' });
  }
  configureBucket(bucket, values.region, accountId, values.prefix || artifacts.DEFAULT_PREFIX);
  io.log(bucket);
  return bucket;
}

function main(argv = process.argv.slice(2)) {
  try { initialize(parseArgs(argv)); }
  catch (error) { console.error(`[silo-artifacts] ${error.message}`); process.exitCode = 1; }
}

if (require.main === module) main();

module.exports = { bucketPolicy, configureBucket, initialize, parseArgs, runAws };
