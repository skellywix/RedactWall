'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const BUCKET_PATTERN = /^(?=.{3,63}$)(?!xn--)(?!.*(?:-s3alias|--ol-s3)$)(?!\d{1,3}(?:\.\d{1,3}){3}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/;
const PREFIX_PATTERN = /^[a-z0-9](?:[a-z0-9/_-]{0,198}[a-z0-9])?$/;
const DEFAULT_PREFIX = 'redactwall/cloudformation';
const MAX_TEMPLATE_BYTES = 1024 * 1024;
const ACCOUNT_PATTERN = /^[0-9]{12}$/;

function validateBucketName(value) {
  const bucket = String(value || '');
  if (!BUCKET_PATTERN.test(bucket) || bucket.includes('.')) {
    throw new Error('artifact bucket name is invalid');
  }
  return bucket;
}

function validatePrefix(value = DEFAULT_PREFIX) {
  const prefix = String(value || '');
  if (!PREFIX_PATTERN.test(prefix) || prefix.includes('//')) throw new Error('artifact prefix is invalid');
  return prefix;
}

function normalizedBucketRegion(location) {
  return location == null || location === '' ? 'us-east-1' : String(location);
}

function plainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function stringList(value) {
  const values = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(values) || values.length === 0
    || values.some((entry) => typeof entry !== 'string' || entry.length === 0)) return null;
  return values;
}

function policyStatements(policy) {
  const policyKeys = plainObject(policy) ? Object.keys(policy) : [];
  if (!plainObject(policy) || policy.Version !== '2012-10-17'
    || policyKeys.some((key) => !['Version', 'Id', 'Statement'].includes(key))
    || (Object.hasOwn(policy, 'Id') && typeof policy.Id !== 'string')
    || !Array.isArray(policy.Statement) || policy.Statement.length === 0
    || policy.Statement.some((statement) => !plainObject(statement))) return null;
  return policy.Statement;
}

function tlsOnlyPolicy(policy, bucket) {
  const statements = policyStatements(policy);
  if (!statements) return false;
  const expectedResources = new Set([`arn:aws:s3:::${bucket}`, `arn:aws:s3:::${bucket}/*`]);
  return statements.some((statement) => {
    const resources = stringList(statement.Resource);
    const actions = stringList(statement.Action);
    const condition = statement.Condition;
    return Object.keys(statement).every((key) => ['Sid', 'Effect', 'Principal', 'Action', 'Resource', 'Condition'].includes(key))
      && (!Object.hasOwn(statement, 'Sid') || typeof statement.Sid === 'string')
      && statement.Effect === 'Deny' && statement.Principal === '*'
      && !Object.hasOwn(statement, 'NotPrincipal') && !Object.hasOwn(statement, 'NotAction')
      && !Object.hasOwn(statement, 'NotResource') && actions?.length === 1 && actions[0] === 's3:*'
      && resources?.length === 2 && resources.every((resource) => expectedResources.has(resource))
      && new Set(resources).size === 2 && plainObject(condition)
      && Object.keys(condition).length === 1 && plainObject(condition.Bool)
      && Object.keys(condition.Bool).length === 1
      && condition.Bool['aws:SecureTransport'] === 'false';
  });
}

function s3CapabilityAction(action) {
  const value = String(action || '').toLowerCase();
  return value === '*' || value.startsWith('s3:');
}

function sameAccountWriter(principal, accountId) {
  if (!principal || principal === '*') return false;
  if (plainObject(principal) && (Object.keys(principal).length !== 1 || !Object.hasOwn(principal, 'AWS'))) return false;
  if (typeof principal !== 'string' && !plainObject(principal)) return false;
  const values = stringList(plainObject(principal) ? principal.AWS : principal);
  if (!values) return false;
  return values.length > 0 && values.every((value) => {
    const text = String(value || '');
    return text === accountId
      || new RegExp(`^arn:(?:aws|aws-us-gov|aws-cn):iam::${accountId}:(?:root|role/[A-Za-z0-9+=,.@_/-]{1,512}|user/[A-Za-z0-9+=,.@_/-]{1,512})$`).test(text);
  });
}

function writerPolicyClosed(policy, accountId) {
  if (!ACCOUNT_PATTERN.test(String(accountId || ''))) return false;
  const statements = policyStatements(policy);
  if (!statements) return false;
  return statements.every((statement) => {
    if (!['Allow', 'Deny'].includes(statement.Effect)) return false;
    if (Object.keys(statement).some((key) => !['Sid', 'Effect', 'Principal', 'Action', 'Resource', 'Condition'].includes(key))
      || (Object.hasOwn(statement, 'Sid') && typeof statement.Sid !== 'string')
      || (Object.hasOwn(statement, 'Condition') && !plainObject(statement.Condition))) return false;
    if (Object.hasOwn(statement, 'NotAction') || Object.hasOwn(statement, 'NotPrincipal')
      || Object.hasOwn(statement, 'NotResource')) return false;
    const actions = stringList(statement.Action);
    const resources = stringList(statement.Resource);
    if (!actions || !resources || (statement.Principal !== '*'
      && !sameAccountWriter(statement.Principal, accountId)) || actions.some((action) => !s3CapabilityAction(action))) return false;
    if (statement.Effect !== 'Allow') return true;
    if (Object.hasOwn(statement, 'Condition')) return false;
    return sameAccountWriter(statement.Principal, accountId);
  });
}

function ownerArgs(accountId) {
  if (!ACCOUNT_PATTERN.test(String(accountId || ''))) throw new Error('active AWS account id is invalid');
  return ['--expected-bucket-owner', accountId];
}

function verifyArtifactBucket(runAws, { bucket, region, accountId }) {
  validateBucketName(bucket);
  const owner = ownerArgs(accountId);
  const location = JSON.parse(runAws(['s3api', 'get-bucket-location', '--bucket', bucket, ...owner, '--region', region, '--output', 'json']));
  if (normalizedBucketRegion(location.LocationConstraint) !== region) throw new Error('artifact bucket is not in the deployment region');
  const block = JSON.parse(runAws(['s3api', 'get-public-access-block', '--bucket', bucket, ...owner, '--region', region, '--output', 'json']));
  if (!Object.values(block.PublicAccessBlockConfiguration || {}).every((value) => value === true)
    || Object.keys(block.PublicAccessBlockConfiguration || {}).length !== 4) throw new Error('artifact bucket public access block is incomplete');
  const versioning = JSON.parse(runAws(['s3api', 'get-bucket-versioning', '--bucket', bucket, ...owner, '--region', region, '--output', 'json']));
  if (versioning.Status !== 'Enabled') throw new Error('artifact bucket versioning is not enabled');
  const ownership = JSON.parse(runAws(['s3api', 'get-bucket-ownership-controls', '--bucket', bucket, ...owner, '--region', region, '--output', 'json']));
  if (ownership.OwnershipControls?.Rules?.[0]?.ObjectOwnership !== 'BucketOwnerEnforced') throw new Error('artifact bucket ownership is not enforced');
  const encryption = JSON.parse(runAws(['s3api', 'get-bucket-encryption', '--bucket', bucket, ...owner, '--region', region, '--output', 'json']));
  const algorithm = encryption.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm;
  if (!['AES256', 'aws:kms'].includes(algorithm)) throw new Error('artifact bucket default encryption is not configured');
  const policyText = JSON.parse(runAws(['s3api', 'get-bucket-policy', '--bucket', bucket, ...owner, '--region', region, '--output', 'json'])).Policy;
  const policy = JSON.parse(policyText);
  if (!tlsOnlyPolicy(policy, bucket)) throw new Error('artifact bucket does not enforce TLS-only access');
  if (!writerPolicyClosed(policy, accountId)) throw new Error('artifact bucket policy permits a cross-account or public writer');
  return { algorithm };
}

function templateUrl(bucket, region, key, versionId) {
  const suffix = region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
  const encodedKey = key.split('/').map(encodeURIComponent).join('/');
  if (!versionId || /[\u0000-\u001f\u007f]/.test(versionId) || versionId.length > 1024) throw new Error('S3 template version id is invalid');
  return `https://${bucket}.s3.${region}.${suffix}/${encodedKey}?versionId=${encodeURIComponent(versionId)}`;
}

function parseTemplateReference(value, { bucket, region }) {
  const parsed = new URL(String(value || ''));
  const suffix = region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
  const versionIds = parsed.searchParams.getAll('versionId');
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port
    || parsed.hostname !== `${bucket}.s3.${region}.${suffix}`
    || parsed.hash || versionIds.length !== 1
    || [...parsed.searchParams.keys()].some((key) => key !== 'versionId')) {
    throw new Error('version-bound CloudFormation template URL is invalid');
  }
  const versionId = versionIds[0] || '';
  templateUrl(bucket, region, 'validation', versionId);
  const key = parsed.pathname.slice(1).split('/').map(decodeURIComponent).join('/');
  if (!key || key.includes('..') || key.startsWith('/')) throw new Error('CloudFormation template object key is invalid');
  return { key, versionId };
}

function verifyTemplateReference(runAws, options) {
  const bucket = validateBucketName(options.bucket);
  const { key, versionId } = parseTemplateReference(options.templateUrl, { bucket, region: options.region });
  if (!/^[a-f0-9]{64}$/.test(String(options.sha256 || ''))) throw new Error('template SHA-256 is invalid');
  const expectedBytes = Number(options.bytes);
  if (!Number.isInteger(expectedBytes) || expectedBytes <= 0 || expectedBytes > MAX_TEMPLATE_BYTES) throw new Error('template byte count is invalid');
  const head = JSON.parse(runAws(['s3api', 'head-object', '--bucket', bucket, '--key', key,
    '--version-id', versionId, '--checksum-mode', 'ENABLED', ...ownerArgs(options.accountId),
    '--region', options.region, '--output', 'json']));
  const checksum = Buffer.from(options.sha256, 'hex').toString('base64');
  if (Number(head.ContentLength) !== expectedBytes || head.Metadata?.sha256 !== options.sha256
    || head.ChecksumSHA256 !== checksum || !['AES256', 'aws:kms'].includes(head.ServerSideEncryption)) {
    throw new Error('version-bound CloudFormation template failed hash or encryption verification');
  }
  return { bucket, key, versionId, sha256: options.sha256, bytes: expectedBytes, templateUrl: options.templateUrl };
}

function privateTemplateSnapshot(templatePath) {
  const target = path.resolve(templatePath);
  const pathBefore = fs.lstatSync(target, { bigint: true });
  if (!pathBefore.isFile() || pathBefore.isSymbolicLink() || pathBefore.nlink !== 1n || pathBefore.size <= 0n
    || pathBefore.size > BigInt(MAX_TEMPLATE_BYTES)) throw new Error('CloudFormation template must be a bounded single-link file');
  const descriptor = fs.openSync(target, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  let bytes;
  try {
    const handleBefore = fs.fstatSync(descriptor, { bigint: true });
    if (!handleBefore.isFile() || handleBefore.nlink !== 1n || handleBefore.dev !== pathBefore.dev
      || handleBefore.ino !== pathBefore.ino || handleBefore.size !== pathBefore.size) {
      throw new Error('CloudFormation template path does not identify the opened file');
    }
    bytes = fs.readFileSync(descriptor);
    const handleAfter = fs.fstatSync(descriptor, { bigint: true });
    const pathAfter = fs.lstatSync(target, { bigint: true });
    for (const field of ['dev', 'ino', 'nlink', 'size', 'mtimeNs', 'ctimeNs']) {
      if (handleBefore[field] !== handleAfter[field] || handleBefore[field] !== pathAfter[field]) {
        throw new Error('CloudFormation template changed while being staged');
      }
    }
  } finally {
    fs.closeSync(descriptor);
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-cfn-'));
  fs.chmodSync(directory, 0o700);
  const file = path.join(directory, 'customer-silo.yml');
  const snapshotDescriptor = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(snapshotDescriptor, bytes); fs.fsyncSync(snapshotDescriptor); } finally { fs.closeSync(snapshotDescriptor); }
  return { bytes, directory, file };
}

function stageTemplate(runAws, options) {
  const bucket = validateBucketName(options.bucket);
  const prefix = validatePrefix(options.prefix);
  const snapshot = privateTemplateSnapshot(options.templatePath);
  const sha256 = crypto.createHash('sha256').update(snapshot.bytes).digest();
  const shaHex = sha256.toString('hex');
  const key = `${prefix}/templates/customer-silo-${shaHex}.yml`;
  const owner = ownerArgs(options.accountId);
  try {
    const publication = JSON.parse(runAws(['s3api', 'put-object', '--bucket', bucket, '--key', key, '--body', snapshot.file,
      '--checksum-algorithm', 'SHA256', '--checksum-sha256', sha256.toString('base64'),
      '--metadata', `sha256=${shaHex}`, ...owner, '--region', options.region, '--output', 'json'],
    { errorMessage: 'Could not stage the CloudFormation template' }));
    const versionId = String(publication.VersionId || '');
    const url = templateUrl(bucket, options.region, key, versionId);
    const head = JSON.parse(runAws(['s3api', 'head-object', '--bucket', bucket, '--key', key,
      '--version-id', versionId, '--checksum-mode', 'ENABLED', ...owner, '--region', options.region, '--output', 'json']));
    if (Number(head.ContentLength) !== snapshot.bytes.length || head.Metadata?.sha256 !== shaHex
      || head.ChecksumSHA256 !== sha256.toString('base64') || !['AES256', 'aws:kms'].includes(head.ServerSideEncryption)) {
      throw new Error('staged CloudFormation template failed hash or encryption verification');
    }
    runAws(['cloudformation', 'validate-template', '--template-url', url, '--region', options.region, '--output', 'json'],
      { errorMessage: 'CloudFormation rejected the staged template URL' });
    return { ...snapshot, bucket, key, prefix, sha256: shaHex, versionId, templateUrl: url };
  } catch (error) {
    fs.rmSync(snapshot.directory, { recursive: true, force: true });
    throw error;
  }
}

function cleanupSnapshot(staged) {
  if (staged?.directory) fs.rmSync(staged.directory, { recursive: true, force: true });
}

module.exports = {
  BUCKET_PATTERN,
  DEFAULT_PREFIX,
  cleanupSnapshot,
  parseTemplateReference,
  stageTemplate,
  templateUrl,
  tlsOnlyPolicy,
  validateBucketName,
  validatePrefix,
  verifyArtifactBucket,
  verifyTemplateReference,
  writerPolicyClosed,
};
