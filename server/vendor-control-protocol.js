'use strict';

const crypto = require('node:crypto');
const { z } = require('zod');
const { isDeploymentId } = require('./deployment-identity');

const PROTOCOL_VERSION = 1;
const DEFAULT_HEARTBEAT_INTERVAL_MS = 60_000;
const MIN_HEARTBEAT_INTERVAL_MS = 30_000;
const MAX_HEARTBEAT_INTERVAL_MS = 300_000;
const DEFAULT_FALLBACK_WINDOW_MS = 72 * 60 * 60 * 1000;
const MAX_FALLBACK_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_ENTITLEMENT_TTL_MS = 10 * 60 * 1000;

const FAILURE_CLASSES = Object.freeze([
  'transport_unavailable',
  'transport_ambiguous',
  'authentication_rejected',
  'invalid_signature',
  'unknown_signing_key',
  'invalid_schema',
  'customer_mismatch',
  'deployment_mismatch',
  'version_conflict',
  'rate_limited',
  'protocol_rejected',
  'response_too_large',
  'expired',
  'clock_rollback',
  'state_corrupt',
]);

const CHANNEL_KINDS = Object.freeze({
  HEARTBEAT: 'heartbeat.v1',
  ENTITLEMENT: 'entitlement.release.v1',
  ACKNOWLEDGEMENT: 'acknowledgement.v1',
  DIAGNOSTIC: 'diagnostic.event.v1',
  SHADOW_CANDIDATE: 'shadow-ai.candidate.v1',
  GLOBAL_CATALOG_RELEASE: 'shadow-ai.global-catalog-release.v1',
  CATALOG_DISTRIBUTION: 'shadow-ai.catalog-distribution.v1',
  // Compatibility name for callers that only need the immutable global artifact.
  CATALOG_RELEASE: 'shadow-ai.global-catalog-release.v1',
  POLICY_DESIRED_STATE: 'policy.desired-state.v1',
  AUDIT_REQUEST: 'audit-support.request.v1',
  AUDIT_RESPONSE: 'audit-support.response.v1',
});

const SIGNATURE_DOMAINS = Object.freeze({
  [CHANNEL_KINDS.ENTITLEMENT]: 'redactwall.vendor-entitlement.v1',
  [CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE]: 'redactwall.vendor-global-shadow-catalog.v1',
  [CHANNEL_KINDS.CATALOG_DISTRIBUTION]: 'redactwall.customer-shadow-catalog-distribution.v1',
  [CHANNEL_KINDS.POLICY_DESIRED_STATE]: 'redactwall.policy-desired-state.v1',
  [CHANNEL_KINDS.AUDIT_REQUEST]: 'redactwall.audit-support-request.v1',
});

const MAX_CHANNEL_BYTES = Object.freeze({
  [CHANNEL_KINDS.HEARTBEAT]: 8 * 1024,
  [CHANNEL_KINDS.ENTITLEMENT]: 16 * 1024,
  [CHANNEL_KINDS.ACKNOWLEDGEMENT]: 8 * 1024,
  [CHANNEL_KINDS.DIAGNOSTIC]: 8 * 1024,
  [CHANNEL_KINDS.SHADOW_CANDIDATE]: 8 * 1024,
  [CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE]: 512 * 1024,
  [CHANNEL_KINDS.CATALOG_DISTRIBUTION]: 16 * 1024,
  [CHANNEL_KINDS.POLICY_DESIRED_STATE]: 16 * 1024,
  [CHANNEL_KINDS.AUDIT_REQUEST]: 16 * 1024,
  [CHANNEL_KINDS.AUDIT_RESPONSE]: 64 * 1024,
});

const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const CUSTOMER_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const VERSION_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const SAFE_SLUG_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{22,86}$/;
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const KEY_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,95}$/;
const PRIVATE_OR_RESERVED_TLDS = new Set([
  'corp', 'example', 'home', 'internal', 'invalid', 'intranet', 'lan', 'local',
  'localdomain', 'localhost', 'onion', 'private', 'test',
]);

const isoTime = z.string().regex(ISO_MS_RE).refine(canonicalIsoTime);
const customerId = z.string().regex(CUSTOMER_ID_RE);
const deploymentId = z.string().refine(isDeploymentId);
const messageId = z.string().uuid();
const monotonicVersion = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const sha256 = z.string().regex(SHA256_RE);
const safeSlug = z.string().regex(SAFE_SLUG_RE);
const plan = z.enum(['standard', 'enterprise']);
const status = z.enum(['active', 'paused', 'revoked']);
const featureList = z.array(safeSlug).max(128)
  .refine((items) => new Set(items).size === items.length)
  .refine(sortedStrings);

const baseFields = Object.freeze({
  schemaVersion: z.literal(PROTOCOL_VERSION),
  messageId,
  customerId,
  deploymentId,
});

const heartbeatSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.HEARTBEAT),
  heartbeatNonce: z.string().regex(NONCE_RE),
  plan,
  seatsUsed: z.number().int().min(0).max(1_000_000),
  seatLimit: z.number().int().min(0).max(1_000_000),
  version: z.string().regex(VERSION_RE),
  sentAt: isoTime,
  lastAppliedEntitlementVersion: monotonicVersion,
  lastAppliedRegistryGeneration: monotonicVersion,
  lastAppliedPolicyVersion: monotonicVersion,
  lastAppliedCatalogVersion: monotonicVersion,
}).strict();

const entitlementSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.ENTITLEMENT),
  status,
  plan,
  seats: z.number().int().min(0).max(1_000_000),
  features: featureList,
  entitlementVersion: monotonicVersion.min(1),
  previousVersion: monotonicVersion,
  issuedAt: isoTime,
  expiresAt: isoTime,
  fallbackUntil: isoTime.nullable(),
  reasonCode: z.enum([
    'billing_active', 'trial_active', 'manual_restore', 'manual_pause',
    'manual_revoke', 'payment_past_due', 'subscription_ended', 'emergency_revoke',
  ]),
}).strict().superRefine(validateEntitlementTimes);

const acknowledgementSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.ACKNOWLEDGEMENT),
  targetKind: z.enum([
    CHANNEL_KINDS.ENTITLEMENT,
    CHANNEL_KINDS.CATALOG_DISTRIBUTION,
    CHANNEL_KINDS.POLICY_DESIRED_STATE,
    CHANNEL_KINDS.AUDIT_REQUEST,
  ]),
  targetVersion: monotonicVersion.min(1),
  targetDigest: sha256,
  targetGlobalReleaseId: messageId.nullable().optional(),
  targetGlobalVersion: monotonicVersion.min(1).nullable().optional(),
  targetGlobalArtifactDigest: sha256.nullable().optional(),
  lifecycleStage: z.enum(['delivered', 'applied']),
  outcome: z.enum(['success', 'rejected']),
  reasonCode: z.enum([
    'delivered', 'applied', 'already_applied', 'invalid_signature', 'invalid_schema', 'stale_version',
    'version_conflict', 'customer_mismatch', 'deployment_mismatch', 'policy_weakening',
    'expired', 'operator_denied', 'internal_failure',
  ]),
  recordedAt: isoTime,
}).strict().superRefine(validateAcknowledgement);

const diagnosticSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.DIAGNOSTIC),
  correlationId: messageId,
  component: z.enum([
    'browser', 'endpoint', 'mcp', 'gateway', 'connector', 'control_plane',
    'storage', 'database', 'policy', 'catalog', 'licensing', 'updater',
  ]),
  code: z.enum([
    'CONNECTOR_AUTH_FAILED', 'CONNECTOR_TIMEOUT', 'CONNECTOR_PROTOCOL_REJECTED',
    'ENTITLEMENT_REJECTED', 'POLICY_REJECTED', 'CATALOG_REJECTED',
    'AUDIT_INTEGRITY_FAILED', 'STORAGE_DEGRADED', 'SENSOR_STALE',
    'VERSION_GAP', 'QUEUE_BACKLOG', 'RATE_LIMITED',
  ]),
  severity: z.enum(['info', 'warning', 'error', 'critical']),
  outcome: z.enum(['healthy', 'degraded', 'retrying', 'blocked', 'recovered']),
  countBucket: z.enum(['0', '1', '2-5', '6-20', '21-100', '100+']),
  sizeBucket: z.enum(['none', '<1kb', '1-16kb', '16-256kb', '256kb-1mb', '1mb+']),
  durationBucket: z.enum(['<10ms', '10-100ms', '100ms-1s', '1-5s', '5-30s', '30s+']),
  retryState: z.enum(['none', 'scheduled', 'exhausted', 'recovered']),
  componentVersion: z.string().regex(VERSION_RE),
  occurredAt: isoTime,
}).strict();

const shadowCandidateSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.SHADOW_CANDIDATE),
  candidateId: messageId,
  registrableDomain: z.string().regex(DOMAIN_RE).refine(safeAggregateDomain),
  sourceType: z.enum(['browser_destination', 'proxy_import', 'catalog_match']),
  firstSeenDay: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine(canonicalDay),
  observationCountBucket: z.enum(['1', '2-5', '6-20', '21-100', '100+']),
  confidenceBps: z.number().int().min(0).max(10_000),
  localClassification: z.enum(['unknown', 'generative_ai', 'ai_adjacent', 'not_ai']),
  localOutcome: z.enum(['observed', 'warned', 'blocked']),
}).strict();

const catalogRecordSchema = z.object({
  catalogId: safeSlug,
  registrableDomain: z.string().regex(DOMAIN_RE).refine(safeAggregateDomain),
  aliases: z.array(z.string().regex(DOMAIN_RE).refine(safeAggregateDomain)).max(32).refine(sortedStrings),
  classification: z.enum(['generative_ai', 'ai_adjacent', 'not_ai']),
  riskTier: z.enum(['low', 'moderate', 'high', 'critical']),
  analystState: z.literal('approved'),
  evidenceClass: z.enum(['public_documentation', 'vendor_validation', 'customer_aggregate']),
  confidenceBps: z.number().int().min(0).max(10_000),
}).strict().refine((record) => new Set(record.aliases).size === record.aliases.length, {
  path: ['aliases'], message: 'invalid protocol value',
});

const catalogReleaseSchema = z.object({
  schemaVersion: z.literal(PROTOCOL_VERSION),
  messageId,
  kind: z.literal(CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE),
  authorityManifestGeneration: monotonicVersion.min(1),
  authorityManifestKeySlot: z.enum(['current', 'next']),
  globalReleaseId: messageId,
  globalVersion: monotonicVersion.min(1),
  previousGlobalVersion: monotonicVersion,
  rollbackOfGlobalVersion: monotonicVersion.min(1).nullable(),
  issuedAt: isoTime,
  recordsDigest: sha256,
  records: z.array(catalogRecordSchema).max(10_000)
    .refine((records) => records.every((record, index) => index === 0
      || records[index - 1].catalogId.localeCompare(record.catalogId) < 0)),
}).strict()
  .superRefine(validateGlobalCatalogProgression)
  .superRefine(validateCatalogRecordsDigest)
  .superRefine(validateCatalogDomains);

const rolloutSchema = z.object({
  mode: z.enum(['preview', 'staged', 'required']),
  cohortBps: z.number().int().min(0).max(10_000),
}).strict().superRefine((value, ctx) => {
  if ((value.mode === 'preview' && value.cohortBps !== 0)
      || (value.mode === 'required' && value.cohortBps !== 10_000)
      || (value.mode === 'staged' && (value.cohortBps < 1 || value.cohortBps >= 10_000))) {
    addIssue(ctx, 'cohortBps');
  }
});

const catalogDistributionSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.CATALOG_DISTRIBUTION),
  authorityManifestGeneration: monotonicVersion.min(1),
  authorityManifestKeySlot: z.enum(['current', 'next']),
  distributionSequence: monotonicVersion.min(1),
  previousDistributionSequence: monotonicVersion,
  globalReleaseId: messageId,
  globalVersion: monotonicVersion.min(1),
  globalArtifactDigest: sha256,
  recordsDigest: sha256,
  rollout: rolloutSchema,
  issuedAt: isoTime,
}).strict().superRefine((value, ctx) => {
  if (value.previousDistributionSequence !== value.distributionSequence - 1) {
    addIssue(ctx, 'previousDistributionSequence');
  }
});

const policyDesiredStateSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.POLICY_DESIRED_STATE),
  policyVersion: monotonicVersion.min(1),
  previousVersion: monotonicVersion,
  rollbackOfVersion: monotonicVersion.min(1).nullable(),
  bundleDigest: sha256,
  mandatoryControlsDigest: sha256,
  issuedAt: isoTime,
  expiresAt: isoTime,
  rollout: z.enum(['preview', 'staged', 'required']),
}).strict().superRefine(validatePolicyTimes);

const auditRequestSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.AUDIT_REQUEST),
  requestId: messageId,
  requestVersion: monotonicVersion.min(1),
  requestType: z.enum(['integrity_status', 'bounded_event_summary', 'deployment_attestation']),
  purposeCode: z.enum(['customer_support', 'security_incident', 'compliance_assistance']),
  notBefore: isoTime,
  expiresAt: isoTime,
  maxRecords: z.number().int().min(1).max(10_000),
  fields: z.array(z.enum([
    'event_type', 'outcome', 'component', 'policy_version', 'catalog_version',
    'entitlement_version', 'coarse_timestamp', 'count', 'integrity_status',
  ])).min(1).max(16),
}).strict().superRefine(validateAuditRequestTimes);

const auditSummarySchema = z.object({
  field: z.enum([
    'event_type', 'outcome', 'component', 'policy_version', 'catalog_version',
    'entitlement_version', 'coarse_timestamp', 'count', 'integrity_status',
  ]),
  valueCode: z.enum([
    'ok', 'failed', 'unknown', 'allowed', 'warned', 'redacted', 'blocked',
    'browser', 'endpoint', 'mcp', 'gateway', 'control_plane', 'current',
    'stale', 'missing', 'intact', 'tampered', 'present', 'absent',
  ]).nullable(),
  version: monotonicVersion.nullable(),
  coarseTimestamp: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:00:00\.000Z$/)
    .refine(canonicalIsoTime).nullable(),
  count: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
}).strict().superRefine(validateAuditSummary);

const auditResponseSchema = z.object({
  ...baseFields,
  kind: z.literal(CHANNEL_KINDS.AUDIT_RESPONSE),
  requestId: messageId,
  requestVersion: monotonicVersion.min(1),
  status: z.enum(['approved', 'denied', 'expired', 'revoked', 'completed']),
  reasonCode: z.enum([
    'customer_approved', 'customer_denied', 'request_expired', 'customer_revoked',
    'completed', 'integrity_unavailable', 'scope_rejected',
  ]),
  respondedAt: isoTime,
  summaries: z.array(auditSummarySchema).max(10_000),
}).strict().superRefine(validateAuditResponse);

const CHANNEL_SCHEMAS = Object.freeze({
  [CHANNEL_KINDS.HEARTBEAT]: heartbeatSchema,
  [CHANNEL_KINDS.ENTITLEMENT]: entitlementSchema,
  [CHANNEL_KINDS.ACKNOWLEDGEMENT]: acknowledgementSchema,
  [CHANNEL_KINDS.DIAGNOSTIC]: diagnosticSchema,
  [CHANNEL_KINDS.SHADOW_CANDIDATE]: shadowCandidateSchema,
  [CHANNEL_KINDS.GLOBAL_CATALOG_RELEASE]: catalogReleaseSchema,
  [CHANNEL_KINDS.CATALOG_DISTRIBUTION]: catalogDistributionSchema,
  [CHANNEL_KINDS.POLICY_DESIRED_STATE]: policyDesiredStateSchema,
  [CHANNEL_KINDS.AUDIT_REQUEST]: auditRequestSchema,
  [CHANNEL_KINDS.AUDIT_RESPONSE]: auditResponseSchema,
});

function timeMs(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function canonicalIsoTime(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function twoLabelDomain(value) {
  return String(value).split('.').length === 2;
}

function safeAggregateDomain(value) {
  if (!twoLabelDomain(value)) return false;
  const labels = String(value).split('.');
  if (PRIVATE_OR_RESERVED_TLDS.has(labels[labels.length - 1])) return false;
  return !labels.some((label) => /\d{4,}/.test(label)
    || /(?:^|-)(?:account|canary|customer|loan|member|patient|secret|ssn|token)(?:-|$)/.test(label));
}

function canonicalDay(value) {
  const parsed = Date.parse(`${value}T00:00:00.000Z`);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === `${value}T00:00:00.000Z`;
}

function sortedStrings(values) {
  return values.every((value, index) => index === 0 || values[index - 1].localeCompare(value) < 0);
}

function validateEntitlementTimes(value, ctx) {
  const issuedAt = timeMs(value.issuedAt);
  const expiresAt = timeMs(value.expiresAt);
  const fallbackUntil = value.fallbackUntil === null ? null : timeMs(value.fallbackUntil);
  if (value.previousVersion >= value.entitlementVersion) addIssue(ctx, 'previousVersion');
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)
      || expiresAt <= issuedAt || expiresAt - issuedAt > MAX_ENTITLEMENT_TTL_MS) addIssue(ctx, 'expiresAt');
  if (value.status !== 'active' && fallbackUntil !== null) addIssue(ctx, 'fallbackUntil');
  if (value.status === 'active' && fallbackUntil === null) addIssue(ctx, 'fallbackUntil');
  if (fallbackUntil !== null && (fallbackUntil <= issuedAt || fallbackUntil - issuedAt > MAX_FALLBACK_WINDOW_MS)) {
    addIssue(ctx, 'fallbackUntil');
  }
  const reasons = {
    active: ['billing_active', 'trial_active', 'manual_restore'],
    paused: ['manual_pause', 'payment_past_due'],
    revoked: ['manual_revoke', 'subscription_ended', 'emergency_revoke'],
  };
  if (!reasons[value.status].includes(value.reasonCode)) addIssue(ctx, 'reasonCode');
}

function validatePolicyTimes(value, ctx) {
  if (value.previousVersion >= value.policyVersion) addIssue(ctx, 'previousVersion');
  if (value.rollbackOfVersion !== null && value.rollbackOfVersion >= value.policyVersion) {
    addIssue(ctx, 'rollbackOfVersion');
  }
  if (timeMs(value.expiresAt) <= timeMs(value.issuedAt)) addIssue(ctx, 'expiresAt');
}

function validateAuditRequestTimes(value, ctx) {
  const start = timeMs(value.notBefore);
  const end = timeMs(value.expiresAt);
  if (end <= start || end - start > 24 * 60 * 60 * 1000) addIssue(ctx, 'expiresAt');
  if (new Set(value.fields).size !== value.fields.length) addIssue(ctx, 'fields');
}

function validateAuditSummary(value, ctx) {
  const supplied = [value.valueCode, value.version, value.coarseTimestamp].filter((item) => item !== null);
  if (supplied.length !== 1) addIssue(ctx, 'valueCode');
  if (value.field.endsWith('_version') && value.version === null) addIssue(ctx, 'version');
  if (value.field === 'coarse_timestamp' && value.coarseTimestamp === null) addIssue(ctx, 'coarseTimestamp');
  if (!value.field.endsWith('_version') && value.field !== 'coarse_timestamp' && value.valueCode === null) {
    addIssue(ctx, 'valueCode');
  }
}

function validateAcknowledgement(value, ctx) {
  const successReasons = {
    delivered: new Set(['delivered']),
    applied: new Set(['applied', 'already_applied']),
  };
  const rejectedReasons = new Set([
    'invalid_signature', 'invalid_schema', 'stale_version', 'version_conflict',
    'customer_mismatch', 'deployment_mismatch', 'policy_weakening', 'expired',
    'operator_denied', 'internal_failure',
  ]);
  const allowed = value.outcome === 'success'
    ? successReasons[value.lifecycleStage]?.has(value.reasonCode)
    : rejectedReasons.has(value.reasonCode);
  if (!allowed) addIssue(ctx, 'reasonCode');
  const catalogTarget = value.targetKind === CHANNEL_KINDS.CATALOG_DISTRIBUTION;
  const catalogBinding = [
    value.targetGlobalReleaseId,
    value.targetGlobalVersion,
    value.targetGlobalArtifactDigest,
  ];
  if (catalogTarget && catalogBinding.some((item) => item === null || item === undefined)) {
    addIssue(ctx, 'targetGlobalReleaseId');
  }
  if (!catalogTarget && catalogBinding.some((item) => item !== null && item !== undefined)) {
    addIssue(ctx, 'targetGlobalReleaseId');
  }
}

function validateGlobalCatalogProgression(value, ctx) {
  if (value.previousGlobalVersion !== value.globalVersion - 1) {
    addIssue(ctx, 'previousGlobalVersion');
  }
  if (value.rollbackOfGlobalVersion !== null
      && value.rollbackOfGlobalVersion >= value.globalVersion) {
    addIssue(ctx, 'rollbackOfGlobalVersion');
  }
}

function validateCatalogRecordsDigest(value, ctx) {
  if (catalogRecordsDigest(value.records) !== value.recordsDigest) addIssue(ctx, 'recordsDigest');
}

function validateAuditResponse(value, ctx) {
  const reasons = {
    approved: 'customer_approved',
    denied: 'customer_denied',
    expired: 'request_expired',
    revoked: 'customer_revoked',
  };
  if (value.status === 'completed') {
    if (!['completed', 'integrity_unavailable', 'scope_rejected'].includes(value.reasonCode)) {
      addIssue(ctx, 'reasonCode');
    }
    if (value.reasonCode !== 'completed' && value.summaries.length) addIssue(ctx, 'summaries');
    return;
  }
  if (reasons[value.status] !== value.reasonCode) addIssue(ctx, 'reasonCode');
  if (value.summaries.length) addIssue(ctx, 'summaries');
}

function validateCatalogDomains(value, ctx) {
  const claimed = new Set();
  for (let index = 0; index < value.records.length; index += 1) {
    const record = value.records[index];
    for (const domain of [record.registrableDomain, ...record.aliases]) {
      if (claimed.has(domain)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['records', index, 'registrableDomain'],
          message: 'invalid protocol value',
        });
        return;
      }
      claimed.add(domain);
    }
  }
}

function validateVersionProgression(field) {
  return (value, ctx) => {
    if (value.previousVersion >= value[field]) addIssue(ctx, 'previousVersion');
    if (value.rollbackOfVersion !== null && value.rollbackOfVersion >= value[field]) {
      addIssue(ctx, 'rollbackOfVersion');
    }
  };
}

function addIssue(ctx, path) {
  ctx.addIssue({ code: z.ZodIssueCode.custom, path: [path], message: 'invalid protocol value' });
}

function parseChannel(value, expectedKind = '') {
  const snapshot = channelSnapshot(value);
  if (!snapshot) return invalid('channel_schema_invalid');
  const kind = snapshot.value && typeof snapshot.value === 'object'
    && !Array.isArray(snapshot.value) ? snapshot.value.kind : '';
  if (!kind || (expectedKind && kind !== expectedKind)) return invalid('channel_kind_invalid');
  const schema = CHANNEL_SCHEMAS[kind];
  if (!schema) return invalid('channel_kind_unsupported');
  if (snapshot.bytes > MAX_CHANNEL_BYTES[kind]) return invalid('channel_too_large');
  const result = schema.safeParse(snapshot.value);
  if (!result.success) return invalid('channel_schema_invalid', result.error.issues.length);
  return { ok: true, value: result.data };
}

function channelSnapshot(value) {
  try {
    const serialized = JSON.stringify(value);
    if (typeof serialized !== 'string') return null;
    return {
      value: JSON.parse(serialized),
      bytes: Buffer.byteLength(serialized, 'utf8'),
    };
  } catch { return null; }
}

function invalid(error, issueCount = 0) {
  return { ok: false, error, issueCount };
}

function assertChannel(value, expectedKind = '') {
  const parsed = parseChannel(value, expectedKind);
  if (parsed.ok) return parsed.value;
  const error = new TypeError('vendor control payload rejected');
  error.code = parsed.error;
  throw error;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!value || typeof value !== 'object') return JSON.stringify(value);
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

function catalogRecordsDigest(records) {
  return crypto.createHash('sha256').update(canonicalJson(records), 'utf8').digest('hex');
}

function payloadDigest(value, expectedKind = '') {
  const parsed = assertChannel(value, expectedKind);
  return crypto.createHash('sha256').update(canonicalJson(parsed), 'utf8').digest('hex');
}

function signingInput(value, keyId) {
  const parsed = assertChannel(value);
  const domain = SIGNATURE_DOMAINS[parsed.kind];
  if (!domain) {
    const error = new TypeError('channel is not signed');
    error.code = 'channel_not_signed';
    throw error;
  }
  if (!KEY_ID_RE.test(String(keyId || ''))) {
    const error = new TypeError('signing key identifier rejected');
    error.code = 'signing_key_id_invalid';
    throw error;
  }
  return Buffer.from(`${domain}\0${keyId}\0${canonicalJson(parsed)}`, 'utf8');
}

function heartbeatIntervalMs(value) {
  if (value === undefined || value === null || value === '') return DEFAULT_HEARTBEAT_INTERVAL_MS;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < MIN_HEARTBEAT_INTERVAL_MS || parsed > MAX_HEARTBEAT_INTERVAL_MS) {
    throw new RangeError('heartbeat interval must be between 30 and 300 seconds');
  }
  return parsed;
}

function fallbackWindowMs(value) {
  if (value === undefined || value === null || value === '') return DEFAULT_FALLBACK_WINDOW_MS;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > MAX_FALLBACK_WINDOW_MS) {
    throw new RangeError('fallback window exceeds the seven-day maximum');
  }
  return parsed;
}

const LIFECYCLE_STAGES = Object.freeze(['requested', 'issued', 'delivered', 'applied', 'acknowledged']);

function lifecycleTransition(current, next) {
  const fromIndex = LIFECYCLE_STAGES.indexOf(current);
  const toIndex = LIFECYCLE_STAGES.indexOf(next);
  if (fromIndex < 0 || toIndex < 0) return { ok: false, reason: 'unknown_stage' };
  if (fromIndex === toIndex) return { ok: true, idempotent: true };
  if (toIndex === fromIndex + 1) return { ok: true, idempotent: false };
  return { ok: false, reason: toIndex < fromIndex ? 'stage_regression' : 'stage_skipped' };
}

function entitlementDecision(candidate, current = null) {
  const parsed = assertChannel(candidate, CHANNEL_KINDS.ENTITLEMENT);
  const digest = payloadDigest(parsed, CHANNEL_KINDS.ENTITLEMENT);
  if (!current) return { action: 'apply', digest, entitlement: parsed };
  if (parsed.entitlementVersion < current.version) return { action: 'reject', reason: 'stale_version' };
  if (parsed.entitlementVersion === current.version) {
    return digest === current.digest
      ? { action: 'acknowledge', reason: 'already_applied', digest, entitlement: parsed }
      : { action: 'reject', reason: 'version_conflict' };
  }
  return { action: 'apply', digest, entitlement: parsed };
}

function fallbackDisposition(state, nowMs = Date.now()) {
  if (!state || !state.connectedEver || !state.highWaterIntact) return blocked('connected_state_missing');
  if (!state.entitlement || state.entitlement.status !== 'active') return blocked('vendor_state_blocks_fallback');
  if (state.failureClass !== 'transport_unavailable') return blocked('fallback_failure_not_transport');
  if (!Number.isFinite(state.trustedTimeMs) || nowMs + 300_000 < state.trustedTimeMs) return blocked('clock_rollback');
  const deadline = timeMs(state.entitlement.fallbackUntil);
  if (!Number.isFinite(deadline) || nowMs > deadline) return blocked('fallback_expired');
  return { mode: 'degraded_fallback', reason: 'vendor_unreachable', deadline };
}

function blocked(reason) {
  return { mode: 'blocked', reason };
}

module.exports = {
  PROTOCOL_VERSION,
  CHANNEL_KINDS,
  CHANNEL_SCHEMAS,
  SIGNATURE_DOMAINS,
  MAX_CHANNEL_BYTES,
  DEFAULT_HEARTBEAT_INTERVAL_MS,
  MIN_HEARTBEAT_INTERVAL_MS,
  MAX_HEARTBEAT_INTERVAL_MS,
  DEFAULT_FALLBACK_WINDOW_MS,
  MAX_FALLBACK_WINDOW_MS,
  MAX_ENTITLEMENT_TTL_MS,
  FAILURE_CLASSES,
  LIFECYCLE_STAGES,
  parseChannel,
  assertChannel,
  canonicalJson,
  catalogRecordsDigest,
  payloadDigest,
  signingInput,
  heartbeatIntervalMs,
  fallbackWindowMs,
  lifecycleTransition,
  entitlementDecision,
  fallbackDisposition,
};
