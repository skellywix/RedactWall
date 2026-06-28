'use strict';
/**
 * Request-body contracts for API boundaries that accept sensor or admin input.
 * Validation errors intentionally include field names only, never submitted
 * values, because those values may be prompts, files, passwords, or notes.
 */
const { z } = require('zod');
const detector = require('./detector');
const customDetectors = require('./custom-detectors');

const LIMITS = {
  promptChars: 200000,
  responseChars: 200000,
  noteChars: 2000,
  metadataChars: 512,
  idChars: 128,
  filenameChars: 512,
  base64Chars: 12 * 1024 * 1024,
  policyListItems: 200,
  destinationReviewReasonChars: 240,
};

const DETECTOR_ID = /^[A-Z0-9_]+$/;
const HOST_OR_LABEL = /^[A-Za-z0-9.*:_/-]+$/;
const DESKTOP_DESTINATION_LABEL = /^[A-Za-z0-9 .:_/-]+$/;
const SENSOR_ID = /^[a-z][a-z0-9_:-]{0,79}$/;
const SENSOR_VERSION = /^[A-Za-z0-9._+:-]+$/;
const ROUTING_RULE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const ROUTING_GROUP = /^[a-z][a-z0-9_-]{0,63}$/;
const ROUTING_ROLE = /^(security_admin|approver)$/;
const ROUTING_REASON = /^[a-z0-9][a-z0-9_:-]{0,79}$/;
const POLICY_MATCH_TEXT = /^[A-Za-z0-9 ._@:+/-]+$/;
const SENSITIVE_ROUTING_CODE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\d{12,19})/;
function knownDetectorIds() {
  return new Set(detector.listDetectors({
    customDetectors: customDetectors.loadCustomDetectors(),
  }).map((d) => d.id));
}

function nonBlankString(max) {
  return z.string().max(max).refine((value) => value.trim().length > 0, {
    message: 'required',
  });
}

function optionalString(max) {
  return z.preprocess(
    (value) => (value == null ? undefined : value),
    z.string().max(max).optional(),
  );
}

function stringDefault(defaultValue, max = LIMITS.metadataChars) {
  return z.preprocess(
    (value) => (value == null ? undefined : value),
    z.string().max(max).default(defaultValue),
  );
}

function nullableString(max = LIMITS.metadataChars) {
  return z.preprocess(
    (value) => (value === undefined ? null : value),
    z.string().max(max).nullable(),
  );
}

const detectorIdSchema = z.string().max(80).regex(DETECTOR_ID).refine((id) => knownDetectorIds().has(id), {
  message: 'unknown detector',
});
const clientScoreSchema = z.number().min(0).max(1);
const severitySchema = z.number().int().min(0).max(4);

const clientFindingSchema = z.object({
  type: detectorIdSchema,
  severity: severitySchema.optional(),
  score: clientScoreSchema.optional(),
  masked: optionalString(256),
}).strict();

const clientCategorySchema = z.union([
  detectorIdSchema,
  z.object({
    category: detectorIdSchema,
    score: clientScoreSchema.optional(),
  }).strict(),
]);

const entityCountsSchema = z.record(
  detectorIdSchema,
  z.number().int().min(0).max(100000),
);

const sensorMetadataSchema = z.object({
  name: optionalString(80),
  version: optionalString(80),
  packageVersion: optionalString(80),
  platform: optionalString(80),
}).strict();

const heartbeatCheckSchema = z.object({
  id: z.string().min(1).max(80).regex(SENSOR_ID),
  ok: z.boolean(),
  detail: optionalString(160),
}).strict();

const clientOutcomeSchema = z.enum([
  'allowed',
  'redacted_sent',
  'redacted_available',
  'injection_blocked',
  'shadow_ai',
  'file_too_large',
  'file_unsupported',
  'ocr_required',
  'scan_unavailable',
  'destination_blocked',
  'file_upload_blocked',
  'action_blocked',
  'paste_flagged',
  'sent_after_warning',
  'justified',
  'blocked_by_user',
  'awaiting_approval',
]).nullable().optional();

const commonSensorContext = {
  user: stringDefault('unknown'),
  destination: stringDefault('unknown'),
  sourceIp: nullableString(),
  source: stringDefault('api'),
  channel: stringDefault('submit'),
  orgId: nullableString(),
  sensor: sensorMetadataSchema.optional(),
};

const gateSchema = z.object({
  prompt: nonBlankString(LIMITS.promptChars),
  ...commonSensorContext,
  clientOutcome: clientOutcomeSchema,
  note: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.noteChars).default(''),
  ),
  clientFindings: z.array(clientFindingSchema).max(250).optional(),
  clientCategories: z.array(clientCategorySchema).max(250).optional(),
  clientEntityCounts: entityCountsSchema.optional(),
  clientRiskScore: z.number().min(0).max(100).optional(),
  clientMaxSeverity: severitySchema.optional(),
  clientMaxSeverityLabel: z.enum(['none', 'low', 'medium', 'high', 'critical']).optional(),
  clientPreRedacted: z.boolean().optional(),
}).strict();

const rehydrateSchema = z.object({
  id: nonBlankString(LIMITS.idChars),
  text: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.responseChars).default(''),
  ),
}).strict();

function isBase64(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) return false;
  return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

const scanFileSchema = z.object({
  filename: nonBlankString(LIMITS.filenameChars),
  contentBase64: z.string().min(1).max(LIMITS.base64Chars).refine(isBase64, {
    message: 'invalid base64',
  }),
  user: stringDefault('unknown'),
  destination: stringDefault('unknown'),
  source: stringDefault('api'),
  channel: stringDefault('file_upload'),
  orgId: nullableString(),
  sensor: sensorMetadataSchema.optional(),
}).strict();

const scanResponseSchema = z.object({
  text: nonBlankString(LIMITS.responseChars),
  user: stringDefault('unknown'),
  destination: stringDefault('unknown'),
  source: stringDefault('api'),
  orgId: nullableString(),
  sensor: sensorMetadataSchema.optional(),
}).strict();

const heartbeatSchema = z.object({
  user: stringDefault('unknown'),
  destination: stringDefault('sensor-health'),
  source: stringDefault('api'),
  orgId: nullableString(),
  sensor: sensorMetadataSchema.optional(),
  checks: z.array(heartbeatCheckSchema).max(40).optional(),
}).strict();

const loginSchema = z.object({
  user: nonBlankString(128),
  password: nonBlankString(512),
  otp: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(32).default(''),
  ),
}).strict();

const revealSchema = z.object({
  password: nonBlankString(512),
}).strict();

const approveSchema = z.object({
  note: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.noteChars).default(''),
  ),
  password: nonBlankString(512),
}).strict();

const noteSchema = z.object({
  note: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.noteChars).default(''),
  ),
}).strict();

const applyTemplateSchema = z.object({
  id: z.string().min(1).max(80).regex(/^[a-z0-9_/-]+$/),
}).strict();

const destinationReviewSchema = z.object({
  destination: z.string().min(1).max(253).regex(HOST_OR_LABEL),
  decision: z.enum(['govern', 'allow', 'block']),
  reason: nonBlankString(LIMITS.destinationReviewReasonChars),
}).strict();

const scannerPolicySchema = z.object({
  ignoreDirectories: z.array(nonBlankString(128)).max(LIMITS.policyListItems).optional(),
  ignoreFilenames: z.array(nonBlankString(128)).max(LIMITS.policyListItems).optional(),
  ignoreExtensions: z.array(z.string().min(2).max(32).regex(/^\.[A-Za-z0-9_-]+$/)).max(LIMITS.policyListItems).optional(),
  maxFileBytes: z.number().int().min(1024).max(50 * 1024 * 1024).optional(),
}).strict();

const sensorIdSchema = z.string().max(80).regex(SENSOR_ID);
const desiredSensorVersionsSchema = z.record(
  sensorIdSchema,
  z.string().min(1).max(80).regex(SENSOR_VERSION),
).refine((value) => Object.keys(value || {}).length <= LIMITS.policyListItems, {
  message: 'too many desired sensor versions',
});

function routingCodeSchema(pattern, max) {
  return z.string().min(1).max(max).regex(pattern).refine((value) => !SENSITIVE_ROUTING_CODE.test(value), {
    message: 'sensitive identifier not allowed',
  });
}

const safePolicyMatchTextSchema = z.string().min(1).max(128).regex(POLICY_MATCH_TEXT).refine((value) => !SENSITIVE_ROUTING_CODE.test(value), {
  message: 'sensitive identifier not allowed',
});

const approvalRoutingRuleSchema = z.object({
  id: routingCodeSchema(ROUTING_RULE_ID, 64),
  enabled: z.boolean().optional(),
  users: z.array(safePolicyMatchTextSchema).max(40).optional(),
  groups: z.array(safePolicyMatchTextSchema).max(40).optional(),
  orgIds: z.array(safePolicyMatchTextSchema).max(40).optional(),
  detectors: z.array(detectorIdSchema).max(40).optional(),
  categories: z.array(detectorIdSchema).max(40).optional(),
  sources: z.array(sensorIdSchema).max(40).optional(),
  channels: z.array(sensorIdSchema).max(40).optional(),
  destinations: z.array(z.string().min(1).max(253).regex(HOST_OR_LABEL)).max(40).optional(),
  minSeverity: z.number().int().min(0).max(4).optional(),
  minRiskScore: z.number().int().min(0).max(100).optional(),
  assignedGroup: routingCodeSchema(ROUTING_GROUP, 64),
  assignedRole: z.enum(['security_admin', 'approver']),
  slaMinutes: z.number().int().min(15).max(7 * 24 * 60),
  reason: routingCodeSchema(ROUTING_REASON, 80).optional(),
}).strict().refine((rule) => {
  return ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations'].some((key) => Array.isArray(rule[key]) && rule[key].length)
    || rule.minSeverity !== undefined
    || rule.minRiskScore !== undefined;
}, {
  message: 'at least one matcher required',
  path: ['id'],
});

const policyMatcherFields = {
  users: z.array(safePolicyMatchTextSchema).max(40).optional(),
  groups: z.array(safePolicyMatchTextSchema).max(40).optional(),
  orgIds: z.array(safePolicyMatchTextSchema).max(40).optional(),
  detectors: z.array(detectorIdSchema).max(40).optional(),
  categories: z.array(detectorIdSchema).max(40).optional(),
  sources: z.array(sensorIdSchema).max(40).optional(),
  channels: z.array(sensorIdSchema).max(40).optional(),
  destinations: z.array(z.string().min(1).max(253).regex(HOST_OR_LABEL)).max(40).optional(),
};

function hasPolicyMatcher(rule) {
  return ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations']
    .some((key) => Array.isArray(rule[key]) && rule[key].length);
}

const policyScopeSchema = z.object({
  id: routingCodeSchema(ROUTING_RULE_ID, 64),
  enabled: z.boolean().optional(),
  ...policyMatcherFields,
  enforcementMode: z.enum(['block', 'warn', 'justify', 'redact']).optional(),
  blockMinSeverity: z.number().int().min(1).max(4).optional(),
  blockRiskScore: z.number().int().min(0).max(100).optional(),
  alwaysBlockAdd: z.array(detectorIdSchema).max(40).optional(),
  reason: routingCodeSchema(ROUTING_REASON, 80).optional(),
}).strict().refine(hasPolicyMatcher, {
  message: 'at least one matcher required',
  path: ['id'],
}).refine((rule) => {
  return rule.enforcementMode !== undefined
    || rule.blockMinSeverity !== undefined
    || rule.blockRiskScore !== undefined
    || (Array.isArray(rule.alwaysBlockAdd) && rule.alwaysBlockAdd.length > 0);
}, {
  message: 'at least one scoped override required',
  path: ['id'],
});

const policyExceptionSchema = z.object({
  id: routingCodeSchema(ROUTING_RULE_ID, 64),
  enabled: z.boolean().optional(),
  ...policyMatcherFields,
  action: z.enum(['allow']).optional(),
  expiresAt: z.string().min(1).max(40).refine((value) => Number.isFinite(Date.parse(value)), {
    message: 'invalid datetime',
  }),
  ownerGroup: routingCodeSchema(ROUTING_GROUP, 64).optional(),
  reviewerRole: z.string().max(32).regex(ROUTING_ROLE).optional(),
  reviewAfter: z.string().min(1).max(40).refine((value) => Number.isFinite(Date.parse(value)), {
    message: 'invalid datetime',
  }).optional(),
  reason: routingCodeSchema(ROUTING_REASON, 80).optional(),
}).strict().refine(hasPolicyMatcher, {
  message: 'at least one matcher required',
  path: ['id'],
}).refine((rule) => {
  if (!rule.reviewAfter) return true;
  return Date.parse(rule.reviewAfter) <= Date.parse(rule.expiresAt);
}, {
  message: 'review must be due before expiry',
  path: ['reviewAfter'],
});

const blockedBrowserActionSchema = z.object({
  id: routingCodeSchema(ROUTING_RULE_ID, 64),
  enabled: z.boolean().optional(),
  action: z.enum(['paste', 'drop', 'copy']),
  destinations: z.array(z.string().min(1).max(253).regex(HOST_OR_LABEL).refine((value) => !SENSITIVE_ROUTING_CODE.test(value), {
    message: 'sensitive identifier not allowed',
  })).min(1).max(40),
  reason: routingCodeSchema(ROUTING_REASON, 80).optional(),
}).strict();

const policyUpdateSchema = z.object({
  enforcementMode: z.enum(['block', 'warn', 'justify', 'redact']).optional(),
  blockMinSeverity: z.number().int().min(1).max(4).optional(),
  blockRiskScore: z.number().int().min(0).max(100).optional(),
  alwaysBlock: z.array(detectorIdSchema).max(LIMITS.policyListItems).optional(),
  storeRawForApproval: z.boolean().optional(),
  rawRetentionDays: z.number().int().min(0).max(3650).optional(),
  ignore: z.array(detectorIdSchema).max(LIMITS.policyListItems).optional(),
  disabledDetectors: z.array(detectorIdSchema).max(LIMITS.policyListItems).optional(),
  governedDestinations: z.array(z.string().min(1).max(253).regex(HOST_OR_LABEL)).max(LIMITS.policyListItems).optional(),
  allowedDestinations: z.array(z.string().min(1).max(253).regex(HOST_OR_LABEL)).max(LIMITS.policyListItems).optional(),
  blockedDestinations: z.array(z.string().min(1).max(253).regex(HOST_OR_LABEL)).max(LIMITS.policyListItems).optional(),
  blockedFileUploadDestinations: z.array(z.string().min(1).max(253).regex(HOST_OR_LABEL)).max(LIMITS.policyListItems).optional(),
  blockedBrowserActions: z.array(blockedBrowserActionSchema).max(40).optional(),
  blockUnapprovedAiDestinations: z.boolean().optional(),
  responseScanMode: z.enum(['flag', 'redact', 'block']).optional(),
  desktopCollectorDestination: z.string().min(1).max(80).regex(DESKTOP_DESTINATION_LABEL).refine((value) => value.trim().length > 0, {
    message: 'required',
  }).optional(),
  approvalRoutingRules: z.array(approvalRoutingRuleSchema).max(40).optional(),
  policyScopes: z.array(policyScopeSchema).max(40).optional(),
  policyExceptions: z.array(policyExceptionSchema).max(40).optional(),
  requiredSensors: z.array(sensorIdSchema).min(1).max(20).optional(),
  desiredSensorVersions: desiredSensorVersionsSchema.optional(),
  scanner: scannerPolicySchema.optional(),
}).strict();

function validationFields(error) {
  const fields = new Set();
  for (const issue of error.issues || []) {
    if (Array.isArray(issue.keys) && issue.keys.length) {
      const prefix = issue.path && issue.path.length ? `${issue.path.join('.')}.` : '';
      for (const key of issue.keys) fields.add(prefix + String(key));
    } else if (issue.path && issue.path.length) fields.add(issue.path.join('.'));
    else fields.add('body');
  }
  return Array.from(fields).sort();
}

function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body || {});
    if (!result.success) {
      return res.status(400).json({
        error: 'invalid request body',
        fields: validationFields(result.error),
      });
    }
    req.body = result.data;
    next();
  };
}

module.exports = {
  LIMITS,
  validateBody,
  validationFields,
  gateSchema,
  rehydrateSchema,
  scanFileSchema,
  scanResponseSchema,
  heartbeatSchema,
  loginSchema,
  revealSchema,
  approveSchema,
  noteSchema,
  applyTemplateSchema,
  destinationReviewSchema,
  policyUpdateSchema,
};
