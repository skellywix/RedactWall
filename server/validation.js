'use strict';
/**
 * Request-body contracts for API boundaries that accept sensor or admin input.
 * Validation errors intentionally include field names only, never submitted
 * values, because those values may be prompts, files, passwords, or notes.
 */
const { z } = require('zod');
const detector = require('./detector');

const LIMITS = {
  promptChars: 200000,
  responseChars: 200000,
  noteChars: 2000,
  metadataChars: 512,
  idChars: 128,
  filenameChars: 512,
  base64Chars: 12 * 1024 * 1024,
  policyListItems: 200,
};

const DETECTOR_ID = /^[A-Z0-9_]+$/;
const HOST_OR_LABEL = /^[A-Za-z0-9.*:_/-]+$/;
const KNOWN_DETECTOR_IDS = new Set(detector.listDetectors().map((d) => d.id));

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

const detectorIdSchema = z.string().max(80).regex(DETECTOR_ID).refine((id) => KNOWN_DETECTOR_IDS.has(id), {
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

const clientOutcomeSchema = z.enum([
  'allowed',
  'redacted_sent',
  'redacted_available',
  'injection_blocked',
  'shadow_ai',
  'file_too_large',
  'file_unsupported',
  'scan_unavailable',
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

const scannerPolicySchema = z.object({
  ignoreDirectories: z.array(nonBlankString(128)).max(LIMITS.policyListItems).optional(),
  ignoreFilenames: z.array(nonBlankString(128)).max(LIMITS.policyListItems).optional(),
  ignoreExtensions: z.array(z.string().min(2).max(32).regex(/^\.[A-Za-z0-9_-]+$/)).max(LIMITS.policyListItems).optional(),
  maxFileBytes: z.number().int().min(1024).max(50 * 1024 * 1024).optional(),
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
  loginSchema,
  revealSchema,
  approveSchema,
  noteSchema,
  applyTemplateSchema,
  policyUpdateSchema,
};
