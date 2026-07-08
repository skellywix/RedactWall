'use strict';
/**
 * Request-body contracts for API boundaries that accept sensor or admin input.
 * Validation errors intentionally include field names only, never submitted
 * values, because those values may be prompts, files, passwords, or notes.
 */
const fs = require('fs');
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
  postureActionNoteChars: 240,
  detectorFeedbackReasonChars: 240,
  updateCommandChars: 256,
  discoverySightings: 100,
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
const UPDATE_REMOTE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/;
const UPDATE_BRANCH_NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const SAFE_OPERATOR_COMMAND = /^[A-Za-z0-9 ._:/\\@+=,-]+$/;
const POSTURE_ACTION_ID = /^[A-Za-z0-9._:@/-]+$/;
const DISCOVERY_DESTINATION_LABEL = /^[A-Za-z0-9.*:-]+$/;
const SENSITIVE_ROUTING_CODE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\d{12,19})/;
// Memoized: a single /api/v1/gate request validates up to ~500 detector ids
// (clientFindings + clientCategories + clientEntityCounts keys), and Zod runs
// this refine once per value. Rebuilding the id set — which reads and parses the
// custom-detector config file each time — per value turned one hot-path request
// into hundreds of synchronous disk reads. Cache on the config file's mtime+size.
let _detectorIdsCache = null;
let _detectorIdsStamp = '';
function knownDetectorIds() {
  let stamp = 'none';
  try {
    const st = fs.statSync(customDetectors.CONFIG_PATH);
    stamp = st.mtimeMs + ':' + st.size;
  } catch { /* no config file — stamp stays 'none' */ }
  if (_detectorIdsCache && _detectorIdsStamp === stamp) return _detectorIdsCache;
  _detectorIdsCache = new Set(detector.listDetectors({
    customDetectors: customDetectors.loadCustomDetectors(),
  }).map((d) => d.id));
  _detectorIdsStamp = stamp;
  return _detectorIdsCache;
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

const licenseInstallSchema = z.object({
  license: z.string().min(1).max(20000),
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
  'proxy_observed',
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
  // Personal-vs-corporate account signal (ROADMAP N4). ENUM ONLY — the strict
  // schema makes it structurally impossible to send a raw account email to the
  // control plane; the sensor classifies locally and reports the result.
  clientAccount: z.object({
    type: z.enum(['personal', 'corporate', 'unknown']),
    signal: z.enum(['workspace_badge', 'org_email_domain', 'personal_email_domain', 'consumer_badge', 'unrecognized_email_domain', 'none']),
  }).strict().optional(),
  // Sanitized origin-app id for data-lineage (e.g. clipboard copied from a
  // core-banking client). Process-name id only — never a title/path/content.
  originApp: z.string().regex(/^[a-z][a-z0-9_]{0,39}$/).optional(),
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
  // Raised 40 -> 80: installs already emit ~25-32 checks, and the endpoint MCP
  // inventory adds an mcp_inventory summary plus up to 12 per-server checks.
  checks: z.array(heartbeatCheckSchema).max(80).optional(),
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

// Inline reassignment of a held decision. Empty string clears a field so the
// console can return an item to "anyone in the group"; omitted fields are
// left unchanged.
function clearableAssignmentField(max, pattern) {
  return z.preprocess(
    (value) => (value === null ? '' : value),
    z.union([z.literal(''), z.string().max(max).regex(pattern)]).optional(),
  );
}

const assignSchema = z.object({
  assignedUser: clearableAssignmentField(LIMITS.idChars, POLICY_MATCH_TEXT),
  assignedGroup: clearableAssignmentField(64, ROUTING_GROUP),
  assignedRole: clearableAssignmentField(16, ROUTING_ROLE),
}).strict().refine(
  (body) => ['assignedUser', 'assignedGroup', 'assignedRole'].some((key) => body[key] !== undefined),
  { message: 'no assignment fields' },
);

const bulkDecisionSchema = z.object({
  ids: z.array(z.string().min(1).max(80)).min(1).max(50),
  action: z.enum(['approve', 'deny']),
  note: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.noteChars).default(''),
  ),
  // Verified by the approve step-up middleware; optional here so an already
  // elevated session can bulk-approve without retyping it.
  password: z.string().max(512).optional(),
}).strict();

const applyTemplateSchema = z.object({
  id: z.string().min(1).max(80).regex(/^[a-z0-9_/-]+$/),
}).strict();

const HEX64 = /^[0-9a-f]{64}$/;

const receiptVerifySchema = z.object({
  v: z.number().int().min(1).max(64),
  id: z.string().min(1).max(80),
  status: z.enum(['allowed', 'redacted', 'warned_sent', 'justified']),
  promptSha256: z.string().regex(HEX64),
  policySha256: z.string().regex(HEX64),
  destination: z.string().min(1).max(253),
  user: z.string().min(1).max(320),
  issuedAt: z.string().min(1).max(40),
  sig: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
}).strict();

const destinationLabelSchema = z.string().min(1).max(253).regex(HOST_OR_LABEL).refine((value) => !SENSITIVE_ROUTING_CODE.test(value), {
  message: 'sensitive identifier not allowed',
});
const mcpToolLabelSchema = z.string().min(1).max(160).regex(/^[A-Za-z0-9.*:_/-]+$/).refine((value) => !SENSITIVE_ROUTING_CODE.test(value), {
  message: 'sensitive identifier not allowed',
});

const destinationReviewSchema = z.object({
  destination: destinationLabelSchema,
  decision: z.enum(['govern', 'allow', 'block']),
  reason: nonBlankString(LIMITS.destinationReviewReasonChars),
}).strict();

const CATALOG_STATUS = ['under_review', 'sanctioned', 'tolerated', 'unsanctioned', 'blocked'];
const catalogAddSchema = z.object({
  destination: destinationLabelSchema,
  appName: optionalString(120),
  sanctionedStatus: z.enum(CATALOG_STATUS).optional(),
}).strict();

const catalogReviewSchema = z.object({
  decision: z.enum(['govern', 'allow', 'block']),
  reason: nonBlankString(LIMITS.destinationReviewReasonChars),
  sanctionedStatus: z.enum(CATALOG_STATUS).optional(),
  owner: optionalString(200),
  notes: optionalString(2000),
}).strict();

const catalogImportSchema = z.object({
  csv: z.string().min(1).max(1024 * 1024),
  source: z.enum(['browser', 'gateway', 'endpoint', 'mcp', 'csv_import', 'manual']).optional(),
}).strict();

// AI use-case inventory (PLANS/ncua-readiness-center.md slice 2). destination
// must be a bare hostname — a URL or anything with a path is rejected so a
// pasted deep link (which can carry query text) never becomes an inventory
// key. Free-text fields are single-line, bounded, and reject sensitive codes
// (safeOperatorText), so prompt-shaped text can't be smuggled into records.
const USE_CASE_HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const USE_CASE_REVIEW_STATUS = ['approved', 'under_review', 'restricted', 'retired'];
const USE_CASE_VENDOR_STATUS = ['reviewed', 'pending', 'not_reviewed'];
const useCaseTextSchema = (max) => z.string().max(max).refine(safeOperatorText, { message: 'unsafe text' })
  .refine((value) => !/:\/\//.test(value), { message: 'urls not allowed' });
// Strict ISO shape, not bare Date.parse: V8's lenient parser accepts
// parenthesized "date comments", which would let free text (or an SSN-shaped
// string) ride a date field into the immutable audit log and examiner packs.
const useCaseDateSchema = z.string().max(40)
  .regex(/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?Z?)?$/, { message: 'invalid datetime' })
  .refine((value) => Number.isFinite(Date.parse(value)), { message: 'invalid datetime' });
const useCaseSchema = z.object({
  destination: z.string().min(1).max(253).regex(USE_CASE_HOST, { message: 'hostname only' })
    .refine((value) => !SENSITIVE_ROUTING_CODE.test(value), { message: 'sensitive identifier not allowed' }),
  department: useCaseTextSchema(80).refine((value) => value.trim().length > 0, { message: 'required' }),
  owner: useCaseTextSchema(160).optional(),
  approvedUse: useCaseTextSchema(240).optional(),
  allowedDataClasses: z.array(detectorIdSchema).max(24).optional(),
  reviewStatus: z.enum(USE_CASE_REVIEW_STATUS).optional(),
  vendorStatus: z.enum(USE_CASE_VENDOR_STATUS).optional(),
  nextReviewAt: useCaseDateSchema.optional(),
  policyScopeId: z.string().max(64).regex(/^[a-z0-9][a-z0-9_-]{0,63}$/).optional(),
}).strict();

const useCaseReviewSchema = z.object({
  reviewStatus: z.enum(USE_CASE_REVIEW_STATUS),
  vendorStatus: z.enum(USE_CASE_VENDOR_STATUS).optional(),
  nextReviewAt: useCaseDateSchema.optional(),
}).strict();

// 72-hour AI incident readiness (slice 3, 12 CFR 748.1(c)). Incidents carry a
// bounded single-line title and referenced query ids only — the timeline is
// derived from those queries, so no event content is accepted here.
const INCIDENT_STATUS = ['open', 'under_review', 'reported', 'closed'];
const incidentSchema = z.object({
  title: useCaseTextSchema(120).refine((value) => value.trim().length > 0, { message: 'required' }),
  queryIds: z.array(z.string().min(1).max(80).regex(/^[A-Za-z0-9_-]+$/)).max(50).optional(),
  detectedAt: useCaseDateSchema.optional(),
  notes: useCaseTextSchema(240).optional(),
}).strict();

const incidentStatusSchema = z.object({
  status: z.enum(INCIDENT_STATUS),
  reportedAt: useCaseDateSchema.optional(),
  notes: useCaseTextSchema(240).optional(),
}).strict();

function safeOperatorText(value) {
  const text = String(value || '');
  return !/[\u0000-\u001F]/.test(text) && !SENSITIVE_ROUTING_CODE.test(text);
}

const postureActionSchema = z.object({
  id: z.string().min(1).max(160).regex(POSTURE_ACTION_ID),
  status: z.enum(['open', 'assigned', 'snoozed', 'resolved']),
  owner: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(120).refine(safeOperatorText, { message: 'sensitive identifier not allowed' }).default(''),
  ),
  note: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.postureActionNoteChars).refine(safeOperatorText, { message: 'sensitive identifier not allowed' }).default(''),
  ),
  snoozeUntil: z.preprocess(
    (value) => (value == null || value === '' ? null : value),
    z.string().min(1).max(80).refine((value) => Number.isFinite(Date.parse(value)), {
      message: 'invalid datetime',
    }).nullable().default(null),
  ),
}).strict().refine((value) => value.status !== 'snoozed' || !!value.snoozeUntil, {
  message: 'snoozeUntil required',
  path: ['snoozeUntil'],
});

const detectorFeedbackSchema = z.object({
  detectorId: detectorIdSchema,
  verdict: z.enum(['valid', 'false_positive', 'too_sensitive', 'missed']),
  reason: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.detectorFeedbackReasonChars).refine(safeOperatorText, { message: 'sensitive identifier not allowed' }).default(''),
  ),
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

function safePolicyTextDefault(defaultValue) {
  return z.preprocess(
    (value) => (value == null || value === '' ? defaultValue : value),
    safePolicyMatchTextSchema,
  );
}

function optionalSafePolicyText() {
  return z.preprocess(
    (value) => (value == null || value === '' ? undefined : value),
    safePolicyMatchTextSchema.optional(),
  );
}

const discoveryTimestampSchema = z.preprocess(
  (value) => (value == null || value === '' ? null : value),
  z.string().min(1).max(40).refine((value) => Number.isFinite(Date.parse(value)), {
    message: 'invalid datetime',
  }).nullable().default(null),
);

const discoveryDestinationSchema = z.string().min(1).max(253).regex(DISCOVERY_DESTINATION_LABEL).refine((value) => !SENSITIVE_ROUTING_CODE.test(value), {
  message: 'sensitive identifier not allowed',
});

const aiDiscoverySightingSchema = z.object({
  destination: discoveryDestinationSchema,
  user: optionalSafePolicyText(),
  orgId: optionalSafePolicyText(),
  events: z.preprocess(
    (value) => (value == null || value === '' ? 1 : Number(value)),
    z.number().int().min(1).max(100000).default(1),
  ),
  firstSeen: discoveryTimestampSchema,
  lastSeen: discoveryTimestampSchema,
  category: z.enum(['chatbot', 'llm', 'agent', 'coding', 'image', 'audio', 'unknown']).default('unknown'),
  confidence: z.number().min(0).max(1).optional(),
}).strict();

const aiDiscoverySchema = z.object({
  source: z.preprocess(
    (value) => (value == null || value === '' ? 'proxy' : value),
    sensorIdSchema,
  ),
  user: safePolicyTextDefault('discovery-import'),
  orgId: z.preprocess(
    (value) => (value == null || value === '' ? null : value),
    safePolicyMatchTextSchema.nullable().default(null),
  ),
  vendor: z.preprocess(
    (value) => (value == null || value === '' ? '' : value),
    z.string().max(80).refine((value) => value === '' || POLICY_MATCH_TEXT.test(value), {
      message: 'invalid',
    }).refine(safeOperatorText, {
      message: 'sensitive identifier not allowed',
    }).default(''),
  ),
  sensor: sensorMetadataSchema.optional(),
  sightings: z.array(aiDiscoverySightingSchema).min(1).max(LIMITS.discoverySightings),
}).strict();

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
  destinations: z.array(destinationLabelSchema).max(40).optional(),
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
  destinations: z.array(destinationLabelSchema).max(40).optional(),
  accountTypes: z.array(z.enum(['personal', 'corporate', 'unknown'])).max(3).optional(),
};

function hasPolicyMatcher(rule) {
  return ['users', 'groups', 'orgIds', 'detectors', 'categories', 'sources', 'channels', 'destinations', 'accountTypes']
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
  action: z.enum(['paste', 'drop', 'copy', 'download']),
  destinations: z.array(destinationLabelSchema).min(1).max(40),
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
  governedDestinations: z.array(destinationLabelSchema).max(LIMITS.policyListItems).optional(),
  allowedDestinations: z.array(destinationLabelSchema).max(LIMITS.policyListItems).optional(),
  blockedDestinations: z.array(destinationLabelSchema).max(LIMITS.policyListItems).optional(),
  blockedFileUploadDestinations: z.array(destinationLabelSchema).max(LIMITS.policyListItems).optional(),
  blockedBrowserActions: z.array(blockedBrowserActionSchema).max(40).optional(),
  mcpAllowedTools: z.array(mcpToolLabelSchema).max(LIMITS.policyListItems).optional(),
  mcpBlockedTools: z.array(mcpToolLabelSchema).max(LIMITS.policyListItems).optional(),
  mcpApprovalRequiredTools: z.array(mcpToolLabelSchema).max(LIMITS.policyListItems).optional(),
  blockUnapprovedAiDestinations: z.boolean().optional(),
  corporateAiAccounts: z.object({
    orgEmailDomains: z.array(z.string().min(1).max(253)).max(40).optional(),
    personalAccountAction: z.enum(['allow', 'coach', 'block']).optional(),
  }).strict().optional(),
  responseScanMode: z.enum(['flag', 'redact', 'block']).optional(),
  unmanagedInstalls: z.enum(['allow', 'flag', 'block']).optional(),
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

function safeGitBranchName(value) {
  const text = String(value || '');
  return !text.startsWith('-')
    && !text.includes('..')
    && !text.includes('//')
    && !text.endsWith('/')
    && !text.endsWith('.')
    && !text.endsWith('.lock');
}

const updateConfigSchema = z.object({
  remoteName: z.string().min(1).max(80).regex(UPDATE_REMOTE_NAME).default('origin'),
  branch: z.string().min(1).max(128).regex(UPDATE_BRANCH_NAME).refine(safeGitBranchName, {
    message: 'invalid branch',
  }).default('main'),
  installMode: z.enum(['npm-ci-omit-dev', 'npm-ci', 'skip']).default('npm-ci-omit-dev'),
  restartCommand: z.preprocess(
    (value) => (value == null ? '' : value),
    z.string().max(LIMITS.updateCommandChars).refine((value) => value === '' || SAFE_OPERATOR_COMMAND.test(value), {
      message: 'unsupported characters',
    }).default(''),
  ),
  restartAfterUpdate: z.boolean().default(false),
}).strict();

const updateApplySchema = z.object({
  confirmBackup: z.literal(true),
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
  licenseInstallSchema,
  rehydrateSchema,
  scanFileSchema,
  scanResponseSchema,
  heartbeatSchema,
  loginSchema,
  revealSchema,
  approveSchema,
  noteSchema,
  assignSchema,
  bulkDecisionSchema,
  applyTemplateSchema,
  receiptVerifySchema,
  aiDiscoverySchema,
  destinationReviewSchema,
  catalogAddSchema,
  catalogReviewSchema,
  catalogImportSchema,
  useCaseSchema,
  useCaseReviewSchema,
  incidentSchema,
  incidentStatusSchema,
  postureActionSchema,
  detectorFeedbackSchema,
  policyUpdateSchema,
  updateConfigSchema,
  updateApplySchema,
};
