import { api, apiJsonBounded, responseJsonBounded } from '../lib/api';
export { policyMatchesCoreUpdate } from './policy-match';

/**
 * Policy endpoints (server/app.js):
 * - GET  /api/policy                 -> normalized server/policy.js policy
 * - PUT  /api/policy                 -> normalized saved policy
 * - GET  /api/policy/templates       -> server/templates.js list()
 * - PUT  /api/policy/apply-template  -> normalized merged policy
 * - POST /api/policy/impact?limit=N  -> server/policy-impact.js report
 *
 * Every successful body remains untrusted until the bounded decoders below
 * accept it. Mutators keep returning Response so callers can surface bounded
 * validation errors without consuming a success body twice.
 */

export type EnforcementMode = 'block' | 'warn' | 'justify' | 'redact';
export type ResponseScanMode = 'flag' | 'redact' | 'block';

/** Subset of validation.policyUpdateSchema this console form-edits. */
export interface PolicyUpdate {
  enforcementMode?: EnforcementMode;
  blockMinSeverity?: number;
  blockRiskScore?: number;
  storeRawForApproval?: boolean;
  rawRetentionDays?: number;
  governedDestinations?: string[];
  allowedDestinations?: string[];
  blockedDestinations?: string[];
  blockedFileUploadDestinations?: string[];
  blockUnapprovedAiDestinations?: boolean;
  responseScanMode?: ResponseScanMode;
  desktopCollectorDestination?: string;
}

/** GET /api/policy shape. loadPolicy() merges DEFAULT_POLICY. */
export interface Policy {
  enforcementMode: EnforcementMode;
  blockMinSeverity: number;
  blockRiskScore: number;
  alwaysBlock: string[];
  storeRawForApproval: boolean;
  rawRetentionDays: number;
  governedDestinations: string[];
  allowedDestinations: string[];
  blockedDestinations: string[];
  blockedFileUploadDestinations: string[];
  blockUnapprovedAiDestinations: boolean;
  responseScanMode: ResponseScanMode;
  desktopCollectorDestination: string;
  /** Advanced fields are narrowed independently at each render site. */
  [advanced: string]: unknown;
}

export interface PolicyTemplate {
  id: string;
  label: string;
  description: string;
  policy: Record<string, unknown>;
}

/** Outcome buckets from server/policy-impact.js OUTCOMES. */
export type ImpactOutcome =
  | 'blocked'
  | 'approval_required'
  | 'justification_required'
  | 'redacted'
  | 'warned'
  | 'allowed'
  | 'observed';

export interface ImpactDelta {
  label: string;
  changed: number;
  newlyBlocked: number;
  newlyAllowed: number;
  proposedBlocked: number;
  currentBlocked: number;
}

/** POST /api/policy/impact response (server/policy-impact.js). */
export interface PolicyImpact {
  generatedAt: string;
  privacy: { mode: string; promptBodiesIncluded: boolean; excludedFields: string[] };
  summary: {
    sampleSize: number;
    changed: number;
    newlyBlocked: number;
    newlyAllowed: number;
    moreRestrictive: number;
    lessRestrictive: number;
    current: Record<ImpactOutcome, number>;
    proposed: Record<ImpactOutcome, number>;
  };
  topDeltas: {
    destinations: ImpactDelta[];
    categories: ImpactDelta[];
    sources: ImpactDelta[];
    reasons: { reason: string; count: number }[];
  };
}

const POLICY_BODY_MAX_BYTES = 4 * 1024 * 1024;
const TEMPLATE_BODY_MAX_BYTES = 1024 * 1024;
const MAX_POLICY_LIST_ITEMS = 200;
const MAX_IMPACT_SAMPLE = 5_000;
const DETECTOR_ID = /^[A-Z0-9_]{1,80}$/;
const DESTINATION = /^[A-Za-z0-9.*:_/-]{1,253}$/;
const DESKTOP_DESTINATION = /^[A-Za-z0-9 .:_/-]{1,80}$/;
const TEMPLATE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

const ENFORCEMENT_MODES = new Set<unknown>(['block', 'warn', 'justify', 'redact']);
const RESPONSE_SCAN_MODES = new Set<unknown>(['flag', 'redact', 'block']);
const IMPACT_OUTCOMES: ImpactOutcome[] = [
  'blocked',
  'approval_required',
  'justification_required',
  'redacted',
  'warned',
  'allowed',
  'observed',
];

// Mirrors server/policy.js DEFAULT_POLICY.alwaysBlock. A normalized policy may
// add detectors, but a response that omits any mandatory hard stop is not safe
// to present as the active enforcement policy.
export const MANDATORY_ALWAYS_BLOCK = [
  'US_SSN',
  'CREDIT_CARD',
  'BANK_ACCOUNT',
  'ROUTING_NUMBER',
  'IBAN',
  'US_PASSPORT',
  'US_ITIN',
  'US_NPI',
  'MEMBER_ID',
  'LOAN_NUMBER',
  'MEDICAL_RECORD_NUMBER',
  'HEALTH_INSURANCE_ID',
  'UK_NINO',
  'UK_NHS_NUMBER',
  'CANADA_SIN',
  'AUSTRALIA_TFN',
  'INDIA_AADHAAR',
  'SECRET_KEY',
  'PRIVATE_KEY',
  'CANARY_TOKEN',
  'EXACT_MATCH',
] as const;

function record(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null ? value as Record<string, unknown> : null;
}

function integer(value: unknown, min: number, max: number): value is number {
  return Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;
}

function boundedString(value: unknown, min: number, max: number, pattern?: RegExp): value is string {
  return typeof value === 'string'
    && value.length >= min
    && value.length <= max
    && (!pattern || pattern.test(value));
}

function stringList(value: unknown, maxItems: number, maxLength: number, pattern?: RegExp): value is string[] {
  return Array.isArray(value)
    && value.length <= maxItems
    && value.every((item) => boundedString(item, 1, maxLength, pattern));
}

function corePolicyFieldsValid(value: Record<string, unknown>): boolean {
  return ENFORCEMENT_MODES.has(value.enforcementMode)
    && integer(value.blockMinSeverity, 1, 4)
    && integer(value.blockRiskScore, 0, 100)
    && stringList(value.alwaysBlock, MAX_POLICY_LIST_ITEMS, 80, DETECTOR_ID)
    && new Set(value.alwaysBlock as string[]).size === (value.alwaysBlock as string[]).length
    && MANDATORY_ALWAYS_BLOCK.every((detector) => (value.alwaysBlock as string[]).includes(detector))
    && typeof value.storeRawForApproval === 'boolean'
    && integer(value.rawRetentionDays, 0, 3650)
    && stringList(value.governedDestinations, MAX_POLICY_LIST_ITEMS, 253, DESTINATION)
    && stringList(value.allowedDestinations, MAX_POLICY_LIST_ITEMS, 253, DESTINATION)
    && stringList(value.blockedDestinations, MAX_POLICY_LIST_ITEMS, 253, DESTINATION)
    && stringList(value.blockedFileUploadDestinations, MAX_POLICY_LIST_ITEMS, 253, DESTINATION)
    && typeof value.blockUnapprovedAiDestinations === 'boolean'
    && RESPONSE_SCAN_MODES.has(value.responseScanMode)
    && boundedString(value.desktopCollectorDestination, 1, 80, DESKTOP_DESTINATION)
    && value.desktopCollectorDestination.trim().length > 0;
}

export function decodePolicy(value: unknown): Policy | null {
  const candidate = record(value);
  return candidate && corePolicyFieldsValid(candidate) ? candidate as Policy : null;
}

function absentOr(value: unknown, valid: (candidate: unknown) => boolean): boolean {
  return value === undefined || valid(value);
}

function templatePolicyValid(value: unknown): value is Record<string, unknown> {
  const candidate = record(value);
  if (!candidate || Object.keys(candidate).length > 64) return false;
  if (Object.keys(candidate).some((key) => ['__proto__', 'constructor', 'prototype'].includes(key))) return false;
  const detectorList = (item: unknown) => stringList(item, MAX_POLICY_LIST_ITEMS, 80, DETECTOR_ID);
  const destinationList = (item: unknown) => stringList(item, MAX_POLICY_LIST_ITEMS, 253, DESTINATION);
  return absentOr(candidate.enforcementMode, (item) => ENFORCEMENT_MODES.has(item))
    && absentOr(candidate.blockMinSeverity, (item) => integer(item, 1, 4))
    && absentOr(candidate.blockRiskScore, (item) => integer(item, 0, 100))
    && ['alwaysBlock', 'ignore', 'disabledDetectors'].every((key) => absentOr(candidate[key], detectorList))
    && ['governedDestinations', 'allowedDestinations', 'blockedDestinations', 'blockedFileUploadDestinations']
      .every((key) => absentOr(candidate[key], destinationList))
    && ['storeRawForApproval', 'blockUnapprovedAiDestinations']
      .every((key) => absentOr(candidate[key], (item) => typeof item === 'boolean'))
    && absentOr(candidate.rawRetentionDays, (item) => integer(item, 0, 3650))
    && absentOr(candidate.responseScanMode, (item) => RESPONSE_SCAN_MODES.has(item))
    && absentOr(candidate.desktopCollectorDestination, (item) => boundedString(item, 1, 80, DESKTOP_DESTINATION) && item.trim().length > 0);
}

export function decodePolicyTemplates(value: unknown): PolicyTemplate[] | null {
  if (!Array.isArray(value) || value.length > 50) return null;
  const ids = new Set<string>();
  const templates: PolicyTemplate[] = [];
  for (const item of value) {
    const candidate = record(item);
    if (!candidate
      || !boundedString(candidate.id, 1, 64, TEMPLATE_ID)
      || ids.has(candidate.id)
      || !boundedString(candidate.label, 1, 160)
      || !candidate.label.trim()
      || !boundedString(candidate.description, 1, 600)
      || !candidate.description.trim()
      || !templatePolicyValid(candidate.policy)) return null;
    ids.add(candidate.id);
    templates.push({
      id: candidate.id,
      label: candidate.label,
      description: candidate.description,
      policy: candidate.policy,
    });
  }
  return templates;
}

function outcomeCounts(value: unknown, sampleSize: number): Record<ImpactOutcome, number> | null {
  const candidate = record(value);
  if (!candidate || Object.keys(candidate).length !== IMPACT_OUTCOMES.length) return null;
  const counts = {} as Record<ImpactOutcome, number>;
  let total = 0;
  for (const outcome of IMPACT_OUTCOMES) {
    const count = candidate[outcome];
    if (!integer(count, 0, sampleSize)) return null;
    counts[outcome] = count;
    total += count;
  }
  return total === sampleSize ? counts : null;
}

function impactDelta(value: unknown, sampleSize: number): ImpactDelta | null {
  const candidate = record(value);
  if (!candidate || !boundedString(candidate.label, 1, 120) || !candidate.label.trim()) return null;
  const keys = ['changed', 'newlyBlocked', 'newlyAllowed', 'proposedBlocked', 'currentBlocked'] as const;
  if (!keys.every((key) => integer(candidate[key], 0, sampleSize))) return null;
  return {
    label: candidate.label,
    changed: candidate.changed as number,
    newlyBlocked: candidate.newlyBlocked as number,
    newlyAllowed: candidate.newlyAllowed as number,
    proposedBlocked: candidate.proposedBlocked as number,
    currentBlocked: candidate.currentBlocked as number,
  };
}

function impactDeltas(value: unknown, sampleSize: number, maxItems: number): ImpactDelta[] | null {
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const decoded = value.map((item) => impactDelta(item, sampleSize));
  return decoded.every((item): item is ImpactDelta => item !== null) ? decoded : null;
}

function impactReasons(value: unknown, sampleSize: number): { reason: string; count: number }[] | null {
  if (!Array.isArray(value) || value.length > 6) return null;
  const decoded: { reason: string; count: number }[] = [];
  for (const item of value) {
    const candidate = record(item);
    if (!candidate
      || !boundedString(candidate.reason, 1, 120)
      || !candidate.reason.trim()
      || !integer(candidate.count, 0, sampleSize)) return null;
    decoded.push({ reason: candidate.reason, count: candidate.count });
  }
  return decoded;
}

function decodeImpactPrivacy(value: unknown): PolicyImpact['privacy'] | null {
  const privacy = record(value);
  if (!privacy
    || privacy.mode !== 'metadata_only'
    || privacy.promptBodiesIncluded !== false
    || !stringList(privacy.excludedFields, 32, 120)) return null;
  return { mode: privacy.mode, promptBodiesIncluded: false, excludedFields: privacy.excludedFields };
}

function decodeImpactSummary(value: unknown): PolicyImpact['summary'] | null {
  const summary = record(value);
  if (!summary || !integer(summary.sampleSize, 0, MAX_IMPACT_SAMPLE)) return null;
  const sampleSize = summary.sampleSize as number;
  const countKeys = ['changed', 'newlyBlocked', 'newlyAllowed', 'moreRestrictive', 'lessRestrictive'] as const;
  if (!countKeys.every((key) => integer(summary[key], 0, sampleSize))) return null;
  const current = outcomeCounts(summary.current, sampleSize);
  const proposed = outcomeCounts(summary.proposed, sampleSize);
  if (!current || !proposed) return null;
  return {
    sampleSize,
    changed: summary.changed as number,
    newlyBlocked: summary.newlyBlocked as number,
    newlyAllowed: summary.newlyAllowed as number,
    moreRestrictive: summary.moreRestrictive as number,
    lessRestrictive: summary.lessRestrictive as number,
    current,
    proposed,
  };
}

function decodeImpactTopDeltas(value: unknown, sampleSize: number): PolicyImpact['topDeltas'] | null {
  const deltas = record(value);
  if (!deltas) return null;
  const destinations = impactDeltas(deltas.destinations, sampleSize, 6);
  const categories = impactDeltas(deltas.categories, sampleSize, 6);
  const sources = impactDeltas(deltas.sources, sampleSize, 5);
  const reasons = impactReasons(deltas.reasons, sampleSize);
  if (!destinations || !categories || !sources || !reasons) return null;
  return { destinations, categories, sources, reasons };
}

export function decodePolicyImpact(value: unknown): PolicyImpact | null {
  const candidate = record(value);
  if (!candidate || !boundedString(candidate.generatedAt, 1, 40) || !Number.isFinite(Date.parse(candidate.generatedAt))) return null;
  const privacy = decodeImpactPrivacy(candidate.privacy);
  const summary = decodeImpactSummary(candidate.summary);
  if (!privacy || !summary) return null;
  const topDeltas = decodeImpactTopDeltas(candidate.topDeltas, summary.sampleSize);
  if (!topDeltas) return null;
  return {
    generatedAt: candidate.generatedAt,
    privacy,
    summary,
    topDeltas,
  };
}

export async function fetchPolicy(): Promise<Policy | null> {
  return decodePolicy(await apiJsonBounded<unknown>('/api/policy', POLICY_BODY_MAX_BYTES));
}

export async function fetchPolicyTemplates(): Promise<PolicyTemplate[] | null> {
  return decodePolicyTemplates(await apiJsonBounded<unknown>('/api/policy/templates', TEMPLATE_BODY_MAX_BYTES));
}

export async function readPolicyResponse(response: Response): Promise<Policy | null> {
  return decodePolicy(await responseJsonBounded<unknown>(response, POLICY_BODY_MAX_BYTES));
}

export async function readPolicyImpactResponse(response: Response): Promise<PolicyImpact | null> {
  return decodePolicyImpact(await responseJsonBounded<unknown>(response, POLICY_BODY_MAX_BYTES));
}

function sendJson(path: string, method: string, body: unknown): Promise<Response | null> {
  return api(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

export function putPolicy(update: PolicyUpdate): Promise<Response | null> {
  return sendJson('/api/policy', 'PUT', update);
}

export function applyPolicyTemplate(id: string): Promise<Response | null> {
  return sendJson('/api/policy/apply-template', 'PUT', { id });
}

export function postPolicyImpact(update: PolicyUpdate): Promise<Response | null> {
  return sendJson('/api/policy/impact?limit=1000', 'POST', update);
}
