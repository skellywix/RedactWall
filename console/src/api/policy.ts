import { api, apiJson } from '../lib/api';

/**
 * Policy endpoints (server/app.js ~2521-2635):
 * - GET  /api/policy                 -> server/policy.js loadPolicy() (full normalized policy)
 * - PUT  /api/policy                 -> validation.policyUpdateSchema; server merges the patch
 *                                       over the stored policy and responds with the saved policy
 * - GET  /api/policy/templates       -> server/templates.js list()
 * - PUT  /api/policy/apply-template  -> validation.applyTemplateSchema ({ id }); merges the preset
 * - POST /api/policy/impact?limit=N  -> policyUpdateSchema body; replays recent sanitized events
 *                                       under the draft policy (server/policy-impact.js)
 *
 * Mutators return the raw Response (not parsed JSON) so views can surface
 * validation-field errors with apiErrorSummary, matching the legacy handlers.
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

/** GET /api/policy shape. loadPolicy() merges DEFAULT_POLICY, so form fields always exist. */
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
  /** Advanced fields (ignore, disabledDetectors, mcp* lists, routing rules,
      scopes, exceptions, requiredSensors, scanner, ...) shown read-only. */
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

/** POST /api/policy/impact response (server/policy-impact.js buildPolicyImpact). */
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

export function fetchPolicy(): Promise<Policy | null> {
  return apiJson<Policy>('/api/policy');
}

export function fetchPolicyTemplates(): Promise<PolicyTemplate[] | null> {
  return apiJson<PolicyTemplate[]>('/api/policy/templates');
}

function sendJson(path: string, method: string, body: unknown): Promise<Response | null> {
  return api(path, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

/** PUT /api/policy — merges `update` over the stored policy; 200 body is the saved policy. */
export function putPolicy(update: PolicyUpdate): Promise<Response | null> {
  return sendJson('/api/policy', 'PUT', update);
}

/** PUT /api/policy/apply-template — merges the preset server-side; 200 body is the merged policy. */
export function applyPolicyTemplate(id: string): Promise<Response | null> {
  return sendJson('/api/policy/apply-template', 'PUT', { id });
}

/** POST /api/policy/impact — metadata-only preview of the draft against recent events. */
export function postPolicyImpact(update: PolicyUpdate): Promise<Response | null> {
  return sendJson('/api/policy/impact?limit=1000', 'POST', update);
}
