type JsonRecord = Record<string, unknown>;

const CODE = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
const LICENSE_STATES = new Set(['active', 'grace', 'readonly', 'unlicensed', 'revoked']);
const SIEM_PROFILE_IDS = new Set(['splunk', 'sentinel', 'chronicle', 'servicenow']);
const TEST_DECISIONS = new Set(['allow', 'block']);

function record(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function own(value: JsonRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function text(value: unknown, max = 256, allowEmpty = false): value is string {
  return typeof value === 'string' && value.length <= max && (allowEmpty || value.trim().length > 0);
}

function code(value: unknown, max = 160): value is string {
  return text(value, max) && CODE.test(value);
}

function integer(value: unknown, min = 0, max = 1_000_000_000): value is number {
  return Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max;
}

function finite(value: unknown, min: number, max: number): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= min && value <= max;
}

function timestamp(value: unknown): value is string {
  return text(value, 40)
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function nullableTimestamp(value: unknown): value is string | null {
  return value === null || timestamp(value);
}

function nullableText(value: unknown, max = 256): value is string | null {
  return value === null || text(value, max, true);
}

function textList(value: unknown, maxItems: number, maxLength: number, allowEmpty = false): value is string[] {
  return Array.isArray(value)
    && value.length <= maxItems
    && value.every((item) => text(item, maxLength, allowEmpty));
}

function exactKeys(value: JsonRecord, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === expected.length && keys.every((key, index) => key === [...expected].sort()[index]);
}

function boundedJson(value: unknown, depth = 0): boolean {
  if (value === null || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'string') return value.length <= 8_192;
  if (depth >= 10) return false;
  if (Array.isArray(value)) return value.length <= 256 && value.every((item) => boundedJson(item, depth + 1));
  if (!record(value) || Object.keys(value).length > 128) return false;
  return Object.entries(value).every(([key, item]) => text(key, 160) && boundedJson(item, depth + 1));
}

export function isExactEmailSuccess(value: unknown): value is { ok: true } {
  return record(value) && exactKeys(value, ['ok']) && value.ok === true;
}

const RESTART_STATE_KEYS = new Set([
  'status', 'stage', 'startedAt', 'completedAt', 'fromCommit', 'toCommit', 'backup', 'install', 'restartRequired',
  'autoRestartRequested', 'restartScheduledAt', 'error', 'updatedAt',
]);
const UPDATE_STAGES = new Set(['checking', 'backup', 'fast-forward', 'install', 'complete', 'failed']);

function validRestartBackup(value: unknown): boolean {
  if (!record(value) || !exactKeys(value, ['auditIntegrity', 'backupSha256', 'bytes', 'file', 'manifestFile', 'ok'])) return false;
  return typeof value.ok === 'boolean'
    && text(value.file, 4_096, true)
    && text(value.manifestFile, 4_096, true)
    && integer(value.bytes, 0, Number.MAX_SAFE_INTEGER)
    && text(value.backupSha256, 128, true)
    && (value.auditIntegrity === null || boundedJson(value.auditIntegrity));
}

function validRestartInstall(value: unknown): boolean {
  return record(value)
    && exactKeys(value, ['command', 'skipped'])
    && typeof value.skipped === 'boolean'
    && text(value.command, 500);
}

function validScheduledRestartState(value: unknown): boolean {
  if (!record(value)
    || Object.keys(value).some((key) => !RESTART_STATE_KEYS.has(key))
    || value.status !== 'restart-scheduled'
    || value.restartRequired !== true
    || !timestamp(value.restartScheduledAt)
    || !timestamp(value.updatedAt)) return false;
  if (own(value, 'stage') && (typeof value.stage !== 'string' || !UPDATE_STAGES.has(value.stage))) return false;
  for (const key of ['startedAt', 'completedAt']) if (own(value, key) && !timestamp(value[key])) return false;
  for (const key of ['fromCommit', 'toCommit']) {
    if (own(value, key) && (typeof value[key] !== 'string' || !/^[a-f0-9]{40,64}$/.test(value[key]))) return false;
  }
  return (!own(value, 'backup') || validRestartBackup(value.backup))
    && (!own(value, 'install') || validRestartInstall(value.install))
    && (!own(value, 'autoRestartRequested') || typeof value.autoRestartRequested === 'boolean')
    && (!own(value, 'error') || text(value.error, 300, true));
}

export function isExactRestartScheduled(value: unknown): value is { ok: true; scheduled: true; state: JsonRecord } {
  return record(value)
    && exactKeys(value, ['ok', 'scheduled', 'state'])
    && value.ok === true
    && value.scheduled === true
    && validScheduledRestartState(value.state);
}

export interface SocNotifyResponse {
  sent: boolean;
  reason?: string;
}

function validPostureReceipt(value: unknown): boolean {
  return record(value)
    && exactKeys(value, ['generatedAt', 'score', 'state'])
    && timestamp(value.generatedAt)
    && finite(value.score, 0, 100)
    && code(value.state, 64);
}

export function decodeSocNotifyResponse(value: unknown): SocNotifyResponse | null {
  if (!record(value) || !validPostureReceipt(value.posture)) return null;
  if (value.sent === true) {
    return exactKeys(value, ['posture', 'sent', 'status']) && integer(value.status, 200, 299)
      ? { sent: true }
      : null;
  }
  if (value.sent === false) {
    return exactKeys(value, ['posture', 'reason', 'sent']) && code(value.reason, 80)
      ? { sent: false, reason: value.reason }
      : null;
  }
  return null;
}

function validPermissions(value: unknown): boolean {
  if (!record(value) || Object.keys(value).length > 16) return false;
  const required = ['administration', 'approvals', 'evidence', 'platform'];
  return required.every((key) => text(value[key], 160, true))
    && Object.entries(value).every(([key, permission]) => code(key, 64) && text(permission, 160, true));
}

function validRole(value: unknown): boolean {
  return record(value) && code(value.id, 64) && text(value.label, 120) && validPermissions(value.permissions);
}

export function isCompleteRolesResponse(value: unknown): boolean {
  return record(value)
    && Array.isArray(value.roles)
    && value.roles.length > 0
    && value.roles.length <= 16
    && value.roles.every(validRole);
}

function validAdminUser(value: unknown): boolean {
  if (!record(value)) return false;
  return text(value.id, 240)
    && text(value.userName, 320)
    && text(value.displayName, 240)
    && text(value.role, 64, true)
    && text(value.roleLabel, 120)
    && typeof value.active === 'boolean'
    && code(value.source, 64)
    && text(value.sourceLabel, 120)
    && textList(value.sources, 16, 64)
    && nullableText(value.orgId, 160)
    && nullableTimestamp(value.firstSeen)
    && nullableTimestamp(value.lastSeen)
    && integer(value.events)
    && code(value.licenseState, 64)
    && text(value.licenseReason, 240, true)
    && nullableTimestamp(value.licenseUpdatedAt)
    && typeof value.mutable === 'boolean';
}

export function isCompleteInvitationResponse(value: unknown, requireInviteUrl = false): boolean {
  if (!record(value)) return false;
  if (requireInviteUrl && !text(value.inviteUrl, 4_096)) return false;
  if (own(value, 'inviteUrl') && !text(value.inviteUrl, 4_096)) return false;
  return text(value.id, 160)
    && text(value.userName, 320)
    && text(value.displayName, 240)
    && code(value.role, 64)
    && text(value.roleLabel, 120)
    && code(value.status, 64)
    && timestamp(value.expiresAt)
    && nullableTimestamp(value.acceptedAt)
    && timestamp(value.createdAt)
    && timestamp(value.updatedAt);
}

function validObservedSeatUser(value: unknown): boolean {
  if (!record(value)) return false;
  return text(value.user, 320)
    && (!own(value, 'orgId') || nullableText(value.orgId, 160))
    && (!own(value, 'firstSeen') || nullableTimestamp(value.firstSeen))
    && (!own(value, 'lastSeen') || nullableTimestamp(value.lastSeen))
    && integer(value.events);
}

function validSeatSummary(value: unknown, requireUsers: boolean): boolean {
  if (!record(value)
    || !nullableText(value.tenantId, 160)
    || typeof value.saasMode !== 'boolean'
    || !integer(value.seatLimit)
    || typeof value.seatLimitValid !== 'boolean'
    || !integer(value.seatsUsed)
    || !(value.seatsRemaining === null || integer(value.seatsRemaining))
    || typeof value.overLimit !== 'boolean') return false;
  const expectedRemaining = value.seatLimit ? Math.max(0, value.seatLimit - value.seatsUsed) : null;
  if (value.seatsRemaining !== expectedRemaining || value.overLimit !== (value.seatLimit > 0 && value.seatsUsed > value.seatLimit)) return false;
  if (!requireUsers) return true;
  return Array.isArray(value.users) && value.users.length <= 2_000 && value.users.every(validObservedSeatUser);
}

export function isCompleteAdminDirectoryResponse(value: unknown): boolean {
  return record(value)
    && Array.isArray(value.users)
    && value.users.length <= 2_000
    && value.users.every(validAdminUser)
    && Array.isArray(value.invitations)
    && value.invitations.length <= 1_000
    && value.invitations.every((invite) => isCompleteInvitationResponse(invite))
    && validSeatSummary(value.seatReport, true);
}

function validRenewalRequest(value: unknown): boolean {
  return record(value)
    && text(value.id, 160)
    && code(value.status, 64)
    && (value.requestedSeats === null || integer(value.requestedSeats, 1, 1_000_000))
    && text(value.contactEmail, 320, true)
    && timestamp(value.createdAt);
}

export function isCompleteRenewalResponse(value: unknown): boolean {
  return record(value) && validRenewalRequest(value.request);
}

export function isCompleteLicenseStatusResponse(value: unknown, requireRenewals = false): boolean {
  if (!record(value)
    || typeof value.state !== 'string'
    || !LICENSE_STATES.has(value.state)
    || !nullableText(value.plan, 120)
    || !(value.seats === null || integer(value.seats, 1, 1_000_000))
    || !nullableText(value.customer, 240)
    || !nullableText(value.customerId, 160)
    || !textList(value.features, 128, 160)
    || !(value.expires === null || timestamp(value.expires))
    || !(value.graceEndsAt === null || timestamp(value.graceEndsAt))
    || !(value.daysRemaining === null || integer(value.daysRemaining, -1_000_000, 1_000_000))
    || !nullableText(value.reason, 160)) return false;
  if (!own(value, 'renewalRequests')) return !requireRenewals;
  return Array.isArray(value.renewalRequests)
    && value.renewalRequests.length <= 50
    && value.renewalRequests.every(validRenewalRequest);
}

export function isCompleteLicenseSeatsResponse(value: unknown): boolean {
  return record(value)
    && isCompleteLicenseStatusResponse(value.license)
    && validSeatSummary(value, false)
    && integer(value.assignedSeats)
    && integer(value.releasedSeats)
    && Array.isArray(value.users)
    && value.users.length <= 2_000
    && value.users.every(validAdminUser);
}

export interface SubmittedLicensePayload {
  customerId: string;
  plan: string;
  seats: number;
  expires: string;
  customer?: string;
  features?: string[];
}

export function decodeSubmittedLicensePayload(value: string): SubmittedLicensePayload | null {
  if (!text(value, 262_144) || value.trim() !== value) return null;
  const parts = value.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1] || parts[0].length > 131_072 || parts[1].length > 131_072) return null;
  try {
    const normalized = parts[0].replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const raw = atob(padded);
    const bytes = Uint8Array.from(raw, (character) => character.charCodeAt(0));
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!record(parsed)
      || !code(parsed.customerId, 160)
      || !code(parsed.plan, 120)
      || !integer(parsed.seats, 1, 1_000_000)
      || !timestamp(parsed.expires)
      || (own(parsed, 'customer') && !text(parsed.customer, 240))
      || (own(parsed, 'features') && !textList(parsed.features, 128, 160))) return null;
    return {
      customerId: parsed.customerId,
      plan: parsed.plan,
      seats: parsed.seats,
      expires: parsed.expires,
      ...(typeof parsed.customer === 'string' ? { customer: parsed.customer } : {}),
      ...(Array.isArray(parsed.features) ? { features: parsed.features as string[] } : {}),
    };
  } catch {
    return null;
  }
}

export function licenseStatusMatchesSubmitted(value: unknown, payload: SubmittedLicensePayload): boolean {
  if (!isCompleteLicenseStatusResponse(value) || !record(value) || !['active', 'grace', 'readonly'].includes(String(value.state))) return false;
  if (value.customerId !== payload.customerId || value.plan !== payload.plan || value.seats !== payload.seats || value.expires !== payload.expires) return false;
  if (payload.customer !== undefined && value.customer !== payload.customer) return false;
  if (payload.features !== undefined && JSON.stringify(value.features) !== JSON.stringify(payload.features)) return false;
  return true;
}

function validDetectorFinding(value: unknown): boolean {
  return record(value)
    && code(value.type, 160)
    && integer(value.severity, 0, 4)
    && code(value.severityLabel, 32)
    && code(value.confidence, 64)
    && text(value.masked, 512, true)
    && textList(value.regulations, 32, 160)
    && (!own(value, 'vendor') || code(value.vendor, 120))
    && (!own(value, 'vendorLabel') || text(value.vendorLabel, 160));
}

function validBreakdown(value: unknown): boolean {
  return record(value)
    && code(value.kind, 32)
    && code(value.type, 160)
    && integer(value.severity, 0, 4)
    && code(value.severityLabel, 32)
    && code(value.confidence, 64)
    && integer(value.points, 0, 1_000)
    && textList(value.regulations, 32, 160);
}

function validCategory(value: unknown): boolean {
  return record(value) && code(value.category, 160) && code(value.confidence, 64);
}

export function isCompleteDetectorTestResult(value: unknown): boolean {
  if (!record(value)
    || typeof value.decision !== 'string'
    || !TEST_DECISIONS.has(value.decision)
    || !Array.isArray(value.reasons)
    || value.reasons.length < 1
    || value.reasons.length > 64
    || !value.reasons.every((reason) => text(reason, 500))
    || !integer(value.riskScore, 0, 100)
    || !code(value.maxSeverityLabel, 32)
    || !textList(value.regulations, 64, 160)
    || !Array.isArray(value.findings)
    || value.findings.length > 256
    || !value.findings.every(validDetectorFinding)
    || !Array.isArray(value.categories)
    || value.categories.length > 128
    || !value.categories.every(validCategory)
    || !Array.isArray(value.scoreBreakdown)
    || value.scoreBreakdown.length > 384
    || !value.scoreBreakdown.every(validBreakdown)) return false;
  return value.scoreBreakdown.length === value.findings.length + value.categories.length;
}

const COVERAGE_TOTAL_KEYS = [
  'events', 'governedDestinations', 'governedActive', 'shadowEvents', 'unresolvedShadowDestinations', 'blocked',
  'requiredSensors', 'activeRequiredSensors', 'activeSensorVersionGaps', 'activeSensorHealthWarnings',
  'endpointAiInventoryReports', 'endpointAiToolDetections', 'endpointAiToolUnapproved', 'endpointMcpInventoryReports',
  'endpointMcpServerDetections', 'endpointMcpServerUnapproved', 'endpointFileFlowReports', 'endpointFileFlowProfiles',
  'endpointFileFlowAttention', 'discoveryFeeds', 'freshDiscoveryFeeds', 'staleDiscoveryFeeds', 'fleetRows', 'fleetCovered',
  'fleetAttention', 'unattributedEvents',
] as const;

function validCoverageTotals(value: unknown): boolean {
  if (!record(value) || !COVERAGE_TOTAL_KEYS.every((key) => integer(value[key]))) return false;
  return nullableTimestamp(value.lastDiscoveryAt)
    && finite(value.unattributedRate, 0, 1)
    && ['allow', 'flag', 'block'].includes(String(value.unmanagedInstallMode));
}

function validVersion(value: unknown): boolean {
  return record(value)
    && text(value.version, 80)
    && integer(value.events)
    && nullableTimestamp(value.lastSeen);
}

function validInstallHealth(value: unknown): boolean {
  if (value === null) return true;
  if (!record(value) || !boundedJson(value)) return false;
  return nullableTimestamp(value.at)
    && ['covered', 'attention'].includes(String(value.state))
    && textList(value.failedChecks, 80, 160)
    && Array.isArray(value.checks)
    && value.checks.length <= 80;
}

function validCoverageSensor(value: unknown, fleet = false): boolean {
  if (!record(value)
    || !code(value.source, 160)
    || !text(value.label, 160)
    || typeof value.required !== 'boolean'
    || !integer(value.events)
    || !nullableTimestamp(value.lastSeen)
    || !nullableText(value.latestVersion, 80)
    || !nullableText(value.desiredVersion, 80)
    || !['missing', 'unknown', 'outdated', 'current', 'mixed'].includes(String(value.versionHealth))
    || !textList(value.platforms, 32, 120)
    || !validInstallHealth(value.installHealth)) return false;
  if (!fleet) {
    if (!Array.isArray(value.versions) || value.versions.length > 64 || !value.versions.every(validVersion)) return false;
  } else if (!text(value.user, 320) || !nullableText(value.orgId, 160)
    || !['attention', 'missing', 'outdated', 'unknown', 'covered'].includes(String(value.state))) return false;
  return true;
}

function validEndpointRow(value: unknown): boolean {
  return record(value)
    && code(value.id, 160)
    && (!own(value, 'label') || text(value.label, 160))
    && code(value.state, 64)
    && text(value.detail, 240, true)
    && text(value.user, 320)
    && nullableText(value.orgId, 160)
    && nullableTimestamp(value.lastSeen)
    && textList(value.platforms, 32, 120)
    && (!own(value, 'approved') || typeof value.approved === 'boolean');
}

function validDestination(value: unknown): boolean {
  return record(value)
    && text(value.destination, 253)
    && code(value.policyState, 64)
    && integer(value.events)
    && integer(value.blocked)
    && integer(value.redacted)
    && integer(value.shadow)
    && integer(value.users)
    && nullableText(value.source, 160)
    && textList(value.sources, 16, 160)
    && nullableTimestamp(value.lastSeen)
    && typeof value.governed === 'boolean'
    && (!own(value, 'risk') || boundedJson(value.risk));
}

function validPostureItem(value: unknown): boolean {
  return record(value)
    && code(value.id, 160)
    && text(value.label, 160)
    && ['covered', 'attention'].includes(String(value.state))
    && text(value.detail, 500, true);
}

function validDiscoveryFeed(value: unknown): boolean {
  return record(value)
    && text(value.source, 160)
    && ['fresh', 'stale', 'missing'].includes(String(value.state))
    && integer(value.observations)
    && integer(value.destinations)
    && integer(value.users)
    && textList(value.categories, 16, 160)
    && nullableTimestamp(value.lastSeen)
    && (value.ageHours === null || finite(value.ageHours, 0, 10_000_000))
    && text(value.privacy, 240);
}

function validDesktopCollector(value: unknown): boolean {
  return record(value)
    && integer(value.events)
    && nullableTimestamp(value.lastSeen)
    && textList(value.destinations, 1_000, 253);
}

function arrayOf(value: unknown, max: number, validator: (item: unknown) => boolean): boolean {
  return Array.isArray(value) && value.length <= max && value.every(validator);
}

export function isCompleteCoverageReport(value: unknown): boolean {
  return record(value)
    && timestamp(value.generatedAt)
    && integer(value.score, 0, 100)
    && validCoverageTotals(value.totals)
    && arrayOf(value.sensors, 128, (item) => validCoverageSensor(item))
    && arrayOf(value.fleet, 2_000, (item) => validCoverageSensor(item, true))
    && arrayOf(value.discoveryFeeds, 128, validDiscoveryFeed)
    && arrayOf(value.endpointAiTools, 1_000, validEndpointRow)
    && arrayOf(value.endpointMcpServers, 1_000, validEndpointRow)
    && arrayOf(value.endpointFileFlowProfiles, 1_000, validEndpointRow)
    && arrayOf(value.governedDestinations, 2_000, validDestination)
    && arrayOf(value.ungovernedDestinations, 1_000, validDestination)
    && arrayOf(value.shadowDestinations, 1_000, validDestination)
    && validDesktopCollector(value.desktopCollector)
    && arrayOf(value.posture, 256, validPostureItem);
}

function validSiemSearch(value: unknown): boolean {
  if (!record(value) || !text(value.name, 240)) return false;
  const queries = ['spl', 'kql', 'udmSearch'].filter((key) => own(value, key));
  return queries.length === 1 && text(value[queries[0]], 8_192);
}

function validNamedArtifact(value: unknown): boolean {
  return record(value) && text(value.name, 240) && boundedJson(value);
}

function validPanelArtifact(value: unknown): boolean {
  return record(value)
    && (text(value.name, 240) || text(value.title, 240))
    && boundedJson(value);
}

function validFieldMapping(value: unknown): boolean {
  return record(value)
    && Object.keys(value).length >= 2
    && Object.keys(value).length <= 16
    && Object.entries(value).every(([key, field]) => code(key, 80) && text(field, 500));
}

function validSiemProfile(value: unknown): boolean {
  if (!record(value)) return false;
  const fieldMappings = value.fieldMappings;
  const samplePayloads = value.samplePayloads;
  const checklist = value.setupChecklist;
  if (typeof value.id !== 'string'
    || !SIEM_PROFILE_IDS.has(value.id)
    || !text(value.label, 160)
    || !text(value.target, 500)
    || !textList(value.docs, 8, 1_024)
    || value.docs.length < 1
    || !record(value.transport)
    || !boundedJson(value.transport)
    || !Array.isArray(fieldMappings)
    || fieldMappings.length < 1
    || fieldMappings.length > 128
    || !fieldMappings.every(validFieldMapping)
    || !textList(checklist, 32, 500)
    || checklist.length < 1) return false;
  if (value.id === 'servicenow') {
    if (samplePayloads !== undefined && (!Array.isArray(samplePayloads) || samplePayloads.length > 32 || !samplePayloads.every(validNamedArtifact))) return false;
  } else if (!Array.isArray(samplePayloads)
    || samplePayloads.length < 1
    || samplePayloads.length > 32
    || !samplePayloads.every(validNamedArtifact)) return false;
  if (value.id === 'splunk') return arrayOf(value.savedSearches, 32, validSiemSearch) && arrayOf(value.dashboardPanels, 32, validPanelArtifact);
  if (value.id === 'sentinel') return arrayOf(value.savedSearches, 32, validSiemSearch)
    && arrayOf(value.workbookPanels, 32, validPanelArtifact)
    && text(value.transformKql, 16_384);
  if (value.id === 'chronicle') return arrayOf(value.detections, 32, validSiemSearch);
  return arrayOf(value.incidentTemplates, 32, validNamedArtifact);
}

function profileSearchCount(profile: JsonRecord): number {
  const searches = Array.isArray(profile.savedSearches) ? profile.savedSearches.length : 0;
  const detections = Array.isArray(profile.detections) ? profile.detections.length : 0;
  return searches || detections;
}

function profileDashboardCount(profile: JsonRecord): number {
  for (const key of ['dashboardPanels', 'workbookPanels', 'incidentTemplates']) {
    if (Array.isArray(profile[key])) return profile[key].length;
  }
  return 0;
}

function profileFileCount(id: unknown): number {
  return id === 'sentinel' ? 7 : id === 'servicenow' ? 5 : 6;
}

function validSiemPrivacy(value: unknown): boolean {
  if (!record(value) || !text(value.sampleData, 1_000)) return false;
  return ['rawPromptBodies', 'redactedPromptBodies', 'rawFindingValues', 'tokenVaultValues', 'secretsOrCredentials', 'rawUrlsOrFilePaths']
    .every((key) => own(value, key) && value[key] === false);
}

export function isCompleteSiemPackageResponse(value: unknown): boolean {
  if (!record(value)
    || value.schemaVersion !== 1
    || !timestamp(value.generatedAt)
    || !code(value.requestedProfile, 64)
    || !textList(value.supportedProfiles, 16, 64)
    || !value.supportedProfiles.every((id) => SIEM_PROFILE_IDS.has(id))
    || new Set(value.supportedProfiles).size !== SIEM_PROFILE_IDS.size
    || !validSiemPrivacy(value.privacy)
    || !record(value.summary)
    || !textList(value.summary.eventTypes, 16, 160)
    || !value.summary.eventTypes.includes('redactwall.security_event')
    || !value.summary.eventTypes.includes('redactwall.posture_snapshot')
    || !textList(value.downloadFormats, 8, 32)
    || !value.downloadFormats.includes('json')
    || !value.downloadFormats.includes('zip')
    || !Array.isArray(value.profiles)
    || value.profiles.length < 1
    || value.profiles.length > 8
    || !value.profiles.every(validSiemProfile)) return false;
  const profiles = value.profiles as JsonRecord[];
  const ids = profiles.map((profile) => profile.id);
  if (new Set(ids).size !== ids.length) return false;
  if (value.requestedProfile !== 'all' && (profiles.length !== 1 || ids[0] !== value.requestedProfile)) return false;
  const samples = profiles.reduce((sum, profile) => sum + (Array.isArray(profile.samplePayloads) ? profile.samplePayloads.length : 0), 0);
  const searches = profiles.reduce((sum, profile) => sum + profileSearchCount(profile), 0);
  const dashboards = profiles.reduce((sum, profile) => sum + profileDashboardCount(profile), 0);
  const packageFiles = 3 + profiles.reduce((sum, profile) => sum + profileFileCount(profile.id), 0);
  return value.summary.profileCount === profiles.length
    && value.summary.samplePayloads === samples
    && value.summary.searches === searches
    && value.summary.dashboards === dashboards
    && value.summary.packageFiles === packageFiles;
}
