import { useCallback, useEffect, useState } from 'react';
import { canReadAuditExports } from '../api/evidence';
import IncidentsPanel from '../components/ncua/IncidentsPanel';
import UseCasesPanel from '../components/ncua/UseCasesPanel';
import { EmptyState } from '../components/Panel';
import { api, responseJsonBounded } from '../lib/api';
import { navigate } from '../lib/router';
import { useSession } from '../lib/session';
import './NcuaReadiness.css';

/**
 * NCUA Readiness: examiner-readiness report for federal credit unions
 * (PLANS/ncua-readiness-center.md, slice 1). Read-only. Route contract from
 * server/app.js:
 *   GET /api/ncua/readiness -> { entitled: boolean, report } — prompt-free
 *     composition of control mappings, member-data outcomes, shadow-AI
 *     rollups, EDM status, exception review, and audit-chain verification
 *     (server/ncua-readiness.js). Any console role can read it; no query
 *     params, no CSRF (GET). `entitled` reflects license.entitled(); when a
 *     licensed install lacks the ncua_readiness add-on the server withholds
 *     the report (report: null) and this view renders only the upsell state.
 *     Demo mode (unlicensed) is always entitled, so demos stay fully visible.
 *   GET /api/export/evidence?examinerProfile=federal_credit_union — exposed
 *     only to Security Admin or Auditor sessions; other roles see a disabled
 *     control and never make the request.
 *   POST /api/ncua/board-packet — Security Admin or Auditor plus the
 *     ncua_readiness entitlement. The UI mirrors those conditions but the
 *     server remains authoritative and can still deny a stale client.
 * No SSE (refresh on demand), no step-up. Never renders prompt content —
 * counts, enums, and bounded labels only.
 */

type ControlState = 'covered' | 'attention' | 'not_provided';
type ReadinessState = 'ready' | 'attention' | 'blocked';

interface NcuaControl {
  id: string;
  title: string;
  state: ControlState;
  controlFamilies: string[];
  summary: string;
}

interface NcuaAction {
  id: string;
  label: string;
  detail: string;
  targetTab: string;
  priority: number;
}

interface NcuaReport {
  profile: 'federal_credit_union';
  generatedAt: string;
  score: number;
  state: ReadinessState;
  controls: NcuaControl[];
  panels: {
    memberData: { identifiers: string[]; events: number; prevented: number; redacted: number; released: number };
    shadowAi: { totalApps: number; sanctioned: number; underReview: number; tolerated: number; unsanctioned: number; blocked: number; unreviewedEvents: number };
    edm: { configured: boolean; enabled: boolean; active: boolean; fingerprints: number; minLength?: number; severity?: number };
    useCases: { total: number; approved: number; underReview: number; restricted: number; retired: number; overdue: number; activeTotal: number; vendorReviewed: number; vendorPending: number; vendorNotReviewed: number } | null;
    incidents: { total: number; open: number; underReview: number; reported: number; closed: number; overdue: number; reportedLate: number } | null;
    exceptions: { total: number; active: number; expiringSoon: number; reviewDue: number; expired: number; disabled: number } | null;
    exportHealth: { scheduled: boolean; cadence?: string | null; nextRunAt?: string | null; retentionDays?: number | null };
    audit: { verified: boolean; count: number };
  };
  nextActions: NcuaAction[];
}

interface NcuaResponse {
  entitled: boolean;
  report: NcuaReport | null;
}

interface BoardPacket {
  generatedAt: string;
  profile: 'federal_credit_union';
  readiness: { score: number; state: ReadinessState };
  memberData: NcuaReport['panels']['memberData'];
  shadowAi: NcuaReport['panels']['shadowAi'];
  useCases: NcuaReport['panels']['useCases'];
  incidents: NcuaReport['panels']['incidents'];
  exceptions: NcuaReport['panels']['exceptions'];
  exportHealth: NcuaReport['panels']['exportHealth'];
  audit: NcuaReport['panels']['audit'];
  seats: {
    tenantId: string | null;
    saasMode: boolean;
    seatLimit: number | null;
    seatsUsed: number;
    seatsRemaining: number | null;
    overLimit: boolean;
    trueUp: {
      licensedSeats: number | null;
      configuredLimit: number | null;
      seatsUsed: number;
      mismatch: boolean;
    };
  };
  license: {
    state: 'unlicensed' | 'active' | 'grace' | 'readonly' | 'revoked';
    plan: string | null;
    expires: string | null;
  } | null;
}

const EXAMINER_PACK_HREF = '/api/export/evidence?examinerProfile=federal_credit_union';
const READINESS_MAX_BYTES = 512 * 1024;
const BOARD_PACKET_MAX_BYTES = 1024 * 1024;
const MAX_COUNT = 1_000_000_000;
const CONTROL_IDS = new Set([
  'ai_prompt_dlp',
  'local_detection_minimization',
  'approval_workflow',
  'tamper_evident_audit',
  'fleet_sensor_coverage',
  'backup_recoverability',
  'ai_usage_governance',
  'prompt_threat_defense',
  'ai_activity_recordkeeping',
  'member_information_safeguards',
  'ai_use_inventory',
  'vendor_service_provider_oversight',
  'incident_readiness',
  'board_reporting',
  'ai_acceptable_use',
]);
const MEMBER_IDENTIFIERS = ['US_SSN', 'MEMBER_ID', 'LOAN_NUMBER', 'BANK_ACCOUNT', 'ROUTING_NUMBER'];
const ACTION_TARGETS = new Set(['ncua', 'catalog', 'coverage', 'deploy', 'audit', 'policy']);
const LICENSE_STATES = new Set(['unlicensed', 'active', 'grace', 'readonly', 'revoked']);
const READINESS_STATES = new Set<ReadinessState>(['ready', 'attention', 'blocked']);
const CONTROL_STATES = new Set<ControlState>(['covered', 'attention', 'not_provided']);

type BoardPacketResult = 'downloaded' | 'denied' | 'unavailable' | 'malformed';

interface ExportPermissions {
  examinerAllowed: boolean;
  examinerMessage: string;
  boardAllowed: boolean;
  boardMessage: string;
}

type JsonObject = Record<string, unknown>;
type DecodeResult<T> = { ok: true; value: T } | { ok: false; value: null };

function jsonObject(value: unknown): JsonObject | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : null;
}

function boundedText(value: unknown, maxLength: number, pattern?: RegExp): string | null {
  if (typeof value !== 'string' || value.length > maxLength) return null;
  const text = value.trim();
  if (!text || (pattern && !pattern.test(text))) return null;
  return text;
}

function validTimestamp(value: unknown): string | null {
  if (typeof value !== 'string' || !value || value.length > 80) return null;
  const match = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z)?$/.exec(value);
  const parsed = Date.parse(value);
  if (!match || !Number.isFinite(parsed)) return null;
  const date = new Date(parsed);
  const expected = match.slice(1, 7).map((part) => part === undefined ? undefined : Number(part));
  const actual = [date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds()];
  if (expected.some((part, index) => part !== undefined && part !== actual[index])) return null;
  const millis = match[7] ? Number(match[7].padEnd(3, '0')) : 0;
  return date.getUTCMilliseconds() === millis ? value : null;
}

function integer(value: unknown, max = MAX_COUNT, min = 0): number | null {
  return Number.isSafeInteger(value) && Number(value) >= min && Number(value) <= max ? Number(value) : null;
}

function countFields<K extends string>(value: unknown, fields: readonly K[]): Record<K, number> | null {
  const body = jsonObject(value);
  if (!body) return null;
  const decoded = {} as Record<K, number>;
  for (const field of fields) {
    const count = integer(body[field]);
    if (count === null) return null;
    decoded[field] = count;
  }
  return decoded;
}

function boundedStringArray(value: unknown, maxItems: number, maxLength: number, pattern?: RegExp): string[] | null {
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const decoded = value.map((item) => boundedText(item, maxLength, pattern));
  if (decoded.some((item) => item === null)) return null;
  const strings = decoded as string[];
  return new Set(strings).size === strings.length ? strings : null;
}

function nullablePanel<T>(value: unknown, decode: (item: unknown) => T | null): DecodeResult<T | null> {
  if (value === null) return { ok: true, value: null };
  const decoded = decode(value);
  return decoded === null ? { ok: false, value: null } : { ok: true, value: decoded };
}

function nullableCount(value: unknown, min = 0): DecodeResult<number | null> {
  if (value === null) return { ok: true, value: null };
  const decoded = integer(value, MAX_COUNT, min);
  return decoded === null ? { ok: false, value: null } : { ok: true, value: decoded };
}

function decodeMemberData(value: unknown): NcuaReport['panels']['memberData'] | null {
  const body = jsonObject(value);
  const identifiers = boundedStringArray(body?.identifiers, 16, 64, /^[A-Z0-9_]+$/);
  const counts = countFields(value, ['events', 'prevented', 'redacted', 'released'] as const);
  if (!body || !identifiers || !counts) return null;
  if (identifiers.length !== MEMBER_IDENTIFIERS.length || MEMBER_IDENTIFIERS.some((id) => !identifiers.includes(id))) return null;
  if (counts.prevented + counts.redacted + counts.released > counts.events) return null;
  return { identifiers, ...counts };
}

function decodeShadowAi(value: unknown): NcuaReport['panels']['shadowAi'] | null {
  const counts = countFields(value, [
    'totalApps', 'sanctioned', 'underReview', 'tolerated', 'unsanctioned', 'blocked', 'unreviewedEvents',
  ] as const);
  if (!counts) return null;
  const classified = counts.sanctioned + counts.underReview + counts.tolerated + counts.unsanctioned + counts.blocked;
  return classified <= counts.totalApps ? counts : null;
}

function decodeEdm(value: unknown): NcuaReport['panels']['edm'] | null {
  const body = jsonObject(value);
  if (!body || typeof body.configured !== 'boolean' || typeof body.enabled !== 'boolean' || typeof body.active !== 'boolean') return null;
  const fingerprints = integer(body.fingerprints);
  if (fingerprints === null || body.active !== (body.configured && body.enabled) || body.configured !== (fingerprints > 0)) return null;
  const decoded: NcuaReport['panels']['edm'] = { configured: body.configured, enabled: body.enabled, active: body.active, fingerprints };
  for (const field of ['minLength', 'severity'] as const) {
    if (body[field] === undefined) continue;
    const count = integer(body[field]);
    if (count === null) return null;
    decoded[field] = count;
  }
  return decoded;
}

function decodeUseCases(value: unknown): NonNullable<NcuaReport['panels']['useCases']> | null {
  const counts = countFields(value, [
    'total', 'approved', 'underReview', 'restricted', 'retired', 'overdue', 'activeTotal',
    'vendorReviewed', 'vendorPending', 'vendorNotReviewed',
  ] as const);
  if (!counts || counts.activeTotal !== counts.approved + counts.underReview + counts.restricted) return null;
  if (counts.approved + counts.underReview + counts.restricted + counts.retired > counts.total) return null;
  if (counts.overdue > counts.activeTotal) return null;
  return counts.vendorReviewed + counts.vendorPending + counts.vendorNotReviewed === counts.activeTotal ? counts : null;
}

function decodeIncidents(value: unknown): NonNullable<NcuaReport['panels']['incidents']> | null {
  const counts = countFields(value, ['total', 'open', 'underReview', 'reported', 'closed', 'overdue', 'reportedLate'] as const);
  if (!counts || counts.open + counts.underReview + counts.reported + counts.closed > counts.total) return null;
  return counts.overdue <= counts.open + counts.underReview && counts.reportedLate <= counts.total ? counts : null;
}

function decodeExceptions(value: unknown): NonNullable<NcuaReport['panels']['exceptions']> | null {
  const counts = countFields(value, ['total', 'active', 'expiringSoon', 'reviewDue', 'expired', 'disabled'] as const);
  if (!counts) return null;
  return ['active', 'expiringSoon', 'reviewDue', 'expired', 'disabled'].every((field) => counts[field as keyof typeof counts] <= counts.total)
    ? counts
    : null;
}

function decodeExportHealth(value: unknown): NcuaReport['panels']['exportHealth'] | null {
  const body = jsonObject(value);
  if (!body || typeof body.scheduled !== 'boolean') return null;
  const decoded: NcuaReport['panels']['exportHealth'] = { scheduled: body.scheduled };
  if (body.cadence !== undefined) {
    if (body.cadence !== null && boundedText(body.cadence, 40) === null) return null;
    decoded.cadence = body.cadence === null ? null : boundedText(body.cadence, 40);
  }
  if (body.nextRunAt !== undefined) {
    if (body.nextRunAt !== null && validTimestamp(body.nextRunAt) === null) return null;
    decoded.nextRunAt = body.nextRunAt === null ? null : validTimestamp(body.nextRunAt);
  }
  if (body.retentionDays !== undefined) {
    const retention = nullableCount(body.retentionDays);
    if (!retention.ok) return null;
    decoded.retentionDays = retention.value;
  }
  return decoded;
}

function decodeAudit(value: unknown): NcuaReport['panels']['audit'] | null {
  const body = jsonObject(value);
  const count = integer(body?.count);
  return body && typeof body.verified === 'boolean' && count !== null ? { verified: body.verified, count } : null;
}

function decodeControl(value: unknown): NcuaControl | null {
  const body = jsonObject(value);
  const id = boundedText(body?.id, 80, /^[a-z0-9_]+$/);
  const title = boundedText(body?.title, 120);
  const state = typeof body?.state === 'string' && CONTROL_STATES.has(body.state as ControlState) ? body.state as ControlState : null;
  const controlFamilies = boundedStringArray(body?.controlFamilies, 8, 160);
  const summary = boundedText(body?.summary, 240);
  return body && id && CONTROL_IDS.has(id) && title && state && controlFamilies && summary
    ? { id, title, state, controlFamilies, summary }
    : null;
}

function decodeControls(value: unknown): NcuaControl[] | null {
  if (!Array.isArray(value) || value.length !== CONTROL_IDS.size) return null;
  const controls = value.map(decodeControl);
  if (controls.some((control) => control === null)) return null;
  const decoded = controls as NcuaControl[];
  return new Set(decoded.map((control) => control.id)).size === CONTROL_IDS.size ? decoded : null;
}

function decodeAction(value: unknown): NcuaAction | null {
  const body = jsonObject(value);
  const id = boundedText(body?.id, 80, /^[a-z0-9_]+$/);
  const label = boundedText(body?.label, 120);
  const detail = boundedText(body?.detail, 240);
  const targetTab = boundedText(body?.targetTab, 40, /^[a-z-]+$/);
  const priority = integer(body?.priority, 100, 1);
  return id && CONTROL_IDS.has(id) && label && detail && targetTab && ACTION_TARGETS.has(targetTab) && priority !== null
    ? { id, label, detail, targetTab, priority }
    : null;
}

function decodeActions(value: unknown, controls: NcuaControl[]): NcuaAction[] | null {
  if (!Array.isArray(value) || value.length > 5) return null;
  const actions = value.map(decodeAction);
  if (actions.some((action) => action === null)) return null;
  const decoded = actions as NcuaAction[];
  const expected = controls.filter((control) => control.state === 'attention').slice(0, 5).map((control) => control.id);
  if (decoded.length !== expected.length || decoded.some((action, index) => action.id !== expected[index] || action.priority !== index + 1)) return null;
  return new Set(decoded.map((action) => action.id)).size === decoded.length ? decoded : null;
}

function expectedScore(controls: NcuaControl[]): number {
  const scored = controls.filter((control) => control.state !== 'not_provided');
  return scored.length ? Math.round((scored.filter((control) => control.state === 'covered').length / scored.length) * 100) : 0;
}

function expectedReadinessState(score: number, auditVerified: boolean): ReadinessState {
  if (!auditVerified) return 'blocked';
  return score >= 90 ? 'ready' : 'attention';
}

function decodePanels(value: unknown): NcuaReport['panels'] | null {
  const body = jsonObject(value);
  if (!body) return null;
  const memberData = decodeMemberData(body.memberData);
  const shadowAi = decodeShadowAi(body.shadowAi);
  const edm = decodeEdm(body.edm);
  const useCases = nullablePanel(body.useCases, decodeUseCases);
  const incidents = nullablePanel(body.incidents, decodeIncidents);
  const exceptions = nullablePanel(body.exceptions, decodeExceptions);
  const exportHealth = decodeExportHealth(body.exportHealth);
  const audit = decodeAudit(body.audit);
  if (!memberData || !shadowAi || !edm || !useCases.ok || !incidents.ok || !exceptions.ok || !exportHealth || !audit) return null;
  return { memberData, shadowAi, edm, useCases: useCases.value, incidents: incidents.value, exceptions: exceptions.value, exportHealth, audit };
}

function decodeNcuaReport(value: unknown): NcuaReport | null {
  const body = jsonObject(value);
  const generatedAt = validTimestamp(body?.generatedAt);
  const score = integer(body?.score, 100);
  const state = typeof body?.state === 'string' && READINESS_STATES.has(body.state as ReadinessState)
    ? body.state as ReadinessState
    : null;
  const controls = decodeControls(body?.controls);
  const panels = decodePanels(body?.panels);
  if (!body || body.profile !== 'federal_credit_union' || !generatedAt || score === null || !state || !controls || !panels) return null;
  const nextActions = decodeActions(body.nextActions, controls);
  if (!nextActions || score !== expectedScore(controls) || state !== expectedReadinessState(score, panels.audit.verified)) return null;
  return { profile: 'federal_credit_union', generatedAt, score, state, controls, panels, nextActions };
}

function decodeReadinessSummary(value: unknown): BoardPacket['readiness'] | null {
  const body = jsonObject(value);
  const score = integer(body?.score, 100);
  const state = typeof body?.state === 'string' && READINESS_STATES.has(body.state as ReadinessState)
    ? body.state as ReadinessState
    : null;
  return score !== null && state ? { score, state } : null;
}

function decodeSeats(value: unknown): BoardPacket['seats'] | null {
  const body = jsonObject(value);
  const trueUp = jsonObject(body?.trueUp);
  if (!body || !trueUp || typeof body.saasMode !== 'boolean' || typeof body.overLimit !== 'boolean' || typeof trueUp.mismatch !== 'boolean') return null;
  const tenantId = body.tenantId === null ? null : boundedText(body.tenantId, 80, /^[A-Za-z0-9._:-]+$/);
  const seatLimit = nullableCount(body.seatLimit, 1);
  const seatsUsed = integer(body.seatsUsed);
  const seatsRemaining = nullableCount(body.seatsRemaining);
  const licensedSeats = nullableCount(trueUp.licensedSeats, 1);
  const configuredLimit = nullableCount(trueUp.configuredLimit, 1);
  const trueUpSeatsUsed = integer(trueUp.seatsUsed);
  if (body.tenantId !== null && !tenantId) return null;
  if (!seatLimit.ok || seatsUsed === null || !seatsRemaining.ok || !licensedSeats.ok || !configuredLimit.ok || trueUpSeatsUsed === null) return null;
  if (configuredLimit.value !== seatLimit.value || trueUpSeatsUsed !== seatsUsed) return null;
  const overLimit = seatLimit.value !== null && seatsUsed > seatLimit.value;
  const remaining = seatLimit.value === null ? null : Math.max(0, seatLimit.value - seatsUsed);
  const mismatch = (licensedSeats.value !== null && configuredLimit.value !== null && licensedSeats.value !== configuredLimit.value)
    || (licensedSeats.value !== null && seatsUsed > licensedSeats.value);
  if (body.overLimit !== overLimit || seatsRemaining.value !== remaining || trueUp.mismatch !== mismatch) return null;
  return {
    tenantId,
    saasMode: body.saasMode,
    seatLimit: seatLimit.value,
    seatsUsed,
    seatsRemaining: seatsRemaining.value,
    overLimit: body.overLimit,
    trueUp: { licensedSeats: licensedSeats.value, configuredLimit: configuredLimit.value, seatsUsed, mismatch: trueUp.mismatch },
  };
}

function decodeLicense(value: unknown): DecodeResult<BoardPacket['license']> {
  if (value === null) return { ok: true, value: null };
  const body = jsonObject(value);
  const state = typeof body?.state === 'string' && LICENSE_STATES.has(body.state) ? body.state as NonNullable<BoardPacket['license']>['state'] : null;
  const plan = body?.plan === null ? null : boundedText(body?.plan, 40, /^[A-Za-z0-9._-]+$/);
  const expires = body?.expires === null ? null : validTimestamp(body?.expires);
  if (!body || !state || (body.plan !== null && !plan) || (body.expires !== null && !expires)) return { ok: false, value: null };
  return { ok: true, value: { state, plan, expires } };
}

function decodeBoardPacket(value: unknown): BoardPacket | null {
  const body = jsonObject(value);
  const generatedAt = validTimestamp(body?.generatedAt);
  const readiness = decodeReadinessSummary(body?.readiness);
  const memberData = decodeMemberData(body?.memberData);
  const shadowAi = decodeShadowAi(body?.shadowAi);
  const useCases = nullablePanel(body?.useCases, decodeUseCases);
  const incidents = nullablePanel(body?.incidents, decodeIncidents);
  const exceptions = nullablePanel(body?.exceptions, decodeExceptions);
  const exportHealth = decodeExportHealth(body?.exportHealth);
  const audit = decodeAudit(body?.audit);
  const seats = decodeSeats(body?.seats);
  const license = decodeLicense(body?.license);
  if (!body || body.profile !== 'federal_credit_union' || !generatedAt || !readiness || !memberData || !shadowAi) return null;
  if (!useCases.ok || !incidents.ok || !exceptions.ok || !exportHealth || !audit || !seats || !license.ok) return null;
  if (readiness.state !== expectedReadinessState(readiness.score, audit.verified)) return null;
  return {
    generatedAt,
    profile: 'federal_credit_union',
    readiness,
    memberData,
    shadowAi,
    useCases: useCases.value,
    incidents: incidents.value,
    exceptions: exceptions.value,
    exportHealth,
    audit,
    seats,
    license: license.value,
  };
}

// Board packet: an explicit CSRF-protected POST (generation is
// state-changing — it appends the BOARD_PACKET_EXPORTED row the cadence
// control grades from, so it must never fire from a prefetch), saved
// client-side (Audit.tsx pattern).
function saveBoardPacket(packet: BoardPacket): void {
  const blob = new Blob([JSON.stringify(packet, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `redactwall-board-packet-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function downloadBoardPacket(): Promise<BoardPacketResult> {
  const res = await api('/api/ncua/board-packet', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  if (!res) return 'unavailable';
  if (res.status === 403) return 'denied';
  if (!res.ok) {
    await responseJsonBounded<unknown>(res, 8 * 1024);
    return 'unavailable';
  }
  const packet = decodeBoardPacket(await responseJsonBounded<unknown>(res, BOARD_PACKET_MAX_BYTES));
  if (!packet) return 'malformed';
  saveBoardPacket(packet);
  return 'downloaded';
}

function exportPermissions(
  role: string | null,
  sessionLoading: boolean,
  readinessLoaded: boolean,
  data: NcuaResponse | null,
): ExportPermissions {
  const roleAllowed = canReadAuditExports(role);
  const roleMessage = 'Global Administrator or Examiner/Auditor access is required.';
  const examinerMessage = sessionLoading ? 'Checking examiner export permission…' : roleAllowed ? '' : roleMessage;
  if (sessionLoading || !readinessLoaded) {
    return {
      examinerAllowed: !sessionLoading && roleAllowed,
      examinerMessage,
      boardAllowed: false,
      boardMessage: 'Checking board packet role and license access…',
    };
  }
  if (!roleAllowed && data?.entitled === false) {
    return { examinerAllowed: false, examinerMessage, boardAllowed: false, boardMessage: `${roleMessage} The NCUA Readiness add-on is also required.` };
  }
  if (!roleAllowed) return { examinerAllowed: false, examinerMessage, boardAllowed: false, boardMessage: roleMessage };
  if (data?.entitled === false) {
    return { examinerAllowed: true, examinerMessage: '', boardAllowed: false, boardMessage: 'Board packets require the NCUA Readiness add-on for this license.' };
  }
  if (!data) {
    return { examinerAllowed: true, examinerMessage: '', boardAllowed: false, boardMessage: 'Board packet access cannot be verified while readiness is unavailable.' };
  }
  return { examinerAllowed: true, examinerMessage: '', boardAllowed: true, boardMessage: '' };
}

const STATE_TONE: Record<string, string> = {
  covered: 'tone-low',
  ready: 'tone-low',
  attention: 'tone-high',
  blocked: 'tone-high',
  not_provided: 'tone-neutral',
};

function decodeNcuaResponse(value: unknown): NcuaResponse | null {
  const body = jsonObject(value);
  if (!body) return null;
  if (body.entitled === false && body.report === null) return { entitled: false, report: null };
  if (body.entitled !== true) return null;
  const report = decodeNcuaReport(body.report);
  return report ? { entitled: true, report } : null;
}

function useNcuaReadiness() {
  const [data, setData] = useState<NcuaResponse | null>(null);
  const [failure, setFailure] = useState<'unavailable' | 'malformed' | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    setBusy(true);
    try {
      const res = await api('/api/ncua/readiness');
      if (!res || !res.ok) {
        if (res) await responseJsonBounded<unknown>(res, 8 * 1024);
        setData(null);
        setFailure('unavailable');
        return;
      }
      const decoded = decodeNcuaResponse(await responseJsonBounded<unknown>(res, READINESS_MAX_BYTES));
      setData(decoded);
      setFailure(decoded ? null : 'malformed');
    } finally {
      setBusy(false);
      setLoaded(true);
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);
  return { data, loaded, busy, failure, load };
}

function Header({
  busy,
  permissions,
  boardBusy,
  boardStatus,
  onBoardPacket,
  onRefresh,
}: {
  busy: boolean;
  permissions: ExportPermissions;
  boardBusy: boolean;
  boardStatus: string;
  onBoardPacket: () => void;
  onRefresh: () => void;
}) {
  return (
    <div className="console-frame-header">
      <div className="console-frame-title">
        <div>
          <h2>Texas FCU Readiness</h2>
          <p>
            Examiner readiness for Texas-based Federal Credit Unions: NCUA Part 748 / GLBA control coverage,
            member-data outcomes, structured hard stops, high-entropy EDM, shadow-AI review, board packets, and live prompt-free evidence.
          </p>
        </div>
      </div>
      <div className="console-frame-actions">
        {permissions.examinerAllowed ? (
          <a className="system-button secondary" href={EXAMINER_PACK_HREF} target="_blank" rel="noopener">
            Export examiner pack
          </a>
        ) : (
          <button className="system-button secondary" type="button" disabled aria-describedby="ncuaExaminerPermission">
            Export examiner pack
          </button>
        )}
        <button
          className="system-button secondary"
          type="button"
          disabled={!permissions.boardAllowed || boardBusy}
          aria-describedby={permissions.boardAllowed ? 'ncuaBoardStatus' : 'ncuaBoardPermission'}
          onClick={onBoardPacket}
        >
          {boardBusy ? 'Preparing board packet…' : 'Board packet'}
        </button>
        <button className="system-button secondary" type="button" disabled={busy} onClick={onRefresh}>
          {busy ? 'Scoring…' : 'Refresh'}
        </button>
        {!permissions.examinerAllowed ? (
          <span id="ncuaExaminerPermission" className="app-panel-meta" role="note">{permissions.examinerMessage}</span>
        ) : null}
        {!permissions.boardAllowed ? (
          <span id="ncuaBoardPermission" className="app-panel-meta" role="note">{permissions.boardMessage}</span>
        ) : null}
        {permissions.boardAllowed ? (
          <span id="ncuaBoardStatus" className="app-panel-meta" role="status" aria-live="polite">{boardStatus}</span>
        ) : null}
      </div>
    </div>
  );
}

function Kpi({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="insights-kpi">
      <span className="insights-kpi-value">{value}</span>
      <span className="insights-kpi-label">{label}</span>
      <span className="insights-kpi-hint">{hint}</span>
    </div>
  );
}

function KpiRow({ report }: { report: NcuaReport }) {
  const { memberData, shadowAi, edm } = report.panels;
  return (
    <div className="insights-kpis">
      <Kpi label="Readiness score" value={`${report.score}/100`} hint={report.state.replace('_', ' ')} />
      <Kpi label="Texas member-data prevented" value={`${memberData.prevented}/${memberData.events}`} hint={`${memberData.redacted} redacted, ${memberData.released} released after review`} />
      <Kpi label="Unreviewed AI apps" value={String(shadowAi.unsanctioned + shadowAi.underReview)} hint={`${shadowAi.unreviewedEvents} sightings pending review`} />
      <Kpi
        label="EDM fingerprints"
        value={edm.configured ? String(edm.fingerprints) : 'not set up'}
        hint={edm.active ? 'random-ID watchlist active' : edm.configured ? 'watchlist loaded but DISABLED' : 'optional random-ID watchlist not configured'}
      />
    </div>
  );
}

function ControlRow({ control }: { control: NcuaControl }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>{control.title}</h2>
          <span>{(control.controlFamilies || []).slice(0, 2).join(' · ')}</span>
        </div>
        <span className={`insights-chip ${STATE_TONE[control.state] || 'tone-neutral'}`}>
          {control.state.replace('_', ' ')}
        </span>
      </div>
      <div style={{ padding: '0 16px 14px' }}>
        <p style={{ margin: 0 }}>{control.summary}</p>
      </div>
    </div>
  );
}

function EdmPanel({ edm }: { edm: NcuaReport['panels']['edm'] }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>High-entropy exact match</h2>
          <span>Versioned SHA-256 fingerprints for non-enumerable random identifiers</span>
        </div>
        <span className={`insights-chip ${edm.active ? 'tone-low' : 'tone-high'}`}>
          {edm.active ? 'active' : edm.configured ? 'disabled' : 'setup needed'}
        </span>
      </div>
      <div style={{ padding: '0 16px 14px' }}>
        {edm.active ? (
          <p style={{ margin: 0 }}>
            {edm.fingerprints} fingerprint(s) loaded; exact matches of eligible random identifiers hard-stop on every
            sensor. The salt and fingerprints never appear in evidence exports.
          </p>
        ) : edm.configured ? (
          <p style={{ margin: 0 }}>
            {edm.fingerprints} fingerprint(s) are loaded but the watchlist is <b>disabled</b> — exact-match detection
            is not running. Re-enable it in <code>config/exact-match.json</code> (<code>"enabled": true</code>).
          </p>
        ) : (
          <p style={{ margin: 0 }}>
            If the institution uses random identifiers with at least 96 bits of source entropy, run{' '}
            <code>npm run edm:fingerprint -- --in random-identifiers.txt</code> locally. Use built-in and tuned custom
            detectors for enumerable member, account, and loan numbers; the EDM CLI rejects them.
          </p>
        )}
      </div>
    </div>
  );
}

function CountsPanel({ title, hint, rows, linkLabel, linkPath }: {
  title: string;
  hint: string;
  rows: Array<[string, string | number]>;
  linkLabel: string;
  linkPath: string;
}) {
  return (
    <div className="panel">
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          <span>{hint}</span>
        </div>
        <button className="ghost mini" type="button" onClick={() => navigate(linkPath)}>
          {linkLabel}
        </button>
      </div>
      <div style={{ padding: '0 16px 14px', display: 'grid', gap: '4px' }}>
        {rows.map(([label, value]) => (
          <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>{label}</span>
            <b>{value}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

function NextActionsPanel({ actions }: { actions: NcuaAction[] }) {
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Close the gaps</h2>
          <span>Controls needing attention before an exam — each opens the owning screen</span>
        </div>
      </div>
      <div className="stats" style={{ padding: '14px 16px' }}>
        {actions.length ? (
          actions.map((action) => (
            <button
              key={action.id}
              className="stat alert"
              type="button"
              onClick={() => navigate(action.targetTab === 'ncua' ? '/ncua' : `/${action.targetTab}`)}
            >
              <div className="l">
                <span className="status-light tone-warn" aria-hidden="true" />
                Priority {action.priority}
              </div>
              <div className="n" style={{ fontSize: '15px' }}>{action.label}</div>
              <div className="m">{action.detail.slice(0, 110)}</div>
              <div className="stat-rule" />
            </button>
          ))
        ) : (
          <div className="empty">Every provided control is covered — you are exam-ready on the mapped evidence.</div>
        )}
      </div>
    </div>
  );
}

function UpsellNotice() {
  return (
    <div className="panel wide-panel">
      <div className="panel-head">
        <div>
          <h2>Not included in this license</h2>
          <span>
            The Texas FCU Readiness Center is licensed as an add-on (included with Enterprise). Evidence export and every
            security function keep working; ask your account contact for the `ncua_readiness` feature, then install
            the updated license under Licensing.
          </span>
        </div>
        <button className="ghost mini" type="button" onClick={() => navigate('/licensing')}>
          Open Licensing
        </button>
      </div>
    </div>
  );
}

export default function NcuaReadiness() {
  const { me, loading: sessionLoading } = useSession();
  const { data, loaded, busy, failure, load } = useNcuaReadiness();
  const [boardBusy, setBoardBusy] = useState(false);
  const [boardStatus, setBoardStatus] = useState('');
  const permissions = exportPermissions(me?.role || null, sessionLoading, loaded, data);
  useEffect(() => {
    if (!permissions.boardAllowed) setBoardStatus('');
  }, [permissions.boardAllowed]);

  const runBoardPacket = async () => {
    if (!permissions.boardAllowed || boardBusy) return;
    setBoardBusy(true);
    setBoardStatus('Preparing the board packet…');
    try {
      const result = await downloadBoardPacket();
      if (result === 'downloaded') setBoardStatus('Board packet download started.');
      else if (result === 'denied') setBoardStatus('Board packet export was denied. Refresh readiness to recheck role and license access.');
      else if (result === 'malformed') setBoardStatus('The board packet response was malformed and was not saved.');
      else setBoardStatus('Board packet export is unavailable. Retry when the control plane is ready.');
    } finally {
      setBoardBusy(false);
    }
  };

  const renderBody = () => {
    if (!loaded) return <div className="app-loading">Scoring NCUA readiness…</div>;
    if (data && !data.entitled) return <UpsellNotice />;
    if (!data?.report) {
      return failure === 'malformed'
        ? <EmptyState title="Readiness report malformed" detail="The server returned an incomplete or malformed readiness report. No score, controls, or export entitlement was trusted. Refresh to retry." />
        : <EmptyState title="Readiness report unavailable" detail="Could not load a verified NCUA readiness report. Refresh to retry." />;
    }
    const { report } = data;
    const { shadowAi, exceptions, exportHealth, audit } = report.panels;
    return (
      <>
        <KpiRow report={report} />
        <NextActionsPanel actions={report.nextActions} />
        <UseCasesPanel />
        <IncidentsPanel />
        <div className="insights-grid">
          <EdmPanel edm={report.panels.edm} />
          <CountsPanel
            title="Shadow AI"
            hint="AI destinations seen by Texas FCU sensors, by review status"
            linkLabel="Review in Catalog"
            linkPath="/catalog"
            rows={[
              ['Sanctioned', shadowAi.sanctioned],
              ['Under review', shadowAi.underReview],
              ['Unsanctioned', shadowAi.unsanctioned],
              ['Blocked', shadowAi.blocked],
              ['Sightings pending review', shadowAi.unreviewedEvents],
            ]}
          />
          <CountsPanel
            title="Policy exceptions"
            hint="Exception review lifecycle (owner, reviewer, expiry)"
            linkLabel="Open Policy Configuration"
            linkPath="/policy"
            rows={exceptions ? [
              ['Active', exceptions.active],
              ['Expiring soon', exceptions.expiringSoon],
              ['Review due', exceptions.reviewDue],
              ['Expired', exceptions.expired],
            ] : [['Status', 'not provided']]}
          />
          <CountsPanel
            title="Evidence health"
            hint="Audit chain and scheduled examiner-pack exports"
            linkLabel="Open Examiner Audit Chain"
            linkPath="/audit"
            rows={[
              ['Audit chain', audit.verified ? `verified (${audit.count})` : 'FAILED'],
              ['Scheduled export', exportHealth.scheduled ? (exportHealth.cadence || 'enabled') : 'not scheduled'],
            ]}
          />
        </div>
        <div className="insights-grid">
          {report.controls.map((control) => (
            <ControlRow key={control.id} control={control} />
          ))}
        </div>
      </>
    );
  };

  return (
    <div className="ncua-view">
      <Header
        busy={busy}
        permissions={permissions}
        boardBusy={boardBusy}
        boardStatus={boardStatus}
        onBoardPacket={() => void runBoardPacket()}
        onRefresh={load}
      />
      {renderBody()}
    </div>
  );
}
