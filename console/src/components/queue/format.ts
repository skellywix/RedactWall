import { isHeldQueryStatus, type QueueQuery, type RevealResult } from '../../api/queries';
import type { Me } from '../../lib/session';

/** Display helpers ported from the legacy dashboard so the queue reads the same. */

export const fmt = (iso?: string): string => (iso ? new Date(iso).toLocaleString() : '-');

export const fmtTime = (iso?: string): string =>
  iso ? new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-';

export const sevClass = (label?: string): string => String(label || 'low').toLowerCase();

export const humanize = (value?: string): string => String(value || '-').replace(/_/g, ' ');

const SOURCE_LABELS: Record<string, string> = {
  browser_extension: 'Browser',
  endpoint_agent: 'Endpoint',
  mcp_guard: 'MCP',
  audit_log: 'Audit',
  approval_queue: 'Approval',
  policy: 'Policy',
  signal_console: 'Console',
  api: 'API',
  proxy: 'Proxy',
};

export function sourceLabel(source?: string): string {
  return SOURCE_LABELS[source || ''] || source || 'API';
}

const GOOD_STATUSES = ['approved', 'allowed', 'justified', 'warned_sent', 'redacted', 'response_redacted'];
const BAD_STATUSES = [
  'denied', 'blocked_by_user', 'destination_blocked', 'file_upload_blocked', 'action_blocked',
  'injection_blocked', 'response_flagged', 'response_blocked', 'seat_limit_blocked', 'ocr_required',
  'file_blocked_unscanned',
];
const WARN_STATUSES = ['shadow_ai', 'paste_flagged', 'flagged'];

export type StatusTone = 'good' | 'bad' | 'warn' | 'info';

export function statusTone(status?: string): StatusTone {
  const s = String(status || '').toLowerCase();
  if (isHeldQueryStatus(s)) return 'warn';
  if (GOOD_STATUSES.includes(s)) return 'good';
  if (BAD_STATUSES.includes(s)) return 'bad';
  if (WARN_STATUSES.includes(s)) return 'warn';
  return 'info';
}

export function detectedSummary(query: QueueQuery): string {
  const detected =
    Object.keys(query.entityCounts || {}).join(', ') || (query.categories || []).join(', ') || 'policy match';
  const reasons = query.reasons || [];
  return reasons.length ? `${detected}; ${reasons.join('; ')}` : detected;
}

function samePrincipal(left?: string, right?: string): boolean {
  return String(left || '').trim().toLowerCase() === String(right || '').trim().toLowerCase();
}

export function canDecide(me: Me | null, query: QueueQuery): boolean {
  if (!me || !isHeldQueryStatus(query.status)) return false;
  if (me.role === 'security_admin') return true;
  if (me.role !== 'approver') return false;
  return query.assignedRole === 'approver' && (!query.assignedUser || samePrincipal(query.assignedUser, me.user));
}

export function canReveal(me: Me | null, query: QueueQuery): boolean {
  return me?.role === 'security_admin' && query.rawRetained === true;
}

export function readonlyLabel(me: Me | null, query: QueueQuery): string {
  if (!me || me.role === 'auditor') return 'Read-only auditor view';
  if (me.role === 'operator') return 'Operator view';
  if (me.role === 'approver') return canDecide(me, query) ? '' : 'Not assigned to your role';
  return 'Read-only view';
}

export interface RevealDisplay {
  kind: 'revealed' | 'retained' | 'unavailable';
  buttonLabel: string;
  statusLabel: string;
  statusDetail: string;
}

export function revealDisplay(reveal: RevealResult | null): RevealDisplay | null {
  if (!reveal) return null;
  if (reveal.rawRetained && reveal.rawDiffersFromRedacted) {
    return {
      kind: 'revealed',
      buttonLabel: 'Raw shown and logged',
      statusLabel: 'Raw prompt revealed',
      statusDetail: 'Audit logged',
    };
  }
  if (reveal.rawRetained) {
    return {
      kind: 'retained',
      buttonLabel: 'Retained copy shown',
      statusLabel: 'Retained copy matches preview',
      statusDetail: 'Audit logged',
    };
  }
  return {
    kind: 'unavailable',
    buttonLabel: 'Raw unavailable, event logged',
    statusLabel: 'Raw unavailable',
    statusDetail: 'Redacted preview shown',
  };
}
