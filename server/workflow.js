'use strict';
/**
 * Approval workflow side effects: notification status and SLA escalation.
 *
 * This module owns persistence. `server/notifiers.js` owns payload shape and
 * adapter delivery so it can be unit-tested without a database.
 */
const notifiers = require('./notifiers');
const routing = require('./routing');
const ticketSync = require('./ticket-sync');

const ACTIVE_WORKFLOW_STATUSES = new Set([
  'pending',
  'pending_justification',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'file_blocked_unscanned',
  'ocr_required',
  'injection_blocked',
  'response_flagged',
  'response_blocked',
]);

function resultStatus(result) {
  return notifiers.deliveryStatus(result);
}

function notificationPatch(query, result, now = new Date()) {
  const status = resultStatus(result);
  if (status === 'not_configured') return { notificationStatus: 'not_configured' };
  return {
    notificationStatus: status,
    notificationLastAttemptAt: now.toISOString(),
    notificationChannels: (result.channels || []).slice(0, 8),
    notificationAttemptCount: (Number(query.notificationAttemptCount) || 0) + 1,
    ...(ticketSync.ticketRefsFromDelivery(query, result, now) || {}),
  };
}

function auditNotification(db, query, result, action, status) {
  if (status === 'not_configured') return null;
  const auditAction = status === 'sent'
    ? 'APPROVAL_NOTIFICATION_SENT'
    : status === 'partial'
      ? 'APPROVAL_NOTIFICATION_PARTIAL'
      : 'APPROVAL_NOTIFICATION_FAILED';
  return db.appendAudit({
    action: auditAction,
    queryId: query.id,
    actor: 'system',
    detail: [
      `workflowAction=${action || 'APPROVAL_ROUTED'}`,
      `status=${status}`,
      `channels=${(result.channels || []).join(',') || 'none'}`,
    ].join('; '),
  });
}

async function emitAndPersistApprovalNotification(query, { db, action = 'APPROVAL_ROUTED', now = new Date(), onUpdate, ...notifyOpts } = {}) {
  if (!db || !query || !query.id) return { sent: false, reason: 'missing_db_or_query' };
  const current = db.getQuery(query.id) || query;
  const result = await notifiers.emitApprovalNotification(current, { action, ...notifyOpts });
  if (result.reason === 'not_routeable' || result.reason === 'disabled') return result;
  const patch = notificationPatch(current, result, now);
  const status = patch.notificationStatus;
  if (status === 'not_configured') return result;
  const updated = db.updateQuery(current.id, patch);
  if (updated) {
    auditNotification(db, updated, result, action, status);
    if (typeof onUpdate === 'function') onUpdate(updated);
  }
  return result;
}

function fireAndPersistApprovalNotification(query, opts = {}) {
  try {
    Promise.resolve(emitAndPersistApprovalNotification(query, opts)).catch(() => {});
  } catch {}
}

function dueForEscalation(query, now) {
  if (!query || !ACTIVE_WORKFLOW_STATUSES.has(String(query.status || ''))) return false;
  if (query.escalatedAt) return false;
  if (!query.slaDueAt) return false;
  const due = Date.parse(query.slaDueAt);
  return Number.isFinite(due) && due <= now.getTime();
}

function escalationPatch(query, now) {
  return {
    escalatedAt: now.toISOString(),
    escalationReason: 'sla_due',
    assignedRole: query.assignedRole === 'security_admin' ? query.assignedRole : 'security_admin',
  };
}

function escalateDueApprovals({ db, now = new Date(), actor = 'system', notify = true, notifyOpts = {}, onUpdate } = {}) {
  if (!db) return { checked: 0, escalated: [] };
  const rows = db.listQueries({ limit: 5000 });
  const escalated = [];
  for (const query of rows) {
    if (!routing.routeableStatus(query.status) || !dueForEscalation(query, now)) continue;
    const updated = db.updateQuery(query.id, escalationPatch(query, now));
    if (!updated) continue;
    db.appendAudit({
      action: 'APPROVAL_ESCALATED',
      queryId: updated.id,
      actor,
      detail: [
        `reason=${updated.escalationReason}`,
        `assignedGroup=${updated.assignedGroup || 'unassigned'}`,
        `assignedRole=${updated.assignedRole || 'unassigned'}`,
        `slaDueAt=${updated.slaDueAt || 'none'}`,
      ].join('; '),
    });
    escalated.push(updated);
    if (typeof onUpdate === 'function') onUpdate(updated);
    if (notify) fireAndPersistApprovalNotification(updated, { db, action: 'APPROVAL_ESCALATED', onUpdate, ...notifyOpts });
  }
  return { checked: rows.length, escalated };
}

module.exports = {
  dueForEscalation,
  emitAndPersistApprovalNotification,
  escalateDueApprovals,
  fireAndPersistApprovalNotification,
  notificationPatch,
};
