'use strict';

const SECURITY_ADMIN = 'security_admin';
const APPROVER = 'approver';
const OPERATOR = 'operator';
const AUDITOR = 'auditor';

const ALL_ROLES = [SECURITY_ADMIN, APPROVER, OPERATOR, AUDITOR];

function normalizeRole(role) {
  const value = String(role || '').trim().toLowerCase();
  return ALL_ROLES.includes(value) ? value : '';
}

function canDecideQuery(user = {}, query = {}) {
  const role = normalizeRole(user.role);
  if (role === SECURITY_ADMIN) return true;
  if (role !== APPROVER) return false;
  if (query.assignedRole !== APPROVER) return false;
  return !query.assignedUser || query.assignedUser === user.user;
}

function loginAuditAction(role) {
  return ({
    [SECURITY_ADMIN]: 'ADMIN_LOGIN',
    [APPROVER]: 'APPROVER_LOGIN',
    [AUDITOR]: 'AUDITOR_LOGIN',
    [OPERATOR]: 'OPERATOR_LOGIN',
  })[normalizeRole(role)] || 'LOGIN';
}

module.exports = {
  SECURITY_ADMIN,
  APPROVER,
  OPERATOR,
  AUDITOR,
  ALL_ROLES,
  normalizeRole,
  canDecideQuery,
  loginAuditAction,
};
