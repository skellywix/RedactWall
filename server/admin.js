'use strict';
/**
 * Customer administration domain helpers.
 *
 * This module presents one FCU-facing directory from four sources:
 * environment break-glass accounts, local invite accounts, SCIM identities,
 * and observed sensor users. It keeps seat-management metadata separate from
 * historical sensor events so licensing actions never erase examiner evidence.
 */
const crypto = require('crypto');
const roles = require('./roles');
const scim = require('./scim');
const tenant = require('./tenant');
const { publicOrigin } = require('./public-url');
const { sanitizeSensitiveText } = require('./sensitive-text');

const SOURCE_LABELS = {
  break_glass: 'Break-glass',
  local_invite: 'Local invite',
  scim: 'SCIM',
  observed: 'Observed by sensor',
};

const SOURCE_PRIORITY = {
  observed: 0,
  local_invite: 1,
  scim: 2,
  break_glass: 3,
};

function normalizeUser(value) {
  return String(value || '').trim().toLowerCase();
}

function orgId(env = process.env) {
  return tenant.config(env).tenantId || null;
}

function tokenHash(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('base64url');
}

function createInviteToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function publicInviteBaseUrl(env = process.env) {
  const source = env || {};
  return publicOrigin(source.REDACTWALL_PUBLIC_URL, { production: source.NODE_ENV === 'production' });
}

function identityExists(db, auth, userName) {
  const target = normalizeUser(userName);
  if (!target) return false;
  const staticAccounts = auth && typeof auth.listStaticAccounts === 'function'
    ? auth.listStaticAccounts()
    : [];
  return staticAccounts.some((account) => normalizeUser(account.user) === target)
    || !!db.getAdminUserByUserName(target)
    || !!db.getScimUserByUserName(target);
}

function invitationError(code, message) {
  const error = new Error(message || code);
  error.code = code;
  return error;
}

function roleRecord(role) {
  const id = roles.normalizeRole(role);
  return id ? { id, label: roles.label(id) } : null;
}

function publicUser(user) {
  const role = roleRecord(user.role);
  return {
    id: user.id,
    userName: user.userName,
    displayName: user.displayName || user.userName,
    role: role ? role.id : '',
    roleLabel: role ? role.label : 'Unassigned',
    active: user.active !== false,
    source: user.source,
    sourceLabel: SOURCE_LABELS[user.source] || user.source,
    sources: user.sources || [user.source],
    orgId: user.orgId || null,
    firstSeen: user.firstSeen || null,
    lastSeen: user.lastSeen || null,
    events: Number(user.events || 0),
    licenseState: user.licenseState || 'unassigned',
    licenseReason: user.licenseReason || '',
    licenseUpdatedAt: user.licenseUpdatedAt || null,
    mutable: user.mutable !== false,
  };
}

function mergeUser(map, record) {
  const key = normalizeUser(record.userName);
  if (!key) return;
  const existing = map.get(key);
  const sources = new Set([...(existing && existing.sources ? existing.sources : []), record.source]);
  const existingPriority = existing ? (SOURCE_PRIORITY[existing.source] || 0) : -1;
  const recordPriority = SOURCE_PRIORITY[record.source] || 0;
  const authority = !existing || recordPriority > existingPriority ? record : existing;
  const merged = {
    ...authority,
    userKey: key,
    userName: authority.userName || key,
    displayName: authority.displayName || authority.userName || key,
    role: authority.role || '',
    active: authority.active !== false,
    source: authority.source,
    sources: [...sources],
    orgId: authority.orgId || record.orgId || (existing && existing.orgId) || null,
    events: Number(record.events || 0) + Number((existing && existing.events) || 0),
    firstSeen: [record.firstSeen, existing && existing.firstSeen].filter(Boolean).sort()[0] || null,
    lastSeen: [record.lastSeen, existing && existing.lastSeen].filter(Boolean).sort().pop() || null,
    mutable: authority.mutable !== false,
  };
  map.set(key, merged);
}

function staticDirectoryRecords(auth) {
  return auth.listStaticAccounts().map((account) => ({
    id: `break:${normalizeUser(account.user)}`,
    userName: account.user,
    displayName: account.user,
    role: account.role,
    active: true,
    source: 'break_glass',
    mutable: false,
  }));
}

function scimDirectoryRecords(db) {
  const groups = db.listScimGroups();
  return db.listScimUsers().map((user) => ({
    id: `scim:${user.id}`,
    userName: user.userName,
    displayName: user.displayName || user.userName,
    role: scim.effectiveUserRole(user, groups),
    active: user.active !== false,
    source: 'scim',
    orgId: user.orgId || null,
    externalId: user.externalId || null,
    mutable: true,
  }));
}

function localDirectoryRecords(db) {
  return db.listAdminUsers().map((user) => ({
    id: `local:${user.id}`,
    userName: user.userName,
    displayName: user.displayName || user.userName,
    role: user.role,
    active: user.active !== false,
    source: 'local_invite',
    orgId: user.orgId || null,
    mutable: true,
  }));
}

function observedDirectoryRecords(seatReport) {
  return (seatReport.users || []).map((user) => ({
    id: `observed:${normalizeUser(user.user)}`,
    userName: user.user,
    displayName: user.user,
    role: '',
    active: true,
    source: 'observed',
    orgId: user.orgId || null,
    firstSeen: user.firstSeen || null,
    lastSeen: user.lastSeen || null,
    events: user.events || 0,
    mutable: false,
  }));
}

function seatAssignmentDirectoryRecords(assignments) {
  return (assignments || []).map((assignment) => ({
    id: `observed:${normalizeUser(assignment.userKey || assignment.userName)}`,
    userName: assignment.userName || assignment.userKey,
    displayName: assignment.userName || assignment.userKey,
    role: '',
    source: 'observed',
    orgId: assignment.orgId || null,
    events: 0,
    mutable: false,
  }));
}

function applyLicenseState(users, assignments) {
  const byKey = new Map(assignments.map((item) => [normalizeUser(item.userKey || item.userName), item]));
  return users.map((user) => {
    const assignment = byKey.get(normalizeUser(user.userName));
    const observed = Number(user.events || 0) > 0;
    const state = assignment ? assignment.status : (observed ? 'in_use' : 'unassigned');
    return publicUser({
      ...user,
      licenseState: state,
      licenseReason: assignment ? assignment.reason : '',
      licenseUpdatedAt: assignment ? assignment.updatedAt : null,
    });
  });
}

function directory(db, auth, env = process.env) {
  const seatReport = tenant.seatReport(db, env);
  const assignments = db.listLicenseSeatAssignments();
  const map = new Map();
  for (const record of staticDirectoryRecords(auth)) mergeUser(map, record);
  for (const record of localDirectoryRecords(db)) mergeUser(map, record);
  for (const record of scimDirectoryRecords(db)) mergeUser(map, record);
  for (const record of observedDirectoryRecords(seatReport)) mergeUser(map, record);
  for (const record of seatAssignmentDirectoryRecords(assignments)) mergeUser(map, record);
  const users = applyLicenseState([...map.values()], assignments)
    .sort((a, b) => a.userName.localeCompare(b.userName));
  return {
    users,
    invitations: db.listAdminInvitations().map(publicInvitation),
    seatReport,
  };
}

function publicInvitation(invitation = {}, token = '', baseUrl = '') {
  const body = {
    id: invitation.id,
    userName: invitation.userName,
    displayName: invitation.displayName || invitation.userName,
    role: invitation.role,
    roleLabel: roles.label(invitation.role),
    status: invitation.status,
    expiresAt: invitation.expiresAt,
    acceptedAt: invitation.acceptedAt || null,
    createdAt: invitation.createdAt,
    updatedAt: invitation.updatedAt,
    reason: invitation.reason || '',
  };
  if (token) {
    body.inviteToken = token;
    // URL fragments are never sent in the HTTP request target, keeping this
    // one-time bearer token out of proxy/access logs and Referer headers.
    body.inviteUrl = `${String(baseUrl || '').replace(/\/$/, '')}/accept-invite.html#token=${encodeURIComponent(token)}`;
  }
  return body;
}

function createInvitation(db, input, actor, baseUrl, env = process.env, auth) {
  if (roles.normalizeRole(input.role) === roles.SECURITY_ADMIN) {
    throw invitationError('LOCAL_SECURITY_ADMIN_MFA_REQUIRED', 'per-user MFA enrollment required');
  }
  if (identityExists(db, auth, input.userName)) {
    throw invitationError('IDENTITY_ALREADY_EXISTS', 'identity already exists');
  }
  const token = createInviteToken();
  const now = Date.now();
  const expiresAt = new Date(now + input.expiresInDays * 86400000).toISOString();
  const saved = db.saveAdminInvitation({
    orgId: orgId(env),
    userName: normalizeUser(input.userName),
    displayName: String(input.displayName || input.userName).trim(),
    role: roles.normalizeRole(input.role),
    status: 'pending',
    tokenHash: tokenHash(token),
    expiresAt,
    reason: sanitizeSensitiveText(input.reason),
    actor,
  });
  return publicInvitation(saved, token, baseUrl);
}

function resendInvitation(db, invitationId, actor, baseUrl) {
  const existing = db.getAdminInvitation(invitationId);
  if (!existing || existing.status === 'accepted' || existing.status === 'revoked') return null;
  const token = createInviteToken();
  const saved = db.saveAdminInvitation({
    ...existing,
    tokenHash: tokenHash(token),
    status: 'pending',
    expiresAt: new Date(Date.now() + 7 * 86400000).toISOString(),
    actor,
    expectedVersion: existing.version,
    expectedStatus: existing.status,
    expectedTokenHash: existing.tokenHash,
  });
  return publicInvitation(saved, token, baseUrl);
}

function revokeInvitation(db, invitationId, actor, reason) {
  const existing = db.getAdminInvitation(invitationId);
  if (!existing || existing.status === 'accepted' || existing.status === 'revoked') return null;
  return db.saveAdminInvitation({
    ...existing,
    status: 'revoked',
    actor,
    revokedBy: actor,
    revokeReason: sanitizeSensitiveText(reason),
    expectedVersion: existing.version,
    expectedStatus: existing.status,
    expectedTokenHash: existing.tokenHash,
  });
}

function accountLookup(db, userName) {
  // A SCIM record owns its username even while inactive. This prevents a
  // preexisting cross-source duplicate from falling through to a local password
  // immediately after IdP deprovisioning.
  if (db.getScimUserByUserName(userName)) return null;
  const user = db.getAdminUserByUserName(userName);
  if (!user || user.active === false || !user.passwordHash || !user.passwordSalt) return null;
  return {
    user: user.userName,
    role: user.role,
    active: user.active !== false,
    salt: user.passwordSalt,
    hash: user.passwordHash,
  };
}

function parseDirectoryId(id) {
  const text = String(id || '');
  const idx = text.indexOf(':');
  if (idx <= 0) return { kind: '', id: text };
  return { kind: text.slice(0, idx), id: text.slice(idx + 1) };
}

function getMutableUser(db, id) {
  const parsed = parseDirectoryId(id);
  if (parsed.kind === 'local') return { kind: parsed.kind, user: db.getAdminUser(parsed.id) };
  if (parsed.kind === 'scim') return { kind: parsed.kind, user: db.getScimUser(parsed.id) };
  return { kind: parsed.kind, user: null };
}

function activeGlobalAdmins(db, auth) {
  const groups = db.listScimGroups();
  const staticAdmins = auth.listStaticAccounts()
    .filter((account) => roles.normalizeRole(account.role) === roles.SECURITY_ADMIN)
    .map((account) => ({ source: 'break_glass', userName: account.user }));
  const localAdmins = db.listAdminUsers()
    .filter((user) => user.active !== false && roles.normalizeRole(user.role) === roles.SECURITY_ADMIN)
    .map((user) => ({ source: 'local', id: user.id, userName: user.userName }));
  const scimAdmins = db.listScimUsers()
    .filter((user) => user.active !== false && scim.effectiveUserRole(user, groups) === roles.SECURITY_ADMIN)
    .map((user) => ({ source: 'scim', id: user.id, userName: user.userName }));
  return [...staticAdmins, ...localAdmins, ...scimAdmins];
}

function wouldRemoveLastGlobalAdmin(db, auth, targetId, next = {}) {
  const parsed = parseDirectoryId(targetId);
  const admins = activeGlobalAdmins(db, auth);
  if (admins.length !== 1) return false;
  const only = admins[0];
  if (parsed.kind !== only.source && !(parsed.kind === 'local' && only.source === 'local')) return false;
  if (parsed.id !== only.id) return false;
  const nextRole = next.role === undefined ? roles.SECURITY_ADMIN : roles.normalizeRole(next.role);
  const nextActive = next.active === undefined ? true : next.active !== false;
  return !nextActive || nextRole !== roles.SECURITY_ADMIN;
}

function patchUser(db, id, patch) {
  const target = getMutableUser(db, id);
  if (!target.user) return null;
  if (target.kind === 'local') {
    return {
      kind: target.kind,
      user: db.saveAdminUser({
        ...target.user,
        displayName: patch.displayName !== undefined ? patch.displayName : target.user.displayName,
        role: patch.role || target.user.role,
        active: patch.active !== undefined ? patch.active : target.user.active !== false,
      }),
    };
  }
  return {
    kind: target.kind,
    user: db.saveScimUser({
      ...target.user,
      displayName: patch.displayName !== undefined ? patch.displayName : target.user.displayName,
      role: patch.role || target.user.role,
      active: patch.active !== undefined ? patch.active : target.user.active !== false,
    }),
  };
}

function disableUser(db, id) {
  const target = getMutableUser(db, id);
  if (!target.user) return null;
  if (target.kind === 'local') return { kind: target.kind, user: db.disableAdminUser(target.user.id) };
  return { kind: target.kind, user: db.deactivateScimUser(target.user.id) };
}

function reactivateUser(db, id) {
  const target = getMutableUser(db, id);
  if (!target.user) return null;
  if (target.kind === 'local') return { kind: target.kind, user: db.reactivateAdminUser(target.user.id) };
  return { kind: target.kind, user: db.saveScimUser({ ...target.user, active: true }) };
}

function seats(db, auth, licenseStatus, env = process.env) {
  const dir = directory(db, auth || { listStaticAccounts: () => [] }, env);
  const assignments = db.listLicenseSeatAssignments();
  const releasedSeats = assignments.filter((item) => item.status === 'released').length;
  const assignedSeats = assignments.filter((item) => item.status === 'assigned').length;
  return {
    license: licenseStatus,
    ...dir.seatReport,
    assignedSeats,
    releasedSeats,
    users: dir.users,
  };
}

function saveSeatState(db, userKey, status, reason, actor, env = process.env) {
  const normalized = normalizeUser(userKey);
  return db.saveLicenseSeatAssignment({
    orgId: orgId(env),
    userKey: normalized,
    userName: normalized,
    status,
    reason: sanitizeSensitiveText(reason),
    actor,
  });
}

function renewalPackage(request, licenseStatus, seatReport) {
  return {
    requestId: request.id,
    requestedAt: request.createdAt,
    customer: licenseStatus.customer || '',
    customerId: licenseStatus.customerId || '',
    plan: licenseStatus.plan || 'unlicensed',
    currentSeats: licenseStatus.seats || seatReport.seatLimit || 0,
    requestedSeats: request.requestedSeats,
    seatsUsed: seatReport.seatsUsed,
    tenantId: seatReport.tenantId || null,
    contactName: request.contactName || '',
    contactEmail: request.contactEmail || '',
    note: request.note || '',
  };
}

module.exports = {
  SOURCE_LABELS,
  accountLookup,
  activeGlobalAdmins,
  createInvitation,
  directory,
  disableUser,
  getMutableUser,
  hashToken: tokenHash,
  identityExists,
  patchUser,
  publicInvitation,
  publicInviteBaseUrl,
  reactivateUser,
  renewalPackage,
  resendInvitation,
  revokeInvitation,
  saveSeatState,
  seats,
  wouldRemoveLastGlobalAdmin,
};
