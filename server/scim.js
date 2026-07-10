'use strict';
/**
 * Minimal SCIM 2.0 provisioning surface for customer-silo deployments.
 *
 * This is identity lifecycle state, not login. OIDC/SAML can later consume the
 * provisioned users/groups to issue sessions with the same role names.
 */
const crypto = require('crypto');
const express = require('express');
const db = require('./db');
const auth = require('./auth');
const roles = require('./roles');
const { opaqueReference } = require('./audit-reference');

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';
const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

const ROLE_GROUPS = [
  [roles.SECURITY_ADMIN, /^(redactwall[-_\s]*)?(security[-_\s]*)?admins?$/i],
  [roles.APPROVER, /^(redactwall[-_\s]*)?(approvers?|reviewers?)$/i],
  [roles.AUDITOR, /^(redactwall[-_\s]*)?(auditors?|read[-_\s]*only)$/i],
  [roles.OPERATOR, /^(redactwall[-_\s]*)?(operators?|ops)$/i],
];

function configuredToken() {
  return String(process.env.SCIM_BEARER_TOKEN || '').trim();
}

function scimError(status, detail, scimType) {
  return {
    schemas: [ERROR_SCHEMA],
    status: String(status),
    detail,
    ...(scimType ? { scimType } : {}),
  };
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function requireScimBearer(req, res, next) {
  const token = configuredToken();
  if (!token) return res.status(404).json(scimError(404, 'SCIM provisioning is not enabled'));
  const header = String(req.get('authorization') || '');
  const match = header.match(/^Bearer\s+(.+)$/i);
  if (!match || !safeEqual(match[1].trim(), token)) {
    res.set('WWW-Authenticate', 'Bearer realm="RedactWall SCIM"');
    return res.status(401).json(scimError(401, 'SCIM bearer token required'));
  }
  next();
}

function cleanString(value, max = 256) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

// SCIM PATCH/PUT bodies from real IdPs (Azure AD) send `active` as the strings
// "True"/"False"; a bare !! coercion turns "False" truthy and silently
// re-activates a deprovisioned user. Map string booleans explicitly.
function scimBool(value, fallback = false) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
    if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  }
  if (value == null) return fallback;
  return !!value;
}

function resourceLocation(req, resourceType, id) {
  return `${req.protocol}://${req.get('host')}/scim/v2/${resourceType}/${encodeURIComponent(id)}`;
}

function roleFromDisplayName(displayName) {
  const name = cleanString(displayName, 128);
  for (const [role, pattern] of ROLE_GROUPS) {
    if (pattern.test(name)) return role;
  }
  return '';
}

function roleFromScimRoles(scimRoles = []) {
  if (!Array.isArray(scimRoles)) return '';
  for (const item of scimRoles) {
    const role = roles.normalizeRole(item && (item.value || item.display));
    if (role) return role;
  }
  return '';
}

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function directRoleFromUserBody(body = {}, existing = {}, replace = false) {
  if (hasOwn(body, 'roles')) {
    const role = roleFromScimRoles(body.roles);
    if (role || !hasOwn(body, 'role')) return role;
  }
  if (hasOwn(body, 'role')) return roles.normalizeRole(body.role);
  return replace ? '' : (existing.role || '');
}

// `groups` may be a pre-loaded db.listScimGroups() result so list handlers can
// resolve N users without re-scanning the group table per user (avoids 2N loads).
function groupMembersForUser(userId, groups) {
  return (groups || db.listScimGroups())
    .filter((group) => (group.members || []).some((member) => member.value === userId))
    .map((group) => ({ value: group.id, display: group.displayName }));
}

function effectiveUserRole(user, groups) {
  const direct = roles.normalizeRole(user.role);
  if (direct) return direct;
  for (const group of groupMembersForUser(user.id, groups)) {
    const role = roleFromDisplayName(group.display);
    if (role) return role;
  }
  return '';
}

function userResource(req, user, groups) {
  const groupList = groups || db.listScimGroups();
  const groupRefs = groupMembersForUser(user.id, groupList);
  const role = effectiveUserRole(user, groupList);
  return {
    schemas: [USER_SCHEMA],
    id: user.id,
    externalId: user.externalId || undefined,
    userName: user.userName,
    displayName: user.displayName || user.userName,
    active: user.active !== false,
    groups: groupRefs,
    roles: role ? [{ value: role, display: role, primary: true }] : [],
    meta: {
      resourceType: 'User',
      created: user.createdAt,
      lastModified: user.updatedAt,
      location: resourceLocation(req, 'Users', user.id),
    },
  };
}

function groupResource(req, group) {
  return {
    schemas: [GROUP_SCHEMA],
    id: group.id,
    externalId: group.externalId || undefined,
    displayName: group.displayName,
    members: (group.members || []).map((member) => ({
      value: member.value,
      display: member.display || member.value,
    })),
    meta: {
      resourceType: 'Group',
      created: group.createdAt,
      lastModified: group.updatedAt,
      location: resourceLocation(req, 'Groups', group.id),
    },
  };
}

function listResponse(req, resources, mapper) {
  const startIndex = Math.max(1, Number(req.query.startIndex) || 1);
  const count = Math.max(1, Math.min(200, Number(req.query.count) || 100));
  const offset = startIndex - 1;
  const page = resources.slice(offset, offset + count);
  return {
    schemas: [LIST_SCHEMA],
    totalResults: resources.length,
    startIndex,
    itemsPerPage: page.length,
    Resources: page.map((item) => mapper(req, item)),
  };
}

function filterEq(req, resources, fields) {
  const filter = cleanString(req.query.filter || '', 512);
  if (!filter) return resources;
  const match = filter.match(/^([A-Za-z][A-Za-z0-9._-]*)\s+eq\s+"([^"]{0,256})"$/i);
  if (!match || !fields.includes(match[1])) return [];
  const field = match[1];
  const wanted = match[2].toLowerCase();
  return resources.filter((item) => cleanString(item[field]).toLowerCase() === wanted);
}

function normalizeMembers(input) {
  const items = Array.isArray(input) ? input : [];
  const seen = new Set();
  const members = [];
  for (const item of items) {
    const value = cleanString(item && (item.value || item.$ref || item.id), 128);
    if (!value || seen.has(value)) continue;
    seen.add(value);
    members.push({ value, display: cleanString(item.display || item.value || value, 256) });
  }
  return members;
}

function normalizeUserBody(body = {}, existing = {}, { replace = false } = {}) {
  const userName = cleanString(replace ? body.userName : (body.userName || existing.userName), 256);
  if (!userName) return null;
  const externalId = hasOwn(body, 'externalId')
    ? cleanString(body.externalId, 256)
    : (replace ? '' : cleanString(existing.externalId, 256));
  const displayName = hasOwn(body, 'displayName')
    ? cleanString(body.displayName, 256)
    : (replace ? '' : cleanString(existing.displayName, 256));
  return {
    id: existing.id,
    ...(existing.id ? { expectedVersion: existing.version } : {}),
    externalId: externalId || undefined,
    userName,
    displayName: displayName || userName,
    active: body.active !== undefined ? scimBool(body.active, existing.active !== false) : existing.active !== false,
    role: directRoleFromUserBody(body, existing, replace),
  };
}

function normalizeGroupBody(body = {}, existing = {}, { replace = false } = {}) {
  const displayName = cleanString(replace ? body.displayName : (body.displayName || existing.displayName), 256);
  if (!displayName) return null;
  const externalId = hasOwn(body, 'externalId')
    ? cleanString(body.externalId, 256)
    : (replace ? '' : cleanString(existing.externalId, 256));
  return {
    id: existing.id,
    ...(existing.id ? { expectedVersion: existing.version } : {}),
    externalId: externalId || undefined,
    displayName,
    members: hasOwn(body, 'members')
      ? normalizeMembers(body.members)
      : (replace ? [] : (existing.members || [])),
  };
}

function applyUserPatch(user, operations = []) {
  const next = { ...user };
  for (const op of operations) {
    const path = cleanString(op.path || '', 80).toLowerCase();
    const kind = cleanString(op.op || 'replace', 20).toLowerCase();
    if ((kind === 'replace' || kind === 'add') && !path && op.value && typeof op.value === 'object' && !Array.isArray(op.value)) {
      if (hasOwn(op.value, 'active')) next.active = scimBool(op.value.active, next.active !== false);
      if (op.value.userName) next.userName = cleanString(op.value.userName, 256) || next.userName;
      if (op.value.displayName) next.displayName = cleanString(op.value.displayName, 256) || next.displayName;
      if (hasOwn(op.value, 'roles')) {
        const role = roleFromScimRoles(op.value.roles);
        next.role = kind === 'replace' ? role : (role || next.role);
      }
      continue;
    }
    if ((kind === 'replace' || kind === 'add') && path === 'active') next.active = scimBool(op.value, next.active !== false);
    if ((kind === 'replace' || kind === 'add') && path === 'username') next.userName = cleanString(op.value, 256) || next.userName;
    if ((kind === 'replace' || kind === 'add') && path === 'displayname') next.displayName = cleanString(op.value, 256) || next.displayName;
    if ((kind === 'replace' || kind === 'add') && path === 'roles') {
      const role = roleFromScimRoles(op.value);
      next.role = kind === 'replace' ? role : (role || next.role);
    }
    if (kind === 'remove' && path === 'roles') next.role = '';
  }
  return next;
}

function memberValueFromPatch(path, value) {
  const direct = cleanString(value && (value.value || value), 128);
  if (direct) return direct;
  const match = String(path || '').match(/^members\s*\[\s*value\s+eq\s+"([^"]{1,128})"\s*\]$/i);
  return match ? cleanString(match[1], 128) : '';
}

// RFC 7644 lets clients remove members either via a path selector or by sending
// `value` as an array of member objects ({op:'remove',path:'members',value:[{value:id}]}).
// Return every member id the op targets; empty means "remove all members".
function memberValuesFromPatch(path, value) {
  if (Array.isArray(value)) {
    const out = [];
    for (const item of value) {
      const id = cleanString(item && (item.value || item.$ref || item.id || item), 128);
      if (id && id !== '[object Object]') out.push(id);
    }
    return out;
  }
  const single = memberValueFromPatch(path, value);
  return single ? [single] : [];
}

function applyMemberWrite(current, value, kind) {
  const incoming = normalizeMembers(value);
  if (kind === 'replace') return incoming;
  const byValue = new Map(current.map((member) => [member.value, member]));
  for (const member of incoming) byValue.set(member.value, member);
  return Array.from(byValue.values());
}

function applyGroupPatch(group, operations = []) {
  let members = normalizeMembers(group.members || []);
  const next = { ...group };
  for (const op of operations) {
    const rawPath = cleanString(op.path || '', 160);
    const path = rawPath.toLowerCase();
    const kind = cleanString(op.op || 'replace', 20).toLowerCase();
    if ((kind === 'replace' || kind === 'add') && !path && op.value && typeof op.value === 'object' && !Array.isArray(op.value)) {
      if (op.value.displayName) next.displayName = cleanString(op.value.displayName, 256) || next.displayName;
      if (hasOwn(op.value, 'members')) members = applyMemberWrite(members, op.value.members, kind);
      continue;
    }
    if ((kind === 'replace' || kind === 'add') && path === 'displayname') next.displayName = cleanString(op.value, 256) || next.displayName;
    if ((kind === 'replace' || kind === 'add') && path === 'members') members = applyMemberWrite(members, op.value, kind);
    if (kind === 'remove' && path.startsWith('members')) {
      const values = memberValuesFromPatch(rawPath, op.value);
      if (values.length) members = members.filter((member) => !values.includes(member.value));
      else members = [];
    }
  }
  next.members = members;
  return next;
}

function patchOperations(body = {}) {
  return Array.isArray(body.Operations) ? body.Operations : [];
}

function userAuditDetail(user) {
  return `userRef=${opaqueReference('scim_user', user && (user.id || user.userName))}; active=${user && user.active !== false}`;
}

function groupAuditDetail(group) {
  const memberCount = Array.isArray(group && group.members) ? group.members.length : 0;
  return `groupRef=${opaqueReference('scim_group', group && (group.id || group.displayName))}; members=${memberCount}`;
}

function conflict(detail) {
  return scimError(409, detail, 'uniqueness');
}

function saveOrConflict(res, detail, fn) {
  try {
    return fn();
  } catch (err) {
    if (err && (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || err.code === '23505'
      || err.code === 'IDENTITY_ALREADY_EXISTS' || err.code === 'IDENTITY_WRITE_CONFLICT'
      || /UNIQUE constraint failed/i.test(err.message || '')
      || /duplicate key value violates unique constraint/i.test(err.message || ''))) {
      res.status(409).json(conflict(detail));
      return null;
    }
    throw err;
  }
}

function normalizedUserName(value) {
  return cleanString(value, 256).toLowerCase();
}

function userNameCollisions(userName, currentScimUser = null) {
  const normalized = normalizedUserName(userName);
  const scimUser = db.getScimUserByUserName(normalized);
  return {
    staticAccount: auth.listStaticAccounts().some((account) => normalizedUserName(account.user) === normalized),
    localAccount: !!db.getAdminUserByUserName(normalized),
    otherScimUser: !!(scimUser && (!currentScimUser || scimUser.id !== currentScimUser.id)),
  };
}

function rejectUserNameCollision(res, nextUser, currentScimUser = null) {
  const collisions = userNameCollisions(nextUser.userName, currentScimUser);
  if (!collisions.staticAccount && !collisions.localAccount && !collisions.otherScimUser) return false;

  // Legacy deployments may already contain a duplicate. Permit only an update
  // that keeps that exact SCIM username inactive, so an IdP can deprovision it;
  // active updates and moves onto another credential source remain rejected.
  const deactivatingPreexistingDuplicate = !!currentScimUser
    && normalizedUserName(currentScimUser.userName) === normalizedUserName(nextUser.userName)
    && nextUser.active === false
    && !collisions.otherScimUser;
  if (deactivatingPreexistingDuplicate) return false;

  res.status(409).json(conflict('userName already exists in another authentication source'));
  return true;
}

function router() {
  const r = express.Router();
  r.use(requireScimBearer);

  r.get('/ServiceProviderConfig', (req, res) => {
    res.json({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
      patch: { supported: true },
      bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
      filter: { supported: true, maxResults: 200 },
      changePassword: { supported: false },
      sort: { supported: false },
      etag: { supported: false },
      authenticationSchemes: [{
        type: 'oauthbearertoken',
        name: 'Bearer token',
        description: 'Static customer-silo SCIM bearer token',
        specUri: 'https://www.rfc-editor.org/rfc/rfc7644',
      }],
    });
  });

  r.get('/Users', (req, res) => {
    const rows = filterEq(req, db.listScimUsers(), ['userName', 'externalId']);
    const groups = db.listScimGroups();
    res.json(listResponse(req, rows, (rq, user) => userResource(rq, user, groups)));
  });

  r.post('/Users', (req, res) => {
    const user = normalizeUserBody(req.body || {});
    if (!user) return res.status(400).json(scimError(400, 'userName is required', 'invalidValue'));
    if (rejectUserNameCollision(res, user)) return;
    const outcome = saveOrConflict(res, 'userName already exists', () => db.mutateWithAudit(
      () => db.saveScimUser(user),
      (saved) => ({ action: 'SCIM_USER_UPSERTED', actor: 'scim', detail: userAuditDetail(saved) }),
    ));
    if (!outcome) return;
    const saved = outcome.result;
    res.status(201).json(userResource(req, saved));
  });

  r.get('/Users/:id', (req, res) => {
    const user = db.getScimUser(req.params.id);
    if (!user) return res.status(404).json(scimError(404, 'user not found'));
    res.json(userResource(req, user));
  });

  r.put('/Users/:id', (req, res) => {
    const existing = db.getScimUser(req.params.id);
    if (!existing) return res.status(404).json(scimError(404, 'user not found'));
    const user = normalizeUserBody(req.body || {}, existing, { replace: true });
    if (!user) return res.status(400).json(scimError(400, 'userName is required', 'invalidValue'));
    if (rejectUserNameCollision(res, user, existing)) return;
    const outcome = saveOrConflict(res, 'userName already exists', () => db.mutateWithAudit(
      () => db.saveScimUser(user),
      (saved) => ({ action: 'SCIM_USER_UPSERTED', actor: 'scim', detail: userAuditDetail(saved) }),
    ));
    if (!outcome) return;
    const saved = outcome.result;
    res.json(userResource(req, saved));
  });

  r.patch('/Users/:id', (req, res) => {
    const existing = db.getScimUser(req.params.id);
    if (!existing) return res.status(404).json(scimError(404, 'user not found'));
    const user = applyUserPatch(existing, patchOperations(req.body));
    if (rejectUserNameCollision(res, user, existing)) return;
    const outcome = saveOrConflict(res, 'userName already exists', () => db.mutateWithAudit(
      () => db.saveScimUser(user),
      (saved) => ({ action: 'SCIM_USER_PATCHED', actor: 'scim', detail: userAuditDetail(saved) }),
    ));
    if (!outcome) return;
    const saved = outcome.result;
    res.json(userResource(req, saved));
  });

  r.delete('/Users/:id', (req, res) => {
    const { result: saved } = db.mutateWithAudit(
      () => db.deactivateScimUser(req.params.id),
      (deactivated) => ({ action: 'SCIM_USER_DEACTIVATED', actor: 'scim', detail: userAuditDetail(deactivated) }),
    );
    if (!saved) return res.status(404).json(scimError(404, 'user not found'));
    res.status(204).end();
  });

  r.get('/Groups', (req, res) => {
    const rows = filterEq(req, db.listScimGroups(), ['displayName', 'externalId']);
    res.json(listResponse(req, rows, groupResource));
  });

  r.post('/Groups', (req, res) => {
    const group = normalizeGroupBody(req.body || {});
    if (!group) return res.status(400).json(scimError(400, 'displayName is required', 'invalidValue'));
    if (db.getScimGroupByDisplayName(group.displayName)) return res.status(409).json(conflict('displayName already exists'));
    const outcome = saveOrConflict(res, 'displayName already exists', () => db.mutateWithAudit(
      () => db.saveScimGroup(group),
      (saved) => ({ action: 'SCIM_GROUP_UPSERTED', actor: 'scim', detail: groupAuditDetail(saved) }),
    ));
    if (!outcome) return;
    const saved = outcome.result;
    res.status(201).json(groupResource(req, saved));
  });

  r.get('/Groups/:id', (req, res) => {
    const group = db.getScimGroup(req.params.id);
    if (!group) return res.status(404).json(scimError(404, 'group not found'));
    res.json(groupResource(req, group));
  });

  r.put('/Groups/:id', (req, res) => {
    const existing = db.getScimGroup(req.params.id);
    if (!existing) return res.status(404).json(scimError(404, 'group not found'));
    const group = normalizeGroupBody(req.body || {}, existing, { replace: true });
    if (!group) return res.status(400).json(scimError(400, 'displayName is required', 'invalidValue'));
    const outcome = saveOrConflict(res, 'displayName already exists', () => db.mutateWithAudit(
      () => db.saveScimGroup(group),
      (saved) => ({ action: 'SCIM_GROUP_UPSERTED', actor: 'scim', detail: groupAuditDetail(saved) }),
    ));
    if (!outcome) return;
    const saved = outcome.result;
    res.json(groupResource(req, saved));
  });

  r.patch('/Groups/:id', (req, res) => {
    const existing = db.getScimGroup(req.params.id);
    if (!existing) return res.status(404).json(scimError(404, 'group not found'));
    const outcome = saveOrConflict(res, 'displayName already exists', () => db.mutateWithAudit(
      () => db.saveScimGroup(applyGroupPatch(existing, patchOperations(req.body))),
      (saved) => ({ action: 'SCIM_GROUP_PATCHED', actor: 'scim', detail: groupAuditDetail(saved) }),
    ));
    if (!outcome) return;
    const saved = outcome.result;
    res.json(groupResource(req, saved));
  });

  r.delete('/Groups/:id', (req, res) => {
    const { result: deleted } = db.mutateWithAudit(
      () => db.deleteScimGroup(req.params.id),
      (removed) => ({ action: 'SCIM_GROUP_DELETED', actor: 'scim', detail: groupAuditDetail(removed) }),
    );
    if (!deleted) return res.status(404).json(scimError(404, 'group not found'));
    res.status(204).end();
  });

  return r;
}

module.exports = {
  router,
  requireScimBearer,
  scimError,
  effectiveUserRole,
  roleFromDisplayName,
  USER_SCHEMA,
  GROUP_SCHEMA,
  LIST_SCHEMA,
  PATCH_SCHEMA,
  _internal: {
    rejectUserNameCollision,
    saveOrConflict,
  },
};
