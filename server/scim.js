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
const roles = require('./roles');

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

function groupMembersForUser(userId) {
  return db.listScimGroups()
    .filter((group) => (group.members || []).some((member) => member.value === userId))
    .map((group) => ({ value: group.id, display: group.displayName }));
}

function effectiveUserRole(user) {
  const direct = roles.normalizeRole(user.role);
  if (direct) return direct;
  for (const group of groupMembersForUser(user.id)) {
    const role = roleFromDisplayName(group.display);
    if (role) return role;
  }
  return roles.AUDITOR;
}

function userResource(req, user) {
  const groupRefs = groupMembersForUser(user.id);
  const role = effectiveUserRole(user);
  return {
    schemas: [USER_SCHEMA],
    id: user.id,
    externalId: user.externalId || undefined,
    userName: user.userName,
    displayName: user.displayName || user.userName,
    active: user.active !== false,
    groups: groupRefs,
    roles: [{ value: role, display: role, primary: true }],
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

function normalizeUserBody(body = {}, existing = {}) {
  const userName = cleanString(body.userName || existing.userName, 256);
  if (!userName) return null;
  return {
    id: existing.id,
    externalId: cleanString(body.externalId || existing.externalId, 256) || undefined,
    userName,
    displayName: cleanString(body.displayName || existing.displayName || userName, 256),
    active: body.active !== undefined ? !!body.active : existing.active !== false,
    role: roleFromScimRoles(body.roles) || roles.normalizeRole(body.role) || existing.role || '',
  };
}

function normalizeGroupBody(body = {}, existing = {}) {
  const displayName = cleanString(body.displayName || existing.displayName, 256);
  if (!displayName) return null;
  return {
    id: existing.id,
    externalId: cleanString(body.externalId || existing.externalId, 256) || undefined,
    displayName,
    members: body.members ? normalizeMembers(body.members) : (existing.members || []),
  };
}

function applyUserPatch(user, operations = []) {
  const next = { ...user };
  for (const op of operations) {
    const path = cleanString(op.path || '', 80).toLowerCase();
    const kind = cleanString(op.op || 'replace', 20).toLowerCase();
    if ((kind === 'replace' || kind === 'add') && !path && op.value && typeof op.value === 'object' && !Array.isArray(op.value)) {
      if (Object.prototype.hasOwnProperty.call(op.value, 'active')) next.active = !!op.value.active;
      if (op.value.displayName) next.displayName = cleanString(op.value.displayName, 256) || next.displayName;
      if (op.value.roles) next.role = roleFromScimRoles(op.value.roles) || next.role;
      continue;
    }
    if ((kind === 'replace' || kind === 'add') && path === 'active') next.active = !!op.value;
    if ((kind === 'replace' || kind === 'add') && path === 'displayname') next.displayName = cleanString(op.value, 256) || next.displayName;
    if ((kind === 'replace' || kind === 'add') && path === 'roles') next.role = roleFromScimRoles(op.value) || next.role;
  }
  return next;
}

function memberValueFromPatch(path, value) {
  const direct = cleanString(value && (value.value || value), 128);
  if (direct) return direct;
  const match = String(path || '').match(/^members\s*\[\s*value\s+eq\s+"([^"]{1,128})"\s*\]$/i);
  return match ? cleanString(match[1], 128) : '';
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
      if (op.value.members) {
        const byValue = new Map(members.map((member) => [member.value, member]));
        for (const member of normalizeMembers(op.value.members)) byValue.set(member.value, member);
        members = Array.from(byValue.values());
      }
      continue;
    }
    if ((kind === 'replace' || kind === 'add') && path === 'displayname') next.displayName = cleanString(op.value, 256) || next.displayName;
    if ((kind === 'replace' || kind === 'add') && (!path || path === 'members')) {
      const incoming = normalizeMembers(op.value);
      const byValue = new Map(members.map((member) => [member.value, member]));
      for (const member of incoming) byValue.set(member.value, member);
      members = Array.from(byValue.values());
    }
    if (kind === 'remove' && path.startsWith('members')) {
      const value = memberValueFromPatch(rawPath, op.value);
      if (value) members = members.filter((member) => member.value !== value);
      else members = [];
    }
  }
  next.members = members;
  return next;
}

function patchOperations(body = {}) {
  return Array.isArray(body.Operations) ? body.Operations : [];
}

function audit(action, actor, detail) {
  db.appendAudit({ action, actor: actor || 'scim', detail: cleanString(detail, 512) });
}

function conflict(detail) {
  return scimError(409, detail, 'uniqueness');
}

function saveOrConflict(res, detail, fn) {
  try {
    return fn();
  } catch (err) {
    if (err && (err.code === 'SQLITE_CONSTRAINT_UNIQUE' || /UNIQUE constraint failed/i.test(err.message || ''))) {
      res.status(409).json(conflict(detail));
      return null;
    }
    throw err;
  }
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
    res.json(listResponse(req, rows, userResource));
  });

  r.post('/Users', (req, res) => {
    const user = normalizeUserBody(req.body || {});
    if (!user) return res.status(400).json(scimError(400, 'userName is required', 'invalidValue'));
    if (db.getScimUserByUserName(user.userName)) return res.status(409).json(conflict('userName already exists'));
    const saved = saveOrConflict(res, 'userName already exists', () => db.saveScimUser(user));
    if (!saved) return;
    audit('SCIM_USER_UPSERTED', 'scim', `user=${saved.userName}; active=${saved.active}`);
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
    const user = normalizeUserBody(req.body || {}, existing);
    if (!user) return res.status(400).json(scimError(400, 'userName is required', 'invalidValue'));
    const saved = saveOrConflict(res, 'userName already exists', () => db.saveScimUser(user));
    if (!saved) return;
    audit('SCIM_USER_UPSERTED', 'scim', `user=${saved.userName}; active=${saved.active}`);
    res.json(userResource(req, saved));
  });

  r.patch('/Users/:id', (req, res) => {
    const existing = db.getScimUser(req.params.id);
    if (!existing) return res.status(404).json(scimError(404, 'user not found'));
    const saved = saveOrConflict(res, 'userName already exists', () => db.saveScimUser(applyUserPatch(existing, patchOperations(req.body))));
    if (!saved) return;
    audit('SCIM_USER_PATCHED', 'scim', `user=${saved.userName}; active=${saved.active}`);
    res.json(userResource(req, saved));
  });

  r.delete('/Users/:id', (req, res) => {
    const saved = db.deactivateScimUser(req.params.id);
    if (!saved) return res.status(404).json(scimError(404, 'user not found'));
    audit('SCIM_USER_DEACTIVATED', 'scim', `user=${saved.userName}`);
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
    const saved = saveOrConflict(res, 'displayName already exists', () => db.saveScimGroup(group));
    if (!saved) return;
    audit('SCIM_GROUP_UPSERTED', 'scim', `group=${saved.displayName}; members=${saved.members.length}`);
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
    const group = normalizeGroupBody(req.body || {}, existing);
    if (!group) return res.status(400).json(scimError(400, 'displayName is required', 'invalidValue'));
    const saved = saveOrConflict(res, 'displayName already exists', () => db.saveScimGroup(group));
    if (!saved) return;
    audit('SCIM_GROUP_UPSERTED', 'scim', `group=${saved.displayName}; members=${saved.members.length}`);
    res.json(groupResource(req, saved));
  });

  r.patch('/Groups/:id', (req, res) => {
    const existing = db.getScimGroup(req.params.id);
    if (!existing) return res.status(404).json(scimError(404, 'group not found'));
    const saved = saveOrConflict(res, 'displayName already exists', () => db.saveScimGroup(applyGroupPatch(existing, patchOperations(req.body))));
    if (!saved) return;
    audit('SCIM_GROUP_PATCHED', 'scim', `group=${saved.displayName}; members=${saved.members.length}`);
    res.json(groupResource(req, saved));
  });

  r.delete('/Groups/:id', (req, res) => {
    const deleted = db.deleteScimGroup(req.params.id);
    if (!deleted) return res.status(404).json(scimError(404, 'group not found'));
    audit('SCIM_GROUP_DELETED', 'scim', `group=${deleted.displayName}`);
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
    saveOrConflict,
  },
};
