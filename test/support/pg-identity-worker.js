'use strict';

const db = require('../../server/db');

const methods = {
  saveAdmin: (payload) => db.saveAdminUser(payload),
  saveScim: (payload) => db.saveScimUser(payload),
  getAdmin: (id) => db.getAdminUser(id),
  getAdminByUserName: (userName) => db.getAdminUserByUserName(userName),
  saveGroup: (payload) => db.saveScimGroup(payload),
  getGroup: (id) => db.getScimGroup(id),
  deleteGroup: (id) => db.deleteScimGroup(id),
  saveInvite: (payload) => db.saveAdminInvitation(payload),
  getInvite: (id) => db.getAdminInvitation(id),
  acceptInvite: (payload) => db.acceptAdminInvitation(
    payload.tokenHash,
    payload.passwordRecord || {},
    payload.displayName,
  ),
  acceptInviteWithAudit: (payload) => db.mutateWithAudit(
    () => db.acceptAdminInvitation(
      payload.tokenHash,
      payload.passwordRecord || {},
      payload.displayName,
    ),
    (accepted) => ({
      action: 'ADMIN_USER_INVITE_ACCEPTED',
      actor: `local:${accepted.user.id}`,
      detail: `invitation=${accepted.invitation.id}`,
    }),
  ).result,
  saveInviteWithAudit: (payload) => db.mutateWithAudit(
    () => db.saveAdminInvitation(payload.record),
    (saved) => ({ action: payload.action, actor: 'postgres-race-test', detail: `invitation=${saved.id}` }),
  ).result,
  listAuditActions: () => db.listAudit(100).map((entry) => entry.action),
  verifyAudit: () => db.verifyAuditChain(),
  applyVendorHeartbeat: (payload) => db.applyVendorHeartbeat(payload),
  lastVendorHeartbeat: (payload) => db.lastVendorHeartbeat(payload.customerId, payload.customerRef),
  vendorHeartbeatEvidence: () => db.listAudit(500)
    .filter((entry) => entry.action === 'VENDOR_HEARTBEAT_OK')
    .map((entry) => JSON.parse(entry.detail).issuedAt),
  createIdempotentIngest: (payload) => db.createQueryWithAudit(
    payload.query,
    payload.audit,
    { idempotency: payload.idempotency },
  ),
  deleteIdempotentMapping: (payload) => db._db.prepare(
    'DELETE FROM ingest_idempotency WHERE scope = ? AND orgId = ? AND keyHash = ?',
  ).run(payload.idempotency.scope, payload.orgId, payload.idempotency.key),
  idempotentIngestEvidence: (payload) => {
    const row = db.getIdempotentIngestQuery({ ...payload.idempotency, orgId: payload.orgId });
    const queries = db.listQueries({ all: true, orgId: payload.orgId })
      .filter((query) => query.user === payload.user);
    const audits = row ? db.listAudit(1000).filter((entry) => entry.queryId === row.id) : [];
    const mapping = db._db.prepare(
      'SELECT COUNT(*) AS n FROM ingest_idempotency WHERE scope = ? AND orgId = ? AND keyHash = ?',
    ).get(payload.idempotency.scope, payload.orgId, payload.idempotency.key);
    return {
      row,
      queryIds: queries.map((query) => query.id),
      auditActions: audits.map((entry) => entry.action),
      mappings: Number(mapping && mapping.n || 0),
    };
  },
};

process.on('message', async ({ id, method, payload }) => {
  try {
    if (method === 'close') {
      db._db.close();
      if (process.send) process.send({ id, ok: true });
      setImmediate(() => process.exit(0));
      return;
    }
    if (!Object.hasOwn(methods, method)) throw new Error(`unsupported worker method: ${method}`);
    const value = await methods[method](payload);
    if (process.send) process.send({ id, ok: true, value });
  } catch (error) {
    if (process.send) {
      process.send({ id, ok: false, code: error.code || '', message: error.message || String(error) });
    }
  }
});

if (process.send) process.send({ ready: true });
