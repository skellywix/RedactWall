'use strict';
/**
 * Exercises the full db.js contract against whatever driver the environment
 * selects, printing one JSON result blob. Run in a child process so the
 * db singleton binds to the Postgres driver via REDACTWALL_DB_DRIVER.
 */
const crypto = require('node:crypto');
const results = {};

function attempt(name, fn) {
  try {
    results[name] = { ok: true, value: fn() };
  } catch (err) {
    results[name] = { ok: false, error: err.message, code: err.code };
  }
}

const db = require('../../server/db');

attempt('driverKind', () => db._driverKind);
attempt('migrations', () => db._db.prepare('SELECT version, name FROM schema_migrations ORDER BY version').all());

attempt('queryCrud', () => {
  const created = db.createQueryWithAudit({
    status: 'pending', user: 'pg@example.test', orgId: 'cu-alpha',
    destination: 'chatgpt.com', redactedPrompt: 'Member [US_SSN]', riskScore: 42,
  }, { action: 'PG_QUERY_CREATED', actor: 'battery', detail: 'query fixture created' }).row;
  const fetched = db.getQuery(created.id);
  const updated = db.mutateQueryWithAudit(
    created.id,
    () => ({ status: 'approved', decisionNote: 'ok' }),
    { action: 'PG_QUERY_UPDATED', actor: 'battery', detail: 'query fixture updated' },
  ).row;
  return { id: created.id, fetchedStatus: fetched.status, updatedStatus: updated.status, risk: fetched.riskScore };
});

attempt('decisionCas', () => {
  const held = db.createQueryWithAudit({
    status: 'pending', user: 'decision@pg.test', orgId: 'cu-alpha', destination: 'chatgpt.com',
  }, { action: 'PG_DECISION_CREATED', actor: 'battery', detail: 'decision fixture created' }).row;
  const expected = {
    status: held.status,
    assignedUser: held.assignedUser,
    assignedGroup: held.assignedGroup,
    assignedRole: held.assignedRole,
    _releaseTokenHash: held._releaseTokenHash,
  };
  const winner = db.transitionQueryWithAudit(
    held.id,
    expected,
    { status: 'approved', decidedBy: 'instance-a', decidedAt: new Date().toISOString() },
    { action: 'APPROVED', actor: 'instance-a', detail: 'winner' },
  );
  const loser = db.transitionQueryWithAudit(
    held.id,
    expected,
    { status: 'denied', decidedBy: 'instance-b', decidedAt: new Date().toISOString() },
    { action: 'DENIED', actor: 'instance-b', detail: 'loser' },
  );
  const audits = db.listAudit(500).filter((entry) => entry.queryId === held.id && ['APPROVED', 'DENIED'].includes(entry.action));
  return {
    winner: winner.outcome,
    loser: loser.outcome,
    finalStatus: db.getQuery(held.id).status,
    auditActions: audits.map((entry) => entry.action),
    chainOk: db.verifyAuditChain().ok,
  };
});

attempt('auditChain', () => {
  db.appendAudit({ action: 'PG_TEST', actor: 'battery', detail: 'first' });
  db.appendAudit({ action: 'PG_TEST', actor: 'battery', detail: 'second' });
  return db.verifyAuditChain();
});

attempt('vendorHeartbeatCas', () => {
  const customerId = 'cu-pg-vendor';
  const customerRef = 'license_' + crypto.createHash('sha256').update(customerId).digest('base64url').slice(0, 24);
  const record = (issuedAt, status) => {
    const state = { customerId, issuedAt, contactAt: issuedAt, status };
    return {
      ...state,
      customerRef,
      audits: [{
        action: 'VENDOR_HEARTBEAT_OK', actor: 'vendor',
        detail: JSON.stringify({ customerRef, issuedAt, contactAt: issuedAt, status }),
      }],
    };
  };
  const newer = db.applyVendorHeartbeat(record(3000, 'revoked'));
  const older = db.applyVendorHeartbeat(record(2000, 'active'));
  return {
    newerApplied: newer.applied,
    olderApplied: older.applied,
    status: db.lastVendorHeartbeat(customerId, customerRef).status,
    issuedAt: db.lastVendorHeartbeat(customerId, customerRef).issuedAt,
    chainOk: db.verifyAuditChain().ok,
  };
});

attempt('auditImmutable', () => {
  const entry = db.listAudit(1)[0];
  try {
    db._db.prepare('UPDATE audit SET actor = ? WHERE id = ?').run('tampered', entry.id);
    return { blocked: false };
  } catch (err) {
    return { blocked: /append-only/.test(err.message) };
  }
});

attempt('tenantScoping', () => {
  db.createQueryWithAudit(
    { status: 'allowed', user: 'a@alpha.test', orgId: 'cu-alpha', destination: 'chatgpt.com' },
    { action: 'PG_TENANT_CREATED', actor: 'battery', detail: 'alpha fixture created' },
  );
  db.createQueryWithAudit(
    { status: 'allowed', user: 'b@beta.test', orgId: 'cu-beta', destination: 'claude.ai' },
    { action: 'PG_TENANT_CREATED', actor: 'battery', detail: 'beta fixture created' },
  );
  const alpha = db.listQueries({ orgId: 'cu-alpha', limit: 100 });
  const beta = db.listQueries({ orgId: 'CU-BETA', limit: 100 });
  return {
    alphaOnly: alpha.every((q) => q.orgId === 'cu-alpha') && alpha.length >= 2,
    betaOnly: beta.every((q) => q.orgId === 'cu-beta') && beta.length === 1,
  };
});

attempt('rowLevelSecurity', () => {
  if (db._driverKind !== 'postgres') return { skipped: true };
  db.setTenantContext('cu-beta');
  const visible = db.listQueries({ limit: 100 });
  const betaOnly = visible.length >= 1 && visible.every((q) => q.orgId === 'cu-beta');
  let crossTenantInsertBlocked = false;
  try {
    db.createQuery({ status: 'allowed', user: 'x@alpha.test', orgId: 'cu-alpha' });
  } catch (err) {
    crossTenantInsertBlocked = /row-level security/.test(err.message);
  }
  db.setTenantContext('');
  const allVisible = db.listQueries({ limit: 100 }).length > visible.length;
  return { betaOnly, crossTenantInsertBlocked, allVisible };
});

attempt('transactionsNest', () => {
  const before = db.listAudit(500).length;
  try {
    db._db.transaction(() => {
      db.appendAudit({ action: 'PG_TX', actor: 'battery', detail: 'inner nests' });
      throw new Error('rollback outer');
    })();
  } catch { /* expected */ }
  const after = db.listAudit(500).length;
  return { rolledBack: before === after, chainOk: db.verifyAuditChain().ok };
});

attempt('scimAndLifecycle', () => {
  const saved = db.saveScimUser({ userName: 'pg-user@example.test', active: true });
  db.deactivateScimUser(saved.id);
  return {
    inactive: db.scimIdentityInactive('pg-user@example.test'),
    revoked: db.identityRevokedSince('pg-user@example.test', Date.now() - 1000),
  };
});

attempt('deliveriesAndApps', () => {
  db.recordDelivery({ destId: 'splunk-1', dedupeKey: 'k1', status: 'delivered' });
  db.upsertAiApp('chatgpt.com', { appName: 'ChatGPT' }, new Date().toISOString());
  return {
    delivered: db.recentDeliverySuccess('splunk-1', 'k1', null),
    app: !!db.getAiApp('chatgpt.com'),
  };
});

attempt('useCases', () => {
  // Exercises the quoted camelCase columns (reviewStatus/nextReviewAt) and
  // the (canonicalHost, department) upsert key on the Postgres dialect.
  const now = new Date().toISOString();
  const a = db.upsertAiUseCase({ canonicalHost: 'chatgpt.com', department: 'Lending', owner: 'pg-owner', nextReviewAt: '2027-01-01T00:00:00Z' }, now);
  db.upsertAiUseCase({ canonicalHost: 'chatgpt.com', department: 'Marketing' }, now);
  db.upsertAiUseCase({ canonicalHost: 'chatgpt.com', department: 'lending ' }, now); // same key as a
  const reviewed = db.reviewAiUseCase(a.id, { reviewStatus: 'approved', vendorStatus: 'reviewed' }, now);
  const rows = db.listAiUseCases();
  return {
    rows: rows.length,
    reviewed: reviewed.reviewStatus === 'approved',
    ownerKept: rows.some((r) => r.owner === 'pg-owner'),
    unknownIsNull: db.reviewAiUseCase('uc_missing', { reviewStatus: 'retired' }, now) === null,
  };
});

attempt('incidents', () => {
  // Exercises the quoted detectedAt/deadlineAt/reportedAt columns on Postgres.
  const now = new Date().toISOString();
  const inc = db.createAiIncident({ title: 'pg incident', queryIds: [], detectedAt: now, deadlineAt: now, orgId: 'PG-Org ' }, now);
  const moved = db.setAiIncidentStatus(inc.id, { status: 'reported', reportedAt: now }, now);
  return {
    created: !!inc.id,
    orgNormalized: inc.orgId === 'pg-org',
    reported: moved.status === 'reported',
    listed: db.listAiIncidents().length === 1,
    unknownIsNull: db.setAiIncidentStatus('inc_missing', { status: 'closed' }, now) === null,
  };
});

attempt('statsAndSeats', () => {
  const s = db.stats();
  const seats = db.seatStats({});
  return { total: s.total >= 3, seatUsers: seats.seatsUsed >= 2 };
});

attempt('seatWindow', () => {
  // The trailing-30-day seat window must filter on the Postgres dialect too:
  // an old-dated row falls outside the window, a recent one counts, and the
  // org-filtered two-parameter path (cutoff + org) binds correctly.
  const old = new Date(Date.now() - 60 * 86400000).toISOString();
  const recent = new Date(Date.now() - 1 * 86400000).toISOString();
  db._db.prepare('INSERT INTO queries (id, "createdAt", status, "user", "orgId", data) VALUES (?,?,?,?,?,?)')
    .run('pg_seatwin_old', old, 'allowed', 'lapsed@pg.test', 'cu-seatwin', '{}');
  db.appendAudit({ action: 'PG_SEAT_WINDOW_CREATED', queryId: 'pg_seatwin_old', actor: 'battery', detail: 'old seat fixture created' });
  db._db.prepare('INSERT INTO queries (id, "createdAt", status, "user", "orgId", data) VALUES (?,?,?,?,?,?)')
    .run('pg_seatwin_new', recent, 'allowed', 'active@pg.test', 'cu-seatwin', '{}');
  db.appendAudit({ action: 'PG_SEAT_WINDOW_CREATED', queryId: 'pg_seatwin_new', actor: 'battery', detail: 'recent seat fixture created' });
  const windowed = db.seatStats({ orgId: 'cu-seatwin' }).seatsUsed;
  process.env.REDACTWALL_SEAT_WINDOW_DAYS = 'all';
  let lifetime;
  try { lifetime = db.seatStats({ orgId: 'cu-seatwin' }).seatsUsed; } finally { delete process.env.REDACTWALL_SEAT_WINDOW_DAYS; }
  return { windowed, lifetime };
});

attempt('mfaRecovery', () => {
  const first = db.consumeMfaRecoveryCode(3);
  const second = db.consumeMfaRecoveryCode(3);
  return { first, second, used: db.mfaRecoveryCodeUsed(3) };
});

attempt('administration', () => {
  const user = db.saveAdminUser({ orgId: 'pg-admin', userName: 'admin-pg@example.test', displayName: 'PG Admin', role: 'security_admin', active: true });
  const invite = db.saveAdminInvitation({
    orgId: 'pg-admin',
    userName: 'invite-pg@example.test',
    displayName: 'Invite PG',
    role: 'auditor',
    tokenHash: 'pg-token-hash',
    status: 'pending',
    expiresAt: '2027-01-01T00:00:00.000Z',
  });
  const seat = db.saveLicenseSeatAssignment({
    orgId: 'pg-admin',
    userKey: 'admin-pg@example.test',
    userName: 'admin-pg@example.test',
    status: 'released',
    reason: 'pg battery',
    actor: 'battery',
  });
  const renewal = db.createLicenseRenewalRequest({
    orgId: 'pg-admin',
    requestedSeats: 25,
    contactEmail: 'admin-pg@example.test',
    note: 'pg battery',
  });
  return {
    user: !!db.getAdminUser(user.id),
    invite: !!db.getAdminInvitation(invite.id),
    seat: db.getLicenseSeatAssignment(seat.userKey).status === 'released',
    renewal: db.listLicenseRenewalRequests().some((row) => row.id === renewal.id),
  };
});

process.stdout.write(JSON.stringify(results));
