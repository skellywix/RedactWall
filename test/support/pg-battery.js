'use strict';
/**
 * Exercises the full db.js contract against whatever driver the environment
 * selects, printing one JSON result blob. Run in a child process so the
 * db singleton binds to the Postgres driver via REDACTWALL_DB_DRIVER.
 */
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
  const created = db.createQuery({
    status: 'pending', user: 'pg@example.test', orgId: 'cu-alpha',
    destination: 'chatgpt.com', redactedPrompt: 'Member [US_SSN]', riskScore: 42,
  });
  const fetched = db.getQuery(created.id);
  const updated = db.updateQuery(created.id, { status: 'approved', decisionNote: 'ok' });
  return { id: created.id, fetchedStatus: fetched.status, updatedStatus: updated.status, risk: fetched.riskScore };
});

attempt('auditChain', () => {
  db.appendAudit({ action: 'PG_TEST', actor: 'battery', detail: 'first' });
  db.appendAudit({ action: 'PG_TEST', actor: 'battery', detail: 'second' });
  return db.verifyAuditChain();
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
  db.createQuery({ status: 'allowed', user: 'a@alpha.test', orgId: 'cu-alpha', destination: 'chatgpt.com' });
  db.createQuery({ status: 'allowed', user: 'b@beta.test', orgId: 'cu-beta', destination: 'claude.ai' });
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
  db._db.prepare('INSERT INTO queries (id, "createdAt", status, "user", "orgId", data) VALUES (?,?,?,?,?,?)')
    .run('pg_seatwin_new', recent, 'allowed', 'active@pg.test', 'cu-seatwin', '{}');
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

process.stdout.write(JSON.stringify(results));
