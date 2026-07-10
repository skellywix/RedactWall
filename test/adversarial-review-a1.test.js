'use strict';
/**
 * A1 — a SCIM role DOWNGRADE on a still-active user must revoke live sessions.
 * Before the fix, revocation was written only on active->inactive, so a demoted
 * security_admin kept releasing PII for the full session TTL. Isolated db path.
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-a1-'));
process.env.REDACTWALL_DB_PATH = path.join(tempRoot, 'a1.db');
process.env.REDACTWALL_SECRET = 'unit-secret-a1';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-a1';
const db = require('../server/db');

test('A1: a SCIM role downgrade on an active user revokes live sessions', () => {
  const issuedAt = Date.now();
  const u = db.saveScimUser({ userName: 'admin@cu.example', role: 'security_admin', active: true, emails: [{ value: 'admin@cu.example' }] });
  assert.strictEqual(db.identityRevokedSince('admin@cu.example', issuedAt - 1000), false, 'not revoked before demotion');
  db.saveScimUser({ ...u, role: 'auditor' });
  assert.strictEqual(db.identityRevokedSince('admin@cu.example', issuedAt - 1000), true, 'demotion revokes the pre-demotion session');
});

test('A1: an unchanged-role save does NOT revoke (no needless logout)', () => {
  const issuedAt = Date.now();
  const stable = db.saveScimUser({ userName: 'stable@cu.example', role: 'auditor', active: true, emails: [{ value: 'stable@cu.example' }] });
  db.saveScimUser({ ...stable });
  assert.strictEqual(db.identityRevokedSince('stable@cu.example', issuedAt - 1000), false, 'unchanged role leaves sessions intact');
});
