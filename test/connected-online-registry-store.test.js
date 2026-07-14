'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const registryState = require('../server/connected-online-registry-state');
const onlineVerdict = require('../server/connected-online-verdict');
const protocol = require('../server/vendor-control-protocol');
const { createConnectedOnlineRegistryStore } = require('../server/connected-online-registry-store');

const CUSTOMER_ID = 'customer_alpha';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
const NOW = Date.parse('2026-07-12T12:00:00.000Z');
const REFERENCE_KEY = Buffer.alloc(32, 31);
const AUDIT_KEY = Buffer.alloc(32, 32);
const keys = crypto.generateKeyPairSync('ed25519');
const wrongKeys = crypto.generateKeyPairSync('ed25519');
const KEY_ID = onlineVerdict.keyIdForPublicKey(keys.publicKey);

function payload(overrides = {}) {
  return {
    kind: registryState.VERDICT_DOMAIN,
    keyId: KEY_ID,
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    issuedAt: new Date(NOW).toISOString(),
    registryGeneration: 7,
    registryStateDigest: 'a'.repeat(64),
    ...overrides,
  };
}

function signedVerdict(value = payload(), privateKey = keys.privateKey) {
  const payloadB64 = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  const input = Buffer.from(`${registryState.VERDICT_DOMAIN}\0${payloadB64}`, 'utf8');
  const signature = crypto.sign(null, input, privateKey).toString('base64');
  return `${payloadB64}.${signature}`;
}

function verifyVerdict(value) {
  return onlineVerdict.verifySignedOnlineVerdict(value, new Map([[KEY_ID, keys.publicKey]]));
}

function tamperSignedVerdict(value, changes) {
  const [payloadB64, signature] = value.split('.');
  const changed = { ...JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8')), ...changes };
  return `${Buffer.from(JSON.stringify(changed), 'utf8').toString('base64')}.${signature}`;
}

function harness(customerId = CUSTOMER_ID, deploymentId = DEPLOYMENT_ID, receivers = null) {
  const db = new Database(':memory:');
  db.exec(`
    CREATE TABLE audit (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      connected_authority_ref TEXT GENERATED ALWAYS AS (
        json_extract(entry, '$.connectedAuthorityRef')
      ) VIRTUAL,
      connected_entry_action TEXT GENERATED ALWAYS AS (
        json_extract(entry, '$.action')
      ) VIRTUAL,
      entry TEXT NOT NULL
    );
    CREATE TABLE connected_online_registry_state (
      customer_id TEXT NOT NULL,
      deployment_id TEXT NOT NULL,
      authority_ref TEXT NOT NULL,
      registry_generation INTEGER NOT NULL,
      registry_state_digest TEXT NOT NULL,
      status TEXT NOT NULL,
      state_json TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (customer_id, deployment_id)
    );
  `);
  let auditHealthy = true;
  const appendAudit = (event) => {
    const body = {
      action: event.action,
      actor: event.actor,
      connectedAuthorityRef: event.connectedAuthorityRef,
      detail: event.detail,
    };
    const entry = { ...body, mac: auditMac(body) };
    db.prepare('INSERT INTO audit (action, entry) VALUES (?, ?)')
      .run(event.action, JSON.stringify(entry));
    return entry;
  };
  const store = createConnectedOnlineRegistryStore({
    customerId,
    deploymentId,
    driver: db,
    appendAudit: observedCallback('appendAudit', appendAudit, receivers),
    registryReference: observedCallback('registryReference', (boundCustomer, boundDeployment) => `connected_registry_${crypto
      .createHmac('sha256', REFERENCE_KEY)
      .update(`${boundCustomer}\0${boundDeployment}`, 'utf8').digest('base64url').slice(0, 32)}`, receivers),
    verifyAuditState: observedCallback('verifyAuditState', () => ({ ok: auditHealthy }), receivers),
    verifyAuditEntry: observedCallback('verifyAuditEntry', (entry) => {
      if (!entry || typeof entry !== 'object') return false;
      const { mac, ...body } = entry;
      return typeof mac === 'string'
        && crypto.timingSafeEqual(Buffer.from(mac, 'hex'), Buffer.from(auditMac(body), 'hex'));
    }, receivers),
    verifyVerdict: observedCallback('verifyVerdict', verifyVerdict, receivers),
  });
  return { db, store, setAuditHealthy(value) { auditHealthy = value; } };
}

function observedCallback(name, callback, receivers) {
  if (!receivers) return callback;
  return function observed(...args) {
    receivers.push([name, this]);
    return Reflect.apply(callback, undefined, args);
  };
}

function apply(store, value = signedVerdict(), nowMs = NOW) {
  return store.applyVerdict({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedVerdict: value,
    nowMs,
  });
}

test('verified verdict, registry high-water, and audit anchor commit together', () => {
  const env = harness();
  const result = apply(env.store);
  assert.equal(result.state.registryGeneration, 7);
  assert.equal(result.state.signingKeyId, KEY_ID);
  assert.equal(env.store.registryGeneration(CUSTOMER_ID, DEPLOYMENT_ID), 7);
  assert.equal(env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID).registryStateDigest, 'a'.repeat(64));
  assert.deepEqual(env.db.prepare('SELECT action FROM audit').all(), [
    { action: 'CONNECTED_REGISTRY_VERDICT_APPLIED' },
  ]);
});

test('store option callbacks never receive the registry context as receiver', () => {
  const receivers = [];
  const env = harness(CUSTOMER_ID, DEPLOYMENT_ID, receivers);
  apply(env.store);
  env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID);
  assert.deepEqual(new Set(receivers.map(([name]) => name)), new Set([
    'appendAudit', 'registryReference', 'verifyAuditState', 'verifyAuditEntry', 'verifyVerdict',
  ]));
  assert.equal(receivers.every(([, receiver]) => receiver === undefined), true);
});

test('unsigned, wrong-key, mutated, stale, and scope-confused verdicts create no authority', () => {
  const env = harness();
  assert.throws(() => apply(env.store, payload()), code('registry_signed_verdict_invalid'));
  assert.throws(() => apply(env.store, signedVerdict(payload(), wrongKeys.privateKey)),
    code('registry_signature_invalid'));
  const changed = tamperSignedVerdict(signedVerdict(), { status: 'revoked' });
  assert.throws(() => apply(env.store, changed), code('registry_signature_invalid'));
  assert.equal(env.db.prepare('SELECT COUNT(*) AS count FROM audit').get().count, 0);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS count FROM connected_online_registry_state').get().count, 0);

  apply(env.store);
  assert.throws(() => apply(env.store, signedVerdict(payload({
    registryGeneration: 6,
    registryStateDigest: '6'.repeat(64),
  }))), code('registry_generation_stale'));
  assert.throws(() => env.store.getState(
    'customer_beta', 'dep_ffffffffffffffffffffffffffffffff',
  ), code('registry_customer_mismatch'));
});

test('audit failure rolls back the registry row and a later retry succeeds', () => {
  const env = harness();
  env.db.exec(`CREATE TRIGGER reject_registry_audit BEFORE INSERT ON audit
    BEGIN SELECT RAISE(ABORT, 'forced registry audit failure'); END`);
  assert.throws(() => apply(env.store), /forced registry audit failure/);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS count FROM connected_online_registry_state').get().count, 0);
  env.db.exec('DROP TRIGGER reject_registry_audit');
  assert.equal(apply(env.store).state.registryGeneration, 7);
});

test('qualified SQLite authority rejects preconstruction and warmed TEMP collisions', () => {
  const preconstruction = new Database(':memory:');
  preconstruction.exec(`
    CREATE TABLE audit (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      connected_authority_ref TEXT GENERATED ALWAYS AS (
        json_extract(entry, '$.connectedAuthorityRef')
      ) VIRTUAL,
      connected_entry_action TEXT GENERATED ALWAYS AS (
        json_extract(entry, '$.action')
      ) VIRTUAL,
      entry TEXT NOT NULL
    );
    CREATE TABLE connected_online_registry_state (
      customer_id TEXT NOT NULL, deployment_id TEXT NOT NULL, authority_ref TEXT NOT NULL,
      registry_generation INTEGER NOT NULL, registry_state_digest TEXT NOT NULL,
      status TEXT NOT NULL, state_json TEXT NOT NULL, updated_at TEXT NOT NULL,
      PRIMARY KEY (customer_id, deployment_id)
    );
    CREATE TEMP TABLE connected_online_registry_state (customer_id TEXT);
  `);
  const preStore = createConnectedOnlineRegistryStore({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    driver: preconstruction,
    appendAudit() { throw new Error('append must not run'); },
    registryReference: () => `connected_registry_${'A'.repeat(32)}`,
    verifyAuditState: () => ({ ok: true }),
    verifyAuditEntry: () => true,
    verifyVerdict,
  });
  assert.throws(() => apply(preStore), integrityFailure);
  assert.equal(preconstruction.prepare(
    'SELECT COUNT(*) AS count FROM main.connected_online_registry_state',
  ).get().count, 0);
  preconstruction.close();

  const warmed = harness();
  assert.equal(warmed.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), null);
  warmed.db.exec(`
    CREATE TEMP TRIGGER capture_registry_state
      BEFORE INSERT ON main.connected_online_registry_state
      BEGIN SELECT RAISE(ABORT, 'TEMP registry trigger ran'); END;
  `);
  assert.throws(() => apply(warmed.store), integrityFailure);
  assert.equal(warmed.db.prepare(
    'SELECT COUNT(*) AS count FROM main.connected_online_registry_state',
  ).get().count, 0);
  assert.equal(warmed.db.prepare('SELECT COUNT(*) AS count FROM main.audit').get().count, 0);
});

test('Postgres registry authority SQL is public-qualified', () => {
  const source = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'server', 'connected-online-registry-store.js'),
    'utf8',
  );
  assert.match(source, /schema = driver\.kind === 'postgres' \? 'public' : 'main'/);
  assert.match(source, /FROM \$\{relation\.state\}/);
  assert.match(source, /INSERT INTO \$\{relation\.state\}/);
  assert.match(source, /FROM \$\{relation\.audit\}/);
  assert.doesNotMatch(source, /FROM connected_online_registry_state\b/);
  assert.doesNotMatch(source, /INSERT INTO connected_online_registry_state\b/);
  assert.doesNotMatch(source, /FROM audit\b/);
});

test('exact replay is not fresh contact while a same-state refresh is durably anchored', () => {
  const env = harness();
  const first = apply(env.store);
  const replay = apply(env.store);
  assert.equal(replay.contactAdvanced, false);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS count FROM audit').get().count, 1);
  const refreshed = apply(env.store, signedVerdict(payload({
    issuedAt: new Date(NOW + 1000).toISOString(),
  })), NOW + 1000);
  assert.equal(refreshed.contactAdvanced, true);
  assert.equal(refreshed.state.registryGeneration, first.state.registryGeneration);
  assert.equal(env.db.prepare('SELECT COUNT(*) AS count FROM audit').get().count, 2);
  assert.equal(env.db.prepare('SELECT action FROM audit ORDER BY seq DESC LIMIT 1').get().action,
    'CONNECTED_REGISTRY_VERDICT_REFRESHED');
});

test('row, projection, audit, deletion, and external checkpoint tamper fail closed', () => {
  const stateTamper = harness();
  apply(stateTamper.store);
  const row = stateTamper.db.prepare('SELECT state_json FROM connected_online_registry_state').get();
  const changed = JSON.parse(row.state_json);
  changed.registryGeneration = 6;
  changed.verdictPayload.registryGeneration = 6;
  stateTamper.db.prepare(`UPDATE connected_online_registry_state
    SET registry_generation = 6, state_json = ?`).run(protocol.canonicalJson(changed));
  assert.throws(() => stateTamper.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);

  const auditTamper = harness();
  apply(auditTamper.store);
  const auditRow = auditTamper.db.prepare('SELECT seq, entry FROM audit').get();
  const entry = JSON.parse(auditRow.entry);
  entry.detail = entry.detail.replace('"active"', '"revoked"');
  auditTamper.db.prepare('UPDATE audit SET entry = ? WHERE seq = ?')
    .run(JSON.stringify(entry), auditRow.seq);
  assert.throws(() => auditTamper.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);

  const missing = harness();
  apply(missing.store);
  missing.db.prepare('DELETE FROM connected_online_registry_state').run();
  assert.throws(() => missing.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);

  const checkpoint = harness();
  apply(checkpoint.store);
  checkpoint.setAuditHealthy(false);
  assert.throws(() => checkpoint.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
});

test('hiding the newest revoke audit through its physical action cannot authorize a rewind', () => {
  const env = harness();
  apply(env.store);
  const active = env.db.prepare(`SELECT authority_ref, registry_generation,
    registry_state_digest, status, state_json, updated_at
    FROM connected_online_registry_state`).get();
  apply(env.store, signedVerdict(payload({
    status: 'revoked',
    issuedAt: new Date(NOW + 1000).toISOString(),
    registryGeneration: 8,
    registryStateDigest: '8'.repeat(64),
  })), NOW + 1000);
  env.db.prepare("UPDATE audit SET action = 'HIDDEN_REVOKE' WHERE action = ?")
    .run('CONNECTED_REGISTRY_VERDICT_REVOKED');
  env.db.prepare(`UPDATE connected_online_registry_state SET authority_ref = ?,
    registry_generation = ?, registry_state_digest = ?, status = ?,
    state_json = ?, updated_at = ?`).run(
    active.authority_ref,
    active.registry_generation,
    active.registry_state_digest,
    active.status,
    active.state_json,
    active.updated_at,
  );
  assert.throws(() => env.store.getState(CUSTOMER_ID, DEPLOYMENT_ID), integrityFailure);
});

test('registry and entitlement remain independent and combine by most restrictive authority', () => {
  const env = harness();
  apply(env.store);
  const paused = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    protectedEgress: 'block', mode: 'paused', reason: 'vendor_paused', authority: null,
  });
  assert.equal(paused.protectedEgress, 'block');
  assert.equal(paused.reason, 'vendor_paused');
  assert.equal(paused.onlineRegistryGeneration, 7);
  const revoked = signedVerdict(payload({
    status: 'revoked',
    registryGeneration: 8,
    registryStateDigest: '8'.repeat(64),
    issuedAt: new Date(NOW + 1000).toISOString(),
  }));
  apply(env.store, revoked, NOW + 1000);
  const disposition = env.store.disposition(CUSTOMER_ID, DEPLOYMENT_ID, {
    protectedEgress: 'allow', mode: 'connected', reason: null,
    authority: { plan: 'enterprise', seats: 20, features: [] },
  });
  assert.equal(disposition.protectedEgress, 'block');
  assert.equal(disposition.reason, 'vendor_registry_revoked');
});

test('unexpected request data and asynchronous verifier authority are rejected', () => {
  const env = harness();
  assert.throws(() => env.store.applyVerdict({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedVerdict: signedVerdict(),
    nowMs: NOW,
    prompt: 'must never cross this boundary',
  }), code('registry_apply_invalid'));
  assert.equal(JSON.stringify(env.db.prepare('SELECT * FROM audit').all()).includes('prompt'), false);

  assert.throws(() => createConnectedOnlineRegistryStore({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    driver: env.db,
    appendAudit() {},
    registryReference: () => `connected_registry_${'A'.repeat(32)}`,
    verifyAuditState: () => ({ ok: true }),
    verifyAuditEntry: () => true,
    verifyVerdict: async () => ({}),
  }).applyVerdict({
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    signedVerdict: signedVerdict(),
    nowMs: NOW,
  }), code('registry_verifier_must_be_synchronous'));
});

function auditMac(value) {
  return crypto.createHmac('sha256', AUDIT_KEY)
    .update(protocol.canonicalJson(value), 'utf8').digest('hex');
}

function code(expected) {
  return (error) => error && error.code === expected;
}

function integrityFailure(error) {
  return error && error.code === 'CONNECTED_REGISTRY_INTEGRITY';
}
