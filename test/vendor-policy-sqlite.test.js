'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const Database = require('better-sqlite3');
const {
  createProductionVendorPolicyAuthority,
  createVendorPolicyAuthority,
} = require('../server/vendor-policy-authority');
const {
  createFilePolicyExternalState,
  createMemoryPolicyExternalState,
} = require('../server/vendor-policy-external-state');
const {
  openVendorPolicySqlite,
  openVendorPolicyStore,
} = require('../server/vendor-policy-sqlite');

function withProcessNodeEnv(value, callback) {
  const previous = process.env.NODE_ENV;
  if (value === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = value;
  try { return callback(); }
  finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
}

function wrapped(revision, label) {
  return {
    integrityVersion: 1,
    keyId: 'rw-policy-integrity-v1',
    domain: 'test',
    payload: { revision, label },
    mac: String(revision).padStart(64, '0'),
  };
}

test('vendor SQLite preserves immutable archives, exact claims, CAS heads, and transaction rollback', async () => {
  const resolver = {
    resolveAuthorization: (id) => ({ id, kind: 'authorization' }),
    resolveConfirmation: (id) => ({ id, kind: 'confirmation' }),
    resolveDualApproval: (id) => ({ id, kind: 'approval' }),
  };
  const store = openVendorPolicyStore({
    driver: 'sqlite',
    path: ':memory:',
    authorityResolver: resolver,
  });
  try {
    assert.equal(store.runtimeProfile, 'test-reference');
    await store.transaction((tx) => {
      assert.deepEqual(tx.resolveAuthorization('auth-1'), resolver.resolveAuthorization('auth-1'));
      assert.equal(tx.claimAuthorization('auth-1', 'a'.repeat(64)), 'claimed');
      assert.equal(tx.claimAuthorization('auth-1', 'a'.repeat(64)), 'replay');
      assert.equal(tx.claimAuthorization('auth-1', 'b'.repeat(64)), 'conflict');
      for (let revision = 1; revision <= 3; revision += 1) {
        assert.equal(tx.insertPolicyRecord(
          'global_release', String(revision), wrapped(revision, `global-${revision}`),
        ), true);
        assert.equal(tx.appendPolicyAuditEvent(
          revision, String(revision).repeat(64).slice(0, 64), wrapped(revision, `audit-${revision}`),
        ), true);
        assert.equal(tx.compareAndSetPolicyAuditHighWater(revision - 1, {
          payload: { sequence: revision },
        }), true);
      }
      assert.equal(tx.insertPolicyRecord('global_head', 'global', wrapped(1, 'head-1')), true);
      assert.equal(tx.compareAndSetPolicyRecord(
        'global_head', 'global', 1, wrapped(2, 'head-2'),
      ), true);
      assert.equal(tx.compareAndSetPolicyRecord(
        'global_head', 'global', 1, wrapped(3, 'stale'),
      ), false);
      assert.equal(tx.insertPolicyOperation('c'.repeat(64), { result: 'stable' }), true);
      assert.equal(tx.insertPolicyOperation('c'.repeat(64), { result: 'changed' }), false);
    });

    assert.deepEqual(await store.compact({
      globalRetain: 1,
      deploymentRetain: 1,
      auditRetain: 1,
    }), { global: 2, distribution: 0, audit: 2 });
    await store.transaction((tx) => {
      assert.equal(tx.readPolicyRecord('global_release', '1').payload.label, 'global-1');
      assert.equal(tx.readPolicyRecord('global_release', '3').payload.label, 'global-3');
      assert.equal(tx.readPolicyAuditEvent(1).payload.label, 'audit-1');
      assert.equal(tx.readPolicyAuditEvent(3).payload.label, 'audit-3');
      assert.equal(tx.insertPolicyRecord('global_release', '1', wrapped(1, 'replacement')), false);
      assert.equal(tx.appendPolicyAuditEvent(1, '9'.repeat(64), wrapped(1, 'replacement')), false);
    });

    await assert.rejects(store.transaction((tx) => {
      tx.insertPolicyRecord('distribution', 'd:rollback:1', wrapped(1, 'must-rollback'));
      throw new Error('rollback');
    }), /rollback/);
    await store.transaction((tx) => {
      assert.equal(tx.readPolicyRecord('distribution', 'd:rollback:1'), null);
    });
    assert.equal(store.readiness().ready, true);
    assert.equal(store.readiness().runtimeProfile, 'test-reference');
    assert.equal(store.productionReady, false);
    assert.equal(store.readiness().productionReady, false);
  } finally {
    store.close();
  }
});

test('vendor policy storage has an explicit Postgres blocker and rejects unknown drivers', () => {
  assert.throws(() => openVendorPolicyStore({ driver: 'postgres' }),
    (error) => error.code === 'policy_postgres_adapter_not_implemented');
  assert.throws(() => openVendorPolicyStore({ driver: 'mysql' }),
    (error) => error.code === 'policy_storage_driver_invalid');
});

test('vendor production policy factory cannot accept test stores, witnesses, or profile overrides', () => {
  const memory = createMemoryPolicyExternalState({ testOnly: true });
  assert.throws(() => createProductionVendorPolicyAuthority({
    storage: { transaction() {} },
    externalState: memory,
    allowTestExternalState: true,
    driver: 'sqlite',
    runtimeProfile: 'test-reference',
  }), (error) => error.code === 'policy_production_options_invalid');
  assert.throws(() => createProductionVendorPolicyAuthority({}),
    (error) => error.code === 'policy_postgres_adapter_not_implemented');
});

test('actual production cannot be downgraded for policy reference constructors or preopened stores', () => {
  const originalNodeEnv = process.env.NODE_ENV;
  const resolver = {
    resolveAuthorization: () => null,
    resolveConfirmation: () => null,
    resolveDualApproval: () => null,
  };
  const preopened = openVendorPolicyStore({
    path: ':memory:', authorityResolver: resolver, env: { NODE_ENV: 'development' },
  });
  const externalDatabase = new Database(':memory:');
  try {
    withProcessNodeEnv('production', () => {
      assert.throws(() => openVendorPolicyStore({
        path: ':memory:', authorityResolver: resolver,
      }), { code: 'policy_reference_storage_unavailable' });
      assert.throws(() => openVendorPolicyStore({
        path: ':memory:', authorityResolver: resolver, env: { NODE_ENV: 'development' },
      }), { code: 'policy_reference_storage_unavailable' });
      assert.throws(() => openVendorPolicySqlite({
        database: externalDatabase,
        authorityResolver: resolver,
        env: { NODE_ENV: 'development' },
        production: false,
      }), { code: 'policy_reference_storage_unavailable' });

      const wrapped = {
        ...preopened,
        assurance: 'managed_postgres',
        productionReady: true,
        runtimeProfile: 'production',
      };
      assert.throws(() => createVendorPolicyAuthority({
        storage: wrapped,
        externalState: {
          assurance: 'independent-exact-cas',
          readPending() {}, readAnchor() {}, preparePending() {},
          compareAndSetAnchor() {}, clearPending() {},
        },
        allowTestExternalState: true,
        env: { NODE_ENV: 'development' },
        production: false,
      }), { code: 'policy_reference_constructor_unavailable' });
      assert.throws(() => createVendorPolicyAuthority({
        storage: preopened,
      }), { code: 'policy_reference_constructor_unavailable' });
    });
    assert.equal(externalDatabase.prepare('SELECT 1 AS value').get().value, 1);
    assert.equal(preopened.readiness().productionReady, false);
    assert.equal(process.env.NODE_ENV, originalNodeEnv);
  } finally {
    preopened.close();
    externalDatabase.close();
  }

  assert.throws(() => openVendorPolicyStore({
    path: ':memory:', authorityResolver: resolver, env: { NODE_ENV: 'production' },
  }), { code: 'policy_reference_storage_unavailable' });
  assert.throws(() => createVendorPolicyAuthority({
    storage: { transaction() {} }, env: { NODE_ENV: 'production' },
  }), { code: 'policy_reference_constructor_unavailable' });
});

test('file witness is a private reference adapter with exact pending and anchor CAS', async () => {
  assert.throws(() => createMemoryPolicyExternalState(),
    (error) => error.code === 'policy_external_memory_test_only');
  const memory = createMemoryPolicyExternalState({ testOnly: true });
  assert.throws(() => createVendorPolicyAuthority({
    storage: { transaction() {} },
    externalState: memory,
  }), (error) => error.code === 'policy_external_assurance_invalid');
  const callerLabeledProduction = {
    assurance: 'independent-exact-cas',
    readPending: (...args) => memory.readPending(...args),
    readAnchor: (...args) => memory.readAnchor(...args),
    preparePending: (...args) => memory.preparePending(...args),
    compareAndSetAnchor: (...args) => memory.compareAndSetAnchor(...args),
    clearPending: (...args) => memory.clearPending(...args),
  };
  assert.throws(() => createVendorPolicyAuthority({
    storage: { transaction() {} },
    externalState: callerLabeledProduction,
    allowTestExternalState: true,
  }), (error) => error.code === 'policy_external_assurance_invalid');

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rw-policy-external-'));
  try {
    const external = createFilePolicyExternalState({ directory });
    assert.equal(external.assurance, 'test-reference');
    const pending = { payload: { sequence: 1 }, kind: 'pending' };
    const pendingDigest = await external.preparePending(pending);
    assert.match(pendingDigest, /^[a-f0-9]{64}$/);
    assert.equal(await external.preparePending(pending), false);
    assert.deepEqual(await external.readPending(), pending);
    assert.equal(await external.clearPending('0'.repeat(64)), false);
    assert.equal(await external.clearPending(pendingDigest), true);
    assert.equal(await external.readPending(), null);

    const first = { payload: { sequence: 1 }, headDigest: '1'.repeat(64) };
    const second = { payload: { sequence: 2 }, headDigest: '2'.repeat(64) };
    assert.equal(await external.compareAndSetAnchor(0, first), true);
    assert.equal(await external.compareAndSetAnchor(0, second), false);
    assert.equal(await external.compareAndSetAnchor(1, second), true);
    assert.deepEqual(await external.readAnchor(), second);

    const anchor = path.join(directory, 'policy-anchor.json');
    const linked = path.join(directory, 'policy-anchor-linked.json');
    fs.linkSync(anchor, linked);
    await assert.rejects(external.readAnchor(),
      (error) => error.code === 'policy_external_state_invalid');
    fs.unlinkSync(linked);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
