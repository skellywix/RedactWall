'use strict';
/** Real HTTP smoke tests for the importable Express app. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Isolate the SQLite store BEFORE requiring the app so the smoke tests never
// open (or mutate) a developer's live data/redactwall.db.
const dbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-server-integration-'));
process.env.REDACTWALL_DB_PATH = path.join(dbDir, 'test.db');

const app = require('../server/app');
const db = require('../server/db');
const privatePaths = require('../server/private-path');
const { listen } = require('./support/listen');

// Close the SQLite handle before deleting: Windows cannot unlink open files.
test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(dbDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});


test('server module exports an app without requiring a fixed listening port', async (t) => {
  assert.strictEqual(typeof app, 'function');
  assert.strictEqual(typeof app.startServer, 'function');

  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();

  const res = await fetch(`http://127.0.0.1:${port}/healthz`);
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.headers.get('x-powered-by'), null);
  assert.match(res.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
  assert.strictEqual(res.headers.get('x-frame-options'), 'DENY');
  assert.strictEqual(res.headers.get('referrer-policy'), 'no-referrer');

  const body = await res.json();
  assert.strictEqual(body.status, 'ok');
  assert.strictEqual(body.service, 'redactwall');
});

test('readiness endpoint is reachable through the importable app', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();

  const res = await fetch(`http://127.0.0.1:${port}/readyz`);
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.ready, true);
  assert.strictEqual(body.database, true);
  assert.ok(['ok', 'warnings'].includes(body.configuration));
});

test('readiness exposes committed durable-state cleanup degradation', async (t) => {
  const original = privatePaths.committedCleanupHealth;
  privatePaths.committedCleanupHealth = () => ({ ok: false, reason: 'durable-storage-cleanup-degraded' });
  t.after(() => { privatePaths.committedCleanupHealth = original; });
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();

  const res = await fetch(`http://127.0.0.1:${port}/readyz`);
  assert.strictEqual(res.status, 503);
  const body = await res.json();
  assert.strictEqual(body.ready, false);
  assert.strictEqual(body.durableStorage, false);
  assert.strictEqual(body.error, 'durable_storage_cleanup_degraded');
});

test('unauthenticated navigation redirects pages but returns API auth errors', async (t) => {
  const server = await listen(app);
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  const root = await fetch(`${base}/`, { redirect: 'manual' });
  assert.strictEqual(root.status, 302);
  assert.strictEqual(root.headers.get('location'), '/app/');

  const gatedApp = await fetch(`${base}/app/`, { redirect: 'manual' });
  assert.strictEqual(gatedApp.status, 302);
  assert.strictEqual(gatedApp.headers.get('location'), '/login.html');

  const login = await fetch(`${base}/login.html`);
  assert.strictEqual(login.status, 200);
  assert.match(login.headers.get('content-type') || '', /text\/html/);
  assert.match(await login.text(), /RedactWall/);

  const me = await fetch(`${base}/api/me`);
  assert.strictEqual(me.status, 401);
  assert.deepStrictEqual(await me.json(), { error: 'unauthenticated' });
});
