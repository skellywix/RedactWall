'use strict';
/**
 * alwaysBlock hard-stop invariant: a prompt containing a raw hard-stop value
 * (e.g. US_SSN) can never be cleared to send, regardless of the admin ignore
 * list or a sensor-declared clientOutcome. Guards the two bypasses fixed in
 * server/policy.js (ignore filter) and server/app.js (clientOutcome override).
 */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass-alwaysblock';
process.env.SENTINEL_SECRET = 'unit-secret-alwaysblock';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-alwaysblock';
process.env.INGEST_API_KEY = 'unit-ingest-alwaysblock';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-alwaysblock-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const policy = require('../server/policy');
const detect = require('../detection-engine/detect');
const { listen } = require('./support/listen');

const SSN_PROMPT = 'Member SSN is 123-45-6789';

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function gate(port, body) {
  return fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.INGEST_API_KEY },
    body: JSON.stringify(body),
  });
}

test('ignore list cannot suppress a hard-stop entity (policy.evaluate)', () => {
  const base = policy.loadPolicy();
  const withIgnore = policy.normalizePolicy({ ...base, ignore: ['US_SSN'] });
  const analysis = detect.analyze(SSN_PROMPT);
  assert.ok(analysis.findings.some((f) => f.type === 'US_SSN'), 'SSN is detected');
  const verdict = policy.evaluate(analysis, withIgnore, { destination: 'chatgpt.com' });
  assert.strictEqual(verdict.decision, 'block', 'ignored SSN still blocks');
});

test('ignore list still suppresses a non-hard-stop finding', () => {
  const base = policy.loadPolicy();
  // A hard-stop type dropped from alwaysBlock AND ignored should be suppressed;
  // proves the exemption is scoped to alwaysBlock membership, not blanket.
  const custom = policy.normalizePolicy({ ...base, alwaysBlock: [], ignore: ['US_SSN'] });
  const analysis = detect.analyze(SSN_PROMPT);
  const verdict = policy.evaluate(analysis, custom, { destination: 'chatgpt.com' });
  assert.strictEqual(verdict.decision, 'allow', 'non-hard-stop ignored type is suppressed');
});

test('clientOutcome=sent_after_warning cannot clear a raw hard-stop value', async (t) => {
  const server = await listen(app);
  t.after(() => close(server));
  const { port } = server.address();
  const res = await gate(port, {
    prompt: SSN_PROMPT,
    user: 'demo@example.com',
    destination: 'chatgpt.com',
    clientOutcome: 'sent_after_warning',
  });
  const body = await res.json();
  assert.notStrictEqual(body.status, 'warned_sent', 'not recorded as cleared-to-send');
  assert.strictEqual(body.status, 'pending', 'held for approval instead');
  assert.ok(!body.receipt, 'no safe-to-send receipt issued for a raw hard-stop value');
});

test('clientOutcome=justified cannot clear a raw hard-stop value', async (t) => {
  const server = await listen(app);
  t.after(() => close(server));
  const { port } = server.address();
  const res = await gate(port, {
    prompt: SSN_PROMPT,
    user: 'demo@example.com',
    destination: 'chatgpt.com',
    clientOutcome: 'justified',
    note: 'business need',
  });
  const body = await res.json();
  assert.notStrictEqual(body.status, 'justified', 'not recorded as justified-sent');
  assert.strictEqual(body.status, 'pending', 'held for approval instead');
  assert.ok(!body.receipt, 'no safe-to-send receipt issued');
});

test('a non-sensitive prompt still resolves normally under a clientOutcome', async (t) => {
  const server = await listen(app);
  t.after(() => close(server));
  const { port } = server.address();
  const res = await gate(port, {
    prompt: 'Draft a friendly lobby announcement about branch hours.',
    user: 'demo@example.com',
    destination: 'chatgpt.com',
    clientOutcome: 'sent_after_warning',
  });
  const body = await res.json();
  assert.strictEqual(res.status, 200);
  assert.strictEqual(body.decision, 'allow', 'benign prompt is allowed, not force-held');
});
