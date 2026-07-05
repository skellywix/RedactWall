'use strict';
/** Posture subscriptions: multi-format envelopes, retry/backoff, dedupe, and
 *  prompt-free delivery history. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const dbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-subs-'));
process.env.SENTINEL_DB_PATH = path.join(dbDir, 'test.db');
process.env.SENTINEL_SUBSCRIPTIONS_PATH = path.join(dbDir, 'subs.json');
// Close the SQLite handle before deleting: Windows cannot unlink open files.
test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(dbDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

const formats = require('../server/siem-formats');
const subscriptions = require('../server/subscriptions');
const db = require('../server/db');

function writeSubs(destinations) {
  fs.writeFileSync(process.env.SENTINEL_SUBSCRIPTIONS_PATH, JSON.stringify({ destinations }));
}

function alert(over = {}) {
  return { schemaVersion: 1, eventType: 'promptwall.security_event', action: 'BLOCKED', queryId: 'q_' + crypto.randomBytes(3).toString('hex'), createdAt: new Date().toISOString(), status: 'pending', user: 'a@cu.org', destination: 'chatgpt.com', riskScore: 80, maxSeverity: 4, maxSeverityLabel: 'critical', findings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '•••• 7843' }], categories: [], reasons: ['Hard-stop'], ...over };
}

test('every SIEM adapter emits a prompt-free, PII-free envelope', () => {
  const raw = '412-22-7843';
  const a = alert({ reasons: ['Hard-stop entity present: US_SSN'] });
  for (const type of formats.supportedTypes()) {
    const req = formats.buildRequest(a, { id: 'd', type, url: 'https://siem.example.com', token: 't' });
    assert.ok(!req.body.includes(raw), `${type} must not contain raw PII`);
    assert.ok(req.url.startsWith('https://') || req.url.startsWith('https://http-intake') || req.url.includes('googleapis'), `${type} url set`);
  }
});

test('delivery succeeds and is recorded prompt-free', async () => {
  writeSubs([{ id: 'splunk1', name: 'Splunk', type: 'splunk_hec', url: 'https://splunk.example.com', token: 'hec' }]);
  const sent = [];
  const fakeFetch = async (url, req) => { sent.push({ url, req }); return { ok: true, status: 200 }; };
  const dest = subscriptions.findDestination('splunk1');
  const rec = await subscriptions.deliverTo(dest, alert(), { fetch: fakeFetch, sleep: async () => {} });
  assert.strictEqual(rec.status, 'delivered');
  assert.strictEqual(rec.attempts, 1);
  assert.strictEqual(sent[0].url, 'https://splunk.example.com/services/collector/event');
  // History carries no payload body.
  const hist = db.listDeliveries(10);
  assert.ok(hist.some((d) => d.status === 'delivered'));
  assert.ok(!JSON.stringify(hist).includes('412-22-7843'));
});

test('delivery retries with backoff then records failure', async () => {
  writeSubs([{ id: 'flaky', name: 'Flaky', type: 'webhook', url: 'https://flaky.example.com', maxAttempts: 3 }]);
  let calls = 0;
  const fakeFetch = async () => { calls++; return { ok: false, status: 503 }; };
  const sleeps = [];
  const dest = subscriptions.findDestination('flaky');
  const rec = await subscriptions.deliverTo(dest, alert(), { fetch: fakeFetch, sleep: async (ms) => { sleeps.push(ms); } });
  assert.strictEqual(rec.status, 'failed');
  assert.strictEqual(rec.attempts, 3);
  assert.strictEqual(calls, 3);
  assert.deepStrictEqual(sleeps, [500, 1000], 'exponential backoff between attempts');
});

test('duplicate events within the window are deduped, not resent', async () => {
  writeSubs([{ id: 'dd', name: 'DD', type: 'webhook', url: 'https://dd.example.com' }]);
  let calls = 0;
  const fakeFetch = async () => { calls++; return { ok: true, status: 200 }; };
  const dest = subscriptions.findDestination('dd');
  const a = alert();
  await subscriptions.deliverTo(dest, a, { fetch: fakeFetch, sleep: async () => {} });
  const second = await subscriptions.deliverTo(dest, a, { fetch: fakeFetch, sleep: async () => {} });
  assert.strictEqual(second.status, 'deduped');
  assert.strictEqual(calls, 1, 'the duplicate is not resent');
});

test('dispatch fans out only to destinations whose filters match', async () => {
  writeSubs([
    { id: 'high', name: 'High', type: 'webhook', url: 'https://high.example.com', minRisk: 75 },
    { id: 'low', name: 'Low', type: 'webhook', url: 'https://low.example.com', minRisk: 10, eventTypes: ['ALLOWED'] },
  ]);
  const hit = [];
  const fakeFetch = async (url) => { hit.push(url); return { ok: true, status: 200 }; };
  await subscriptions.dispatch(alert({ action: 'BLOCKED', riskScore: 80 }), { fetch: fakeFetch, sleep: async () => {}, force: true });
  assert.ok(hit.some((u) => u.includes('high.example.com')), 'risk-80 event reaches the high-risk destination');
  assert.ok(!hit.some((u) => u.includes('low.example.com')), 'event type BLOCKED does not match eventTypes [ALLOWED]');
});

test('a lone minRisk floor filters on its own (not a no-op)', async () => {
  writeSubs([{ id: 'r50', name: 'R50', type: 'webhook', url: 'https://r50.example.com', minRisk: 50 }]);
  const hit = [];
  const fakeFetch = async (url) => { hit.push(url); return { ok: true, status: 200 }; };
  await subscriptions.dispatch(alert({ riskScore: 20, maxSeverity: 0, action: 'FLAGGED' }), { fetch: fakeFetch, sleep: async () => {}, force: true });
  assert.strictEqual(hit.length, 0, 'a risk-20 event is below the risk-50 floor and must not deliver');
  await subscriptions.dispatch(alert({ riskScore: 90, maxSeverity: 0, action: 'BLOCKED' }), { fetch: fakeFetch, sleep: async () => {}, force: true });
  assert.strictEqual(hit.length, 1, 'a risk-90 event clears the floor and delivers');
});

test('non-HTTPS destinations are rejected at load', () => {
  writeSubs([{ id: 'insecure', type: 'webhook', url: 'http://plaintext.example.com' }]);
  assert.strictEqual(subscriptions.destinations().length, 0);
});
