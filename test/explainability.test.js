'use strict';
/** Every score explains itself: severity x confidence points + the regulation
 *  (GLBA, PCI-DSS, HIPAA, ...) that makes the data sensitive, engine to verdict. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.AUDITOR_USER = 'auditor@x';
process.env.AUDITOR_PASSWORD = 'auditor-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-explain-' + crypto.randomBytes(6).toString('hex') + '.db');

const detector = require('../server/detector');
const policy = require('../server/policy');
const app = require('../server/app');
const auth = require('../server/auth');
const { listen } = require('./support/listen');

const SAMPLE = 'Member SSN 524-71-8812 and card 4111 1111 1111 1111 for the dispute.';

test('analyze emits a per-detection score breakdown with regulations', () => {
  const a = detector.analyze(SAMPLE);
  assert.ok(a.scoreBreakdown.length >= 2);
  const ssn = a.scoreBreakdown.find((e) => e.type === 'US_SSN');
  assert.strictEqual(ssn.severityLabel, 'critical');
  assert.strictEqual(ssn.confidence, 'very_likely');
  assert.ok(ssn.points > 0);
  assert.ok(ssn.regulations.includes('GLBA 501(b)'));
  const card = a.scoreBreakdown.find((e) => e.type === 'CREDIT_CARD');
  assert.ok(card.regulations.includes('PCI-DSS Req 3'));
  assert.ok(a.regulations.includes('NCUA 12 CFR 748'));
  const totalPoints = a.scoreBreakdown.reduce((s, e) => s + e.points, 0);
  assert.ok(Math.abs(Math.min(100, totalPoints) - a.riskScore) <= a.scoreBreakdown.length, 'points sum to the risk score within rounding');
});

test('clean text explains itself as empty, not undefined', () => {
  const a = detector.analyze('What are our branch hours next week?');
  assert.deepStrictEqual(a.scoreBreakdown, []);
  assert.deepStrictEqual(a.regulations, []);
});

test('block reasons cite the regulation behind the decision', () => {
  const verdict = policy.evaluate(detector.analyze(SAMPLE));
  assert.strictEqual(verdict.decision, 'block');
  const hardStop = verdict.reasons.find((r) => r.startsWith('Hard-stop entity present: US_SSN'));
  assert.match(hardStop, /GLBA 501\(b\)/);
  assert.match(hardStop, /NCUA 12 CFR 748/);
});

test('detection tester returns the rationale without storing the sample', async () => {
  const server = await listen(app);
  const port = server.address().port;
  const cookie = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('admin', 'security_admin')}`;
  try {
    const csrf = await (await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie } })).json();
    const r = await fetch(`http://127.0.0.1:${port}/api/detectors/test`, {
      method: 'POST',
      headers: { cookie, 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
      body: JSON.stringify({ text: SAMPLE }),
    });
    assert.strictEqual(r.status, 200);
    const body = await r.json();
    assert.strictEqual(body.decision, 'block');
    assert.ok(body.regulations.includes('GLBA 501(b)'));
    assert.ok(body.findings.every((f) => !f.value), 'raw values never leave the tester');
    assert.ok(body.findings.some((f) => f.masked && f.masked.includes('8812')));

    const audit = await (await fetch(`http://127.0.0.1:${port}/api/audit`, { headers: { cookie } })).json();
    assert.ok(!audit.entries.some((e) => (e.detail || '').includes('8812')), 'sample text stays out of the audit log');
    const queries = await (await fetch(`http://127.0.0.1:${port}/api/queries`, { headers: { cookie } })).json();
    assert.strictEqual(queries.length, 0, 'tester never creates a query row');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('detector metadata endpoint exposes the regulation map for historical rows', async () => {
  const server = await listen(app);
  const port = server.address().port;
  const cookie = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('auditor@x', 'auditor')}`;
  try {
    const meta = await (await fetch(`http://127.0.0.1:${port}/api/detectors/meta`, { headers: { cookie } })).json();
    assert.strictEqual(meta.severityLabels['4'], 'critical');
    assert.ok(meta.regulations.US_SSN.includes('GLBA 501(b)'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
