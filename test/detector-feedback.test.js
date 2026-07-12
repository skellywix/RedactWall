'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.APPROVER_USER = 'feedback-approver';
process.env.APPROVER_PASSWORD = 'feedback-approver-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-detector-feedback-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.REDACTWALL_POLICY_PATH = path.join(os.tmpdir(), 'ps-detector-feedback-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), process.env.REDACTWALL_POLICY_PATH);

const app = require('../server/app');
const db = require('../server/db');
const feedback = require('../server/detector-feedback');
const { listen } = require('./support/listen');

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port, user = 'admin', password = 'unit-pass') {
  const res = await jsonFetch(port, '/api/login', {
    body: { user, password },
  });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrfRes = await jsonFetch(port, '/api/csrf', { method: 'GET', headers: { cookie } });
  assert.strictEqual(csrfRes.status, 200);
  const { csrfToken } = await csrfRes.json();
  return { cookie, csrfToken };
}

function seedQuery(id = 'q_feedback', overrides = {}) {
  return db.createQuery({
    id,
    createdAt: '2026-07-04T14:00:00.000Z',
    status: 'pending',
    user: 'analyst@example.test',
    orgId: 'qa-org',
    destination: 'https://chatgpt.com/c/feedback',
    source: 'browser_extension',
    channel: 'submit',
    findings: [{ type: 'US_SSN', severity: 4, score: 0.98, masked: '***-**-9043' }],
    categories: ['PII'],
    entityCounts: { US_SSN: 1 },
    riskScore: 91,
    maxSeverity: 4,
    redactedPrompt: 'Member [US_SSN] flagged for feedback',
    _rawPrompt: 'Member SSN 524-71-9043 flagged for feedback',
    ...overrides,
  });
}

test('detector feedback records sanitized query-scoped tuning signals', async () => {
  const q = seedQuery();
  const server = await listen(app);
  try {
    const port = server.address().port;
    const unauth = await jsonFetch(port, '/api/detector-feedback/report', { method: 'GET' });
    assert.strictEqual(unauth.status, 401);

    const { cookie, csrfToken } = await login(port);
    const headers = { cookie, 'x-csrf-token': csrfToken };

    const badReason = await jsonFetch(port, `/api/queries/${q.id}/detector-feedback`, {
      headers,
      body: { detectorId: 'US_SSN', verdict: 'false_positive', reason: 'member 524-71-9043 was a test' },
    });
    assert.strictEqual(badReason.status, 400);
    const badBody = await badReason.json();
    assert.deepStrictEqual(badBody.fields, ['reason']);
    assert.strictEqual(JSON.stringify(badBody).includes('524-71-9043'), false);

    const created = await jsonFetch(port, `/api/queries/${q.id}/detector-feedback`, {
      headers,
      body: { detectorId: 'US_SSN', verdict: 'false_positive', reason: 'synthetic_false_positive' },
    });
    assert.strictEqual(created.status, 200);
    const createdBody = await created.json();
    assert.strictEqual(createdBody.feedback.detectorId, 'US_SSN');
    assert.strictEqual(createdBody.feedback.verdict, 'false_positive');
    assert.ok(createdBody.audit.hash);
    assert.strictEqual(JSON.stringify(createdBody).includes('524-71-9043'), false);

    const reportRes = await jsonFetch(port, '/api/detector-feedback/report?queryLimit=100&feedbackLimit=100', {
      method: 'GET',
      headers: { cookie },
    });
    assert.strictEqual(reportRes.status, 200);
    const report = await reportRes.json();
    assert.strictEqual(report.summary.falsePositive, 1);
    assert.strictEqual(report.summary.privacy, 'metadata only; prompt bodies excluded');
    assert.ok(report.detectors.some((item) => item.detectorId === 'US_SSN' && item.state === 'attention'));
    assert.ok(report.reviewQueue.some((item) => item.queryId === q.id && item.feedbackCount === 1));
    assert.strictEqual(JSON.stringify(report).includes('524-71-9043'), false);

    const evidenceRes = await jsonFetch(port, '/api/export/evidence?queryLimit=100&auditLimit=100', {
      method: 'GET',
      headers: { cookie },
    });
    assert.strictEqual(evidenceRes.status, 200);
    const pack = await evidenceRes.json();
    assert.strictEqual(pack.detectorFeedback.summary.falsePositive, 1);
    assert.strictEqual(pack.detectorFeedback.detectors[0].detectorId, 'US_SSN');
    assert.strictEqual(JSON.stringify(pack.detectorFeedback).includes('524-71-9043'), false);
  } finally {
    await close(server);
  }
});

test('detector feedback report exposes requester-specific candidate authority without weakening POST authorization', async () => {
  const owned = seedQuery('q_feedback_owned', {
    assignedRole: 'approver',
    assignedUser: ' FEEDBACK-APPROVER ',
    riskScore: 99,
  });
  const forbidden = seedQuery('q_feedback_forbidden', {
    assignedRole: 'security_admin',
    assignedUser: null,
    riskScore: 98,
  });
  const server = await listen(app);
  try {
    const port = server.address().port;
    const approver = await login(port, 'feedback-approver', 'feedback-approver-pass');
    const headers = { cookie: approver.cookie, 'x-csrf-token': approver.csrfToken };
    const reportRes = await jsonFetch(port, '/api/detector-feedback/report?queryLimit=100&feedbackLimit=100', {
      method: 'GET',
      headers: { cookie: approver.cookie },
    });
    assert.strictEqual(reportRes.status, 200);
    const report = await reportRes.json();
    const ownedCandidate = report.reviewQueue.find((item) => item.queryId === owned.id);
    const forbiddenCandidate = report.reviewQueue.find((item) => item.queryId === forbidden.id);
    assert.ok(ownedCandidate);
    assert.ok(forbiddenCandidate);
    assert.strictEqual(ownedCandidate.canFeedback, true);
    assert.strictEqual(forbiddenCandidate.canFeedback, false);
    assert.strictEqual(JSON.stringify(report).includes('524-71-9043'), false);

    const accepted = await jsonFetch(port, `/api/queries/${owned.id}/detector-feedback`, {
      headers,
      body: { detectorId: 'US_SSN', verdict: 'valid', reason: 'candidate_authority_test' },
    });
    assert.strictEqual(accepted.status, 200);
    const denied = await jsonFetch(port, `/api/queries/${forbidden.id}/detector-feedback`, {
      headers,
      body: { detectorId: 'US_SSN', verdict: 'valid', reason: 'candidate_authority_test' },
    });
    assert.strictEqual(denied.status, 403);
  } finally {
    await close(server);
  }
});

test('detector feedback report summarizes valid, noisy, and missed detector signals', () => {
  const report = feedback.report({
    rows: [{
      id: 'q1',
      createdAt: '2026-07-04T14:00:00.000Z',
      status: 'pending',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
      findings: [{ type: 'US_SSN' }],
      categories: ['PII'],
      entityCounts: { US_SSN: 1 },
      riskScore: 90,
      maxSeverity: 4,
      _rawPrompt: 'Member SSN 524-71-9043',
    }],
    feedback: [
      { id: 'f1', createdAt: '2026-07-04T14:01:00.000Z', queryId: 'q1', detectorId: 'US_SSN', verdict: 'valid', actor: 'admin', destination: 'chatgpt.com', riskScore: 90, maxSeverity: 4 },
      { id: 'f2', createdAt: '2026-07-04T14:02:00.000Z', queryId: 'q1', detectorId: 'US_SSN', verdict: 'too_sensitive', actor: 'admin', destination: 'chatgpt.com', riskScore: 90, maxSeverity: 4 },
      { id: 'f3', createdAt: '2026-07-04T14:03:00.000Z', queryId: 'q1', detectorId: 'SECRET_KEY', verdict: 'missed', actor: 'admin', destination: 'chatgpt.com', riskScore: 90, maxSeverity: 4 },
    ],
  });
  assert.strictEqual(report.summary.total, 3);
  assert.strictEqual(report.summary.noisy, 1);
  assert.strictEqual(report.summary.missed, 1);
  assert.ok(report.detectors.some((item) => item.detectorId === 'SECRET_KEY' && item.missed === 1));
  assert.strictEqual(JSON.stringify(report).includes('524-71-9043'), false);
});
