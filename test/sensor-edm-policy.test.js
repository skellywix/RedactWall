'use strict';
/** Managed sensors receive the fingerprint-only EDM pack they enforce locally. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-sensor-edm-'));
const syntheticValue = '550e8400-e29b-41d4-a716-446655440000';
const salt = 'sensor-edm-unit-salt-0123456789abcdef';
process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable-sensor-edm-00000001';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-sensor-edm-000000000001';
process.env.INGEST_API_KEY = 'unit-ingest-key-sensor-edm-00000000001';
process.env.REDACTWALL_DB_PATH = path.join(tmp, 'test.db');
process.env.REDACTWALL_POLICY_PATH = path.join(tmp, 'policy.json');
process.env.REDACTWALL_EXACT_MATCH_PATH = path.join(tmp, 'exact-match.json');

const detector = require('../detection-engine/detect');
fs.writeFileSync(process.env.REDACTWALL_POLICY_PATH, JSON.stringify({
  enforcementMode: 'block',
  blockMinSeverity: 4,
  blockRiskScore: 100,
}));
fs.writeFileSync(process.env.REDACTWALL_EXACT_MATCH_PATH, JSON.stringify({
  formatVersion: 2,
  algorithm: 'sha256',
  valuePolicy: 'offline-random-id-v1',
  salt,
  minLen: 20,
  maxWords: 1,
  fingerprints: [detector.edmFingerprint(syntheticValue, salt)],
}));

const app = require('../server/app');
const db = require('../server/db');
const endpoint = require('../sensors/endpoint-agent/agent');
const mcp = require('../sensors/mcp-guard/guard');
const { listen } = require('./support/listen');

test('sensor policy and signed bundle publish fingerprint-only EDM config', async () => {
  const server = await listen(app);
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    for (const route of ['/api/v1/policy', '/api/v1/policy/bundle']) {
      const res = await fetch(base + route, { headers: { 'x-api-key': process.env.INGEST_API_KEY } });
      assert.strictEqual(res.status, 200);
      const body = await res.json();
      const policy = body.policy || body;
      assert.strictEqual(policy.exactMatch.salt, salt);
      assert.strictEqual(policy.exactMatch.fingerprints.length, 1);
      assert.ok(!JSON.stringify(body).includes(syntheticValue));
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('endpoint and MCP local analyzers enforce the published EDM config', () => {
  const exactMatch = JSON.parse(fs.readFileSync(process.env.REDACTWALL_EXACT_MATCH_PATH, 'utf8'));
  const text = `Review ${syntheticValue} before using the model.`;
  const endpointFindings = detector.analyze(text, endpoint.sensorPolicy({ exactMatch })).findings;
  const mcpFindings = detector.analyze(text, mcp.detectionOptions({ exactMatch })).findings;

  assert.ok(endpointFindings.some((finding) => finding.type === 'EXACT_MATCH'));
  assert.ok(mcpFindings.some((finding) => finding.type === 'EXACT_MATCH'));
});

test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(tmp, { recursive: true, force: true });
});
