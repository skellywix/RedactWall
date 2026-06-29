'use strict';
/** Sensor heartbeats record install health without prompt bodies. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-heartbeat-test-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const { listen, loopbackHttpFetch } = require('./support/listen');
const db = require('../server/db');
const coverage = require('../server/coverage');
const evidence = require('../server/evidence');


function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await close(server);
  }
}

async function heartbeat(port, body, key = 'unit-ingest-key') {
  return loopbackHttpFetch(`http://127.0.0.1:${port}/api/v1/heartbeat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': key },
    body: JSON.stringify(body),
  });
}

test('sensor heartbeat stores bounded install checks and feeds coverage evidence', async () => withServer(async (port) => {
  const secret = 'native-handoff-secret-should-not-appear';
  const res = await heartbeat(port, {
    user: 'tech@example.test',
    orgId: 'cu-acme',
    source: 'endpoint_agent',
    destination: 'endpoint-install',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
    checks: [
      { id: 'endpoint_env_file', ok: true, detail: 'found' },
      { id: 'handoff_secret', ok: false, detail: 'missing 32-plus character handoff secret' },
    ],
    secret,
  });
  assert.strictEqual(res.status, 400);
  const invalid = await res.json();
  assert.deepStrictEqual(invalid.fields, ['secret']);

  const ok = await heartbeat(port, {
    user: 'tech@example.test',
    orgId: 'cu-acme',
    source: 'endpoint_agent',
    destination: 'endpoint-install',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
    checks: [
      { id: 'endpoint_env_file', ok: true, detail: 'found' },
      { id: 'handoff_secret', ok: false, detail: 'missing 32-plus character handoff secret' },
    ],
  });
  assert.strictEqual(ok.status, 200);
  const body = await ok.json();
  assert.strictEqual(body.decision, 'recorded');
  assert.strictEqual(body.status, 'sensor_heartbeat');
  assert.deepStrictEqual(body.failedChecks, ['handoff_secret']);

  const row = db.getQuery(body.id);
  assert.strictEqual(row.status, 'sensor_heartbeat');
  assert.strictEqual(row.mode, 'sensor_health');
  assert.strictEqual(row.channel, 'sensor_health');
  assert.strictEqual(row.redactedPrompt, '[sensor heartbeat] endpoint_agent');
  assert.deepStrictEqual(row.installChecks.map((item) => [item.id, item.ok]), [
    ['endpoint_env_file', true],
    ['handoff_secret', false],
  ]);
  assert.ok(!JSON.stringify(row).includes(secret));

  const audit = db.listAudit(10);
  assert.strictEqual(audit[0].action, 'SENSOR_HEALTH_ATTENTION');
  assert.strictEqual(audit[0].queryId, row.id);
  assert.strictEqual(db.verifyAuditChain().ok, true);

  const report = coverage.summarize(db.listQueries({ limit: 10 }), {
    requiredSensors: ['endpoint_agent'],
    desiredSensorVersions: { endpoint_agent: '0.3.0' },
  });
  const sensor = report.sensors.find((item) => item.source === 'endpoint_agent');
  assert.strictEqual(report.totals.activeSensorHealthWarnings, 1);
  assert.strictEqual(sensor.installHealth.state, 'attention');
  assert.deepStrictEqual(sensor.installHealth.failedChecks, ['handoff_secret']);
  assert.ok(report.posture.some((item) => item.id === 'endpoint_agent' && item.state === 'attention' && /failed checks/.test(item.detail)));

  const pack = evidence.buildEvidencePack({
    version: '0.3.0',
    queryLimit: 10,
    auditLimit: 10,
    policy: {},
    stats: db.stats(),
    auditIntegrity: db.verifyAuditChain(),
    coverage: report,
    queries: db.listQueries({ limit: 10 }),
    audit,
  });
  assert.strictEqual(pack.queries[0].installChecks[1].id, 'handoff_secret');
  assert.strictEqual(pack.coverage.sensors[0].installHealth.state, 'attention');
  assert.ok(!JSON.stringify(pack).includes(secret));
}));

test('endpoint AI tool inventory attention does not emit sensor-health failure', async () => withServer(async (port) => {
  const res = await heartbeat(port, {
    user: 'ai-tools@example.test',
    orgId: 'cu-acme',
    source: 'endpoint_agent',
    destination: 'endpoint-install',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
    checks: [
      { id: 'endpoint_env_file', ok: true, detail: 'found' },
      { id: 'ai_tool_inventory', ok: true, detail: 'detected:2' },
      { id: 'ai_tool_cursor', ok: true, detail: 'detected' },
      { id: 'ai_tool_claude_desktop', ok: false, detail: 'unapproved detected' },
    ],
  });
  assert.strictEqual(res.status, 200);
  const body = await res.json();
  assert.strictEqual(body.decision, 'recorded');
  assert.strictEqual(body.status, 'sensor_heartbeat');
  assert.deepStrictEqual(body.failedChecks, []);

  const row = db.getQuery(body.id);
  assert.deepStrictEqual(row.reasons, ['Endpoint AI tool inventory attention: claude_desktop']);
  assert.deepStrictEqual(row.installChecks.map((item) => [item.id, item.ok]), [
    ['endpoint_env_file', true],
    ['ai_tool_inventory', true],
    ['ai_tool_cursor', true],
    ['ai_tool_claude_desktop', false],
  ]);

  const audit = db.listAudit(20).filter((item) => item.queryId === row.id);
  assert.deepStrictEqual(audit.map((item) => item.action), ['ENDPOINT_AI_TOOL_ATTENTION', 'SENSOR_HEARTBEAT']);
  assert.ok(!audit.some((item) => item.action === 'SENSOR_HEALTH_ATTENTION'));
  assert.strictEqual(db.verifyAuditChain().ok, true);

  const report = coverage.summarize([row], {
    requiredSensors: ['endpoint_agent'],
    desiredSensorVersions: { endpoint_agent: '0.3.0' },
  });
  const sensor = report.sensors.find((item) => item.source === 'endpoint_agent');
  assert.strictEqual(report.totals.activeSensorHealthWarnings, 0);
  assert.strictEqual(report.totals.endpointAiToolUnapproved, 1);
  assert.strictEqual(sensor.installHealth.state, 'covered');
  assert.deepStrictEqual(sensor.installHealth.failedChecks, []);
  assert.ok(report.posture.some((item) => item.id === 'endpoint_agent' && item.state === 'covered'));
  assert.ok(report.posture.some((item) => item.id === 'endpoint_ai_tools' && item.state === 'attention' && /1 unapproved/.test(item.detail)));

  const pack = evidence.buildEvidencePack({
    version: '0.3.0',
    queryLimit: 10,
    auditLimit: 10,
    policy: {},
    stats: db.stats(),
    auditIntegrity: db.verifyAuditChain(),
    coverage: report,
    queries: [row],
    audit,
  });
  const coverageControl = pack.controlMappings.find((item) => item.id === 'fleet_sensor_coverage');
  assert.strictEqual(coverageControl.state, 'attention');
  assert.match(coverageControl.summary, /Endpoint AI tools: 2 detected tools \/ 1 unapproved/);
}));

test('heartbeat endpoint rejects unknown prompt-like fields without echoing values', async () => withServer(async (port) => {
  const rawPrompt = 'Member SSN 524-71-9043';
  const res = await heartbeat(port, {
    source: 'endpoint_agent',
    rawPrompt,
    checks: [{ id: 'endpoint_env_file', ok: true }],
  });
  assert.strictEqual(res.status, 400);
  const body = await res.json();
  assert.deepStrictEqual(body, {
    error: 'invalid request body',
    fields: ['rawPrompt'],
  });
  assert.ok(!JSON.stringify(body).includes(rawPrompt));
}));

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
});
