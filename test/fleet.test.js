'use strict';
/** Sensors report on each other: heartbeats build a per-user presence map,
 *  heartbeat responses carry companion state, and the console sees the gaps. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-fleet-' + crypto.randomBytes(6).toString('hex') + '.db');

const app = require('../server/app');
const auth = require('../server/auth');
const { listen } = require('./support/listen');

const INGEST = { 'x-api-key': 'unit-ingest-key', 'Content-Type': 'application/json' };

async function withServer(fn) {
  const server = await listen(app);
  try {
    return await fn(server.address().port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function heartbeat(port, body) {
  return fetch(`http://127.0.0.1:${port}/api/v1/heartbeat`, { method: 'POST', headers: INGEST, body: JSON.stringify(body) });
}

test('heartbeat response tells a sensor about its companions', async () => withServer(async (port) => {
  const first = await heartbeat(port, { user: 'pat@example.test', source: 'browser_extension', sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome' } });
  assert.strictEqual(first.status, 200);
  const view = (await first.json()).companions;
  assert.strictEqual(view.endpoint_agent, 'missing', 'extension learns the agent is not installed');
  assert.strictEqual(view.mcp_guard, 'missing');
  assert.strictEqual(view.browser_extension, undefined, 'a sensor is not told about itself');

  const second = await heartbeat(port, { user: 'pat@example.test', source: 'endpoint_agent', sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'linux' } });
  const agentView = (await second.json()).companions;
  assert.strictEqual(agentView.browser_extension, 'active', 'agent learns the extension is reporting');

  const third = await heartbeat(port, { user: 'pat@example.test', source: 'browser_extension' });
  assert.strictEqual((await third.json()).companions.endpoint_agent, 'active', 'gap closes once the agent reports');
}));

test('fleet summary shows per-user sensors and companion gaps to the console', async () => withServer(async (port) => {
  await heartbeat(port, { user: 'solo@example.test', source: 'browser_extension', sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome' } });
  const cookie = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('auditor@x', 'auditor')}`;
  const r = await fetch(`http://127.0.0.1:${port}/api/fleet`, { headers: { cookie } });
  assert.strictEqual(r.status, 200);
  const fleet = await r.json();
  assert.deepStrictEqual(fleet.trackedSensors, ['browser_extension', 'endpoint_agent', 'mcp_guard']);
  const solo = fleet.users.find((u) => u.user === 'solo@example.test');
  assert.strictEqual(solo.sensors.browser_extension.state, 'active');
  assert.strictEqual(solo.sensors.browser_extension.version, '0.3.0');
  assert.strictEqual(solo.sensors.endpoint_agent.state, 'missing');
  assert.ok(solo.gaps.some((g) => g.sensor === 'endpoint_agent' && g.reportedBy === 'browser_extension'));
  assert.ok(fleet.gapCount >= 1);
  assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/fleet`)).status, 401, 'fleet view requires a session');
}));

test('gate traffic counts as presence, not just heartbeats', async () => withServer(async (port) => {
  const gate = await fetch(`http://127.0.0.1:${port}/api/v1/gate`, {
    method: 'POST',
    headers: INGEST,
    body: JSON.stringify({ prompt: 'What are our branch hours?', user: 'gate-only@example.test', destination: 'chatgpt.com', source: 'endpoint_agent', channel: 'submit', sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' } }),
  });
  assert.strictEqual(gate.status, 200);
  const beat = await heartbeat(port, { user: 'gate-only@example.test', source: 'browser_extension' });
  assert.strictEqual((await beat.json()).companions.endpoint_agent, 'active');
}));

test('agent and guard heartbeat senders post the right shape', async () => {
  const agent = require('../sensors/endpoint-agent/agent');
  const guard = require('../sensors/mcp-guard/guard');
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, body: JSON.parse(opts.body) });
    return { ok: true, status: 200, json: async () => ({ companions: { browser_extension: 'missing' } }) };
  };
  await agent.sendHeartbeat({ server: 'http://x', key: 'k', fetchImpl, user: 'tech@example.test' });
  await guard.sendHeartbeat({ server: 'http://x', key: 'k', fetchImpl, agent: 'copilot-agent' });
  assert.strictEqual(calls.length, 2);
  assert.ok(calls[0].url.endsWith('/api/v1/heartbeat'));
  assert.deepStrictEqual(calls[0].body.source, 'endpoint_agent');
  assert.strictEqual(calls[0].body.user, 'tech@example.test');
  assert.strictEqual(calls[0].body.sensor.name, 'endpoint_agent');
  assert.strictEqual(calls[1].body.source, 'mcp_guard');
  assert.strictEqual(calls[1].body.user, 'copilot-agent');
});
