'use strict';
/**
 * Local single-host redundancy smoke for the AI gateway shared SQLite limiter.
 *
 * This does not call an external LLM provider. It starts two gateway replicas
 * against one local SQLite counter store, removes one replica, and proves the
 * survivor plus a restarted replica retain the same privacy-safe counter.
 */
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createGatewayServer } = require('./ai-llm-gateway');

function jsonFetchResponse(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

function listen(server, host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve) => {
    if (!server || !server.listening) return resolve();
    return server.close(() => resolve());
  });
}

function gatewayRequest(port, token) {
  const payload = JSON.stringify({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: 'Summarize the public pilot readiness checklist.' }],
  });
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: '/v1/chat/completions',
      headers: {
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        'x-redactwall-user': 'gateway-ha-smoke@example.test',
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function runSmoke(opts = {}) {
  if (!globalThis.fetch) throw new Error('global fetch is required for the shared limiter smoke');
  const clientToken = opts.clientToken || 'gateway-ha-client-token';
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-gateway-redundancy-'));
  const limiterDb = path.join(tempRoot, 'gateway-rate-limits.db');
  let gatewayA;
  let gatewayB;
  let gatewayRestarted;
  try {
    const fetchImpl = async (url) => {
      const target = String(url || '');
      if (target.includes('/api/v1/gate')) {
        return jsonFetchResponse(200, { id: 'q_gateway_ha_smoke', decision: 'allow', status: 'allowed' });
      }
      if (target.includes('/api/v1/scan-response')) {
        return jsonFetchResponse(200, { leaked: false, decision: 'allow', status: 'allowed', blocked: false });
      }
      return jsonFetchResponse(200, { choices: [{ message: { role: 'assistant', content: 'safe gateway HA smoke answer' } }] });
    };
    const gatewayOpts = {
      clientToken,
      key: 'gateway-ha-smoke-ingest-key',
      redactwall: 'https://redactwall-control.local',
      upstream: 'https://upstream.local',
      rateLimitStore: 'sqlite',
      rateLimit: 1,
      rateWindowMs: 60000,
      rateLimitDbPath: limiterDb,
      fetchImpl,
    };
    gatewayA = createGatewayServer(gatewayOpts);
    gatewayB = createGatewayServer(gatewayOpts);
    const gatewayAPort = await listen(gatewayA);
    const gatewayBPort = await listen(gatewayB);

    const first = await gatewayRequest(gatewayAPort, clientToken);
    await close(gatewayA);
    gatewayA = null;
    const second = await gatewayRequest(gatewayBPort, clientToken);
    if (first.status !== 200) throw new Error(`first gateway replica returned ${first.status}: ${first.body}`);
    if (second.status !== 429) throw new Error(`second gateway replica did not share limiter state: ${second.status}`);
    await close(gatewayB);
    gatewayB = null;
    gatewayRestarted = createGatewayServer(gatewayOpts);
    const restartedPort = await listen(gatewayRestarted);
    const restarted = await gatewayRequest(restartedPort, clientToken);
    if (restarted.status !== 429) throw new Error(`restarted gateway lost limiter state: ${restarted.status}`);
    return {
      ok: true,
      sharedLimiter: true,
      gatewayReplicaStatuses: [first.status, second.status],
      restartedReplicaStatus: restarted.status,
      limiterStore: 'sqlite',
      scope: 'single_host',
    };
  } finally {
    await close(gatewayA);
    await close(gatewayB);
    await close(gatewayRestarted);
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

if (require.main === module) {
  runSmoke().then((result) => {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  }).catch((err) => {
    process.stderr.write(`${err && err.message ? err.message : err}\n`);
    process.exitCode = 1;
  });
}

module.exports = { runSmoke };
