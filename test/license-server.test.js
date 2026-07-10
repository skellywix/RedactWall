'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { once } = require('node:events');

const REPO_ROOT = path.join(__dirname, '..');
const SERVER_PATH = path.join(REPO_ROOT, 'infra', 'license-server', 'server.js');
const LICENSE_INFRA = path.dirname(SERVER_PATH);
const VERDICT_DOMAIN = 'redactwall.connected-license-verdict.v1';
const TOKENS = Object.freeze({
  active: 'rwls_test_active_0123456789abcdef0123456789',
  revoked: 'rwls_test_revoked_0123456789abcdef01234567',
  other: 'rwls_test_other_0123456789abcdef0123456789',
});

function tokenSha256(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

function writePrivateJson(file, value) {
  fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function customerRegistry() {
  return {
    'cu-active': { tokenSha256: tokenSha256(TOKENS.active), plans: ['standard'] },
    'cu-revoked': { tokenSha256: tokenSha256(TOKENS.revoked), plans: ['standard'] },
    'cu-other': { tokenSha256: tokenSha256(TOKENS.other), plans: ['standard', 'enterprise'] },
  };
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = once(child, 'exit');
  child.kill();
  let timer;
  await Promise.race([exited, new Promise((resolve) => {
    timer = setTimeout(resolve, 3000);
    if (timer.unref) timer.unref();
  })]);
  clearTimeout(timer);
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
}

async function startLicenseServer(t, options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-server-test-'));
  const keyPath = path.join(dir, 'verdict-signing-key.pem');
  const rootPublicKeyPath = path.join(dir, 'offline-license-root-pub.pem');
  const revokedPath = path.join(dir, 'revoked.json');
  const customersPath = path.join(dir, 'customers.json');
  const logPath = path.join(dir, 'heartbeats.jsonl');
  const online = crypto.generateKeyPairSync('ed25519');
  const offline = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(keyPath, online.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.chmodSync(keyPath, 0o600);
  fs.writeFileSync(rootPublicKeyPath, offline.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  fs.chmodSync(rootPublicKeyPath, 0o600);
  writePrivateJson(revokedPath, []);
  writePrivateJson(customersPath, options.customers || customerRegistry());

  const child = spawn(process.execPath, [SERVER_PATH], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      LICENSE_SERVER_HOST: '127.0.0.1',
      LICENSE_SERVER_PORT: '0',
      LICENSE_SIGNING_KEY_PATH: '',
      LICENSE_VERDICT_SIGNING_KEY_PATH: keyPath,
      LICENSE_ROOT_PUBLIC_KEY_PATH: rootPublicKeyPath,
      LICENSE_REVOKED_PATH: revokedPath,
      LICENSE_CUSTOMERS_PATH: customersPath,
      LICENSE_HEARTBEAT_LOG: logPath,
      LICENSE_BODY_TIMEOUT_MS: String(options.bodyTimeoutMs || 500),
      LICENSE_RATE_LIMIT_PER_MINUTE: String(options.rateLimit || 60),
      LICENSE_HEARTBEAT_LOG_MAX_BYTES: String(options.logMaxBytes || (1024 * 1024)),
      ...(options.env || {}),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => { stdout += chunk; });
  child.stderr.on('data', (chunk) => { stderr += chunk; });

  const port = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`license server start timed out: ${stderr}`)), 5000);
    const inspect = () => {
      const match = stdout.match(/http:\/\/127\.0\.0\.1:(\d+)/);
      if (!match) return;
      clearTimeout(timeout);
      resolve(Number(match[1]));
    };
    child.stdout.on('data', inspect);
    child.once('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`license server exited ${code}: ${stderr}`));
    });
  });

  t.after(async () => {
    await stopChild(child);
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return {
    origin: `http://127.0.0.1:${port}`,
    port,
    publicKey: online.publicKey,
    offlinePublicKey: offline.publicKey,
    revokedPath,
    customersPath,
    logPath,
    output: () => ({ stdout, stderr }),
  };
}

function heartbeatBody(customerId, over = {}) {
  return {
    customerId,
    plan: 'standard',
    seatsUsed: 3,
    seatLimit: 10,
    version: '0.3.0',
    sentAt: '2026-07-10T12:00:00.000Z',
    ...over,
  };
}

async function heartbeat(origin, customerId, token, over = {}) {
  const headers = { 'content-type': 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  return fetch(`${origin}/heartbeat`, {
    method: 'POST',
    headers,
    body: JSON.stringify(heartbeatBody(customerId, over)),
  });
}

async function verifiedPayload(response, publicKey) {
  assert.strictEqual(response.status, 200);
  const signed = (await response.text()).trim();
  const parts = signed.split('.');
  assert.strictEqual(parts.length, 2);
  assert.strictEqual(
    crypto.verify(
      null,
      Buffer.from(`${VERDICT_DOMAIN}\0${parts[0]}`, 'utf8'),
      publicKey,
      Buffer.from(parts[1], 'base64'),
    ),
    true,
    'heartbeat verdict is signed by the dedicated online verdict key and domain',
  );
  return { payload: JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8')), signed };
}

function readLog(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch (error) {
    if (error && error.code === 'ENOENT') return '';
    throw error;
  }
}

function slowHeartbeat(port, token) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let response = '';
    const timeout = setTimeout(() => {
      socket.destroy();
      reject(new Error('slow request was not bounded'));
    }, 2000);
    socket.on('connect', () => {
      socket.write([
        'POST /heartbeat HTTP/1.1',
        'Host: 127.0.0.1',
        'Content-Type: application/json',
        `Authorization: Bearer ${token}`,
        'Transfer-Encoding: chunked',
        'Connection: close',
        '',
        '1',
        '{',
        '',
      ].join('\r\n'));
    });
    socket.on('data', (chunk) => { response += chunk.toString('utf8'); });
    socket.on('error', reject);
    socket.on('close', () => {
      clearTimeout(timeout);
      resolve({ response, elapsedMs: Date.now() - started });
    });
  });
}

async function rejectedStartup({ host = '127.0.0.1', reuseOfflineRoot = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-license-root-reuse-test-'));
  const root = crypto.generateKeyPairSync('ed25519');
  const online = reuseOfflineRoot ? root : crypto.generateKeyPairSync('ed25519');
  const privatePath = path.join(dir, 'root-private.pem');
  const publicPath = path.join(dir, 'root-public.pem');
  fs.writeFileSync(privatePath, online.privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(publicPath, root.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  const child = spawn(process.execPath, [SERVER_PATH], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      LICENSE_SERVER_HOST: host,
      LICENSE_SERVER_PORT: '0',
      LICENSE_SIGNING_KEY_PATH: '',
      LICENSE_VERDICT_SIGNING_KEY_PATH: privatePath,
      LICENSE_ROOT_PUBLIC_KEY_PATH: publicPath,
    },
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  });
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  const [code] = await once(child, 'exit');
  fs.rmSync(dir, { recursive: true, force: true });
  return { code, stderr };
}

test('connected license server requires customer-bound authentication and a dedicated signing domain', async (t) => {
  const fixture = await startLicenseServer(t);

  assert.strictEqual((await heartbeat(fixture.origin, 'cu-active')).status, 401, 'anonymous signing is denied');
  assert.strictEqual((await heartbeat(fixture.origin, 'cu-active', TOKENS.other)).status, 401, 'another customer token is denied');
  assert.strictEqual((await heartbeat(fixture.origin, 'cu-unlisted', TOKENS.active)).status, 401, 'arbitrary customer signing is denied');
  assert.strictEqual(readLog(fixture.logPath), '', 'denied signing attempts create no misleading heartbeat log');

  const result = await verifiedPayload(
    await heartbeat(fixture.origin, 'cu-active', TOKENS.active),
    fixture.publicKey,
  );
  assert.deepStrictEqual(
    { kind: result.payload.kind, status: result.payload.status, customerId: result.payload.customerId },
    { kind: VERDICT_DOMAIN, status: 'active', customerId: 'cu-active' },
  );
  const [payloadB64, signatureB64] = result.signed.split('.');
  assert.strictEqual(
    crypto.verify(
      null,
      Buffer.from(`${VERDICT_DOMAIN}\0${payloadB64}`, 'utf8'),
      fixture.offlinePublicKey,
      Buffer.from(signatureB64, 'base64'),
    ),
    false,
    'the offline license-root public key does not verify online verdicts',
  );
});

test('connected license server refuses one bearer credential shared across customer identities', async (t) => {
  const shared = tokenSha256(TOKENS.active);
  const fixture = await startLicenseServer(t, {
    customers: {
      'cu-active': { tokenSha256: shared, plans: ['standard'] },
      'cu-other': { tokenSha256: shared, plans: ['standard'] },
    },
  });
  assert.strictEqual((await fetch(`${fixture.origin}/healthz`)).status, 503);
  assert.strictEqual((await heartbeat(fixture.origin, 'cu-active', TOKENS.active)).status, 503);
  assert.strictEqual(readLog(fixture.logPath), '');
});

test('connected license server refuses the offline license root as its online verdict key', async () => {
  const result = await rejectedStartup({ reuseOfflineRoot: true });
  assert.notStrictEqual(result.code, 0);
  assert.match(result.stderr, /online verdict key must differ from the offline license root/);
});

test('connected license server refuses a cleartext non-loopback listener', async () => {
  const result = await rejectedStartup({ host: '0.0.0.0' });
  assert.notStrictEqual(result.code, 0);
  assert.match(result.stderr, /must bind to a numeric loopback address/);
});

test('connected license server applies revocations and fails closed on unavailable authority', async (t) => {
  const fixture = await startLicenseServer(t);

  let health = await fetch(`${fixture.origin}/healthz`);
  assert.strictEqual(health.status, 200);
  let result = await verifiedPayload(await heartbeat(fixture.origin, 'cu-active', TOKENS.active), fixture.publicKey);
  assert.strictEqual(result.payload.status, 'active');

  writePrivateJson(fixture.revokedPath, ['cu-revoked']);
  result = await verifiedPayload(await heartbeat(fixture.origin, 'cu-revoked', TOKENS.revoked), fixture.publicKey);
  assert.strictEqual(result.payload.status, 'revoked');
  result = await verifiedPayload(await heartbeat(fixture.origin, 'cu-other', TOKENS.other), fixture.publicKey);
  assert.strictEqual(result.payload.status, 'active');

  if (process.platform !== 'win32') {
    fs.chmodSync(fixture.revokedPath, 0o666);
    health = await fetch(`${fixture.origin}/healthz`);
    assert.strictEqual(health.status, 503, 'writable revocation authority makes the service unready');
    const writableRejected = await heartbeat(fixture.origin, 'cu-revoked', TOKENS.revoked);
    assert.strictEqual(writableRejected.status, 503, 'writable authority never signs an active verdict');
    fs.chmodSync(fixture.revokedPath, 0o600);
  }

  writePrivateJson(fixture.revokedPath, '{not valid json');
  health = await fetch(`${fixture.origin}/healthz`);
  assert.strictEqual(health.status, 503, 'malformed revocation state makes the service unready');
  let rejected = await heartbeat(fixture.origin, 'cu-revoked', TOKENS.revoked);
  assert.strictEqual(rejected.status, 503, 'malformed state never signs an active verdict');
  assert.strictEqual((await rejected.text()).trim(), 'service unavailable');

  fs.rmSync(fixture.revokedPath);
  health = await fetch(`${fixture.origin}/healthz`);
  assert.strictEqual(health.status, 503, 'missing revocation state makes the service unready');
  rejected = await heartbeat(fixture.origin, 'cu-revoked', TOKENS.revoked);
  assert.strictEqual(rejected.status, 503, 'missing state never signs an active verdict');

  const logged = readLog(fixture.logPath).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
  assert.deepStrictEqual(
    logged.map((entry) => entry.verdict),
    ['active', 'revoked', 'active'],
    'failed authority checks do not create misleading heartbeat evidence',
  );
  assert.ok(logged.every((entry) => !Object.hasOwn(entry, 'customerId')), 'logs use a bounded customer reference');
});

test('malformed, oversized, and slow heartbeat requests are bounded without leaking attacker input', async (t) => {
  const fixture = await startLicenseServer(t, { bodyTimeoutMs: 100 });
  const secret = 'raw-secret-value-should-never-be-logged';

  const malformed = await heartbeat(fixture.origin, 'cu-active', TOKENS.active, {
    version: `0.3.0\n${secret}`,
  });
  assert.strictEqual(malformed.status, 400);
  assert.strictEqual((await malformed.text()).trim(), 'bad request');

  const badPlan = await heartbeat(fixture.origin, 'cu-active', TOKENS.active, { plan: 'unlimited' });
  assert.strictEqual(badPlan.status, 400);

  const badCustomer = await heartbeat(fixture.origin, `cu-active\n${secret}`, TOKENS.active);
  assert.strictEqual(badCustomer.status, 400);

  const longVersion = await heartbeat(fixture.origin, 'cu-active', TOKENS.active, {
    version: `1.2.3-${'a'.repeat(40)}`,
  });
  assert.strictEqual(longVersion.status, 400);

  const oversized = await fetch(`${fixture.origin}/heartbeat`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${TOKENS.active}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ padding: 'x'.repeat(20 * 1024), secret }),
  });
  assert.strictEqual(oversized.status, 413);

  const slow = await slowHeartbeat(fixture.port, TOKENS.active);
  assert.ok(slow.elapsedMs < 1500, `absolute body deadline closed the request in ${slow.elapsedMs}ms`);
  assert.match(slow.response, /HTTP\/1\.1 408 Request Timeout/);

  const output = `${fixture.output().stdout}\n${fixture.output().stderr}\n${readLog(fixture.logPath)}`;
  assert.ok(!output.includes(secret));
  assert.ok(!output.includes(TOKENS.active));
  assert.strictEqual(readLog(fixture.logPath), '', 'rejected requests never enter the heartbeat log');
});

test('per-credential rate limiting and the heartbeat log cap bound online abuse', async (t) => {
  const limited = await startLicenseServer(t, { rateLimit: 2 });
  assert.strictEqual((await heartbeat(limited.origin, 'cu-active', TOKENS.active)).status, 200);
  assert.strictEqual((await heartbeat(limited.origin, 'cu-active', TOKENS.active)).status, 200);
  const rejected = await heartbeat(limited.origin, 'cu-active', TOKENS.active);
  assert.strictEqual(rejected.status, 429);
  assert.strictEqual(rejected.headers.get('retry-after'), '60');

  const capped = await startLicenseServer(t, { logMaxBytes: 512 });
  for (let i = 0; i < 12; i += 1) {
    const response = await heartbeat(capped.origin, 'cu-active', TOKENS.active, { seatsUsed: i });
    assert.strictEqual(response.status, 200);
  }
  assert.ok(fs.statSync(capped.logPath).size <= 512, 'heartbeat log never grows past its configured cap');
});

test('connected-license deployment files wire the hardened key and credential contract', () => {
  const service = fs.readFileSync(path.join(LICENSE_INFRA, 'redactwall-license.service'), 'utf8');
  const caddy = fs.readFileSync(path.join(LICENSE_INFRA, 'Caddyfile'), 'utf8');
  const overlay = fs.readFileSync(path.join(LICENSE_INFRA, 'docker-compose.connected.override.yml'), 'utf8');
  const readme = fs.readFileSync(path.join(LICENSE_INFRA, 'README.md'), 'utf8');

  assert.doesNotMatch(service, /^Environment=LICENSE_SIGNING_KEY_PATH=/m);
  assert.match(service, /^Environment=LICENSE_VERDICT_SIGNING_KEY_PATH=/m);
  assert.match(service, /^Environment=LICENSE_ROOT_PUBLIC_KEY_PATH=/m);
  assert.match(service, /^Environment=LICENSE_CUSTOMERS_PATH=/m);
  assert.match(caddy, /@heartbeat path \/heartbeat/);
  assert.match(caddy, /handle @heartbeat \{[\s\S]*reverse_proxy 127\.0\.0\.1:8080/);
  assert.match(caddy, /header_up X-Forwarded-For \{remote_host\}/);
  assert.match(caddy, /handle \{\s*respond 404\s*\}/);
  assert.match(overlay, /REDACTWALL_LICENSE_SERVER_TOKEN/);
  assert.match(overlay, /REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY/);
  assert.match(readme, /offline private key must never be copied to this host/i);
});
