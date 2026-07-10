'use strict';
/** Single-host redundant gateway assets should stay hardened and smokeable. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { runSmoke } = require('../scripts/smoke-ai-gateway-ha');

const root = path.join(__dirname, '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.gateway-ha.yml'), 'utf8');
const nginx = fs.readFileSync(path.join(root, 'infra', 'ai-gateway-ha', 'nginx.conf'), 'utf8');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const gatewayDocs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'AI_LLM_GATEWAY.md'), 'utf8');
const deploymentDocs = fs.readFileSync(path.join(root, 'docs', 'deployment', 'DEPLOYMENT.md'), 'utf8');

test('AI gateway redundant compose publishes only a loopback-bound load balancer', () => {
  for (const service of ['ai-gateway-a', 'ai-gateway-b', 'ai-gateway-lb']) {
    assert.match(compose, new RegExp(`^  ${service}:`, 'm'), service);
  }
  assert.doesNotMatch(compose, /^  ai-gateway-limiter:/m);
  assert.strictEqual((compose.match(/REDACTWALL_GATEWAY_RATE_LIMIT_STORE:\s+sqlite/g) || []).length, 1);
  assert.match(compose, /REDACTWALL_GATEWAY_RATE_LIMIT_DB:\s+\/data\/gateway-rate-limits\.db/);
  assert.match(compose, /REDACTWALL_URL:\s+\$\{REDACTWALL_URL:\?set an HTTPS REDACTWALL_URL\}/);
  assert.strictEqual((compose.match(/-\s+gateway-limiter-data:\/data/g) || []).length, 2);
  assert.match(compose, /"\$\{REDACTWALL_GATEWAY_BIND_ADDRESS:-127\.0\.0\.1\}:\$\{REDACTWALL_GATEWAY_PUBLIC_PORT:-4182\}:4182"/);
  assert.doesNotMatch(compose, /network_mode:|REDACTWALL_GATEWAY_RATE_LIMIT_TOKEN/);
  assert.doesNotMatch(compose, /4183:4183/);
});

test('AI gateway redundant containers use the hardened runtime posture', () => {
  assert.strictEqual((compose.match(/command: \["node", "scripts\/ai-llm-gateway\.js", "--host", "0\.0\.0\.0", "--port", "4182"\]/g) || []).length, 2);
  assert.match(compose, /read_only:\s+true/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /cap_drop:\r?\n\s+- ALL/);
  assert.match(compose, /\/tmp:rw,noexec,nosuid,size=64m/);
  assert.match(compose, /\/readyz/);
  assert.match(compose, /ai-gateway-lb:[\s\S]*?user: "101:101"/);
  for (const target of ['/var/cache/nginx', '/var/run', '/tmp']) {
    const escaped = target.replaceAll('/', '\\/');
    assert.match(compose, new RegExp(`${escaped}:rw,noexec,nosuid,uid=101,gid=101,mode=0700`));
  }
});

test('AI gateway load balancer health follows authenticated backend readiness', () => {
  const balancer = compose.match(/\n  ai-gateway-lb:[\s\S]*?\nvolumes:/)?.[0] || '';
  assert.match(balancer, /http:\/\/127\.0\.0\.1:4182\/readyz/);
  assert.doesNotMatch(balancer, /http:\/\/127\.0\.0\.1:4182\/healthz/);
});

test('AI gateway redundant balancer disables prompt-sensitive access logging', () => {
  assert.match(nginx, /access_log off;/);
  assert.match(nginx, /resolver 127\.0\.0\.11 valid=5s ipv6=off;/);
  assert.match(nginx, /upstream redactwall_ai_gateway/);
  assert.match(nginx, /zone redactwall_ai_gateway 64k;/);
  assert.match(nginx, /server ai-gateway-a:4182 resolve/);
  assert.match(nginx, /server ai-gateway-b:4182 resolve/);
  assert.match(nginx, /proxy_connect_timeout 2s;/);
  assert.match(nginx, /proxy_next_upstream error timeout;/);
  assert.match(nginx, /proxy_next_upstream_tries 2;/);
  assert.doesNotMatch(nginx, /non_idempotent/);
  assert.match(nginx, /proxy_buffering off;/);
  assert.match(nginx, /X-RedactWall-Request-Id/);
});

test('AI gateway docs state the single-host failure domain and expose a smoke path', () => {
  assert.strictEqual(packageJson.scripts['gateway:ha:smoke'], 'node scripts/smoke-ai-gateway-ha.js');
  assert.match(gatewayDocs, /docker compose -f docker-compose\.gateway-ha\.yml up -d --build/);
  assert.match(gatewayDocs, /not multi-host high availability/);
  assert.match(gatewayDocs, /REDACTWALL_GATEWAY_BIND_ADDRESS.*default `127\.0\.0\.1`/s);
  assert.match(gatewayDocs, /npm run gateway:ha:smoke/);
  assert.match(deploymentDocs, /single-host redundant gateway layer/);
  assert.match(deploymentDocs, /disables load-balancer access logs/);
  assert.match(deploymentDocs, /not multi-host high\s+availability/);
});

test('AI gateway redundancy smoke proves survivor and restart limiter continuity', async () => {
  const result = await runSmoke();
  assert.deepStrictEqual(result.gatewayReplicaStatuses, [200, 429]);
  assert.strictEqual(result.restartedReplicaStatus, 429);
  assert.strictEqual(result.sharedLimiter, true);
  assert.strictEqual(result.limiterStore, 'sqlite');
  assert.strictEqual(result.scope, 'single_host');
});
