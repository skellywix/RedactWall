'use strict';
/** HA gateway deployment assets should stay hardened and smokeable. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { runSmoke } = require('../scripts/smoke-ai-gateway-ha');

const root = path.join(__dirname, '..');
const compose = fs.readFileSync(path.join(root, 'docker-compose.gateway-ha.yml'), 'utf8');
const nginx = fs.readFileSync(path.join(root, 'infra', 'ai-gateway-ha', 'nginx.conf'), 'utf8');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const gatewayDocs = fs.readFileSync(path.join(root, 'docs', 'AI_LLM_GATEWAY.md'), 'utf8');
const deploymentDocs = fs.readFileSync(path.join(root, 'docs', 'DEPLOYMENT.md'), 'utf8');

test('AI gateway HA compose publishes only the load-balanced gateway', () => {
  for (const service of ['ai-gateway-limiter', 'ai-gateway-a', 'ai-gateway-b', 'ai-gateway-lb']) {
    assert.match(compose, new RegExp(`^  ${service}:`, 'm'), service);
  }
  assert.match(compose, /PROMPTWALL_GATEWAY_RATE_LIMIT_STORE:\s+http/);
  assert.match(compose, /PROMPTWALL_GATEWAY_RATE_LIMIT_URL:\s+http:\/\/ai-gateway-limiter:4183\/check/);
  assert.match(compose, /PROMPTWALL_GATEWAY_RATE_LIMIT_TOKEN:\s+\$\{PROMPTWALL_RATE_LIMITER_TOKEN:\?set PROMPTWALL_RATE_LIMITER_TOKEN\}/);
  assert.match(compose, /PROMPTWALL_RATE_LIMITER_STORE:\s+\$\{PROMPTWALL_RATE_LIMITER_STORE:-sqlite\}/);
  assert.match(compose, /PROMPTWALL_RATE_LIMITER_REDIS_URL:\s+\$\{PROMPTWALL_RATE_LIMITER_REDIS_URL:-\}/);
  assert.match(compose, /PROMPTWALL_RATE_LIMITER_DB:\s+\/data\/gateway-shared-rate-limiter\.db/);
  assert.match(compose, /-\s+gateway-limiter-data:\/data/);
  assert.match(compose, /"\$\{PROMPTWALL_GATEWAY_PUBLIC_PORT:-4182\}:4182"/);
  assert.doesNotMatch(compose, /4183:4183/);
});

test('AI gateway HA containers use the hardened runtime posture', () => {
  assert.match(compose, /command: \["node", "scripts\/ai-llm-gateway\.js", "--host", "0\.0\.0\.0", "--port", "4182"\]/);
  assert.match(compose, /command: \["node", "scripts\/ai-gateway-rate-limiter\.js", "--host", "0\.0\.0\.0", "--port", "4183"\]/);
  assert.match(compose, /read_only:\s+true/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /cap_drop:\r?\n\s+- ALL/);
  assert.match(compose, /\/tmp:rw,noexec,nosuid,size=64m/);
  assert.match(compose, /\/readyz/);
});

test('AI gateway HA balancer disables prompt-sensitive access logging', () => {
  assert.match(nginx, /access_log off;/);
  assert.match(nginx, /upstream promptwall_ai_gateway/);
  assert.match(nginx, /server ai-gateway-a:4182/);
  assert.match(nginx, /server ai-gateway-b:4182/);
  assert.match(nginx, /proxy_buffering off;/);
  assert.match(nginx, /X-PromptWall-Request-Id/);
});

test('AI gateway HA docs and scripts expose an operator smoke path', () => {
  assert.strictEqual(packageJson.scripts['gateway:ha:smoke'], 'node scripts/smoke-ai-gateway-ha.js');
  assert.match(gatewayDocs, /docker compose -f docker-compose\.gateway-ha\.yml up -d --build/);
  assert.match(gatewayDocs, /PROMPTWALL_RATE_LIMITER_STORE = "redis"/);
  assert.match(gatewayDocs, /--scale ai-gateway-limiter=2/);
  assert.match(gatewayDocs, /npm run gateway:ha:smoke/);
  assert.match(deploymentDocs, /docker-compose\.gateway-ha\.yml` publishes only the gateway load balancer/);
  assert.match(deploymentDocs, /disables load-balancer access logs/);
  assert.match(deploymentDocs, /active-active limiter replicas/);
});

test('AI gateway HA smoke proves shared limiter state across replicas', async () => {
  const result = await runSmoke();
  assert.deepStrictEqual(result.gatewayReplicaStatuses, [200, 429]);
  assert.strictEqual(result.sharedLimiter, true);
  assert.strictEqual(result.limiterStore, 'http');
});
