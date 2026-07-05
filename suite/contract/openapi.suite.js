// @tier smoke
'use strict';
/**
 * Contract: the OpenAPI 3.1 spec at /api/v1/openapi.json stays in sync with the
 * real routes and the Zod validators, and never contains PII or the ingest key.
 * If the spec and the validators drift, the example-validation checks go red.
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const support = require('../support/app');
support.bootEnv();
const app = support.requireApp();
const ROOT = path.join(__dirname, '..', '..');
const validation = require(path.join(ROOT, 'server', 'validation'));
const pkg = require(path.join(ROOT, 'package.json'));

// Same canonical list the sensor-routes contract uses.
const SENSOR_ROUTES = [
  ['post', '/api/v1/gate'], ['post', '/api/v1/discovery'], ['post', '/api/v1/heartbeat'],
  ['get', '/api/v1/policy'], ['get', '/api/v1/policy/bundle'], ['get', '/api/v1/policy/pubkey'],
  ['get', '/api/v1/detectors'], ['post', '/api/v1/scan-file'], ['post', '/api/v1/scan-response'],
  ['post', '/api/v1/rehydrate'], ['get', '/api/v1/status/{id}'],
];

test('serves an OpenAPI 3.1 document with the package version', async () => support.withServer(app, async (port) => {
  const res = await support.request(port, '/api/v1/openapi.json', { method: 'GET' });
  assert.strictEqual(res.status, 200, 'openapi.json is public (no key)');
  const doc = await res.json();
  assert.ok(String(doc.openapi).startsWith('3.1'), 'OpenAPI 3.1');
  assert.strictEqual(doc.info.version, pkg.version);
  assert.ok(doc.components.securitySchemes.IngestKey);
}));

test('spec covers every sensor route and each is key-guarded', async () => support.withServer(app, async (port) => {
  const doc = await (await support.request(port, '/api/v1/openapi.json', { method: 'GET' })).json();
  for (const [method, route] of SENSOR_ROUTES) {
    assert.ok(doc.paths[route] && doc.paths[route][method], `spec missing ${method} ${route}`);
  }
  // Two-way parity: every documented op answers 401 without the ingest key.
  for (const [method, route] of SENSOR_ROUTES) {
    if (route === '/api/v1/openapi.json') continue;
    const realPath = route.replace('{id}', 'q_nope');
    const r = await support.request(port, realPath, { method: method.toUpperCase(), body: method === 'post' ? {} : undefined });
    assert.strictEqual(r.status, 401, `${method} ${route} must be key-guarded`);
  }
}));

test('every POST example validates against its Zod schema and drift fails', async () => support.withServer(app, async (port) => {
  const doc = await (await support.request(port, '/api/v1/openapi.json', { method: 'GET' })).json();
  const schemaFor = {
    '/api/v1/gate': validation.gateSchema,
    '/api/v1/scan-file': validation.scanFileSchema,
    '/api/v1/scan-response': validation.scanResponseSchema,
    '/api/v1/rehydrate': validation.rehydrateSchema,
    '/api/v1/discovery': validation.aiDiscoverySchema,
    '/api/v1/heartbeat': validation.heartbeatSchema,
  };
  for (const [route, schema] of Object.entries(schemaFor)) {
    const example = doc.paths[route].post.requestBody.content['application/json'].example;
    assert.ok(example, `${route} POST must embed an example`);
    assert.ok(schema.safeParse(example).success, `${route} example must satisfy its validator`);
  }
  // A mutated gate example (no prompt) must fail its validator.
  assert.strictEqual(validation.gateSchema.safeParse({ destination: 'x' }).success, false);
  // GateRequest is generated from Zod: prompt required with the real maxLength.
  const gateReq = doc.components.schemas.GateRequest;
  assert.ok((gateReq.required || []).includes('prompt'));
  assert.strictEqual(gateReq.properties.prompt.maxLength, validation.LIMITS.promptChars);
}));

test('the spec leaks no ingest key and no unexpected PII', async () => support.withServer(app, async (port) => {
  const raw = await (await support.request(port, '/api/v1/openapi.json', { method: 'GET' })).text();
  assert.ok(!raw.includes(support.INGEST_KEY), 'spec must not contain the ingest key');
  // No 16-digit PAN-shaped sequences; the only SSN-shaped string allowed is the
  // documented synthetic example 123-45-6789 (repo-standard test value).
  assert.ok(!/\b(?:\d[ -]?){16}\b/.test(raw), 'no card-number-shaped sequences');
  const ssns = (raw.match(/\d{3}-\d{2}-\d{4}/g) || []).filter((s) => s !== '123-45-6789');
  assert.deepStrictEqual(ssns, [], 'only the synthetic example SSN may appear');
}));
