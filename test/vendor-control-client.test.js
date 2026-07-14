'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const clientModule = require('../server/vendor-control-client');
const onlineVerdict = require('../server/connected-online-verdict');
const protocol = require('../server/vendor-control-protocol');
const { keyFingerprint } = require('../server/vendor-signed-artifact');

const onlineKeys = crypto.generateKeyPairSync('ed25519');
const entitlementKeys = crypto.generateKeyPairSync('ed25519');
const ONLINE_KEY_ID = onlineVerdict.keyIdForPublicKey(onlineKeys.publicKey);
const ENTITLEMENT_KEY_ID = `rw-entitlement-${keyFingerprint(entitlementKeys.publicKey)}`;
const HEARTBEAT_TOKEN = 'rwcp_customer_connector_token_0123456789abcdef';
const TOKENS = Object.freeze({
  heartbeat: HEARTBEAT_TOKEN,
  acknowledgement: 'rwcp_acknowledgement_token_0123456789abcdef',
  diagnostic: 'rwcp_diagnostic_token_0123456789abcdef',
  shadowCandidate: 'rwcp_shadow_candidate_token_0123456789abcdef',
});
const CUSTOMER_ID = 'cu-client-1';
const DEPLOYMENT_ID = `dep_${'a'.repeat(32)}`;
const MESSAGE_ID = '1ae82809-8407-47b4-89b6-5e49bd3df74e';
const NOW_MS = Date.parse('2026-07-13T12:00:00.000Z');

function heartbeat(overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: MESSAGE_ID,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.HEARTBEAT,
    heartbeatNonce: 'R4ndomHeartbeatNonce_1234567890',
    plan: 'standard',
    seatsUsed: 4,
    seatLimit: 10,
    version: '1.2.3',
    sentAt: '2026-07-13T12:00:00.000Z',
    lastAppliedEntitlementVersion: 1,
    lastAppliedRegistryGeneration: 1,
    lastAppliedPolicyVersion: 2,
    lastAppliedCatalogVersion: 3,
    ...overrides,
  };
}

function entitlement(overrides = {}) {
  return {
    schemaVersion: 1,
    messageId: 'a4b47a3c-1ff2-4b35-a9c9-bd17566a7eca',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    status: 'active',
    plan: 'standard',
    seats: 10,
    features: ['policy'],
    entitlementVersion: 2,
    previousVersion: 1,
    issuedAt: '2026-07-13T12:00:00.000Z',
    expiresAt: '2026-07-13T12:05:00.000Z',
    fallbackUntil: '2026-07-16T12:00:00.000Z',
    reasonCode: 'billing_active',
    ...overrides,
  };
}

function signedEntitlement(payload = entitlement(), key = entitlementKeys.privateKey,
  keyId = ENTITLEMENT_KEY_ID) {
  return {
    keyId,
    payload,
    signature: crypto.sign(null, protocol.signingInput(payload, keyId), key).toString('base64'),
  };
}

function verdictPayload(overrides = {}) {
  return {
    kind: onlineVerdict.VERDICT_DOMAIN,
    keyId: ONLINE_KEY_ID,
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    issuedAt: '2026-07-13T12:00:00.000Z',
    registryGeneration: 7,
    registryStateDigest: 'b'.repeat(64),
    ...overrides,
  };
}

function signedVerdict(payload = verdictPayload(), key = onlineKeys.privateKey) {
  const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
  const input = Buffer.from(`${onlineVerdict.VERDICT_DOMAIN}\0${payloadB64}`, 'utf8');
  return `${payloadB64}.${crypto.sign(null, input, key).toString('base64')}`;
}

function composite(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'heartbeat.response.v1',
    requestMessageId: MESSAGE_ID,
    onlineRegistryVerdict: signedVerdict(),
    entitlementArtifact: signedEntitlement(),
    ...overrides,
  };
}

function responseHeaders(body, overrides = {}) {
  return {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    pragma: 'no-cache',
    'x-content-type-options': 'nosniff',
    'content-length': String(Buffer.byteLength(body, 'utf8')),
    ...overrides,
  };
}

function compositeResponse(value = composite(), options = {}) {
  const body = options.body === undefined ? JSON.stringify(value) : options.body;
  return new Response(body, {
    status: options.status || 200,
    headers: responseHeaders(body, options.headers),
  });
}

function client(fetchImpl, overrides = {}) {
  return clientModule.createVendorControlClient({
    baseUrl: 'https://control.vendor.example/',
    tokens: TOKENS,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    onlineVerdictPublicKeys: { [ONLINE_KEY_ID]: onlineKeys.publicKey },
    entitlementPublicKeys: { [ENTITLEMENT_KEY_ID]: entitlementKeys.publicKey },
    now: () => NOW_MS,
    fetchImpl,
    ...overrides,
  });
}

test('heartbeat posts only to /v1/heartbeat and returns both raw artifacts with verified metadata', async () => {
  let observed;
  const raw = composite();
  const api = client(async (url, options) => {
    observed = { url: String(url), options };
    return compositeResponse(raw);
  });
  const result = await api.heartbeat(heartbeat());

  assert.equal(result.ok, true);
  assert.equal(result.requestMessageId, MESSAGE_ID);
  assert.equal(result.signedOnlineRegistryVerdict, raw.onlineRegistryVerdict);
  assert.deepEqual(result.verifiedOnlineRegistryVerdict.payload, verdictPayload());
  assert.deepEqual(result.signedEntitlementArtifact, raw.entitlementArtifact);
  assert.deepEqual(result.verifiedEntitlementArtifact.payload, entitlement());
  assert.equal(Object.isFrozen(result.verifiedOnlineRegistryVerdict.payload), true);
  assert.equal(Object.isFrozen(result.verifiedEntitlementArtifact.payload), true);
  assert.equal(Object.isFrozen(result.signedEntitlementArtifact), true);
  assert.equal(Object.isFrozen(result.signedEntitlementArtifact.payload), true);
  assert.equal(Object.isFrozen(result.signedEntitlementArtifact.payload.features), true);
  assert.equal(observed.url, 'https://control.vendor.example/v1/heartbeat');
  assert.equal(observed.options.method, 'POST');
  assert.equal(observed.options.redirect, 'error');
  assert.equal(observed.options.headers.authorization, `Bearer ${HEARTBEAT_TOKEN}`);
  assert.equal(observed.options.headers['content-type'], 'application/json');
  assert.deepEqual(Object.keys(JSON.parse(observed.options.body)), [
    'schemaVersion', 'messageId', 'customerId', 'deploymentId', 'kind',
    'heartbeatNonce', 'plan', 'seatsUsed', 'seatLimit', 'version', 'sentAt',
    'lastAppliedEntitlementVersion', 'lastAppliedRegistryGeneration',
    'lastAppliedPolicyVersion', 'lastAppliedCatalogVersion',
  ]);
});

test('a null entitlement grants nothing while the online verdict remains independently verified', async () => {
  const raw = composite({ entitlementArtifact: null });
  const result = await client(async () => compositeResponse(raw)).heartbeat(heartbeat());
  assert.equal(result.ok, true);
  assert.equal(result.verifiedOnlineRegistryVerdict.payload.status, 'active');
  assert.equal(result.signedEntitlementArtifact, null);
  assert.equal(result.verifiedEntitlementArtifact, null);
  assert.equal(Object.hasOwn(result, 'entitlement'), false);
});

test('response envelope requires exact ordered keys, schema, kind, and request correlation', async () => {
  const cases = [
    { value: { ...composite(), extra: true } },
    { value: { kind: 'heartbeat.response.v1', schemaVersion: 1, requestMessageId: MESSAGE_ID,
      onlineRegistryVerdict: signedVerdict(), entitlementArtifact: null } },
    { value: composite({ schemaVersion: 2 }) },
    { value: composite({ kind: 'heartbeat.v1' }) },
    { value: composite({ requestMessageId: 'a4b47a3c-1ff2-4b35-a9c9-bd17566a7eca' }) },
    { value: composite({ onlineRegistryVerdict: null }) },
    { value: composite({ entitlementArtifact: { keyId: ENTITLEMENT_KEY_ID } }) },
  ];
  for (const entry of cases) {
    assert.deepEqual(
      await client(async () => compositeResponse(entry.value)).heartbeat(heartbeat()),
      { ok: false, failureClass: 'invalid_schema' },
    );
  }
  const duplicateKeyBody = JSON.stringify(composite()).replace(/}$/, ',"schemaVersion":1}');
  assert.deepEqual(
    await client(async () => compositeResponse(null, { body: duplicateKeyBody })).heartbeat(heartbeat()),
    { ok: false, failureClass: 'invalid_schema' },
  );
});

test('response requires exact media, cache, nosniff, and byte-length headers', async () => {
  const mutations = [
    { 'content-type': 'application/json' },
    { 'content-type': 'application/json; charset=UTF-8' },
    { 'cache-control': 'private, no-store' },
    { pragma: '' },
    { 'x-content-type-options': 'none' },
    { 'content-length': '0001' },
    { 'content-length': '1' },
  ];
  for (const headers of mutations) {
    assert.deepEqual(
      await client(async () => compositeResponse(composite(), { headers })).heartbeat(heartbeat()),
      { ok: false, failureClass: 'invalid_schema' },
    );
  }
});

test('response body is bounded to 24576 bytes and decoded as strict UTF-8', async () => {
  const oversized = 'x'.repeat(24_577);
  assert.deepEqual(
    await client(async () => compositeResponse(null, { body: oversized })).heartbeat(heartbeat()),
    { ok: false, failureClass: 'response_too_large' },
  );
  const invalidUtf8 = Buffer.from([0xc3, 0x28]);
  const invalidResponse = new Response(invalidUtf8, {
    status: 200,
    headers: responseHeaders(invalidUtf8, { 'content-length': String(invalidUtf8.length) }),
  });
  assert.deepEqual(
    await client(async () => invalidResponse).heartbeat(heartbeat()),
    { ok: false, failureClass: 'invalid_schema' },
  );
});

test('online verdict and entitlement signatures, key IDs, and scopes are verified independently', async () => {
  const otherOnline = crypto.generateKeyPairSync('ed25519');
  const otherOnlineId = onlineVerdict.keyIdForPublicKey(otherOnline.publicKey);
  const unknownPayload = verdictPayload({ keyId: otherOnlineId });
  const cases = [
    [composite({ onlineRegistryVerdict: signedVerdict(verdictPayload(), otherOnline.privateKey) }), 'invalid_signature'],
    [composite({ onlineRegistryVerdict: signedVerdict(unknownPayload, otherOnline.privateKey) }), 'unknown_signing_key'],
    [composite({ onlineRegistryVerdict: signedVerdict(verdictPayload({ customerId: 'cu-client-2' })) }), 'customer_mismatch'],
    [composite({ onlineRegistryVerdict: signedVerdict(verdictPayload({ deploymentId: `dep_${'b'.repeat(32)}` })) }), 'deployment_mismatch'],
    [composite({ entitlementArtifact: signedEntitlement(entitlement(), crypto.generateKeyPairSync('ed25519').privateKey) }), 'invalid_signature'],
    [composite({ entitlementArtifact: signedEntitlement(entitlement(), entitlementKeys.privateKey, 'rw-entitlement-unknown') }), 'unknown_signing_key'],
    [composite({ entitlementArtifact: signedEntitlement(entitlement({ customerId: 'cu-client-2' })) }), 'customer_mismatch'],
    [composite({ entitlementArtifact: signedEntitlement(entitlement({ deploymentId: `dep_${'b'.repeat(32)}` })) }), 'deployment_mismatch'],
  ];
  for (const [value, failureClass] of cases) {
    assert.deepEqual(
      await client(async () => compositeResponse(value)).heartbeat(heartbeat()),
      { ok: false, failureClass },
    );
  }
});

test('HTTP response statuses use the frozen failure mapping', async () => {
  const cases = new Map([
    [401, 'authentication_rejected'], [403, 'authentication_rejected'],
    [409, 'version_conflict'], [429, 'rate_limited'],
    [408, 'transport_unavailable'], [502, 'transport_unavailable'],
    [503, 'transport_unavailable'], [504, 'transport_unavailable'],
    [500, 'transport_ambiguous'], [418, 'transport_ambiguous'],
    [400, 'protocol_rejected'], [404, 'protocol_rejected'],
    [405, 'protocol_rejected'], [413, 'protocol_rejected'],
    [415, 'protocol_rejected'], [422, 'protocol_rejected'],
  ]);
  for (const [status, failureClass] of cases) {
    assert.deepEqual(
      await client(async () => new Response(null, { status })).heartbeat(heartbeat()),
      { ok: false, failureClass },
    );
  }
});

test('only allowlisted network failures and total deadline expiry are transport unavailable', async () => {
  const refused = new TypeError('fetch failed', {
    cause: Object.assign(new Error('connect failed'), { code: 'ECONNREFUSED' }),
  });
  assert.deepEqual(
    await client(async () => { throw refused; }).heartbeat(heartbeat()),
    { ok: false, failureClass: 'transport_unavailable' },
  );
  assert.deepEqual(
    await client(async () => { throw new TypeError('unexpected redirect'); }).heartbeat(heartbeat()),
    { ok: false, failureClass: 'transport_ambiguous' },
  );

  const result = await Promise.race([
    client(() => new Promise(() => {}), { timeoutMs: 10 }).heartbeat(heartbeat()),
    new Promise((resolve) => setTimeout(() => resolve({ testTimedOut: true }), 200)),
  ]);
  assert.deepEqual(result, { ok: false, failureClass: 'transport_unavailable' });
});

test('the total deadline also bounds a stalled 200 response body', async () => {
  const stream = new ReadableStream({ pull() {} });
  const response = new Response(stream, {
    status: 200,
    headers: responseHeaders('', { 'content-length': '1' }),
  });
  const result = await Promise.race([
    client(async () => response, { timeoutMs: 10 }).heartbeat(heartbeat()),
    new Promise((resolve) => setTimeout(() => resolve({ testTimedOut: true }), 200)),
  ]);
  assert.deepEqual(result, { ok: false, failureClass: 'transport_unavailable' });
});

test('closing the client aborts and drains active requests without reporting a vendor outage', async () => {
  let requestStarted;
  const started = new Promise((resolve) => { requestStarted = resolve; });
  let aborts = 0;
  const api = client((_url, options) => {
    requestStarted();
    return new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        aborts += 1;
        const error = new Error('customer runtime is shutting down');
        error.name = 'AbortError';
        reject(error);
      }, { once: true });
    });
  });

  const active = api.heartbeat(heartbeat());
  await started;
  const closing = api.close();
  assert.deepEqual(await active, { ok: false, failureClass: 'shutdown_cancelled' });
  assert.deepEqual(await closing, { ok: true });
  assert.equal(aborts, 1);
  assert.deepEqual(await api.close(), { ok: true });
  await assert.rejects(
    () => api.heartbeat(heartbeat()),
    (error) => error && error.code === 'vendor_client_closed',
  );
});

test('heartbeat sentAt is accepted at inclusive five-minute boundaries and rejected one millisecond beyond', async () => {
  let calls = 0;
  const api = client(async () => { calls += 1; return compositeResponse(); });
  for (const sentAt of [NOW_MS - 300_000, NOW_MS, NOW_MS + 300_000]) {
    assert.equal((await api.heartbeat(heartbeat({ sentAt: new Date(sentAt).toISOString() }))).ok, true);
  }
  for (const sentAt of [NOW_MS - 300_001, NOW_MS + 300_001]) {
    await assert.rejects(
      () => api.heartbeat(heartbeat({ sentAt: new Date(sentAt).toISOString() })),
      (error) => error.code === 'heartbeat_sent_at_out_of_range',
    );
  }
  assert.equal(calls, 3);

  for (const badNow of [() => Number.NaN, () => NOW_MS + 0.5, () => { throw new Error('clock failed'); }]) {
    const invalidClock = client(async () => { calls += 1; return compositeResponse(); }, { now: badNow });
    await assert.rejects(
      () => invalidClock.heartbeat(heartbeat()),
      (error) => error.code === 'vendor_clock_invalid',
    );
  }
  assert.equal(calls, 3);
});

test('injected clock and transport receive no credential-bearing config receiver', async () => {
  let clockReceiver = null;
  let fetchReceiver = null;
  const api = client(async function fetchWithoutAuthority() {
    'use strict';
    fetchReceiver = this;
    return compositeResponse();
  }, {
    now: function clockWithoutAuthority() {
      'use strict';
      clockReceiver = this;
      return NOW_MS;
    },
  });

  assert.equal((await api.heartbeat(heartbeat())).ok, true);
  assert.equal(clockReceiver, undefined);
  assert.equal(fetchReceiver, undefined);
});

test('body stream transport failures remain distinct from invalid UTF-8, JSON, and schema', async () => {
  function erroredStreamResponse(error) {
    return {
      status: 200,
      headers: new Headers(responseHeaders('x', { 'content-length': '1' })),
      body: {
        async *[Symbol.asyncIterator]() { throw error; },
      },
    };
  }
  const reset = Object.assign(new Error('stream reset'), { code: 'ECONNRESET' });
  const socket = new Error('outer', {
    cause: new Error('middle', {
      cause: Object.assign(new Error('socket'), { code: 'UND_ERR_SOCKET' }),
    }),
  });
  assert.deepEqual(
    await client(async () => erroredStreamResponse(reset)).heartbeat(heartbeat()),
    { ok: false, failureClass: 'transport_unavailable' },
  );
  assert.deepEqual(
    await client(async () => erroredStreamResponse(socket)).heartbeat(heartbeat()),
    { ok: false, failureClass: 'transport_unavailable' },
  );
  assert.deepEqual(
    await client(async () => erroredStreamResponse(new Error('unexpected stream failure'))).heartbeat(heartbeat()),
    { ok: false, failureClass: 'transport_ambiguous' },
  );
  assert.deepEqual(
    await client(async () => compositeResponse(null, { body: '{' })).heartbeat(heartbeat()),
    { ok: false, failureClass: 'invalid_schema' },
  );
});

test('prompt, unknown, and cross-tenant request fields are rejected before fetch', async () => {
  let calls = 0;
  const api = client(async () => { calls += 1; return compositeResponse(); });
  await assert.rejects(
    () => api.heartbeat({ ...heartbeat(), prompt: '123-45-6789' }),
    (error) => error.code === 'channel_schema_invalid',
  );
  await assert.rejects(
    () => api.heartbeat(heartbeat({ customerId: 'cu-client-2' })),
    (error) => error.code === 'customer_mismatch',
  );
  assert.equal(calls, 0);
});

function acknowledgement() {
  return {
    schemaVersion: 1,
    messageId: 'af7984df-2b52-4a45-836a-9b4d5d1889cb',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    kind: protocol.CHANNEL_KINDS.ACKNOWLEDGEMENT,
    targetKind: protocol.CHANNEL_KINDS.ENTITLEMENT,
    targetVersion: 2,
    targetDigest: 'a'.repeat(64),
    lifecycleStage: 'delivered',
    outcome: 'success',
    reasonCode: 'delivered',
    recordedAt: '2026-07-13T12:00:00.000Z',
  };
}

test('ACK accepts exactly 204 and rejects every other successful status', async () => {
  assert.deepEqual(
    await client(async () => new Response(null, { status: 204 })).acknowledge(acknowledgement()),
    { ok: true, accepted: true },
  );
  for (const status of [200, 201, 202, 205]) {
    assert.deepEqual(
      await client(async () => new Response(null, { status })).acknowledge(acknowledgement()),
      { ok: false, failureClass: 'protocol_rejected' },
    );
  }
});

test('optional customer channels accept only exact durable 204 responses', async () => {
  const base = {
    schemaVersion: 1,
    messageId: 'af7984df-2b52-4a45-836a-9b4d5d1889cb',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
  };
  const diagnostic = {
    ...base, kind: protocol.CHANNEL_KINDS.DIAGNOSTIC,
    correlationId: '780cc8de-447e-4921-9868-0fec01c56ab8', component: 'connector',
    code: 'CONNECTOR_TIMEOUT', severity: 'warning', outcome: 'retrying',
    countBucket: '1', sizeBucket: 'none', durationBucket: '5-30s', retryState: 'scheduled',
    componentVersion: '1.2.3', occurredAt: '2026-07-13T12:00:00.000Z',
  };
  const candidate = {
    ...base, kind: protocol.CHANNEL_KINDS.SHADOW_CANDIDATE,
    candidateId: '02815769-c0ac-477e-856b-7585fbb9151d', registrableDomain: 'example.ai',
    sourceType: 'browser_destination', firstSeenDay: '2026-07-13',
    observationCountBucket: '1', confidenceBps: 8000,
    localClassification: 'generative_ai', localOutcome: 'observed',
  };
  for (const [method, payload] of [['sendDiagnostic', diagnostic], ['sendShadowCandidate', candidate]]) {
    assert.deepEqual(
      await client(async () => new Response(null, { status: 204 }))[method](payload),
      { ok: true, accepted: true },
    );
    for (const status of [200, 201, 202, 205]) {
      assert.deepEqual(
        await client(async () => new Response(null, { status }))[method](payload),
        { ok: false, failureClass: 'protocol_rejected' },
      );
    }
  }
});

test('ACK, diagnostics, and candidate intelligence keep separate endpoints and credentials', async () => {
  const calls = [];
  const api = client(async (url, options) => {
    calls.push({ url: String(url), authorization: options.headers.authorization });
    return new Response(null, { status: 204 });
  });
  const base = {
    schemaVersion: 1,
    messageId: 'af7984df-2b52-4a45-836a-9b4d5d1889cb',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
  };
  await api.acknowledge(acknowledgement());
  await api.sendDiagnostic({
    ...base, kind: protocol.CHANNEL_KINDS.DIAGNOSTIC,
    correlationId: '780cc8de-447e-4921-9868-0fec01c56ab8', component: 'connector',
    code: 'CONNECTOR_TIMEOUT', severity: 'warning', outcome: 'retrying',
    countBucket: '1', sizeBucket: 'none', durationBucket: '5-30s', retryState: 'scheduled',
    componentVersion: '1.2.3', occurredAt: '2026-07-13T12:00:00.000Z',
  });
  await api.sendShadowCandidate({
    ...base, kind: protocol.CHANNEL_KINDS.SHADOW_CANDIDATE,
    candidateId: '02815769-c0ac-477e-856b-7585fbb9151d', registrableDomain: 'example.ai',
    sourceType: 'browser_destination', firstSeenDay: '2026-07-13',
    observationCountBucket: '1', confidenceBps: 8000,
    localClassification: 'generative_ai', localOutcome: 'observed',
  });
  assert.deepEqual(calls, [
    { url: 'https://control.vendor.example/v1/acknowledgements', authorization: `Bearer ${TOKENS.acknowledgement}` },
    { url: 'https://control.vendor.example/v1/diagnostics', authorization: `Bearer ${TOKENS.diagnostic}` },
    { url: 'https://control.vendor.example/v1/shadow-ai/candidates', authorization: `Bearer ${TOKENS.shadowCandidate}` },
  ]);
});

test('client configuration requires explicit separate keyrings and pairwise key identities', () => {
  const base = {
    baseUrl: 'https://control.vendor.example/',
    tokens: TOKENS,
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    onlineVerdictPublicKeys: { [ONLINE_KEY_ID]: onlineKeys.publicKey },
    entitlementPublicKeys: { [ENTITLEMENT_KEY_ID]: entitlementKeys.publicKey },
    now: () => NOW_MS,
    fetchImpl: async () => compositeResponse(),
  };
  for (const baseUrl of [
    'http://control.vendor.example/',
    'https://user:pass@control.vendor.example/',
    'https://control.vendor.example/base',
    'https://127.0.0.1/',
  ]) assert.throws(() => clientModule.createVendorControlClient({ ...base, baseUrl }), TypeError);

  assert.throws(() => clientModule.createVendorControlClient({
    ...base,
    onlineVerdictPublicKeys: undefined,
    publicKeys: { [ONLINE_KEY_ID]: onlineKeys.publicKey },
  }), (error) => error.code === 'vendor_client_options_invalid');
  assert.throws(() => clientModule.createVendorControlClient({
    ...base,
    publicKeys: { [ONLINE_KEY_ID]: onlineKeys.publicKey },
  }), (error) => error.code === 'vendor_client_options_invalid');
  assert.throws(() => clientModule.createVendorControlClient({
    ...base,
    entitlementPublicKeys: {
      [`rw-entitlement-${keyFingerprint(onlineKeys.publicKey)}`]: onlineKeys.publicKey,
    },
  }), (error) => error.code === 'vendor_key_identity_reused');
  assert.throws(() => clientModule.createVendorControlClient({
    ...base,
    entitlementPublicKeys: { 'rw-entitlement-2026-01': entitlementKeys.publicKey },
  }), (error) => error.code === 'vendor_key_purpose_mismatch');
  assert.throws(() => clientModule.createVendorControlClient({
    ...base,
    entitlementPublicKeys: {
      [`rw-entitlement-${'a'.repeat(64)}`]: entitlementKeys.publicKey,
    },
  }), (error) => error.code === 'vendor_key_purpose_mismatch');
  assert.throws(() => clientModule.createVendorControlClient({
    ...base,
    offlineKeyFingerprint: keyFingerprint(entitlementKeys.publicKey),
  }), (error) => error.code === 'vendor_key_identity_reused');
  assert.throws(() => clientModule.createVendorControlClient({
    ...base,
    tokens: { ...TOKENS, acknowledgement: TOKENS.heartbeat },
  }), (error) => error.code === 'connector_token_scope_reused');
  assert.throws(() => clientModule.createVendorControlClient({ ...base, timeoutMs: 0 }), TypeError);
  assert.throws(() => clientModule.createVendorControlClient({ ...base, timeoutMs: '10' }), TypeError);
  assert.throws(() => clientModule.createVendorControlClient({ ...base, timeoutMs: 30_001 }), TypeError);
  assert.throws(() => clientModule.createVendorControlClient({ ...base, fetchImpl: null }), TypeError);
  assert.throws(() => clientModule.createVendorControlClient({ ...base, now: NOW_MS }), TypeError);
  assert.throws(() => clientModule.createVendorControlClient({
    ...base, clock: () => NOW_MS,
  }), (error) => error.code === 'vendor_client_options_invalid');
  assert.throws(() => clientModule.createVendorControlClient({
    ...base, deploymentId: 'deployment_client_001',
  }), (error) => error.code === 'deployment_invalid');
});

test('current and next key slots rotate independently and private PEM never enters a customer verifier', async () => {
  const nextOnline = crypto.generateKeyPairSync('ed25519');
  const nextEntitlement = crypto.generateKeyPairSync('ed25519');
  const nextOnlineId = onlineVerdict.keyIdForPublicKey(nextOnline.publicKey);
  const nextEntitlementId = `rw-entitlement-${keyFingerprint(nextEntitlement.publicKey)}`;
  const nextVerdict = signedVerdict(verdictPayload({ keyId: nextOnlineId }), nextOnline.privateKey);
  const nextArtifact = signedEntitlement(
    entitlement({ entitlementVersion: 3, previousVersion: 2 }),
    nextEntitlement.privateKey,
    nextEntitlementId,
  );
  const api = client(async () => compositeResponse(composite({
    onlineRegistryVerdict: nextVerdict,
    entitlementArtifact: nextArtifact,
  })), {
    onlineVerdictPublicKeys: {
      [ONLINE_KEY_ID]: onlineKeys.publicKey,
      [nextOnlineId]: nextOnline.publicKey,
    },
    entitlementPublicKeys: {
      [ENTITLEMENT_KEY_ID]: entitlementKeys.publicKey,
      [nextEntitlementId]: nextEntitlement.publicKey,
    },
  });
  const result = await api.heartbeat(heartbeat());
  assert.equal(result.ok, true);
  assert.equal(result.verifiedOnlineRegistryVerdict.signingKeyId, nextOnlineId);
  assert.equal(result.verifiedEntitlementArtifact.keyId, nextEntitlementId);

  const onlinePrivatePem = onlineKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const entitlementPrivatePem = entitlementKeys.privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => client(async () => compositeResponse(), {
    onlineVerdictPublicKeys: { [ONLINE_KEY_ID]: onlinePrivatePem },
  }), (error) => error.code === 'registry_public_key_invalid');
  assert.throws(() => client(async () => compositeResponse(), {
    entitlementPublicKeys: { [ENTITLEMENT_KEY_ID]: entitlementPrivatePem },
  }), (error) => error.code === 'vendor_key_invalid');
});

test('oversized heartbeat requests fail before fetch and rejected responses cancel their body', async () => {
  let fetchCalls = 0;
  const api = client(async () => { fetchCalls += 1; return compositeResponse(); });
  const withEmptyPadding = { ...heartbeat(), padding: '' };
  const fixedBytes = Buffer.byteLength(JSON.stringify(withEmptyPadding), 'utf8');
  const atLimit = { ...withEmptyPadding, padding: 'x'.repeat(8192 - fixedBytes) };
  const overLimit = { ...atLimit, padding: `${atLimit.padding}x` };
  assert.equal(Buffer.byteLength(JSON.stringify(atLimit), 'utf8'), 8192);
  assert.equal(Buffer.byteLength(JSON.stringify(overLimit), 'utf8'), 8193);
  await assert.rejects(
    () => api.heartbeat(atLimit),
    (error) => error.code === 'channel_schema_invalid',
  );
  await assert.rejects(
    () => api.heartbeat(overLimit),
    (error) => error.code === 'channel_too_large',
  );
  assert.equal(fetchCalls, 0);

  let cancelCalls = 0;
  const rejected = client(async () => ({
    status: 200,
    body: { cancel: async () => { cancelCalls += 1; } },
  }));
  assert.deepEqual(
    await rejected.acknowledge(acknowledgement()),
    { ok: false, failureClass: 'protocol_rejected' },
  );
  assert.equal(cancelCalls, 1);
});
