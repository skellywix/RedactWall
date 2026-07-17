'use strict';

const assert = require('node:assert');
const path = require('node:path');
const test = require('node:test');
const { pathToFileURL } = require('node:url');
const posture = require('../server/posture');

const helpers = import(pathToFileURL(path.join(__dirname, '..', 'console', 'src', 'components', 'overview', 'leakMapTraffic.ts')).href);

function row(id, destination, status) {
  return {
    id,
    destination,
    status,
    source: 'browser_extension',
    findings: [{ type: 'US_SSN', severity: 4, masked: '***' }],
  };
}

function edge(map, destination) {
  return map.edges.find((item) => item.to === destination);
}

test('leak map continuation is explicit and conservative for missing or malformed counts', async () => {
  const { continuedEventCount } = await helpers;
  assert.strictEqual(continuedEventCount({}), 0);
  assert.strictEqual(continuedEventCount({ continued: 'invalid' }), 0);
  assert.strictEqual(continuedEventCount({ continued: '2' }), 0);
  assert.strictEqual(continuedEventCount({ continued: true }), 0);
  assert.strictEqual(continuedEventCount({ continued: 1.5 }), 0);
  assert.strictEqual(continuedEventCount({ continued: -4 }), 0);
  assert.strictEqual(continuedEventCount({ continued: 2 }), 2);
});

test('frontend decoder whitelists a complete server leak-map snapshot', async () => {
  const { decodeLeakMapReport } = await helpers;
  const original = posture.leakMapGraph({
    rows: [
      row('allowed', 'allowed.example', 'allowed'),
      row('pending', 'pending.example', 'pending'),
    ],
  });
  original.unknownPayload = { prompt: 'must not cross the decoder' };
  original.edges[0].unknownPayload = 'discard me';
  const decoded = decodeLeakMapReport(original);
  assert.ok(decoded);
  assert.strictEqual(Object.hasOwn(decoded, 'unknownPayload'), false);
  assert.strictEqual(Object.hasOwn(decoded.edges[0], 'unknownPayload'), false);
  assert.strictEqual(JSON.stringify(decoded).includes('must not cross'), false);
});

test('producer and decoder agree at the leak-map wire-contract boundaries', async () => {
  const { decodeLeakMapReport } = await helpers;
  const longDestination = `${'a'.repeat(245)}.example`; // 253 chars — the hostname maximum
  const rows = [row('long', longDestination, 'allowed')];
  for (let i = 0; i < 17; i += 1) {
    rows.push({ ...row(`src-${i}`, 'allowed.example', 'allowed'), source: `sensor_${i}` });
  }
  const original = posture.leakMapGraph({ rows });
  assert.strictEqual(original.channels.length, 16, 'producer caps channels at the decoder limit');
  const decoded = decodeLeakMapReport(original);
  assert.ok(decoded, 'a server-valid report with a maximum-length destination must decode');
  assert.ok(decoded.destinations.some((item) => item.id === longDestination));
});

test('frontend decoder rejects ambiguous continuation counts and graph relationships', async () => {
  const { decodeLeakMapReport } = await helpers;
  const original = posture.leakMapGraph({ rows: [row('allowed', 'allowed.example', 'allowed')] });
  const malformed = (mutate) => {
    const candidate = structuredClone(original);
    mutate(candidate);
    return decodeLeakMapReport(candidate);
  };

  assert.strictEqual(malformed((map) => { map.edges[0].continued = true; }), null);
  assert.strictEqual(malformed((map) => { map.edges[0].uncontrolledContinued = '0'; }), null);
  assert.strictEqual(malformed((map) => { map.edges[0].continued = 0.5; }), null);
  assert.strictEqual(malformed((map) => { map.edges[0].to = 'missing.example'; }), null);
  assert.strictEqual(malformed((map) => { map.edges.push(structuredClone(map.edges[0])); map.summary.shownEdges += 1; }), null);
  assert.strictEqual(malformed((map) => {
    const duplicate = structuredClone(map.edges[0]);
    duplicate.id = 'duplicate-relation-id';
    map.edges.push(duplicate);
    map.summary.shownEdges += 1;
  }), null);
  assert.strictEqual(malformed((map) => {
    const seed = map.segments[0];
    map.segments.push(...Array.from({ length: 6 }, (_, index) => ({ ...seed, id: `org:bounded-${index}` })));
    map.summary.segments = 7;
  }), null);
  assert.strictEqual(malformed((map) => { map.summary.controlRate = 99; }), null);
});

test('frontend decoder accepts overlapping controlled outcome dimensions emitted by the server', async () => {
  const { decodeLeakMapReport } = await helpers;
  const original = posture.leakMapGraph({
    rows: [
      row('justification-hold', 'justify.example', 'pending_justification'),
      row('coached-stop', 'blocked.example', 'blocked_by_user'),
    ],
  });
  const decoded = decodeLeakMapReport(original);

  assert.ok(decoded, 'server snapshots may count one controlled event as both blocked and coached');
  assert.ok(decoded.edges.every((item) => item.blocked === 1 && item.coached === 1 && item.controlled === 1));

  const impossible = structuredClone(original);
  impossible.edges[0].coached = 2;
  assert.strictEqual(decodeLeakMapReport(impossible), null, 'each overlapping dimension remains bounded by controlled');
});

test('backend leak-map aggregate authorizes only explicit continuation outcomes', async () => {
  const { continuedEventCount } = await helpers;
  const map = posture.leakMapGraph({
    rows: [
      row('pending', 'pending.example', 'pending'),
      row('mixed-held', 'mixed.example', 'pending'),
      row('mixed-allowed', 'mixed.example', 'allowed'),
      row('blocked', 'blocked.example', 'destination_blocked'),
      row('redacted', 'redacted.example', 'redacted'),
      { ...row('response-redacted', 'response-redacted.example', 'response_redacted'), channel: 'ai_response' },
      row('paste', 'paste.example', 'paste_flagged'),
      row('warning', 'warning.example', 'warned'),
      { id: 'shadow', destination: 'shadow.example', status: 'shadow_ai', source: 'proxy', channel: 'shadow_ai' },
      row('unknown', 'unknown.example', 'unexpected_status'),
    ],
  });

  assert.strictEqual(continuedEventCount(edge(map, 'pending.example')), 0);
  assert.strictEqual(continuedEventCount(edge(map, 'mixed.example')), 1);
  assert.strictEqual(continuedEventCount(edge(map, 'blocked.example')), 0);
  assert.strictEqual(continuedEventCount(edge(map, 'redacted.example')), 1);
  assert.strictEqual(edge(map, 'response-redacted.example'), undefined);
  assert.strictEqual(continuedEventCount(edge(map, 'paste.example')), 0);
  assert.strictEqual(continuedEventCount(edge(map, 'warning.example')), 0);
  assert.strictEqual(continuedEventCount(edge(map, 'shadow.example')), 0);
  assert.strictEqual(continuedEventCount(edge(map, 'unknown.example')), 0);
  assert.strictEqual(edge(map, 'mixed.example').uncontrolledContinued, 1);
  assert.strictEqual(map.summary.continued, 2);
});

test('aggregate continuation does not get correlated with a different uncontrolled event', () => {
  const map = posture.leakMapGraph({
    rows: [
      { id: 'clean-allowed', destination: 'aggregate.example', status: 'allowed', source: 'browser_extension', findings: [] },
      row('unknown-aggregate', 'aggregate.example', 'unexpected_status'),
    ],
  });
  const aggregate = edge(map, 'aggregate.example');
  assert.strictEqual(aggregate.uncontrolled, 1);
  assert.strictEqual(aggregate.continued, 1);
  assert.strictEqual(aggregate.uncontrolledContinued, 0);
});

test('accepted warning, justification, and held justification remain distinct', async () => {
  const { continuedEventCount } = await helpers;
  const map = posture.leakMapGraph({
    rows: [
      row('warned-sent', 'warned-sent.example', 'warned_sent'),
      row('justified', 'justified.example', 'justified'),
      row('pending-justification', 'pending-justification.example', 'pending_justification'),
    ],
  });

  assert.strictEqual(continuedEventCount(edge(map, 'warned-sent.example')), 1);
  assert.strictEqual(continuedEventCount(edge(map, 'justified.example')), 1);
  assert.strictEqual(continuedEventCount(edge(map, 'pending-justification.example')), 0);
  assert.strictEqual(edge(map, 'pending-justification.example').pending, 1);
  assert.strictEqual(map.summary.continued, 2);
});
