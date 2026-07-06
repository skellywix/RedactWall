'use strict';
/** Native endpoint handoff events must be signed metadata, not file payloads. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const handoff = require('../sensors/endpoint-agent/native-handoff');

const SECRET = 'native-handoff-secret-000000000000000001';

function event(overrides = {}) {
  return {
    version: handoff.EVENT_VERSION,
    id: 'evt_unit_1',
    createdAt: '2026-06-26T15:00:00.000Z',
    operation: 'upload',
    filePath: path.join(os.tmpdir(), 'loan.txt'),
    destination: { app: 'Desktop AI', process: 'desktop-ai.exe' },
    user: 'analyst@example.test',
    nonce: 'nonce-1',
    ...overrides,
  };
}

test('native handoff events sign and validate without file content', () => {
  const signed = handoff.signHandoffEvent(event(), SECRET);
  assert.match(signed.signature, /^[0-9a-f]{64}$/);
  assert.strictEqual(JSON.stringify(signed).includes('contentBase64'), false);

  const validated = handoff.validateHandoffEvent(signed, {
    secret: SECRET,
    now: new Date('2026-06-26T15:01:00.000Z'),
  });
  assert.strictEqual(validated.id, 'evt_unit_1');
  assert.strictEqual(validated.destination.app, 'Desktop AI');
  assert.strictEqual(handoff.publicDestination(validated.destination), 'Desktop AI');
});

test('signatureFor over a raw string-destination event validates after normalization', () => {
  // A third-party collector signs the raw event (destination as a plain string).
  // canonicalEvent must produce the same bytes before and after normalization or
  // the legitimately signed event is rejected.
  const raw = event({ destination: 'Claude Desktop' });
  const signed = { ...raw, signature: handoff.signatureFor(raw, SECRET) };
  const validated = handoff.validateHandoffEvent(signed, {
    secret: SECRET,
    now: new Date('2026-06-26T15:01:00.000Z'),
  });
  assert.strictEqual(validated.destination.app, 'Claude Desktop');
});

test('native handoff rejects bad signatures, stale events, and raw payload keys', () => {
  const signed = handoff.signHandoffEvent(event(), SECRET);
  assert.throws(
    () => handoff.validateHandoffEvent({ ...signed, signature: '0'.repeat(64) }, {
      secret: SECRET,
      now: new Date('2026-06-26T15:01:00.000Z'),
    }),
    /signature/,
  );
  assert.throws(
    () => handoff.validateHandoffEvent(signed, {
      secret: SECRET,
      now: new Date('2026-06-26T15:30:00.000Z'),
    }),
    /time window/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ meta: { content_base64: 'abc' } }), SECRET),
    /not allowed/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ RawText: 'secret' }), SECRET),
    /not allowed/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ payloadRef: 'anything-extra' }), SECRET),
    /event\.payloadRef is not allowed/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ destination: { app: 'Desktop AI', extra: 'anything-extra' } }), SECRET),
    /event\.destination\.extra is not allowed/,
  );
});

test('native handoff validates the event schema before trusting file metadata', () => {
  assert.throws(
    () => handoff.validateHandoffEvent([], { secret: SECRET }),
    /JSON object/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ destination: [] }), SECRET),
    /destination is not allowed/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ version: 2 }), SECRET),
    /version is unsupported/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ operation: 'download' }), SECRET),
    /operation is unsupported/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ filePath: 'loan.txt' }), SECRET),
    /filePath must be absolute/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ filePath: '\\\\server\\share\\loan.txt' }), SECRET),
    /local path/,
  );
  assert.throws(
    () => handoff.signHandoffEvent(event({ createdAt: 'not-a-date' }), SECRET),
    /createdAt is invalid/,
  );

  const signed = handoff.signHandoffEvent(event({ destination: 'Desktop AI\r\nApp' }), SECRET);
  // String destinations normalize to the same {app,process,url} shape as object
  // destinations, so signatureFor() is stable across a re-normalization pass.
  assert.deepStrictEqual(signed.destination, { app: 'Desktop AI  App', process: '', url: '' });
  assert.strictEqual(handoff.publicDestination('Claude Desktop'), 'Claude Desktop');
});

test('native handoff files are size-bounded and require a configured secret', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-native-handoff-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const handoffPath = path.join(dir, 'handoff.json');
  fs.writeFileSync(handoffPath, JSON.stringify(handoff.signHandoffEvent(event(), SECRET)));

  const validated = handoff.readHandoffFile(handoffPath, {
    secret: SECRET,
    now: new Date('2026-06-26T15:01:00.000Z'),
  });
  assert.strictEqual(validated.filePath, path.join(os.tmpdir(), 'loan.txt'));
  assert.throws(() => handoff.readHandoffFile(handoffPath, {
    now: new Date('2026-06-26T15:01:00.000Z'),
  }), /secret/);

  const largePath = path.join(dir, 'large.json');
  fs.writeFileSync(largePath, 'x'.repeat(handoff.MAX_EVENT_BYTES + 1));
  assert.throws(() => handoff.readHandoffFile(largePath, { secret: SECRET }), /too large/);
});

test('native handoff accepts RedactWall endpoint env aliases', () => {
  const oldSecret = process.env.ENDPOINT_AGENT_HANDOFF_SECRET;
  const oldRedactWallSecret = process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET;
  delete process.env.ENDPOINT_AGENT_HANDOFF_SECRET;
  process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET = SECRET;
  try {
    assert.strictEqual(
      handoff.defaultHandoffDir({ REDACTWALL_ENDPOINT_AGENT_HANDOFF_DIR: 'C:/RedactWall/handoff' }),
      'C:/RedactWall/handoff',
    );
    assert.strictEqual(handoff.configuredHandoffSecret(), SECRET);
  } finally {
    if (oldSecret === undefined) delete process.env.ENDPOINT_AGENT_HANDOFF_SECRET;
    else process.env.ENDPOINT_AGENT_HANDOFF_SECRET = oldSecret;
    if (oldRedactWallSecret === undefined) delete process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET;
    else process.env.REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET = oldRedactWallSecret;
  }
});
