'use strict';
/** Safe-to-send receipts: signed, prompt-free proof a cleared text was scanned. */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable-receipts';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-receipts-test-' + crypto.randomBytes(6).toString('hex') + '.db');
process.env.SENTINEL_POLICY_PATH = path.join(os.tmpdir(), 'ps-receipts-policy-' + crypto.randomBytes(6).toString('hex') + '.json');

fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), process.env.SENTINEL_POLICY_PATH);

const app = require('../server/app');
const receipts = require('../server/receipts');
const { listen } = require('./support/listen');

function sha256Hex(text) {
  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');
}

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

async function jsonFetch(port, apiPath, { method = 'POST', body, headers = {} } = {}) {
  return fetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port) {
  const res = await jsonFetch(port, '/api/login', { body: { user: 'admin', password: 'unit-pass' } });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  const csrfRes = await jsonFetch(port, '/api/csrf', { method: 'GET', headers: { cookie } });
  const { csrfToken } = await csrfRes.json();
  return { cookie, csrfToken };
}

async function gate(port, body) {
  const res = await jsonFetch(port, '/api/v1/gate', {
    headers: { 'x-api-key': 'unit-ingest-key' },
    body,
  });
  assert.strictEqual(res.status, 200);
  return res.json();
}

const RECEIPT_KEYS = ['v', 'id', 'status', 'promptSha256', 'policySha256', 'destination', 'user', 'issuedAt', 'sig'];

test('issueReceipt and verifyReceipt round-trip; edits fail verification', () => {
  const receipt = receipts.issueReceipt({
    id: 'q_test1',
    status: 'allowed',
    outboundText: 'What is the NCUA exam cadence?',
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'] },
    destination: 'chatgpt.com',
    user: 'analyst@example.test',
  });
  assert.deepStrictEqual(Object.keys(receipt).sort(), [...RECEIPT_KEYS].sort());
  assert.deepStrictEqual(receipts.verifyReceipt(receipt), { ok: true });

  for (const [field, value] of [
    ['status', 'redacted'],
    ['promptSha256', sha256Hex('another prompt')],
    ['policySha256', sha256Hex('another policy')],
    ['destination', 'evil.example'],
    ['user', 'someone-else@example.test'],
    ['issuedAt', new Date(0).toISOString()],
    ['sig', receipt.sig.slice(0, -2) + 'xx'],
  ]) {
    const tampered = { ...receipt, [field]: value };
    assert.strictEqual(receipts.verifyReceipt(tampered).ok, false, `${field} edit must fail verification`);
  }
  assert.strictEqual(receipts.verifyReceipt({ ...receipt, v: 999 }).ok, false);
});

test('receipt signatures do not allow field-boundary shifting', () => {
  const receipt = receipts.issueReceipt({
    id: 'q_shift',
    status: 'allowed',
    outboundText: 'boundary check',
    policy: { enforcementMode: 'block' },
    destination: 'chatgpt.com',
    user: 'jdoe\nx',
  });
  assert.deepStrictEqual(receipts.verifyReceipt(receipt), { ok: true });
  // Moving content across the destination/user boundary must not verify.
  const shifted = { ...receipt, destination: 'chatgpt.com\njdoe', user: 'x' };
  assert.strictEqual(receipts.verifyReceipt(shifted).ok, false);
});

test('policy hash is stable regardless of object key order', () => {
  const a = receipts.policyHash({ enforcementMode: 'block', blockRiskScore: 20 });
  const b = receipts.policyHash({ blockRiskScore: 20, enforcementMode: 'block' });
  assert.strictEqual(a, b);
});

test('receipts are only issued for cleared outbound text', () => {
  assert.strictEqual(receipts.issueReceipt({
    id: 'q_x', status: 'pending', outboundText: 'held text', policy: {}, destination: 'a', user: 'b',
  }), null);
  assert.strictEqual(receipts.issueReceipt({
    id: 'q_x', status: 'redacted', outboundText: '', policy: {}, destination: 'a', user: 'b',
  }), null);
});

test('gate issues verifiable receipts on allow, warn-sent, and redact paths only', async () => withServer(async (port) => {
  const cleanPrompt = 'Draft a friendly reminder about the branch holiday schedule.';
  const allowed = await gate(port, {
    prompt: cleanPrompt,
    user: 'receipt-allow@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
  });
  assert.strictEqual(allowed.decision, 'allow');
  assert.ok(allowed.receipt, 'allow response carries a receipt');
  assert.strictEqual(allowed.receipt.status, 'allowed');
  assert.strictEqual(allowed.receipt.promptSha256, sha256Hex(cleanPrompt));
  assert.deepStrictEqual(receipts.verifyReceipt(allowed.receipt), { ok: true });
  assert.deepStrictEqual(Object.keys(allowed.receipt).sort(), [...RECEIPT_KEYS].sort());

  const heldPrompt = 'Member SSN 524-71-3010 is in this synthetic note.';
  const held = await gate(port, {
    prompt: heldPrompt,
    user: 'receipt-held@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
  });
  assert.strictEqual(held.status, 'pending');
  assert.strictEqual(held.receipt, undefined, 'held prompts must not get a safe-to-send receipt');

  // warn-sent is a legitimate outcome only for sensitive content that is NOT a
  // hard-stop entity (a raw alwaysBlock value can never be cleared to send — see
  // test/alwaysblock-invariant.test.js). Use non-hard-stop PII so the warn-sent
  // receipt path is exercised without asserting the fixed bypass.
  const warnedPrompt = 'Employee home phone 555-234-5678 and personal email jane.doe@example.com sent after a warning.';
  const warned = await gate(port, {
    prompt: warnedPrompt,
    user: 'receipt-warn@example.test',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
    clientOutcome: 'sent_after_warning',
  });
  assert.strictEqual(warned.status, 'warned_sent');
  assert.strictEqual(warned.receipt.status, 'warned_sent');
  assert.strictEqual(warned.receipt.promptSha256, sha256Hex(warnedPrompt));
  assert.deepStrictEqual(receipts.verifyReceipt(warned.receipt), { ok: true });

  const { cookie, csrfToken } = await login(port);
  const setRedact = await jsonFetch(port, '/api/policy', {
    method: 'PUT',
    headers: { cookie, 'x-csrf-token': csrfToken },
    body: { enforcementMode: 'redact' },
  });
  assert.strictEqual(setRedact.status, 200);
  try {
    const redactPrompt = 'Synthetic member SSN 524-71-3012 needs a payoff letter.';
    const redacted = await gate(port, {
      prompt: redactPrompt,
      user: 'receipt-redact@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    });
    assert.strictEqual(redacted.status, 'redacted');
    assert.ok(redacted.tokenizedPrompt && !redacted.tokenizedPrompt.includes('524-71-3012'));
    assert.strictEqual(redacted.receipt.status, 'redacted');
    assert.strictEqual(
      redacted.receipt.promptSha256,
      sha256Hex(redacted.tokenizedPrompt),
      'redact receipt binds to the tokenized text that actually leaves the device',
    );
    assert.deepStrictEqual(receipts.verifyReceipt(redacted.receipt), { ok: true });
  } finally {
    const restore = await jsonFetch(port, '/api/policy', {
      method: 'PUT',
      headers: { cookie, 'x-csrf-token': csrfToken },
      body: { enforcementMode: 'block' },
    });
    assert.strictEqual(restore.status, 200);
  }
}));

test('POST /api/receipts/verify checks receipts for any console session', async () => withServer(async (port) => {
  const outcome = await gate(port, {
    prompt: 'Summarize our public rate sheet for the newsletter.',
    user: 'receipt-verify@example.test',
    destination: 'claude.ai',
    source: 'api',
    channel: 'submit',
  });
  assert.ok(outcome.receipt);

  const unauthenticated = await jsonFetch(port, '/api/receipts/verify', { body: outcome.receipt });
  assert.strictEqual(unauthenticated.status, 401);

  const { cookie, csrfToken } = await login(port);
  const missingCsrf = await jsonFetch(port, '/api/receipts/verify', {
    headers: { cookie },
    body: outcome.receipt,
  });
  assert.strictEqual(missingCsrf.status, 403);

  const headers = { cookie, 'x-csrf-token': csrfToken };
  const ok = await jsonFetch(port, '/api/receipts/verify', { headers, body: outcome.receipt });
  assert.strictEqual(ok.status, 200);
  assert.deepStrictEqual(await ok.json(), { ok: true });

  const tampered = await jsonFetch(port, '/api/receipts/verify', {
    headers,
    body: { ...outcome.receipt, user: 'forged@example.test' },
  });
  assert.strictEqual(tampered.status, 200);
  const tamperedBody = await tampered.json();
  assert.strictEqual(tamperedBody.ok, false);
  assert.strictEqual(tamperedBody.reason, 'signature mismatch');

  const malformed = await jsonFetch(port, '/api/receipts/verify', {
    headers,
    body: { ...outcome.receipt, promptSha256: 'not-a-hash' },
  });
  assert.strictEqual(malformed.status, 400);
}));

test('verifyReceipt rejects every malformed receipt shape with a specific reason', () => {
  const valid = receipts.issueReceipt({
    id: 'q_reason', status: 'allowed', outboundText: 'cleared text',
    policy: { enforcementMode: 'block' }, destination: 'chat.example.com', user: 'u@example.test',
  });
  assert.deepStrictEqual(receipts.verifyReceipt(valid), { ok: true }, 'baseline receipt verifies');

  const reasonFor = (receipt) => receipts.verifyReceipt(receipt).reason;
  assert.strictEqual(reasonFor(null), 'not a receipt object');
  assert.strictEqual(reasonFor('a-string'), 'not a receipt object');
  assert.strictEqual(reasonFor({ ...valid, v: 99 }), 'unsupported receipt version');
  assert.strictEqual(reasonFor({ ...valid, status: 'blocked' }), 'unknown receipt status');
  assert.strictEqual(reasonFor({ ...valid, policySha256: 'zz' }), 'malformed policy hash');
  assert.strictEqual(reasonFor({ ...valid, issuedAt: 'not-a-time' }), 'malformed issue time');
  assert.strictEqual(reasonFor({ ...valid, sig: '' }), 'signature mismatch', 'missing signature (length mismatch)');
  assert.strictEqual(reasonFor({ ...valid, sig: valid.sig.slice(0, -2) }), 'signature mismatch', 'truncated signature');
});

test('issueReceipt refuses unknown statuses and empty outbound text', () => {
  assert.strictEqual(receipts.issueReceipt({ id: 'q_x', status: 'blocked', outboundText: 'text', policy: {} }), null);
  assert.strictEqual(receipts.issueReceipt({ id: 'q_x', status: 'allowed', outboundText: '', policy: {} }), null);
  const defaulted = receipts.issueReceipt({ id: 'q_x', status: 'allowed', outboundText: 'text', policy: {} });
  assert.strictEqual(defaulted.destination, 'unknown');
  assert.strictEqual(defaulted.user, 'unknown');
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(process.env.SENTINEL_POLICY_PATH); } catch {}
});
