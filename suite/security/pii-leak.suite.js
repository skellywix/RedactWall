// @tier smoke
'use strict';
/**
 * Security: synthetic PII pushed through the gate must never come back raw
 * from any read surface (queue JSON, audit log, evidence export, stats) nor be
 * written to the server process stdout/stderr. Stdout is captured in-process
 * by wrapping the write streams before the app is loaded, so every console
 * line the server emits during the test is inspected.
 */
const test = require('node:test');
const assert = require('node:assert');

const capturedOutput = [];
for (const stream of [process.stdout, process.stderr]) {
  const originalWrite = stream.write.bind(stream);
  stream.write = (chunk, ...rest) => {
    capturedOutput.push(String(chunk));
    return originalWrite(chunk, ...rest);
  };
}

const support = require('../support/app');
support.bootEnv();
const app = support.requireApp();

const RAW_SSN = '123-45-6789';
const RAW_CARD = '4111111111111111';
const RAW_CARD_SPACED = '4111 1111 1111 1111';

function assertClean(text, label) {
  for (const raw of [RAW_SSN, RAW_CARD, RAW_CARD_SPACED]) {
    assert.ok(!text.includes(raw), `${label} leaked raw value ${raw}`);
  }
}

test('raw SSN and card numbers never appear on any read surface or stdout', async () => support.withServer(app, async (port) => {
  const ssnGate = await support.gate(port, {
    prompt: `Synthetic member SSN ${RAW_SSN} in a loan question.`,
    user: 'jane.doe@example.com',
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
  });
  assert.strictEqual(ssnGate.status, 200);
  const ssnBody = await ssnGate.json();
  assert.strictEqual(ssnBody.status, 'pending');
  assertClean(JSON.stringify(ssnBody), 'gate response (ssn)');

  const cardGate = await support.gate(port, {
    prompt: `Synthetic dispute for card ${RAW_CARD_SPACED} exp 09/27.`,
    user: 'jane.doe@example.com',
    destination: 'claude.ai',
    source: 'browser_extension',
    channel: 'submit',
  });
  assert.strictEqual(cardGate.status, 200);
  assertClean(JSON.stringify(await cardGate.json()), 'gate response (card)');

  const admin = await support.login(port, 'admin');
  const deny = await support.request(port, `/api/queries/${ssnBody.id}/deny`, {
    method: 'POST',
    headers: { cookie: admin.cookie, 'x-csrf-token': admin.csrfToken },
    body: { note: 'synthetic pii-leak sweep' },
  });
  assert.strictEqual(deny.status, 200);

  for (const route of [
    '/api/queries',
    '/api/queries?status=pending',
    `/api/queries/${ssnBody.id}`,
    '/api/audit',
    '/api/export/evidence',
    '/api/stats',
    '/api/lineage',
    '/api/risk',
    '/api/posture',
  ]) {
    const res = await support.request(port, route, { headers: { cookie: admin.cookie } });
    assert.strictEqual(res.status, 200, route);
    assertClean(await res.text(), route);
  }

  assertClean(capturedOutput.join(''), 'server stdout/stderr');
}));

test('masked findings still identify the type so the queue stays reviewable', async () => support.withServer(app, async (port) => {
  const admin = await support.login(port, 'admin');
  const rows = await (await support.request(port, '/api/queries', { headers: { cookie: admin.cookie } })).json();
  const types = rows.flatMap((q) => (q.findings || []).map((f) => f.type));
  assert.ok(types.includes('US_SSN'), 'US_SSN finding recorded');
  assert.ok(types.includes('CREDIT_CARD'), 'CREDIT_CARD finding recorded');
}));
