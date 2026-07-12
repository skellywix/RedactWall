'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const publicFile = (name) => fs.readFileSync(path.join(ROOT, 'server', 'public', name), 'utf8');

function loadReader() {
  const authWindow = { setTimeout, clearTimeout };
  vm.runInNewContext(publicFile('auth-response.js'), {
    window: authWindow,
    TextDecoder,
    Uint8Array,
  });
  return authWindow.RedactWallAuthResponse;
}

test('auth response helper reads valid JSON exactly once', async () => {
  const reader = loadReader();
  const response = new Response(JSON.stringify({ ok: true }), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });

  const body = await reader.readJson(response);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(body)), { ok: true });
  assert.strictEqual(await reader.readJson(response), null);
});

test('auth response helper rejects declared and streamed oversize bodies', async () => {
  const reader = loadReader();
  const declared = new Response('{}', {
    headers: { 'content-type': 'application/json', 'content-length': '999' },
  });
  assert.strictEqual(await reader.readJson(declared, 8), null);

  const streamed = new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"payload":"too large"}'));
      controller.close();
    },
  }), { headers: { 'content-type': 'application/json' } });
  assert.strictEqual(await reader.readJson(streamed, 8), null);
});

test('auth response helper rejects malformed JSON, invalid UTF-8, and wrong media types', async () => {
  const reader = loadReader();
  const malformed = new Response('{', { headers: { 'content-type': 'application/json' } });
  assert.strictEqual(await reader.readJson(malformed), null);

  const invalidUtf8 = new Response(Uint8Array.from([0xc3, 0x28]), {
    headers: { 'content-type': 'application/json' },
  });
  assert.strictEqual(await reader.readJson(invalidUtf8), null);

  const html = new Response('<html></html>', { headers: { 'content-type': 'text/html' } });
  assert.strictEqual(await reader.readJson(html), null);
});

test('auth response helper cancels a stalled body at its deadline', async () => {
  const reader = loadReader();
  let cancelled = false;
  const stalled = new Response(new ReadableStream({
    pull() { return new Promise(() => {}); },
    cancel() { cancelled = true; },
  }), { headers: { 'content-type': 'application/json' } });

  assert.strictEqual(await reader.readJson(stalled, 1024, 20), null);
  await new Promise((resolve) => setImmediate(resolve));
  assert.strictEqual(cancelled, true);
});

test('auth surfaces load the bounded reader before consumers and support recovery codes', () => {
  const loginHtml = publicFile('login.html');
  const inviteHtml = publicFile('accept-invite.html');
  const loginJs = publicFile('login.js');
  const inviteJs = publicFile('accept-invite.js');

  assert.ok(loginHtml.indexOf('/auth-response.js') < loginHtml.indexOf('/login.js'));
  assert.ok(inviteHtml.indexOf('/auth-response.js') < inviteHtml.indexOf('/accept-invite.js'));
  assert.match(loginHtml, /Authenticator or recovery code/);
  assert.match(loginHtml, /id="otp"[^>]*maxlength="11"/);
  assert.doesNotMatch(loginHtml, /id="otp"[^>]*inputmode="numeric"/);
  assert.match(loginJs, /boundedResponse\?\.readJson\(r\)/);
  assert.match(inviteJs, /boundedResponse\?\.readJson\(response\)/);
  assert.match(loginJs, /fetch\('\/api\/login',[\s\S]*?redirect: 'error'/);
  assert.match(inviteJs, /fetch\('\/api\/invitations\/accept',[\s\S]*?redirect: 'error'/);
  assert.match(loginJs, /let submitting = false/);
  assert.match(loginJs, /if \(submitting\) return/);
  assert.match(loginJs, /submitButton\.disabled = true/);
  assert.match(loginJs, /f\.setAttribute\('aria-busy', 'true'\)/);
  assert.doesNotMatch(loginJs, /\.json\s*\(/);
  assert.doesNotMatch(inviteJs, /\.json\s*\(/);
});
