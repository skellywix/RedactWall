'use strict';
/** Email notifications: the zero-dep SMTP sender speaks a full dialogue with a
 *  relay, and 'email' subscription destinations deliver the same prompt-free
 *  events the SIEM adapters send. */
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.REDACTWALL_SECRET = 'unit-secret-stable';
process.env.REDACTWALL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.REDACTWALL_DB_PATH = path.join(os.tmpdir(), 'ps-email-' + crypto.randomBytes(6).toString('hex') + '.db');
const SUBS_PATH = path.join(os.tmpdir(), 'ps-email-subs-' + crypto.randomBytes(4).toString('hex') + '.json');
process.env.REDACTWALL_SUBSCRIPTIONS_PATH = SUBS_PATH;

const email = require('../server/email');
const subscriptions = require('../server/subscriptions');
const app = require('../server/app');
const auth = require('../server/auth');
const { listen } = require('./support/listen');

// A tiny in-process SMTP relay that records the whole conversation.
function fakeSmtpServer() {
  const seen = { commands: [], data: '' };
  let inData = false;
  const server = net.createServer((socket) => {
    socket.write('220 fake ESMTP\r\n');
    socket.on('data', (chunk) => {
      const text = chunk.toString('utf8');
      if (inData) {
        seen.data += text;
        if (seen.data.includes('\r\n.\r\n')) { inData = false; socket.write('250 queued\r\n'); }
        return;
      }
      for (const line of text.split(/\r?\n/).filter(Boolean)) {
        seen.commands.push(line);
        if (line.startsWith('EHLO')) socket.write('250 fake hello\r\n');
        else if (line === 'AUTH LOGIN') socket.write('334 VXNlcm5hbWU6\r\n');
        else if (line === Buffer.from('mailer').toString('base64')) socket.write('334 UGFzc3dvcmQ6\r\n');
        else if (line === Buffer.from('mailer-pass').toString('base64')) socket.write('235 ok\r\n');
        else if (line.startsWith('MAIL FROM') || line.startsWith('RCPT TO')) socket.write('250 ok\r\n');
        else if (line === 'DATA') { inData = true; socket.write('354 go\r\n'); }
        else if (line === 'QUIT') { socket.write('221 bye\r\n'); socket.end(); }
        else socket.write('500 what\r\n');
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen })));
}

test('send() completes an authenticated SMTP dialogue without leaking content to logs', async () => {
  const { server, port, seen } = await fakeSmtpServer();
  try {
    const result = await email.send(
      { to: ['approver@example.test', 'not-an-address'], subject: 'RedactWall: prompt held', text: 'Risk 60. Entities: US_SSN.\n.leading dot line' },
      { SMTP_HOST: '127.0.0.1', SMTP_PORT: String(port), SMTP_SECURE: 'none', SMTP_USER: 'mailer', SMTP_PASS: 'mailer-pass', SMTP_FROM: 'alerts@redactwall.test' },
    );
    assert.deepStrictEqual(result, { ok: true });
    assert.ok(seen.commands.includes('MAIL FROM:<alerts@redactwall.test>'));
    assert.ok(seen.commands.includes('RCPT TO:<approver@example.test>'));
    assert.ok(!seen.commands.some((c) => c.includes('not-an-address')), 'invalid recipients filtered');
    assert.ok(seen.data.includes('Subject: RedactWall: prompt held'));
    assert.ok(seen.data.includes('..leading dot line'), 'dot-stuffed per RFC 5321');
  } finally {
    server.close();
  }
});

test('send() fails cleanly when SMTP is not configured or unreachable', async () => {
  assert.deepStrictEqual(await email.send({ to: 'x@y.z', subject: 's', text: 't' }, {}), { ok: false, error: 'smtp_not_configured' });
  const down = await email.send({ to: 'x@y.z', subject: 's', text: 't' }, { SMTP_HOST: '127.0.0.1', SMTP_PORT: '1', SMTP_SECURE: 'none' });
  assert.strictEqual(down.ok, false);
});

test('email destinations load without a URL and deliver prompt-free events', async () => {
  fs.writeFileSync(SUBS_PATH, JSON.stringify({
    destinations: [
      { id: 'ciso-inbox', type: 'email', to: ['ciso@example.test'], eventTypes: ['digest', 'BLOCKED'], maxAttempts: 1 },
      { id: 'broken-email', type: 'email', to: [] },
    ],
  }));
  const dests = subscriptions.destinations();
  const inbox = dests.find((d) => d.id === 'ciso-inbox');
  assert.ok(inbox, 'email destination normalizes without a url');
  assert.strictEqual(inbox.url, null);
  assert.ok(!dests.some((d) => d.id === 'broken-email'), 'recipient-less email destinations dropped');
  assert.strictEqual(subscriptions.publicDestinations().find((d) => d.id === 'ciso-inbox').recipients, 1);

  const sent = [];
  const record = await subscriptions.deliverTo(inbox,
    { action: 'BLOCKED', riskScore: 60, maxSeverity: 4, user: 'analyst@demo.cu', destination: 'chatgpt.com' },
    { sendMail: async (mail) => { sent.push(mail); return { ok: true }; }, force: true });
  assert.strictEqual(record.status, 'delivered');
  assert.deepStrictEqual(sent[0].to, ['ciso@example.test']);
  assert.ok(sent[0].subject.length > 0);
  assert.ok(!JSON.stringify(sent[0]).match(/\d{3}-\d{2}-\d{4}/), 'no raw identifiers in the mail payload');

  const failed = await subscriptions.deliverTo(inbox,
    { action: 'BLOCKED', riskScore: 61, maxSeverity: 4 },
    { sendMail: async () => ({ ok: false, error: 'smtp_not_configured' }), force: true, sleep: async () => {} });
  assert.strictEqual(failed.status, 'failed');
  assert.strictEqual(failed.lastError, 'smtp_not_configured');
});

test('an alert storm is rate-limited per destination, never silently dropped', async () => {
  fs.writeFileSync(SUBS_PATH, JSON.stringify({
    destinations: [{ id: 'storm-inbox', type: 'email', to: ['soc@example.test'], maxPerHour: 3, maxAttempts: 1 }],
  }));
  const dest = subscriptions.destinations().find((d) => d.id === 'storm-inbox');
  const sent = [];
  const sendMail = async () => { sent.push(1); return { ok: true }; };
  const outcomes = [];
  for (let i = 0; i < 5; i += 1) {
    const record = await subscriptions.deliverTo(dest, { action: 'BLOCKED', riskScore: 50 + i, maxSeverity: 4, user: `u${i}` }, { sendMail, force: true });
    outcomes.push(record.status === 'failed' ? record.lastError : record.status);
  }
  assert.deepStrictEqual(outcomes, ['delivered', 'delivered', 'delivered', 'rate_limited', 'rate_limited']);
  assert.strictEqual(sent.length, 3, 'the relay never sees the storm overflow');
});

test('digest emails are human-readable, not raw JSON', async () => {
  fs.writeFileSync(SUBS_PATH, JSON.stringify({
    destinations: [{ id: 'digest-inbox', type: 'email', to: ['ciso@example.test'], eventTypes: ['digest'], maxAttempts: 1 }],
  }));
  const dest = subscriptions.destinations().find((d) => d.id === 'digest-inbox');
  const sent = [];
  await subscriptions.deliverTo(dest,
    { action: 'digest', status: 'digest', riskScore: 0, maxSeverity: 0, summary: { pending: 3, todayBlocked: 7, approved: 12, denied: 2, totalQueries: 40 } },
    { sendMail: async (mail) => { sent.push(mail); return { ok: true }; }, force: true });
  assert.ok(sent[0].text.includes('Pending approvals: 3'));
  assert.ok(sent[0].text.includes('Blocked today:     7'));
  assert.ok(!sent[0].text.trim().startsWith('{'), 'digest body is prose, not JSON');
});

test('notification status and test-email routes are admin-gated and secret-free', async () => {
  const server = await listen(app);
  const port = server.address().port;
  const admin = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('admin', 'security_admin')}`;
  try {
    const status = await (await fetch(`http://127.0.0.1:${port}/api/notifications/status`, { headers: { cookie: admin } })).json();
    assert.strictEqual(status.smtp.configured, false, 'unit env has no SMTP relay');
    assert.ok(!('pass' in status.smtp) && !('user' in status.smtp), 'credentials never leave the server');
    assert.strictEqual(status.digest.intervalHours, 24);

    const csrf = await (await fetch(`http://127.0.0.1:${port}/api/csrf`, { headers: { cookie: admin } })).json();
    const bad = await fetch(`http://127.0.0.1:${port}/api/notifications/test-email`, {
      method: 'POST', headers: { cookie: admin, 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken }, body: JSON.stringify({ to: 'not-an-address' }),
    });
    assert.strictEqual(bad.status, 400);
    const unconfigured = await fetch(`http://127.0.0.1:${port}/api/notifications/test-email`, {
      method: 'POST', headers: { cookie: admin, 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken }, body: JSON.stringify({ to: 'ciso@example.test' }),
    });
    assert.deepStrictEqual(await unconfigured.json(), { ok: false, error: 'smtp_not_configured' });

    const audit = await (await fetch(`http://127.0.0.1:${port}/api/audit`, { headers: { cookie: admin } })).json();
    const entry = audit.entries.find((e) => e.action === 'EMAIL_TEST_SENT');
    assert.ok(entry && entry.detail.startsWith('c***@example.test'), 'recipient audited masked');

    const auditor = `${auth.SESSION_COOKIE_NAME}=${auth.createSession('aud@x', 'auditor')}`;
    assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/notifications/status`, { headers: { cookie: auditor } })).status, 403);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
