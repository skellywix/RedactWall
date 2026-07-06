'use strict';
/** SMTP transport must deliver sanitized approval metadata and fail closed. */
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const { EventEmitter } = require('node:events');

const smtp = require('../server/smtp');
const { listenNet } = require('./support/listen');

function payload(overrides = {}) {
  return {
    summary: 'Approval routed for review',
    action: 'APPROVAL_ROUTED',
    queryId: 'q_smtp',
    workflow: {
      assignedGroup: 'compliance',
      assignedRole: 'approver',
      slaDueAt: '2026-07-04T12:00:00.000Z',
    },
    source: 'browser_extension',
    channel: 'web',
    destination: 'chat.openai.com',
    user: 'analyst@example.test',
    orgId: 'cu-example',
    maxSeverityLabel: 'high',
    riskScore: 91,
    labels: ['US_SSN'],
    reasons: ['structured pii detected'],
    ...overrides,
  };
}

function channel(port, overrides = {}) {
  return {
    host: '127.0.0.1',
    port,
    from: 'RedactWall <alerts@example.test>',
    to: ['compliance@example.test'],
    secure: false,
    requireTls: false,
    timeoutMs: 100,
    ...overrides,
  };
}

async function scriptedServer(t, onCommand, opts = {}) {
  const commands = [];
  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    if (opts.greeting !== false) socket.write('220 smtp.test ESMTP\r\n');
    let buffer = '';
    let dataMode = false;
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      while (buffer.includes('\n')) {
        const idx = buffer.indexOf('\n');
        const line = buffer.slice(0, idx).replace(/\r$/, '');
        buffer = buffer.slice(idx + 1);
        commands.push(line);
        if (dataMode && line !== '.') continue;
        if (line === 'DATA') dataMode = true;
        if (line === '.') dataMode = false;
        onCommand({ line, socket, commands });
      }
    });
  });
  await listenNet(server);
  t.after(() => new Promise((resolve) => {
    for (const socket of sockets) socket.destroy();
    server.close(() => resolve());
  }));
  return { port: server.address().port, commands };
}

test('smtpSend hook receives a sanitized generated message', async () => {
  let captured;
  const result = await smtp.send(channel(25), payload({
    summary: 'Approval routed\r\nBcc: attacker@example.test',
  }), {
    now: new Date('2026-07-04T12:00:00.000Z'),
    smtpSend: async (smtpChannel, smtpPayload, message) => {
      captured = { smtpChannel, smtpPayload, message };
      return { channel: 'smtp-test', sent: true, status: 202 };
    },
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(result.status, 202);
  assert.strictEqual(captured.smtpChannel.from, 'RedactWall <alerts@example.test>');
  assert.doesNotMatch(captured.message, /^Bcc:/m);
  assert.match(captured.message, /Subject: \[RedactWall\] Approval routed: q_smtp/);
});

test('SMTP delivery falls back to HELO when EHLO is refused', async (t) => {
  const relay = await scriptedServer(t, ({ line, socket }) => {
    if (/^EHLO\b/i.test(line)) socket.write('500 try helo\r\n');
    else if (/^HELO\b/i.test(line)) socket.write('250 smtp.test\r\n');
    else if (/^MAIL FROM:/i.test(line)) socket.write('250 sender ok\r\n');
    else if (/^RCPT TO:/i.test(line)) socket.write('250 recipient ok\r\n');
    else if (/^DATA$/i.test(line)) socket.write('354 end with dot\r\n');
    else if (line === '.') socket.write('250 queued\r\n');
    else if (/^QUIT$/i.test(line)) {
      socket.write('221 bye\r\n');
      socket.end();
    }
  });

  const result = await smtp.send(channel(relay.port), payload());

  assert.strictEqual(result.sent, true);
  assert.ok(relay.commands.some((line) => /^EHLO\b/.test(line)));
  assert.ok(relay.commands.some((line) => /^HELO\b/.test(line)));
});

test('SMTP delivery times out when the relay never sends a greeting', async (t) => {
  const relay = await scriptedServer(t, () => {}, { greeting: false });

  await assert.rejects(
    () => smtp.send(channel(relay.port, { timeoutMs: 20 }), payload()),
    /smtp_timeout/
  );
});

test('SMTP refuses cleartext TLS-required or authenticated delivery', async (t) => {
  const relay = await scriptedServer(t, ({ line, socket }) => {
    if (/^EHLO\b/i.test(line)) socket.write('250 smtp.test\r\n');
  });

  await assert.rejects(
    () => smtp.send(channel(relay.port, { requireTls: true }), payload()),
    /smtp_tls_required/
  );

  await assert.rejects(
    () => smtp.send(channel(relay.port, {
      requireTls: false,
      username: 'smtp-user',
      password: 'smtp-secret',
    }), payload()),
    (err) => {
      assert.match(err.message, /smtp_auth_requires_tls/);
      assert.ok(!err.message.includes('smtp-secret'));
      return true;
    }
  );
});

test('SMTP STARTTLS path re-issues EHLO, authenticates only after upgrade, and sends data', async () => {
  const rawSocket = { end: () => {} };
  const writes = [];
  const secureSocket = {
    write: (text) => writes.push(text),
    end: () => {},
  };
  const commands = [];
  let detached = false;
  let upgraded = false;
  let authCommand = '';
  const firstIo = {
    command: async (commandText) => {
      commands.push(commandText || '<connect>');
      if (!commandText) return { code: 220, text: '220 smtp.test ESMTP' };
      if (/^EHLO\b/.test(commandText)) return { code: 250, text: '250-smtp.test\n250 STARTTLS' };
      if (commandText === 'STARTTLS') return { code: 220, text: '220 ready' };
      throw new Error(`unexpected cleartext command ${commandText}`);
    },
    detach: () => { detached = true; },
  };
  const secondIo = {
    command: async (commandText) => {
      commands.push(commandText || '<message accepted>');
      if (/^EHLO\b/.test(commandText)) return { code: 250, text: '250 smtp.test' };
      if (/^AUTH PLAIN\b/.test(commandText)) {
        authCommand = commandText;
        return { code: 235, text: '235 authenticated' };
      }
      if (/^MAIL FROM:/.test(commandText)) return { code: 250, text: '250 sender ok' };
      if (/^RCPT TO:/.test(commandText)) return { code: 251, text: '251 recipient ok' };
      if (commandText === 'DATA') return { code: 354, text: '354 end with dot' };
      if (!commandText) return { code: 250, text: '250 queued' };
      if (commandText === 'QUIT') return { code: 221, text: '221 bye' };
      throw new Error(`unexpected secure command ${commandText}`);
    },
    detach: () => {},
  };
  const transports = [firstIo, secondIo];

  const result = await smtp.send(channel(25, {
    requireTls: true,
    username: 'smtp-user',
    password: 'smtp-secret',
  }), payload(), {
    openSocket: async () => rawSocket,
    startTls: async (socket, smtpChannel) => {
      assert.strictEqual(socket, rawSocket);
      assert.strictEqual(smtpChannel.host, '127.0.0.1');
      upgraded = true;
      return secureSocket;
    },
    transport: () => transports.shift(),
    now: new Date('2026-07-04T12:00:00.000Z'),
  });

  assert.strictEqual(result.sent, true);
  assert.strictEqual(detached, true);
  assert.strictEqual(upgraded, true);
  assert.ok(commands.filter((line) => /^EHLO\b/.test(line)).length >= 2);
  assert.match(authCommand, /^AUTH PLAIN /);
  assert.strictEqual(Buffer.from(authCommand.split(' ').pop(), 'base64').toString('utf8'), '\u0000smtp-user\u0000smtp-secret');
  assert.ok(writes.join('').includes('Subject: [RedactWall] Approval routed: q_smtp'));
});

test('SMTP internals expose deterministic timeout and TLS-upgrade seams', async () => {
  const timeoutSocket = new EventEmitter();
  let destroyed = false;
  timeoutSocket.setTimeout = (ms) => { timeoutSocket.timeoutMs = ms; };
  timeoutSocket.destroy = () => { destroyed = true; };
  const pending = smtp._internal.openSocket({
    host: 'smtp.test',
    port: 25,
    secure: false,
    timeoutMs: 5,
  }, {
    netCreateConnection: () => timeoutSocket,
  });
  timeoutSocket.emit('timeout');

  await assert.rejects(pending, /smtp_timeout/);
  assert.strictEqual(timeoutSocket.timeoutMs, 5);
  assert.strictEqual(destroyed, true);

  const rawSocket = new EventEmitter();
  const secureSocket = new EventEmitter();
  let tlsOptions;
  const upgraded = await smtp._internal.startTls(rawSocket, { host: 'smtp.test' }, {
    tlsConnect: (options, callback) => {
      tlsOptions = options;
      process.nextTick(callback);
      return secureSocket;
    },
  });

  assert.strictEqual(upgraded, secureSocket);
  assert.strictEqual(tlsOptions.socket, rawSocket);
  assert.strictEqual(tlsOptions.servername, 'smtp.test');
});

test('transport keeps a socket-error listener so a mid-session error fails closed instead of crashing', async () => {
  const socket = new EventEmitter();
  socket.write = () => {};
  const io = smtp._internal.transport(socket, 50);
  const pending = io.command('EHLO redactwall.test'); // registers a reader waiting on data
  // A relay resetting the connection mid-transaction. Before the fix transport
  // attached no 'error' listener, so this emit was an unhandled 'error' event
  // that threw synchronously and took down the whole process.
  socket.emit('error', new Error('ECONNRESET'));
  await assert.rejects(pending, /ECONNRESET|smtp_socket_error/);
  // A late error after the reader already rejected must still not throw.
  assert.doesNotThrow(() => socket.emit('error', new Error('ECONNRESET again')));
});

test('SMTP delivery surfaces sanitized relay failures and connection errors', async (t) => {
  const relay = await scriptedServer(t, ({ line, socket }) => {
    if (/^EHLO\b/i.test(line)) socket.write('250 smtp.test\r\n');
    else if (/^MAIL FROM:/i.test(line)) socket.write('250 sender ok\r\n');
    else if (/^RCPT TO:/i.test(line)) socket.write('550 denied\r\n');
  });

  await assert.rejects(
    () => smtp.send(channel(relay.port), payload()),
    /smtp_rcpt_550/
  );

  const closed = net.createServer();
  await listenNet(closed);
  const port = closed.address().port;
  await new Promise((resolve) => closed.close(resolve));

  await assert.rejects(
    () => smtp.send(channel(port, { timeoutMs: 50 }), payload()),
    (err) => {
      assert.ok(/ECONNREFUSED|ECONNRESET|smtp_timeout/.test(err.message));
      return true;
    }
  );
});
