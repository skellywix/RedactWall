'use strict';
/**
 * Minimal SMTP delivery for sanitized approval workflow email.
 *
 * This module intentionally sends only plain-text routing metadata prepared by
 * `server/notifiers.js`. It owns SMTP wire handling and mail-header hygiene.
 */
const crypto = require('node:crypto');
const net = require('node:net');
const os = require('node:os');
const tls = require('node:tls');

function cleanHeader(value, max = 320) {
  return String(value || '').replace(/[\r\n]+/g, ' ').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);
}

function extractEmailAddress(value) {
  const clean = cleanHeader(value);
  const match = clean.match(/<([^<>\s]+@[^<>\s]+)>/);
  const email = (match ? match[1] : clean).trim();
  return /^[^\s<>@]+@[^\s<>@]+$/.test(email) ? email : '';
}

function parseRecipients(value) {
  return Array.from(new Set(String(value || '')
    .split(/[;,]/)
    .map(extractEmailAddress)
    .filter(Boolean)))
    .slice(0, 20);
}

function subject(payload) {
  const action = payload.action === 'APPROVAL_ESCALATED' ? 'Approval escalated' : 'Approval routed';
  return `[PromptWall] ${action}: ${payload.queryId || 'unknown'}`;
}

function body(payload) {
  const workflow = payload.workflow || {};
  return [
    payload.summary,
    '',
    `Action: ${payload.action || 'APPROVAL_ROUTED'}`,
    `Query: ${payload.queryId || 'unknown'}`,
    `Owner: ${workflow.assignedGroup || 'unassigned'} / ${workflow.assignedRole || 'unassigned'}`,
    `SLA: ${workflow.slaDueAt || 'none'}`,
    `Source: ${payload.source || 'unknown'}`,
    `Channel: ${payload.channel || 'unknown'}`,
    `Destination: ${payload.destination || 'unknown'}`,
    `User: ${payload.user || 'unknown'}`,
    `Org: ${payload.orgId || 'none'}`,
    `Risk: ${payload.maxSeverityLabel || 'none'} (${payload.riskScore || 0})`,
    `Labels: ${payload.labels && payload.labels.length ? payload.labels.join(', ') : 'none'}`,
    `Reasons: ${payload.reasons && payload.reasons.length ? payload.reasons.join('; ') : 'none'}`,
    '',
    'Review this item in the PromptWall dashboard.',
  ].map((line) => cleanHeader(line, 1000)).join('\n');
}

function messageForPayload(channel, payload, now = new Date()) {
  const to = (channel.to || []).map((recipient) => cleanHeader(recipient)).join(', ');
  const messageIdHost = cleanHeader(os.hostname() || 'localhost').replace(/[^a-z0-9.-]/gi, '') || 'localhost';
  const headers = [
    `From: ${cleanHeader(channel.from)}`,
    `To: ${to}`,
    `Subject: ${cleanHeader(subject(payload), 180)}`,
    `Date: ${now.toUTCString()}`,
    `Message-ID: <promptwall-${crypto.randomBytes(12).toString('hex')}@${messageIdHost}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
  ];
  return headers.join('\r\n') + '\r\n\r\n' + body(payload).replace(/\n/g, '\r\n') + '\r\n';
}

function mailboxPath(value) {
  const email = extractEmailAddress(value);
  if (!email) throw new Error('invalid_smtp_address');
  return `<${email}>`;
}

function dotStuff(message) {
  return String(message).replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
}

function openSocket(channel, deps = {}) {
  const timeoutMs = channel.timeoutMs || 10000;
  return new Promise((resolve, reject) => {
    const options = { host: channel.host, port: channel.port, servername: channel.host };
    const tlsConnect = deps.tlsConnect || tls.connect;
    const netCreateConnection = deps.netCreateConnection || net.createConnection;
    const socket = channel.secure ? tlsConnect(options) : netCreateConnection(options);
    const event = channel.secure ? 'secureConnect' : 'connect';
    const cleanup = () => {
      socket.off('error', onError);
      socket.off(event, onConnect);
      socket.off('timeout', onTimeout);
    };
    const onError = (err) => {
      cleanup();
      reject(err);
    };
    const onTimeout = () => {
      cleanup();
      socket.destroy();
      reject(new Error('smtp_timeout'));
    };
    const onConnect = () => {
      cleanup();
      resolve(socket);
    };
    socket.setTimeout(timeoutMs);
    socket.once('error', onError);
    socket.once('timeout', onTimeout);
    socket.once(event, onConnect);
  });
}

function transport(socket, timeoutMs = 10000) {
  let buffer = '';
  let waiter = null;
  const onData = (chunk) => {
    buffer += chunk.toString('utf8');
    if (!waiter) return;
    const notify = waiter;
    waiter = null;
    notify();
  };
  socket.on('data', onData);

  function waitForData() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        waiter = null;
        reject(new Error('smtp_timeout'));
      }, timeoutMs);
      waiter = () => {
        clearTimeout(timer);
        resolve();
      };
    });
  }

  async function readLine() {
    while (true) {
      const idx = buffer.indexOf('\n');
      if (idx >= 0) {
        const line = buffer.slice(0, idx + 1);
        buffer = buffer.slice(idx + 1);
        return line.replace(/\r?\n$/, '');
      }
      await waitForData();
    }
  }

  async function command(commandText) {
    if (commandText) socket.write(commandText + '\r\n');
    const lines = [];
    while (true) {
      const line = await readLine();
      lines.push(line);
      if (/^\d{3} /.test(line) || !/^\d{3}-/.test(line)) break;
    }
    const code = Number(String(lines[lines.length - 1] || '').slice(0, 3));
    return { code, lines, text: lines.join('\n') };
  }

  return { command, detach: () => socket.off('data', onData) };
}

function expect(response, expected, context) {
  if (!expected.includes(response.code)) {
    throw new Error(`${context || 'smtp'}_${response.code || 'invalid_response'}`);
  }
  return response;
}

async function hello(io, host) {
  const domain = cleanHeader(host || os.hostname() || 'localhost').replace(/[^a-z0-9.-]/gi, '') || 'localhost';
  const ehlo = await io.command(`EHLO ${domain}`);
  if (ehlo.code === 250) return ehlo;
  return expect(await io.command(`HELO ${domain}`), [250], 'smtp_helo');
}

function startTls(socket, channel, deps = {}) {
  return new Promise((resolve, reject) => {
    const tlsConnect = deps.tlsConnect || tls.connect;
    const secureSocket = tlsConnect({ socket, servername: channel.host }, () => resolve(secureSocket));
    secureSocket.once('error', reject);
  });
}

async function send(channel, payload, opts = {}) {
  if (typeof opts.smtpSend === 'function') {
    return opts.smtpSend(channel, payload, messageForPayload(channel, payload, opts.now || new Date()));
  }
  const open = opts.openSocket || ((smtpChannel) => openSocket(smtpChannel, opts));
  const makeTransport = opts.transport || transport;
  let socket = await open(channel);
  let io = makeTransport(socket, channel.timeoutMs);
  let encrypted = !!channel.secure;
  try {
    expect(await io.command(), [220], 'smtp_connect');
    let helloResponse = await hello(io, channel.host);
    if (!encrypted && /\bSTARTTLS\b/i.test(helloResponse.text)) {
      expect(await io.command('STARTTLS'), [220], 'smtp_starttls');
      io.detach();
      socket = opts.startTls ? await opts.startTls(socket, channel) : await startTls(socket, channel, opts);
      encrypted = true;
      io = makeTransport(socket, channel.timeoutMs);
      await hello(io, channel.host);
    }
    if (!encrypted && channel.requireTls) throw new Error('smtp_tls_required');
    if (channel.username || channel.password) {
      if (!encrypted) throw new Error('smtp_auth_requires_tls');
      const auth = Buffer.from(`\u0000${channel.username || ''}\u0000${channel.password || ''}`).toString('base64');
      expect(await io.command(`AUTH PLAIN ${auth}`), [235, 503], 'smtp_auth');
    }
    expect(await io.command(`MAIL FROM:${mailboxPath(channel.from)}`), [250], 'smtp_mail');
    for (const recipient of channel.to || []) {
      expect(await io.command(`RCPT TO:${mailboxPath(recipient)}`), [250, 251], 'smtp_rcpt');
    }
    expect(await io.command('DATA'), [354], 'smtp_data');
    socket.write(dotStuff(messageForPayload(channel, payload, opts.now || new Date())) + '\r\n.\r\n');
    expect(await io.command(), [250], 'smtp_message');
    await io.command('QUIT');
    return { channel: channel.name || 'smtp', sent: true, status: 250 };
  } finally {
    try { socket.end(); } catch {}
  }
}

module.exports = {
  extractEmailAddress,
  messageForPayload,
  parseRecipients,
  send,
  _internal: {
    cleanHeader,
    dotStuff,
    expect,
    hello,
    mailboxPath,
    openSocket,
    startTls,
    transport,
  },
};
