'use strict';
/**
 * Minimal, dependency-free SMTP sender for approver alerts and digests.
 * Speaks EHLO -> (STARTTLS) -> AUTH LOGIN -> MAIL/RCPT/DATA against a relay
 * configured via env. Message bodies are the same prompt-free event payloads
 * the SIEM adapters send; nothing here ever logs message content.
 *
 *   SMTP_HOST, SMTP_PORT (default 587), SMTP_FROM (default redactwall@host),
 *   SMTP_USER + SMTP_PASS (optional AUTH LOGIN),
 *   SMTP_SECURE: 'starttls' (default) | 'tls' (implicit) | 'none' (test relays)
 */
require('./env').loadEnv();
const net = require('net');
const tls = require('tls');

function config(env = process.env) {
  const host = String(env.SMTP_HOST || '').trim();
  return {
    host,
    port: Number(env.SMTP_PORT) || 587,
    from: String(env.SMTP_FROM || (host ? `redactwall@${host}` : '')).trim(),
    user: String(env.SMTP_USER || '').trim(),
    pass: String(env.SMTP_PASS || ''),
    secure: ['tls', 'starttls', 'none'].includes(env.SMTP_SECURE) ? env.SMTP_SECURE : 'starttls',
    enabled: !!host,
  };
}

// Line-oriented SMTP dialogue over an existing socket. Each step sends one
// command and waits for a final reply line (multiline "250-" continues).
function dialogue(socket, timeoutMs) {
  let buffer = '';
  let pending = null;
  // A final reply line ("250 ok" vs "250-more") completes the pending expect.
  // Checked both on new data AND when an expect registers, because the reply
  // (e.g. the server greeting) can arrive before the caller starts waiting.
  function drain() {
    if (!pending) return;
    for (const line of buffer.split(/\r?\n/)) {
      if (/^\d{3} /.test(line)) {
        const resolve = pending.resolve; pending = null; buffer = '';
        resolve(line);
        return;
      }
    }
  }
  socket.on('data', (chunk) => { buffer += chunk.toString('utf8'); drain(); });
  return {
    expect(code, command) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('smtp_timeout')), timeoutMs);
        pending = {
          resolve: (line) => {
            clearTimeout(timer);
            if (!line.startsWith(String(code))) return reject(new Error('smtp_' + line.slice(0, 3)));
            resolve(line);
          },
        };
        if (command != null) socket.write(command + '\r\n');
        drain();
      });
    },
  };
}

const CONNECT_TIMEOUT_MS = (() => {
  const n = Number(process.env.SMTP_CONNECT_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : 10000;
})();

function connect(cfg) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const onConnect = () => {
      if (settled) return;
      settled = true;
      socket.setTimeout(0); // clear the connect deadline; expects have their own timers
      resolve(socket);
    };
    const socket = cfg.secure === 'tls'
      ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host }, onConnect)
      : net.connect({ host: cfg.host, port: cfg.port }, onConnect);
    socket.once('error', (e) => { if (settled) return; settled = true; reject(new Error('smtp_connect: ' + e.message)); });
    // A black-holed host that never ACKs the SYN would otherwise hang for the
    // OS TCP timeout (1-2 min); fail the attempt fast instead.
    socket.setTimeout(CONNECT_TIMEOUT_MS, () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error('smtp_connect_timeout'));
    });
  });
}

function message(cfg, { to, subject, text }) {
  // Dot-stuff body lines per RFC 5321 and keep headers single-line.
  const body = String(text || '').split(/\r?\n/).map((l) => (l.startsWith('.') ? '.' + l : l)).join('\r\n');
  return [
    `From: RedactWall <${cfg.from}>`,
    `To: ${to.join(', ')}`,
    `Subject: ${String(subject || 'RedactWall notification').replace(/[\r\n]/g, ' ').slice(0, 200)}`,
    `Date: ${new Date().toUTCString()}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    body,
    '.',
  ].join('\r\n');
}

async function transact(socket, cfg, mail) {
  const smtp = dialogue(socket, 10000);
  await smtp.expect(220, null);
  await smtp.expect(250, 'EHLO redactwall');
  if (cfg.secure === 'starttls') {
    await smtp.expect(220, 'STARTTLS');
    socket = await new Promise((resolve, reject) => {
      const upgraded = tls.connect({ socket, servername: cfg.host }, () => resolve(upgraded));
      upgraded.once('error', (e) => reject(new Error('smtp_tls: ' + e.message)));
    });
    return transactAuthed(socket, cfg, mail, dialogue(socket, 10000), true);
  }
  return transactAuthed(socket, cfg, mail, smtp, false);
}

async function transactAuthed(socket, cfg, mail, smtp, resendEhlo) {
  if (resendEhlo) await smtp.expect(250, 'EHLO redactwall');
  if (cfg.user) {
    await smtp.expect(334, 'AUTH LOGIN');
    await smtp.expect(334, Buffer.from(cfg.user).toString('base64'));
    await smtp.expect(235, Buffer.from(cfg.pass).toString('base64'));
  }
  await smtp.expect(250, `MAIL FROM:<${cfg.from}>`);
  for (const rcpt of mail.to) await smtp.expect(250, `RCPT TO:<${rcpt}>`);
  await smtp.expect(354, 'DATA');
  await smtp.expect(250, message(cfg, mail));
  socket.write('QUIT\r\n');
  socket.end();
  return { ok: true };
}

// Send one prompt-free notification. Never throws; never logs content.
async function send({ to, subject, text }, env = process.env) {
  const cfg = config(env);
  const recipients = (Array.isArray(to) ? to : [to]).map((r) => String(r || '').trim()).filter((r) => /^[^\s@]+@[^\s@]+$/.test(r));
  if (!cfg.enabled) return { ok: false, error: 'smtp_not_configured' };
  if (!recipients.length) return { ok: false, error: 'no_valid_recipients' };
  let socket;
  try {
    socket = await connect(cfg);
    return await transact(socket, cfg, { to: recipients, subject, text });
  } catch (e) {
    try { if (socket) socket.destroy(); } catch { /* already closed */ }
    return { ok: false, error: String(e.message || 'smtp_error').slice(0, 120) };
  }
}

module.exports = { send, config };
