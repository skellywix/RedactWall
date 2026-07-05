'use strict';
/**
 * Browser -> endpoint native messaging host for local file-upload intent.
 *
 * When the browser extension blocks an upload it cannot inspect locally
 * (unsupported type, OCR required, oversized), it sends a tiny metadata-only
 * intent message - file name, size, destination host - over Chrome native
 * messaging. This host resolves that intent against a small set of local
 * search roots (Downloads/Desktop/Documents by default) and, on exactly one
 * name+size match, writes the existing signed handoff event so the endpoint
 * agent scans the real file through the shared local detector path.
 *
 * Privacy contract: the message may not carry file bytes or prompt text,
 * replies never echo paths or file names, and only the signed handoff spool
 * (already metadata-only) learns the resolved path.
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const { withEnvAliases } = require('../../server/env');
const writeHandoff = require('./write-handoff');

const MAX_MESSAGE_BYTES = 16 * 1024;
const MAX_MESSAGES_PER_RUN = 100;
const MAX_FILE_NAME_CHARS = 255;
const MAX_INTENT_FILE_BYTES = 1024 * 1024 * 1024;
const ALLOWED_INTENT_KEYS = new Set(['type', 'fileName', 'sizeBytes', 'destination', 'destinationUrl', 'user', 'id']);
const DEFAULT_SEARCH_SUBDIRS = ['Downloads', 'Desktop', 'Documents'];

function boundedText(value, max) {
  return String(value == null ? '' : value).replace(/[\r\n\t]/g, ' ').trim().slice(0, max);
}

function intentSearchRoots(env = process.env, home = os.homedir()) {
  const resolved = withEnvAliases(env);
  const configured = String(resolved.ENDPOINT_AGENT_INTENT_SEARCH_DIRS || '').trim();
  const roots = configured
    ? configured.split(path.delimiter).map((dir) => dir.trim()).filter(Boolean)
    : DEFAULT_SEARCH_SUBDIRS.map((name) => path.join(home, name));
  return [...new Set(roots.map((dir) => path.resolve(dir)))].slice(0, 8);
}

function normalizeIntent(message) {
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    throw new Error('intent message must be a JSON object');
  }
  for (const key of Object.keys(message)) {
    if (!ALLOWED_INTENT_KEYS.has(key)) throw new Error(`intent key ${key} is not allowed`);
  }
  if (message.type !== 'upload_intent') throw new Error('intent type is unsupported');
  const fileName = path.basename(boundedText(message.fileName, MAX_FILE_NAME_CHARS));
  if (!fileName || fileName === '.' || fileName === '..') throw new Error('intent fileName is required');
  const sizeBytes = Number(message.sizeBytes);
  if (!Number.isInteger(sizeBytes) || sizeBytes <= 0 || sizeBytes > MAX_INTENT_FILE_BYTES) {
    throw new Error('intent sizeBytes is invalid');
  }
  const destination = boundedText(message.destination, 80) || 'browser-ai-destination';
  return {
    id: boundedText(message.id, 120),
    fileName,
    sizeBytes,
    destination,
    destinationUrl: boundedText(message.destinationUrl, 200),
    user: boundedText(message.user, 160),
  };
}

// Direct children of each root only: intent resolution is a convenience for
// common staging folders, not a disk crawl.
function resolveIntentFile(intent, opts = {}) {
  const fsImpl = opts.fs || fs;
  const roots = Array.isArray(opts.roots) ? opts.roots : intentSearchRoots(opts.env, opts.home);
  const matches = [];
  for (const root of roots) {
    const candidate = path.join(root, intent.fileName);
    try {
      const stat = fsImpl.statSync(candidate);
      if (stat.isFile() && stat.size === intent.sizeBytes) matches.push(candidate);
    } catch { /* root or candidate missing */ }
  }
  return matches;
}

function handleIntentMessage(message, opts = {}) {
  let intent;
  try {
    intent = normalizeIntent(message);
  } catch (err) {
    return { ok: false, error: boundedText(err.message, 160) };
  }
  const matches = resolveIntentFile(intent, opts);
  if (!matches.length) return { ok: true, status: 'not_found', matches: 0 };
  if (matches.length > 1) return { ok: true, status: 'ambiguous', matches: matches.length };
  try {
    const write = opts.writeHandoffFile || writeHandoff.writeHandoffFile;
    const result = write({
      filePath: matches[0],
      destination: intent.destination,
      destinationProcess: 'browser',
      ...(intent.destinationUrl ? { destinationUrl: intent.destinationUrl } : {}),
      ...(intent.user ? { user: intent.user } : {}),
      ...(intent.id ? { id: intent.id } : {}),
      ...(opts.dir ? { dir: opts.dir } : {}),
      ...(opts.envPath ? { envPath: opts.envPath } : {}),
      ...(opts.secret !== undefined ? { secret: opts.secret } : {}),
    });
    return { ok: true, status: 'handoff_written', matches: 1, id: result.event.id };
  } catch (err) {
    return { ok: false, error: boundedText(err.message, 160) };
  }
}

function encodeFrame(value) {
  const body = Buffer.from(JSON.stringify(value), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return Buffer.concat([header, body]);
}

// Consume complete native-messaging frames from an accumulating buffer.
// Returns the parsed messages and the unconsumed remainder.
function decodeFrames(buffer) {
  const messages = [];
  let rest = buffer;
  while (rest.length >= 4) {
    const length = rest.readUInt32LE(0);
    if (length > MAX_MESSAGE_BYTES) throw new Error('intent message is too large');
    if (rest.length < 4 + length) break;
    messages.push(JSON.parse(rest.subarray(4, 4 + length).toString('utf8')));
    rest = rest.subarray(4 + length);
  }
  return { messages, rest };
}

function parseArgs(argv = process.argv.slice(2)) {
  const args = [...argv];
  const parsed = {};
  while (args.length) {
    const arg = args.shift();
    if (arg === '--env') parsed.envPath = args.shift();
    else if (arg === '--dir') parsed.dir = args.shift();
    // Chrome passes the extension origin and a window handle; ignore them.
  }
  return parsed;
}

function run(opts = {}) {
  const stdin = opts.stdin || process.stdin;
  const stdout = opts.stdout || process.stdout;
  const stderr = opts.stderr || process.stderr;
  let pending = Buffer.alloc(0);
  let handled = 0;
  return new Promise((resolve) => {
    stdin.on('data', (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      let decoded;
      try {
        decoded = decodeFrames(pending);
      } catch (err) {
        stdout.write(encodeFrame({ ok: false, error: boundedText(err.message, 160) }));
        stdin.destroy();
        return;
      }
      pending = decoded.rest;
      for (const message of decoded.messages) {
        if (handled >= MAX_MESSAGES_PER_RUN) { stdin.destroy(); return; }
        handled += 1;
        const reply = handleIntentMessage(message, opts);
        if (reply.ok === false) stderr.write(JSON.stringify({ nativeIntent: 'rejected', error: reply.error }) + '\n');
        stdout.write(encodeFrame(reply));
      }
    });
    stdin.on('close', () => resolve(handled));
    stdin.on('end', () => resolve(handled));
  });
}

function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  try {
    writeHandoff.loadEndpointEnv(opts.envPath);
  } catch (err) {
    (deps.console || console).error(err.message || err);
    return Promise.resolve(1);
  }
  return (deps.run || run)(opts).then(() => 0);
}

if (require.main === module) {
  main().then((code) => { process.exitCode = code; });
}

module.exports = {
  MAX_MESSAGE_BYTES,
  MAX_MESSAGES_PER_RUN,
  decodeFrames,
  encodeFrame,
  handleIntentMessage,
  intentSearchRoots,
  main,
  normalizeIntent,
  parseArgs,
  resolveIntentFile,
  run,
};
