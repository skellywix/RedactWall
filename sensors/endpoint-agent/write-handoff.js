'use strict';
/**
 * Write signed native handoff events for desktop-AI file upload attempts.
 *
 * This helper is intentionally metadata-only: it verifies the referenced file
 * exists, but it never reads file bytes or prompt text into the event spool.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nativeHandoff = require('./native-handoff');
const { loadEnv } = require('../../server/env');
const privatePaths = require('../../server/private-path');

function usage() {
  return [
    'Usage: node sensors/endpoint-agent/write-handoff.js --file <path> --destination <app> [options]',
    '',
    'Options:',
    '  --file <path>                 Local file path attempted for upload',
    '  --destination <app>           Desktop AI app or destination name',
    '  --destination-process <name>  Optional destination process name',
    '  --destination-url <url>       Optional destination URL',
    '  --user <id>                   Optional managed user identity',
    '  --dir <path>                  Handoff spool directory',
    '  --env <path>                  Endpoint agent env file to load',
    '  --id <id>                     Optional event id for tests or hooks',
    '  --nonce <value>               Optional event nonce for tests or hooks',
  ].join('\n');
}

function parseArgs(argv = process.argv.slice(2)) {
  const args = [...argv];
  const parsed = {};
  while (args.length) {
    const arg = args.shift();
    if (arg === '--help' || arg === '-h') return { ...parsed, help: true };
    const takeValue = (key) => {
      const value = args.shift();
      if (!value) throw new Error(`${arg} requires a value`);
      parsed[key] = value;
    };
    if (arg === '--file') takeValue('filePath');
    else if (arg === '--destination') takeValue('destination');
    else if (arg === '--destination-process') takeValue('destinationProcess');
    else if (arg === '--destination-url') takeValue('destinationUrl');
    else if (arg === '--user') takeValue('user');
    else if (arg === '--dir') takeValue('dir');
    else if (arg === '--env') takeValue('envPath');
    else if (arg === '--id') takeValue('id');
    else if (arg === '--nonce') takeValue('nonce');
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else throw new Error(`Unexpected argument: ${arg}`);
  }
  return parsed;
}

function loadEndpointEnv(envPath) {
  const requested = envPath || process.env.REDACTWALL_ENV_PATH || process.env.PROMPTWALL_ENV_PATH || process.env.SENTINEL_ENV_PATH;
  if (!requested) return { loaded: false, path: null, keys: [], skipped: [], errors: [] };
  const result = loadEnv(requested);
  if (result.errors && result.errors.length) {
    throw new Error(`endpoint env has ${result.errors.length} parse error(s)`);
  }
  return result;
}

function absoluteLocalFilePath(filePath) {
  if (!filePath || typeof filePath !== 'string') {
    throw new Error('handoff file path is required');
  }
  if (/^\\\\/.test(filePath)) {
    throw new Error('native handoff filePath must be a local path');
  }
  const resolved = path.resolve(filePath);
  const stat = fs.statSync(resolved);
  if (!stat.isFile()) {
    throw new Error('handoff path must reference a file');
  }
  return resolved;
}

function destinationFromOptions(opts = {}) {
  const destination = {
    app: opts.destination || 'desktop-ai-app',
  };
  if (opts.destinationProcess) destination.process = opts.destinationProcess;
  if (opts.destinationUrl) destination.url = opts.destinationUrl;
  return destination;
}

function safeEventFileName(id) {
  const safe = String(id || '').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 100);
  return safe || `handoff-${Date.now()}`;
}

function verifyPublishedEvent(file, body) {
  privatePaths.assertPrivatePath(file, {
    fs,
    directory: false,
    label: 'native handoff event',
    ownerLabel: 'native handoff event',
  });
  const expected = Buffer.from(body, 'utf8');
  const published = privatePaths.readBoundedRegularFile(file, {
    fs,
    maxBytes: Math.max(expected.length, 1),
    label: 'native handoff event',
  });
  if (!published.equals(expected)) {
    throw new Error('native handoff event changed during publication verification');
  }
}

function writeAtomicJson(file, body) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `${path.basename(file)}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  let fd;
  let stagedIdentity;
  let sourceConsumed = false;
  try {
    fd = fs.openSync(tmp, 'wx', 0o600);
    privatePaths.securePrivatePath(tmp, {
      fs,
      directory: false,
      fresh: true,
      label: 'native handoff event staging file',
      ownerLabel: 'native handoff event staging file',
    });
    fs.writeFileSync(fd, body, { encoding: 'utf8' });
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    stagedIdentity = fs.lstatSync(tmp, { bigint: true });
    privatePaths.publishFileExclusiveDurably(tmp, file, {
      fs,
      consumeSource: true,
      verifyPublished(publishedFile) {
        verifyPublishedEvent(publishedFile, body);
      },
    });
    sourceConsumed = true;
  } finally {
    if (fd !== undefined) {
      if (!stagedIdentity) try { stagedIdentity = fs.fstatSync(fd, { bigint: true }); } catch {}
      try { fs.closeSync(fd); } catch {}
    }
    if (!sourceConsumed && stagedIdentity) {
      try { privatePaths.removeExactPublicationFile(tmp, stagedIdentity, { fs }); } catch {}
    }
  }
}

function writeHandoffFile(opts = {}) {
  loadEndpointEnv(opts.envPath);
  const secret = nativeHandoff.configuredHandoffSecret(opts);
  if (!secret) throw new Error('native handoff secret is not configured');

  const filePath = absoluteLocalFilePath(opts.filePath);
  const handoffDir = path.resolve(opts.dir || nativeHandoff.defaultHandoffDir());
  nativeHandoff.ensurePrivateDirectory(handoffDir);

  const now = opts.now instanceof Date ? opts.now : new Date();
  const event = nativeHandoff.signHandoffEvent({
    version: nativeHandoff.EVENT_VERSION,
    id: opts.id || (crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex')),
    createdAt: now.toISOString(),
    operation: 'upload',
    filePath,
    destination: destinationFromOptions(opts),
    user: opts.user || '',
    nonce: opts.nonce || crypto.randomBytes(16).toString('hex'),
  }, secret);

  const body = JSON.stringify(event, null, 2) + '\n';
  if (Buffer.byteLength(body, 'utf8') > nativeHandoff.MAX_EVENT_BYTES) {
    throw new Error('native handoff event is too large');
  }

  const handoffPath = path.join(handoffDir, `${safeEventFileName(event.id)}.json`);
  try {
    writeAtomicJson(handoffPath, body);
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('native handoff event already exists');
    throw error;
  }
  return { path: handoffPath, event };
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const write = deps.writeHandoffFile || writeHandoffFile;
  try {
    const opts = parseArgs(argv);
    if (opts.help) {
      io.log(usage());
      return 0;
    }
    const result = write(opts);
    io.log(JSON.stringify({
      status: 'written',
      handoffPath: result.path,
      id: result.event.id,
      destination: nativeHandoff.publicDestination(result.event.destination),
    }, null, 2));
    return 0;
  } catch (err) {
    io.error(err.message || err);
    return 1;
  }
}

if (require.main === module) process.exitCode = main();

module.exports = {
  absoluteLocalFilePath,
  destinationFromOptions,
  loadEndpointEnv,
  main,
  parseArgs,
  safeEventFileName,
  usage,
  writeHandoffFile,
  _internal: { writeAtomicJson },
};
