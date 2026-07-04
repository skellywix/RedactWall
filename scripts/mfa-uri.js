'use strict';
/**
 * Print a standard otpauth:// URI for enrolling the Security Admin TOTP secret.
 * This command intentionally reveals the MFA seed, so it only runs on explicit
 * operator request and never as part of normal setup/preflight output.
 */
const path = require('path');
const { effectiveEnv } = require('./setup');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_ENV_PATH = path.join(ROOT, '.env');

function normalizeBase32(value) {
  return String(value || '').replace(/[\s=-]/g, '').toUpperCase();
}

function validateSecret(secret) {
  const normalized = normalizeBase32(secret);
  if (normalized.length < 16) return null;
  if (!/^[A-Z2-7]+$/.test(normalized)) return null;
  return normalized;
}

function otpauthUri({ secret, account = 'admin', issuer = 'PromptWall' } = {}) {
  const normalized = validateSecret(secret);
  if (!normalized) throw new Error('ADMIN_TOTP_SECRET must be valid base32 and at least 16 characters.');
  const safeIssuer = String(issuer || 'PromptWall').trim() || 'PromptWall';
  const safeAccount = String(account || 'admin').trim() || 'admin';
  const label = encodeURIComponent(`${safeIssuer}:${safeAccount}`);
  const params = new URLSearchParams({
    secret: normalized,
    issuer: safeIssuer,
    algorithm: 'SHA1',
    digits: '6',
    period: '30',
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

function parseArgs(argv = process.argv.slice(2)) {
  const opts = {
    envPath: DEFAULT_ENV_PATH,
    issuer: 'PromptWall',
    account: '',
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--') continue;
    if (arg === '--env') opts.envPath = path.resolve(argv[++i] || DEFAULT_ENV_PATH);
    else if (arg === '--recovery') opts.recovery = true;
    else if (arg === '--issuer') opts.issuer = argv[++i] || opts.issuer;
    else if (arg === '--account') opts.account = argv[++i] || '';
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown option: ${arg}`);
  }
  return opts;
}

function printHelp(io = console) {
  io.log([
    'Usage: npm run mfa:uri',
    '       npm run mfa:uri -- [options]',
    '       node scripts/mfa-uri.js [options]',
    '',
    'Options:',
    '  --env <path>       Read a non-default env file',
    '  --issuer <name>    Authenticator issuer label (default PromptWall)',
    '  --account <name>   Authenticator account label (default ADMIN_USER)',
    '  --recovery         Print single-use MFA recovery codes instead of the URI',
  ].join('\n'));
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const loadEnv = deps.effectiveEnv || effectiveEnv;
  const opts = parseArgs(argv);
  if (opts.help) {
    printHelp(io);
    return 0;
  }
  const env = loadEnv(opts.envPath);
  const account = opts.account || env.ADMIN_USER || 'admin';
  if (opts.recovery) {
    const auth = deps.auth || require('../server/auth');
    const codes = auth.recoveryCodes(env.ADMIN_TOTP_SECRET);
    if (!codes.length) throw new Error('ADMIN_TOTP_SECRET must be valid base32 and at least 16 characters.');
    io.log('Store these single-use MFA recovery codes offline. Each works exactly once at the admin login.');
    for (const code of codes) io.log(code);
    return 0;
  }
  const uri = otpauthUri({
    secret: env.ADMIN_TOTP_SECRET,
    account,
    issuer: opts.issuer,
  });
  io.log('Treat this MFA enrollment URI as a secret. Enroll it once, then keep ADMIN_TOTP_SECRET protected.');
  io.log(uri);
  return 0;
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (e) {
    console.error('MFA enrollment URI failed: ' + (e && e.message ? e.message : e));
    process.exitCode = 1;
  }
}

module.exports = {
  main,
  normalizeBase32,
  otpauthUri,
  parseArgs,
  printHelp,
  validateSecret,
};
