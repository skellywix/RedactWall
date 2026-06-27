'use strict';
/** MFA enrollment URI helper stays explicit and validates the configured seed. */
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  normalizeBase32,
  otpauthUri,
  parseArgs,
  validateSecret,
} = require('../scripts/mfa-uri');

test('normalizes and validates base32 totp secrets', () => {
  assert.strictEqual(normalizeBase32('jbsw y3dp-ehpk3pxp='), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(validateSecret('jbsw y3dp-ehpk3pxp='), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(validateSecret('short'), null);
  assert.strictEqual(validateSecret('not-valid-*'), null);
});

test('builds a standard otpauth uri for authenticator enrollment', () => {
  const uri = new URL(otpauthUri({
    secret: 'jbsw y3dp-ehpk3pxp=',
    account: 'alice@example.test',
    issuer: 'PromptSentinel Demo',
  }));

  assert.strictEqual(uri.protocol, 'otpauth:');
  assert.strictEqual(uri.hostname, 'totp');
  assert.strictEqual(decodeURIComponent(uri.pathname), '/PromptSentinel Demo:alice@example.test');
  assert.strictEqual(uri.searchParams.get('secret'), 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(uri.searchParams.get('issuer'), 'PromptSentinel Demo');
  assert.strictEqual(uri.searchParams.get('algorithm'), 'SHA1');
  assert.strictEqual(uri.searchParams.get('digits'), '6');
  assert.strictEqual(uri.searchParams.get('period'), '30');
});

test('rejects invalid enrollment secrets and parses cli options', () => {
  assert.throws(() => otpauthUri({ secret: 'bad-*' }), /ADMIN_TOTP_SECRET/);
  const opts = parseArgs(['--env', 'pilot.env', '--issuer', 'Pilot CU', '--account', 'admin@pilot.test']);
  assert.match(opts.envPath, /pilot\.env$/);
  assert.strictEqual(opts.issuer, 'Pilot CU');
  assert.strictEqual(opts.account, 'admin@pilot.test');

  const separated = parseArgs(['--', '--env', 'pilot.env']);
  assert.match(separated.envPath, /pilot\.env$/);
});

function childEnv() {
  const env = { ...process.env };
  delete env.ADMIN_TOTP_SECRET;
  delete env.ADMIN_USER;
  return env;
}

test('cli reads an explicit env file and prints enrollment uri only on request', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-mfa-uri-'));
  const envPath = path.join(dir, 'pilot.env');
  fs.writeFileSync(envPath, [
    'ADMIN_USER=pilot-admin',
    'ADMIN_TOTP_SECRET=jbsw y3dp-ehpk3pxp=',
    '',
  ].join('\n'));

  const output = execFileSync(process.execPath, [
    path.join(__dirname, '..', 'scripts', 'mfa-uri.js'),
    '--env',
    envPath,
    '--issuer',
    'PromptSentinel Test',
  ], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    env: childEnv(),
  });

  assert.match(output, /Treat this MFA enrollment URI as a secret/);
  assert.match(output, /otpauth:\/\/totp\/PromptSentinel%20Test%3Apilot-admin\?/);
  assert.match(output, /secret=JBSWY3DPEHPK3PXP/);
  assert.match(output, /issuer=PromptSentinel\+Test/);
});

test('cli exits nonzero for invalid configured secret', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-mfa-uri-bad-'));
  const envPath = path.join(dir, 'bad.env');
  fs.writeFileSync(envPath, 'ADMIN_USER=admin\nADMIN_TOTP_SECRET=not-valid-*-\n');

  const result = spawnSync(process.execPath, [
    path.join(__dirname, '..', 'scripts', 'mfa-uri.js'),
    '--env',
    envPath,
  ], {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    env: childEnv(),
  });

  assert.notStrictEqual(result.status, 0);
  assert.match(result.stderr, /MFA enrollment URI failed: ADMIN_TOTP_SECRET/);
  assert.strictEqual(result.stdout, '');
});
