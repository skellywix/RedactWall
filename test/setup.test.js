'use strict';
/** First-run setup config generation. */
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseEnv } = require('../server/env');
const {
  assertNodeVersion,
  buildEnv,
  installDependencies,
  main,
  mergeEnv,
  npmCommand,
  parseArgs,
  placeholderValue,
  printHelp,
  printStatus,
  quoteEnvValue,
  readEnvFile,
  renderEnv,
  writeEnvAtomic,
  run,
  statusFromEnv,
} = require('../scripts/setup');

const ROOT = path.join(__dirname, '..');
const SETUP_ENV_KEYS = [
  'PORT',
  'NODE_ENV',
  'HTTPS',
  'COOKIE_SECURE',
  'REDACTWALL_DB_PATH',
  'REDACTWALL_SAAS_MODE',
  'REDACTWALL_TENANT_ID',
  'REDACTWALL_LICENSE_CUSTOMER_ID',
  'REDACTWALL_SEAT_LIMIT',
  'REDACTWALL_REQUIRE_TENANT_CONTEXT',
  'REDACTWALL_REQUIRE_USER_IDENTITY',
  'ADMIN_USER',
  'ADMIN_PASSWORD',
  'ADMIN_TOTP_SECRET',
  'APPROVER_USER',
  'APPROVER_PASSWORD',
  'REDACTWALL_SECRET',
  'REDACTWALL_DATA_KEY',
  'INGEST_API_KEY',
  'SCIM_BEARER_TOKEN',
  'OIDC_ISSUER',
  'OIDC_CLIENT_ID',
  'OIDC_CLIENT_SECRET',
  'OIDC_REDIRECT_URI',
  'OIDC_SCOPE',
  'OIDC_AUTHORIZATION_ENDPOINT',
  'OIDC_TOKEN_ENDPOINT',
  'OIDC_JWKS_URI',
  'REDACTWALL_REQUEST_TIMEOUT_MS',
  'SIEM_WEBHOOK_URL',
  'SIEM_WEBHOOK_TOKEN',
  'SIEM_ALERT_MIN_RISK',
  'SIEM_ALERT_MIN_SEVERITY',
  'SIEM_POSTURE_FEED_ENABLED',
  'SIEM_POSTURE_MIN_INTERVAL_MS',
  'AUDITOR_USER',
  'AUDITOR_PASSWORD',
  'REDACTWALL_ENV_PATH',
  'REDACTWALL_DB_PATH',
  'REDACTWALL_SAAS_MODE',
  'REDACTWALL_TENANT_ID',
  'REDACTWALL_LICENSE_CUSTOMER_ID',
  'REDACTWALL_SEAT_LIMIT',
  'REDACTWALL_REQUIRE_TENANT_CONTEXT',
  'REDACTWALL_REQUIRE_USER_IDENTITY',
  'REDACTWALL_SECRET',
  'REDACTWALL_DATA_KEY',
  'REDACTWALL_INGEST_API_KEY',
  'REDACTWALL_SCIM_BEARER_TOKEN',
  'REDACTWALL_OIDC_ISSUER',
  'REDACTWALL_OIDC_CLIENT_ID',
  'REDACTWALL_OIDC_CLIENT_SECRET',
  'REDACTWALL_OIDC_REDIRECT_URI',
  'REDACTWALL_OIDC_SCOPE',
  'REDACTWALL_OIDC_AUTHORIZATION_ENDPOINT',
  'REDACTWALL_OIDC_TOKEN_ENDPOINT',
  'REDACTWALL_OIDC_JWKS_URI',
  'REDACTWALL_REQUEST_TIMEOUT_MS',
  'REDACTWALL_ENV_PATH',
];

function childEnv() {
  const env = { ...process.env };
  for (const key of SETUP_ENV_KEYS) delete env[key];
  return env;
}

test('production setup env passes deployment preflight', () => {
  const env = buildEnv({ production: true });
  const unboundStatus = statusFromEnv(env);

  assert.strictEqual(env.NODE_ENV, 'production');
  assert.strictEqual(env.HTTPS, 'true');
  assert.strictEqual(env.COOKIE_SECURE, 'true');
  assert.notStrictEqual(env.ADMIN_PASSWORD, 'ChangeMe!2026');
  assert.match(env.ADMIN_TOTP_SECRET, /^[A-Z2-7]{16,}$/);
  assert.notStrictEqual(env.INGEST_API_KEY, 'dev-ingest-key');
  assert.strictEqual(env.OIDC_ISSUER, '');
  assert.strictEqual(env.OIDC_SCOPE, 'openid email profile');
  assert.ok(env.REDACTWALL_SECRET.length >= 32);
  assert.ok(env.REDACTWALL_DATA_KEY.length >= 32);
  assert.strictEqual(env.REDACTWALL_SAAS_MODE, 'false');
  assert.strictEqual(env.REDACTWALL_LICENSE_CUSTOMER_ID, '');
  assert.strictEqual(unboundStatus.ready, false);
  assert.strictEqual(unboundStatus.checks.find((item) => item.id === 'license_customer_binding').ok, false);

  const boundEnv = buildEnv({ production: true, customerId: 'CU-Setup' });
  assert.strictEqual(boundEnv.REDACTWALL_LICENSE_CUSTOMER_ID, 'cu-setup');
  const status = statusFromEnv(boundEnv);
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'ok');
});

test('setup preflight accepts RedactWall env aliases', () => {
  const status = statusFromEnv({
    NODE_ENV: 'production',
    HTTPS: 'true',
    COOKIE_SECURE: 'true',
    REDACTWALL_DB_PATH: '/var/lib/redactwall/redactwall.db',
    REDACTWALL_SAAS_MODE: 'true',
    REDACTWALL_TENANT_ID: 'cu-acme',
    REDACTWALL_SEAT_LIMIT: '25',
    ADMIN_USER: 'admin',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    REDACTWALL_SECRET: 's'.repeat(32),
    REDACTWALL_DATA_KEY: 'd'.repeat(32),
    REDACTWALL_INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    REDACTWALL_REQUEST_TIMEOUT_MS: '10000',
  });

  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'ok');
});

test('mergeEnv replaces placeholders but preserves custom values', () => {
  const merged = mergeEnv({
    ADMIN_PASSWORD: 'ChangeMe!2026',
    ADMIN_TOTP_SECRET: '',
    INGEST_API_KEY: 'dev-ingest-key',
    REDACTWALL_SECRET: '',
    SIEM_WEBHOOK_URL: 'https://soc.example.test/hook',
  }, {
    ADMIN_PASSWORD: 'generated-pass',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'generated-key',
    REDACTWALL_SECRET: 'generated-secret',
    SIEM_WEBHOOK_URL: '',
  });

  assert.strictEqual(merged.ADMIN_PASSWORD, 'generated-pass');
  assert.strictEqual(merged.ADMIN_TOTP_SECRET, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(merged.INGEST_API_KEY, 'generated-key');
  assert.strictEqual(merged.REDACTWALL_SECRET, 'generated-secret');
  assert.strictEqual(merged.SIEM_WEBHOOK_URL, 'https://soc.example.test/hook');
});

test('renderEnv quotes only values that need quoting', () => {
  const rendered = renderEnv({
    PORT: '4000',
    ADMIN_PASSWORD: 'has space',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'ps_ingest_safe',
  });

  assert.match(rendered, /^PORT=4000$/m);
  assert.match(rendered, /^ADMIN_PASSWORD="has space"$/m);
  assert.match(rendered, /^ADMIN_TOTP_SECRET=JBSWY3DPEHPK3PXP$/m);
  assert.match(rendered, /^INGEST_API_KEY=ps_ingest_safe$/m);
  assert.strictEqual(quoteEnvValue(''), '');
  assert.strictEqual(quoteEnvValue('safe-value_1'), 'safe-value_1');
  assert.strictEqual(quoteEnvValue('has # mark'), '"has # mark"');
});

test('atomic env writer replaces an existing file privately and preserves it on publish failure', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-setup-env-write-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const envPath = path.join(dir, '.env');
  fs.writeFileSync(envPath, 'OLD=1\n', { mode: 0o644 });
  fs.chmodSync(envPath, 0o644);

  writeEnvAtomic(envPath, 'NEW=2\n');
  assert.strictEqual(fs.readFileSync(envPath, 'utf8'), 'NEW=2\n');
  if (process.platform !== 'win32') assert.strictEqual(fs.statSync(envPath).mode & 0o777, 0o600);
  assert.deepStrictEqual(fs.readdirSync(dir), ['.env']);

  const failingFs = {
    ...fs,
    renameSync() { throw new Error('injected publish failure'); },
  };
  assert.throws(() => writeEnvAtomic(envPath, 'BROKEN=1\n', { fs: failingFs }), /injected publish failure/);
  assert.strictEqual(fs.readFileSync(envPath, 'utf8'), 'NEW=2\n');
  assert.deepStrictEqual(fs.readdirSync(dir), ['.env']);
});

test('atomic env writer rejects a real directory-fsync failure and restores exact prior bytes', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-setup-env-durable-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const envPath = path.join(dir, '.env');
  const baseline = Buffer.from('OLD_EXACT=1\r\n');
  fs.writeFileSync(envPath, baseline, { mode: 0o600 });
  const failingFs = {
    ...fs,
    fsyncSync(fd) {
      if (fs.fstatSync(fd).isDirectory()) {
        const error = new Error('injected directory durability failure');
        error.code = 'EIO';
        throw error;
      }
      return fs.fsyncSync(fd);
    },
  };

  assert.throws(
    () => writeEnvAtomic(envPath, 'NEW=2\n', { fs: failingFs }),
    /injected directory durability failure/,
  );
  assert.deepStrictEqual(fs.readFileSync(envPath), baseline);
  assert.deepStrictEqual(fs.readdirSync(dir), ['.env']);
});

test('parseArgs supports check and alternate env file', () => {
  const opts = parseArgs(['--check', '--skip-install', '--with-browser', '--force', '--customer-id', 'cu-setup', '--prod', '--env', 'demo.env']);
  assert.strictEqual(opts.check, true);
  assert.strictEqual(opts.skipInstall, true);
  assert.strictEqual(opts.withBrowser, true);
  assert.strictEqual(opts.force, true);
  assert.strictEqual(opts.customerId, 'cu-setup');
  assert.strictEqual(opts.production, true);
  assert.match(opts.envPath, /demo\.env$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['--bad']), /Unknown option: --bad/);
  assert.throws(() => parseArgs(['--customer-id']), /requires a customer slug/);
});

test('setup helpers cover placeholder, env-file, install, and console output branches', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-setup-helpers-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const envPath = path.join(dir, 'setup.env');
  fs.writeFileSync(envPath, 'ADMIN_PASSWORD=existing-pass\nREDACTWALL_INGEST_API_KEY=alias-key\n');
  assert.deepStrictEqual(readEnvFile(path.join(dir, 'missing.env')), {});
  assert.strictEqual(readEnvFile(envPath).ADMIN_PASSWORD, 'existing-pass');
  assert.strictEqual(placeholderValue('ADMIN_PASSWORD', 'ChangeMe!2026'), true);
  assert.strictEqual(placeholderValue('INGEST_API_KEY', 'dev-ingest-key'), true);
  assert.strictEqual(placeholderValue('REDACTWALL_SEAT_LIMIT', ''), false);
  assert.strictEqual(placeholderValue('CUSTOM', ''), false);

  const commands = [];
  installDependencies({ production: true }, {
    existsSync: () => true,
    npmCommand: () => 'npm-test',
    run: (command, args) => commands.push([command, args]),
  });
  installDependencies({ withBrowser: true }, {
    existsSync: () => false,
    npmCommand: () => 'npm-test',
    run: (command, args) => commands.push([command, args]),
  });
  const consoleDir = path.resolve(__dirname, '..', 'console');
  assert.deepStrictEqual(commands, [
    ['npm-test', ['ci', '--omit=dev']],
    ['npm-test', ['ci', '--prefix', consoleDir]],
    ['npm-test', ['run', 'build', '--prefix', consoleDir]],
    ['npm-test', ['install']],
    ['npm-test', ['exec', '--', 'playwright', 'install', 'chromium']],
  ]);

  const logs = [];
  const io = { log: (line) => logs.push(String(line)) };
  printHelp(io);
  assert.match(logs.join('\n'), /Usage: npm run setup/);
  logs.length = 0;
  printStatus({
    level: 'warn',
    ready: false,
    checks: [
      { id: 'ok_check', ok: true, message: 'good' },
      { id: 'bad_check', ok: false, severity: 'blocker', remediation: 'fix it' },
    ],
  }, io);
  assert.match(logs.join('\n'), /Preflight: warn \(blocked\)/);
  assert.match(logs.join('\n'), /ok: ok_check - good/);
  assert.match(logs.join('\n'), /blocker: bad_check - fix it/);
});

test('setup command runner reports child-process success, failure, and spawn errors', () => {
  assert.doesNotThrow(() => assertNodeVersion());
  const nodeVersionDescriptor = Object.getOwnPropertyDescriptor(process.versions, 'node');
  Object.defineProperty(process.versions, 'node', { ...nodeVersionDescriptor, value: '16.0.0' });
  try {
    assert.throws(() => assertNodeVersion(), /requires Node\.js \d+\+/);
  } finally {
    Object.defineProperty(process.versions, 'node', nodeVersionDescriptor);
  }
  assert.match(npmCommand(), /^npm(\.cmd)?$/);
  assert.doesNotThrow(() => run(process.execPath, ['-e', 'process.exit(0)'], { stdio: 'ignore' }));
  assert.throws(
    () => run(process.execPath, ['-e', 'process.exit(7)'], { stdio: 'ignore' }),
    /exited with 7/,
  );
  assert.throws(
    () => run('redactwall-definitely-missing-command', [], { stdio: 'ignore' }),
    /ENOENT|not found|no such file/i,
  );
});

test('setup main supports injected help, check, write, and blocked status flows', () => {
  const logs = [];
  const io = { log: (line) => logs.push(String(line)) };
  assert.strictEqual(main(['--help'], { console: io }), 0);
  assert.match(logs.join('\n'), /--production/);
  logs.length = 0;

  const readyStatus = { level: 'ok', ready: true, checks: [] };
  const blockedStatus = { level: 'error', ready: false, checks: [{ id: 'admin_password', ok: false, severity: 'blocker', remediation: 'rotate' }] };
  assert.strictEqual(main(['--check', '--env', 'check.env'], {
    console: io,
    assertNodeVersion: () => {},
    effectiveEnv: (envPath) => ({ envPath }),
    statusFromEnv: (env) => {
      assert.match(env.envPath, /check\.env$/);
      return readyStatus;
    },
  }), 0);
  assert.match(logs.join('\n'), /Preflight: ok \(ready\)/);
  logs.length = 0;

  const writes = [];
  const code = main(['--skip-install', '--env', 'pilot.env'], {
    console: io,
    env: {},
    assertNodeVersion: () => {},
    buildEnv: () => ({ REDACTWALL_DB_PATH: 'data/test.db', ADMIN_PASSWORD: 'generated' }),
    readEnvFile: () => ({ ADMIN_PASSWORD: 'ChangeMe!2026' }),
    mergeEnv: (existing, generated) => ({ ...existing, ...generated }),
    renderEnv: (values) => `ADMIN_PASSWORD=${values.ADMIN_PASSWORD}\n`,
    writeEnvFile: (file, body) => writes.push(['write', file, body]),
    initializeRuntime: (envPath) => {
      assert.match(envPath, /pilot\.env$/);
      return { ok: true };
    },
    statusFromEnv: () => readyStatus,
  });
  assert.strictEqual(code, 0);
  assert.ok(writes.some((item) => item[0] === 'write' && /pilot\.env$/.test(item[1])));
  assert.match(logs.join('\n'), /Setup complete/);
  logs.length = 0;

  assert.strictEqual(main(['--skip-install'], {
    console: io,
    env: {},
    assertNodeVersion: () => {},
    buildEnv: () => ({ REDACTWALL_DB_PATH: 'data/test.db' }),
    readEnvFile: () => ({}),
    mergeEnv: (existing, generated) => ({ ...existing, ...generated }),
    renderEnv: () => '',
    writeEnvFile: () => {},
    initializeRuntime: () => ({ ok: false }),
    statusFromEnv: () => blockedStatus,
  }), 1);
  assert.match(logs.join('\n'), /Audit chain: failed/);
  assert.match(logs.join('\n'), /Preflight: error \(blocked\)/);
});

test('production setup, mfa enrollment, and setup check work end to end without setup leaking secrets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-setup-prod-'));
  const envPath = path.join(dir, 'pilot.env');
  // Production SQLite owns and hardens its complete parent directory before
  // publishing any state. Keep the operator env file outside that dedicated
  // directory so this happy-path fixture does not plant unrelated broad-ACL
  // state beside the future database.
  const dbPath = path.join(dir, 'data', 'redactwall.db').replace(/\\/g, '/');
  fs.writeFileSync(envPath, `REDACTWALL_DB_PATH=${dbPath}\n`);
  const env = childEnv();

  const setupOut = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'setup.js'),
    '--production',
    '--customer-id',
    'cu-setup',
    '--skip-install',
    '--env',
    envPath,
  ], { cwd: ROOT, encoding: 'utf8', env });

  const parsed = parseEnv(fs.readFileSync(envPath, 'utf8')).parsed;
  assert.match(parsed.ADMIN_TOTP_SECRET, /^[A-Z2-7]{16,}$/);
  assert.match(parsed.ADMIN_PASSWORD, /^Ps-/);
  assert.match(parsed.INGEST_API_KEY, /^ps_ingest_/);
  assert.strictEqual(parsed.REDACTWALL_LICENSE_CUSTOMER_ID, 'cu-setup');
  assert.strictEqual(parsed.REDACTWALL_DB_PATH, dbPath);
  assert.strictEqual(fs.existsSync(dbPath), true);
  assert.match(setupOut, /Preflight: ok \(ready\)/);
  assert.strictEqual(setupOut.includes(parsed.ADMIN_TOTP_SECRET), false);
  assert.strictEqual(setupOut.includes(parsed.ADMIN_PASSWORD), false);
  assert.strictEqual(setupOut.includes(parsed.INGEST_API_KEY), false);

  const mfaOut = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'mfa-uri.js'),
    '--env',
    envPath,
    '--issuer',
    'RedactWall Smoke',
  ], { cwd: ROOT, encoding: 'utf8', env });
  const uriLine = mfaOut.split(/\r?\n/).find((line) => line.startsWith('otpauth://'));
  assert.ok(uriLine);
  const uri = new URL(uriLine);
  assert.strictEqual(uri.searchParams.get('secret'), parsed.ADMIN_TOTP_SECRET);
  assert.strictEqual(uri.searchParams.get('issuer'), 'RedactWall Smoke');
  assert.strictEqual(mfaOut.includes(parsed.ADMIN_PASSWORD), false);
  assert.strictEqual(mfaOut.includes(parsed.INGEST_API_KEY), false);

  const checkOut = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'setup.js'),
    '--check',
    '--skip-install',
    '--env',
    envPath,
  ], { cwd: ROOT, encoding: 'utf8', env });
  assert.match(checkOut, /Preflight: ok \(ready\)/);
  assert.strictEqual(checkOut.includes(parsed.ADMIN_TOTP_SECRET), false);
  assert.strictEqual(checkOut.includes(parsed.ADMIN_PASSWORD), false);
  assert.strictEqual(checkOut.includes(parsed.INGEST_API_KEY), false);
});
