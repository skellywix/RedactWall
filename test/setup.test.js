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
  run,
  statusFromEnv,
} = require('../scripts/setup');

const ROOT = path.join(__dirname, '..');
const SETUP_ENV_KEYS = [
  'PORT',
  'NODE_ENV',
  'HTTPS',
  'COOKIE_SECURE',
  'SENTINEL_DB_PATH',
  'SENTINEL_SAAS_MODE',
  'SENTINEL_TENANT_ID',
  'SENTINEL_SEAT_LIMIT',
  'SENTINEL_REQUIRE_TENANT_CONTEXT',
  'SENTINEL_REQUIRE_USER_IDENTITY',
  'ADMIN_USER',
  'ADMIN_PASSWORD',
  'ADMIN_TOTP_SECRET',
  'APPROVER_USER',
  'APPROVER_PASSWORD',
  'SENTINEL_SECRET',
  'SENTINEL_DATA_KEY',
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
  'SENTINEL_REQUEST_TIMEOUT_MS',
  'SIEM_WEBHOOK_URL',
  'SIEM_WEBHOOK_TOKEN',
  'SIEM_ALERT_MIN_RISK',
  'SIEM_ALERT_MIN_SEVERITY',
  'SIEM_POSTURE_FEED_ENABLED',
  'SIEM_POSTURE_MIN_INTERVAL_MS',
  'AUDITOR_USER',
  'AUDITOR_PASSWORD',
  'SENTINEL_ENV_PATH',
  'PROMPTWALL_DB_PATH',
  'PROMPTWALL_SAAS_MODE',
  'PROMPTWALL_TENANT_ID',
  'PROMPTWALL_SEAT_LIMIT',
  'PROMPTWALL_REQUIRE_TENANT_CONTEXT',
  'PROMPTWALL_REQUIRE_USER_IDENTITY',
  'PROMPTWALL_SECRET',
  'PROMPTWALL_DATA_KEY',
  'PROMPTWALL_INGEST_API_KEY',
  'PROMPTWALL_SCIM_BEARER_TOKEN',
  'PROMPTWALL_OIDC_ISSUER',
  'PROMPTWALL_OIDC_CLIENT_ID',
  'PROMPTWALL_OIDC_CLIENT_SECRET',
  'PROMPTWALL_OIDC_REDIRECT_URI',
  'PROMPTWALL_OIDC_SCOPE',
  'PROMPTWALL_OIDC_AUTHORIZATION_ENDPOINT',
  'PROMPTWALL_OIDC_TOKEN_ENDPOINT',
  'PROMPTWALL_OIDC_JWKS_URI',
  'PROMPTWALL_REQUEST_TIMEOUT_MS',
  'PROMPTWALL_ENV_PATH',
];

function childEnv() {
  const env = { ...process.env };
  for (const key of SETUP_ENV_KEYS) delete env[key];
  return env;
}

test('production setup env passes deployment preflight', () => {
  const env = buildEnv({ production: true });
  const status = statusFromEnv(env);

  assert.strictEqual(env.NODE_ENV, 'production');
  assert.strictEqual(env.HTTPS, 'true');
  assert.strictEqual(env.COOKIE_SECURE, 'true');
  assert.notStrictEqual(env.ADMIN_PASSWORD, 'ChangeMe!2026');
  assert.match(env.ADMIN_TOTP_SECRET, /^[A-Z2-7]{16,}$/);
  assert.notStrictEqual(env.INGEST_API_KEY, 'dev-ingest-key');
  assert.strictEqual(env.OIDC_ISSUER, '');
  assert.strictEqual(env.OIDC_SCOPE, 'openid email profile');
  assert.ok(env.SENTINEL_SECRET.length >= 32);
  assert.ok(env.SENTINEL_DATA_KEY.length >= 32);
  assert.strictEqual(env.SENTINEL_SAAS_MODE, 'false');
  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'ok');
});

test('setup preflight accepts PromptWall env aliases', () => {
  const status = statusFromEnv({
    NODE_ENV: 'production',
    HTTPS: 'true',
    COOKIE_SECURE: 'true',
    PROMPTWALL_DB_PATH: '/var/lib/promptwall/promptwall.db',
    PROMPTWALL_SAAS_MODE: 'true',
    PROMPTWALL_TENANT_ID: 'cu-acme',
    PROMPTWALL_SEAT_LIMIT: '25',
    ADMIN_USER: 'admin',
    ADMIN_PASSWORD: 'long-admin-password',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    PROMPTWALL_SECRET: 's'.repeat(32),
    PROMPTWALL_DATA_KEY: 'd'.repeat(32),
    PROMPTWALL_INGEST_API_KEY: 'ps_ingest_' + 'a'.repeat(32),
    PROMPTWALL_REQUEST_TIMEOUT_MS: '10000',
  });

  assert.strictEqual(status.ready, true);
  assert.strictEqual(status.level, 'ok');
});

test('mergeEnv replaces placeholders but preserves custom values', () => {
  const merged = mergeEnv({
    ADMIN_PASSWORD: 'ChangeMe!2026',
    ADMIN_TOTP_SECRET: '',
    INGEST_API_KEY: 'dev-ingest-key',
    SENTINEL_SECRET: '',
    SIEM_WEBHOOK_URL: 'https://soc.example.test/hook',
  }, {
    ADMIN_PASSWORD: 'generated-pass',
    ADMIN_TOTP_SECRET: 'JBSWY3DPEHPK3PXP',
    INGEST_API_KEY: 'generated-key',
    SENTINEL_SECRET: 'generated-secret',
    SIEM_WEBHOOK_URL: '',
  });

  assert.strictEqual(merged.ADMIN_PASSWORD, 'generated-pass');
  assert.strictEqual(merged.ADMIN_TOTP_SECRET, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(merged.INGEST_API_KEY, 'generated-key');
  assert.strictEqual(merged.SENTINEL_SECRET, 'generated-secret');
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

test('parseArgs supports check and alternate env file', () => {
  const opts = parseArgs(['--check', '--skip-install', '--with-browser', '--force', '--prod', '--env', 'demo.env']);
  assert.strictEqual(opts.check, true);
  assert.strictEqual(opts.skipInstall, true);
  assert.strictEqual(opts.withBrowser, true);
  assert.strictEqual(opts.force, true);
  assert.strictEqual(opts.production, true);
  assert.match(opts.envPath, /demo\.env$/);
  assert.strictEqual(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['--bad']), /Unknown option: --bad/);
});

test('setup helpers cover placeholder, env-file, install, and console output branches', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-setup-helpers-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const envPath = path.join(dir, 'setup.env');
  fs.writeFileSync(envPath, 'ADMIN_PASSWORD=existing-pass\nPROMPTWALL_INGEST_API_KEY=alias-key\n');
  assert.deepStrictEqual(readEnvFile(path.join(dir, 'missing.env')), {});
  assert.strictEqual(readEnvFile(envPath).ADMIN_PASSWORD, 'existing-pass');
  assert.strictEqual(placeholderValue('ADMIN_PASSWORD', 'ChangeMe!2026'), true);
  assert.strictEqual(placeholderValue('INGEST_API_KEY', 'dev-ingest-key'), true);
  assert.strictEqual(placeholderValue('SENTINEL_SEAT_LIMIT', ''), false);
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
    () => run('promptwall-definitely-missing-command', [], { stdio: 'ignore' }),
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
    buildEnv: () => ({ SENTINEL_DB_PATH: 'data/test.db', ADMIN_PASSWORD: 'generated' }),
    readEnvFile: () => ({ ADMIN_PASSWORD: 'ChangeMe!2026' }),
    mergeEnv: (existing, generated) => ({ ...existing, ...generated }),
    renderEnv: (values) => `ADMIN_PASSWORD=${values.ADMIN_PASSWORD}\n`,
    mkdirSync: (dirPath) => writes.push(['mkdir', dirPath]),
    writeFileSync: (file, body, opts) => writes.push(['write', file, body, opts.mode]),
    initializeRuntime: (envPath) => {
      assert.match(envPath, /pilot\.env$/);
      return { ok: true };
    },
    statusFromEnv: () => readyStatus,
  });
  assert.strictEqual(code, 0);
  assert.ok(writes.some((item) => item[0] === 'write' && /pilot\.env$/.test(item[1]) && item[3] === 0o600));
  assert.match(logs.join('\n'), /Setup complete/);
  logs.length = 0;

  assert.strictEqual(main(['--skip-install'], {
    console: io,
    env: {},
    assertNodeVersion: () => {},
    buildEnv: () => ({ SENTINEL_DB_PATH: 'data/test.db' }),
    readEnvFile: () => ({}),
    mergeEnv: (existing, generated) => ({ ...existing, ...generated }),
    renderEnv: () => '',
    mkdirSync: () => {},
    writeFileSync: () => {},
    initializeRuntime: () => ({ ok: false }),
    statusFromEnv: () => blockedStatus,
  }), 1);
  assert.match(logs.join('\n'), /Audit chain: failed/);
  assert.match(logs.join('\n'), /Preflight: error \(blocked\)/);
});

test('production setup, mfa enrollment, and setup check work end to end without setup leaking secrets', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-setup-prod-'));
  const envPath = path.join(dir, 'pilot.env');
  const dbPath = path.join(dir, 'sentinel.db').replace(/\\/g, '/');
  fs.writeFileSync(envPath, `SENTINEL_DB_PATH=${dbPath}\n`);
  const env = childEnv();

  const setupOut = execFileSync(process.execPath, [
    path.join(ROOT, 'scripts', 'setup.js'),
    '--production',
    '--skip-install',
    '--env',
    envPath,
  ], { cwd: ROOT, encoding: 'utf8', env });

  const parsed = parseEnv(fs.readFileSync(envPath, 'utf8')).parsed;
  assert.match(parsed.ADMIN_TOTP_SECRET, /^[A-Z2-7]{16,}$/);
  assert.match(parsed.ADMIN_PASSWORD, /^Ps-/);
  assert.match(parsed.INGEST_API_KEY, /^ps_ingest_/);
  assert.strictEqual(parsed.SENTINEL_DB_PATH, dbPath);
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
    'PromptWall Smoke',
  ], { cwd: ROOT, encoding: 'utf8', env });
  const uriLine = mfaOut.split(/\r?\n/).find((line) => line.startsWith('otpauth://'));
  assert.ok(uriLine);
  const uri = new URL(uriLine);
  assert.strictEqual(uri.searchParams.get('secret'), parsed.ADMIN_TOTP_SECRET);
  assert.strictEqual(uri.searchParams.get('issuer'), 'PromptWall Smoke');
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
