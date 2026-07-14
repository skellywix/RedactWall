'use strict';
/**
 * Cross-platform first-run setup for RedactWall.
 *
 * Runs before dependencies exist, so keep this file on Node built-ins only.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const { parseEnv, withEnvAliases } = require('../server/env');
const preflight = require('../server/preflight');
const license = require('../server/license');
const { isDeploymentId } = require('../server/deployment-identity');
const {
  assertPrivatePath,
  publishFileDurably,
  securePrivatePath,
} = require('../server/private-path');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_ENV_PATH = path.join(ROOT, '.env');
const NODE_MAJOR_MIN = 22;

function committedCleanupWarning(warning) {
  const retained = warning && warning.retainedPath ? `; retained=${warning.retainedPath}` : '';
  process.stderr.write(`[warn] committed setup file needs cleanup (${warning.code})${retained}\n`);
}

const ENV_ORDER = [
  'PORT',
  'NODE_ENV',
  'HTTPS',
  'COOKIE_SECURE',
  'REDACTWALL_DB_PATH',
  'REDACTWALL_SAAS_MODE',
  'REDACTWALL_TENANT_ID',
  'REDACTWALL_CONNECTED_DEPLOYMENT_ID',
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
];

function randomText(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function randomBase32(chars = 32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(chars);
  let out = '';
  for (const b of bytes) out += alphabet[b % alphabet.length];
  return out;
}

function randomPassword() {
  return `Ps-${randomText(18)}!`;
}

function nativeDataPath() {
  return path.join(ROOT, 'data', 'redactwall.db').replace(/\\/g, '/');
}

function buildEnv(opts = {}) {
  const production = !!opts.production;
  const deploymentId = exactDeploymentId(opts.deploymentId);
  const customerId = String(opts.customerId || '').trim().toLowerCase();
  const connected = production || !!deploymentId;
  return {
    PORT: '4000',
    NODE_ENV: production ? 'production' : 'development',
    HTTPS: production ? 'true' : 'false',
    COOKIE_SECURE: production ? 'true' : 'false',
    REDACTWALL_DB_PATH: nativeDataPath(),
    REDACTWALL_SAAS_MODE: connected ? 'true' : 'false',
    REDACTWALL_LICENSE_MODE: connected ? 'connected' : 'offline',
    REDACTWALL_TENANT_ID: connected ? customerId : '',
    REDACTWALL_CONNECTED_DEPLOYMENT_ID: deploymentId,
    REDACTWALL_LICENSE_CUSTOMER_ID: customerId,
    REDACTWALL_SEAT_LIMIT: '',
    REDACTWALL_REQUIRE_TENANT_CONTEXT: connected ? 'true' : 'false',
    REDACTWALL_REQUIRE_USER_IDENTITY: connected ? 'true' : 'false',
    ADMIN_USER: 'admin',
    ADMIN_PASSWORD: randomPassword(),
    ADMIN_TOTP_SECRET: production ? randomBase32(32) : '',
    APPROVER_USER: '',
    APPROVER_PASSWORD: '',
    REDACTWALL_SECRET: randomText(32),
    REDACTWALL_DATA_KEY: randomText(32),
    INGEST_API_KEY: `ps_ingest_${randomText(32)}`,
    SCIM_BEARER_TOKEN: '',
    OIDC_ISSUER: '',
    OIDC_CLIENT_ID: '',
    OIDC_CLIENT_SECRET: '',
    OIDC_REDIRECT_URI: '',
    OIDC_SCOPE: 'openid email profile',
    OIDC_AUTHORIZATION_ENDPOINT: '',
    OIDC_TOKEN_ENDPOINT: '',
    OIDC_JWKS_URI: '',
    REDACTWALL_REQUEST_TIMEOUT_MS: '10000',
    SIEM_WEBHOOK_URL: '',
    SIEM_WEBHOOK_TOKEN: '',
    SIEM_ALERT_MIN_RISK: '25',
    SIEM_ALERT_MIN_SEVERITY: '3',
    SIEM_POSTURE_FEED_ENABLED: 'false',
    SIEM_POSTURE_MIN_INTERVAL_MS: '300000',
  };
}

function exactDeploymentId(value) {
  if (value === undefined || value === null || value === '') return '';
  if (!isDeploymentId(value)) {
    const error = new Error('Vendor-issued deployment identity must match dep_ plus 32 lowercase hexadecimal characters');
    error.code = 'REDACTWALL_DEPLOYMENT_ID_INVALID';
    throw error;
  }
  return value;
}

function deploymentIdFromSources(...sources) {
  const key = 'REDACTWALL_CONNECTED_DEPLOYMENT_ID';
  let resolved = '';
  for (const source of sources) {
    if (!source || typeof source !== 'object' || !Object.prototype.hasOwnProperty.call(source, key)) {
      continue;
    }
    const candidate = exactDeploymentId(source[key]);
    if (!candidate) continue;
    if (resolved && resolved !== candidate) {
      const error = new Error('Vendor-issued deployment identity is immutable after enrollment');
      error.code = 'REDACTWALL_DEPLOYMENT_ID_IMMUTABLE';
      throw error;
    }
    resolved = candidate;
  }
  return resolved;
}

function placeholderValue(key, value) {
  const v = String(value || '').trim();
  if (key === 'ADMIN_PASSWORD') return !v || v === 'ChangeMe!2026';
  if (key === 'ADMIN_TOTP_SECRET') return !v;
  if (key === 'INGEST_API_KEY') return !v || v === 'dev-ingest-key';
  if (key === 'REDACTWALL_SECRET' || key === 'REDACTWALL_DATA_KEY') return !v;
  if (key === 'REDACTWALL_DB_PATH') return !v;
  if (key === 'REDACTWALL_SEAT_LIMIT') return false;
  if (key === 'REDACTWALL_TENANT_ID'
      || key === 'REDACTWALL_CONNECTED_DEPLOYMENT_ID'
      || key === 'REDACTWALL_LICENSE_CUSTOMER_ID') return false;
  return false;
}

function mergeEnv(existing, generated, opts = {}) {
  const out = { ...(existing || {}) };
  const deploymentId = mergedDeploymentId(existing, generated);
  for (const [key, value] of Object.entries(generated)) {
    if (key === 'REDACTWALL_CONNECTED_DEPLOYMENT_ID') continue;
    const shouldReplace = opts.force || !Object.prototype.hasOwnProperty.call(out, key) || placeholderValue(key, out[key]);
    if (shouldReplace) out[key] = value;
  }
  if (deploymentId.present) out.REDACTWALL_CONNECTED_DEPLOYMENT_ID = deploymentId.value;
  if (opts.production) {
    if (opts.force || !out.NODE_ENV || out.NODE_ENV === 'development') out.NODE_ENV = 'production';
    if (opts.force || !out.HTTPS || out.HTTPS === 'false') out.HTTPS = 'true';
    if (opts.force || !out.COOKIE_SECURE || out.COOKIE_SECURE === 'false') out.COOKIE_SECURE = 'true';
  }
  return out;
}

function mergedDeploymentId(existing = {}, generated = {}) {
  const key = 'REDACTWALL_CONNECTED_DEPLOYMENT_ID';
  const hasExisting = Object.prototype.hasOwnProperty.call(existing, key);
  const hasRequested = Object.prototype.hasOwnProperty.call(generated, key);
  const current = hasExisting ? exactDeploymentId(existing[key]) : '';
  const requested = hasRequested ? exactDeploymentId(generated[key]) : '';
  if (current && requested && current !== requested) {
    const error = new Error('Vendor-issued deployment identity is immutable after enrollment');
    error.code = 'REDACTWALL_DEPLOYMENT_ID_IMMUTABLE';
    throw error;
  }
  return {
    present: hasExisting || hasRequested,
    value: current || requested,
  };
}

function quoteEnvValue(value) {
  const text = String(value == null ? '' : value);
  if (!text) return '';
  if (/^[A-Za-z0-9_./:@+-]+$/.test(text)) return text;
  return JSON.stringify(text);
}

function renderEnv(values, opts = {}) {
  const seen = new Set();
  const lines = [
    '# RedactWall local configuration',
    `# Generated by npm run setup${opts.production ? ':prod' : ''} on ${new Date().toISOString()}`,
    '',
    '# Web/admin server',
  ];
  const add = (key) => {
    if (seen.has(key) || !Object.prototype.hasOwnProperty.call(values, key)) return;
    lines.push(`${key}=${quoteEnvValue(values[key])}`);
    seen.add(key);
  };
  ['PORT', 'NODE_ENV', 'HTTPS', 'COOKIE_SECURE', 'REDACTWALL_DB_PATH'].forEach(add);
  lines.push('', '# SaaS/customer tenancy. Enable these for a paid customer stack.');
  ['REDACTWALL_SAAS_MODE', 'REDACTWALL_TENANT_ID', 'REDACTWALL_SEAT_LIMIT', 'REDACTWALL_REQUIRE_TENANT_CONTEXT', 'REDACTWALL_REQUIRE_USER_IDENTITY'].forEach(add);
  lines.push('', '# Vendor-issued immutable identity for one connected deployment.');
  ['REDACTWALL_CONNECTED_DEPLOYMENT_ID'].forEach(add);
  lines.push('', '# Stable customer slug for licensed standalone deployments.');
  ['REDACTWALL_LICENSE_CUSTOMER_ID'].forEach(add);
  lines.push('', '# Security Admin console');
  ['ADMIN_USER', 'ADMIN_PASSWORD', 'ADMIN_TOTP_SECRET'].forEach(add);
  lines.push('', '# Stable secrets. Keep these values across restarts.');
  ['REDACTWALL_SECRET', 'REDACTWALL_DATA_KEY'].forEach(add);
  lines.push('', '# Sensor/API configuration');
  ['INGEST_API_KEY', 'REDACTWALL_REQUEST_TIMEOUT_MS'].forEach(add);
  lines.push('', '# Customer identity provisioning and console SSO');
  ['SCIM_BEARER_TOKEN', 'OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_REDIRECT_URI', 'OIDC_SCOPE', 'OIDC_AUTHORIZATION_ENDPOINT', 'OIDC_TOKEN_ENDPOINT', 'OIDC_JWKS_URI'].forEach(add);
  lines.push('', '# Optional sanitized SIEM/SOC webhook');
  ['SIEM_WEBHOOK_URL', 'SIEM_WEBHOOK_TOKEN', 'SIEM_ALERT_MIN_RISK', 'SIEM_ALERT_MIN_SEVERITY', 'SIEM_POSTURE_FEED_ENABLED', 'SIEM_POSTURE_MIN_INTERVAL_MS'].forEach(add);
  for (const key of Object.keys(values).sort()) add(key);
  return lines.join('\n') + '\n';
}

function readEnvFile(envPath = DEFAULT_ENV_PATH) {
  if (!fs.existsSync(envPath)) return {};
  return parseEnv(fs.readFileSync(envPath, 'utf8')).parsed;
}

function effectiveEnv(envPath = DEFAULT_ENV_PATH, env = process.env) {
  return withEnvAliases({ ...readEnvFile(envPath), ...env });
}

function statusFromEnv(env) {
  const resolved = withEnvAliases(env);
  const managedLicenseHealth = license.managedLicenseHealth({
    env: resolved,
    ...(resolved.REDACTWALL_LICENSE_PATH ? { licensePath: resolved.REDACTWALL_LICENSE_PATH } : {}),
  });
  return preflight.configStatus({
    env: resolved,
    adminPasswordIsDefault: !resolved.ADMIN_PASSWORD || resolved.ADMIN_PASSWORD === 'ChangeMe!2026',
    ingestKeyIsDefault: !resolved.INGEST_API_KEY || resolved.INGEST_API_KEY === 'dev-ingest-key',
    secretSource: resolved.REDACTWALL_SECRET ? 'env' : 'generated',
    dataCryptoEnabled: !!(resolved.REDACTWALL_DATA_KEY || resolved.REDACTWALL_SECRET),
    cookieSecure: preflight.bool(resolved.COOKIE_SECURE || resolved.HTTPS),
    requireLicenseBinding: true,
    managedLicenseHealth,
    licenseTrustAnchorStatus: license.productionTrustAnchorStatus(resolved),
  });
}

function parseArgs(argv = process.argv.slice(2)) {
  const opts = {
    production: false,
    skipInstall: false,
    withBrowser: false,
    force: false,
    check: false,
    envPath: DEFAULT_ENV_PATH,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--production' || arg === '--prod') opts.production = true;
    else if (arg === '--skip-install' || arg === '--no-install') opts.skipInstall = true;
    else if (arg === '--with-browser') opts.withBrowser = true;
    else if (arg === '--force') opts.force = true;
    else if (arg === '--check') opts.check = true;
    else if (arg === '--customer-id') {
      opts.customerId = String(argv[++i] || '').trim();
      if (!opts.customerId) throw new Error('--customer-id requires a customer slug');
    }
    else if (arg === '--deployment-id') {
      const deploymentId = argv[++i];
      if (deploymentId === undefined || deploymentId === '') {
        throw new Error('--deployment-id requires an exact vendor-issued deployment identity');
      }
      opts.deploymentId = exactDeploymentId(deploymentId);
    }
    else if (arg === '--env') opts.envPath = path.resolve(argv[++i] || DEFAULT_ENV_PATH);
    else if (arg === '--help' || arg === '-h') opts.help = true;
    else throw new Error(`Unknown option: ${arg}`);
  }
  return opts;
}

function assertNodeVersion() {
  const major = Number(process.versions.node.split('.')[0]);
  if (!Number.isFinite(major) || major < NODE_MAJOR_MIN) {
    throw new Error(`RedactWall requires Node.js ${NODE_MAJOR_MIN}+; found ${process.version}`);
  }
}

function npmCommand() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function run(command, args, opts = {}) {
  const result = spawnSync(command, args, { cwd: ROOT, stdio: 'inherit', shell: false, ...opts });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} exited with ${result.status}`);
}

function installDependencies(opts = {}, deps = {}) {
  const exists = deps.existsSync || fs.existsSync;
  const execute = deps.run || run;
  const npm = deps.npmCommand || npmCommand;
  const args = exists(path.join(ROOT, 'package-lock.json')) ? ['ci'] : ['install'];
  if (opts.production) args.push('--omit=dev');
  execute(npm(), args);
  buildConsole({ exists, execute, npm });
  if (opts.withBrowser && !opts.production) {
    execute(npm(), ['exec', '--', 'playwright', 'install', 'chromium']);
  }
}

// The admin console ships as a built bundle (server/public/app is gitignored),
// so a source install must build it or /app serves nothing.
function buildConsole({ exists, execute, npm }) {
  const consoleDir = path.join(ROOT, 'console');
  if (!exists(path.join(consoleDir, 'package.json'))) return;
  const ciOrInstall = exists(path.join(consoleDir, 'package-lock.json')) ? 'ci' : 'install';
  execute(npm(), [ciOrInstall, '--prefix', consoleDir]);
  execute(npm(), ['run', 'build', '--prefix', consoleDir]);
}

function initializeRuntime(envPath) {
  require('../server/env').loadEnv(envPath);
  fs.mkdirSync(path.join(ROOT, 'data'), { recursive: true });
  const db = require('../server/db');
  db.stats();
  return db.verifyAuditChain();
}

function printStatus(status, io = console) {
  io.log(`Preflight: ${status.level}${status.ready ? ' (ready)' : ' (blocked)'}`);
  for (const item of status.checks) {
    const mark = item.ok ? 'ok' : item.severity;
    io.log(`  ${mark}: ${item.id} - ${item.ok ? item.message : item.remediation}`);
  }
}

function printHelp(io = console) {
  io.log([
    'Usage: npm run setup -- [options]',
    '',
    'Options:',
    '  --production       Generate production-safe defaults and install runtime deps only',
    '  --skip-install     Write/check config without running npm ci',
    '  --with-browser     Also install Chromium for Playwright E2E tests',
    '  --force            Replace existing generated/default .env values',
    '  --customer-id <id> Stable licensed-customer slug for a standalone deployment',
    '  --deployment-id <dep_...> Enroll the exact vendor-issued connected deployment identity once',
    '  --check            Check current config and exit without writing',
    '  --env <path>       Use a non-default env file path',
  ].join('\n'));
}

function writeEnvAtomic(filePath, body, deps = {}) {
  const fsImpl = deps.fs || fs;
  const dir = path.dirname(filePath);
  const nonce = `${process.pid}.${crypto.randomBytes(8).toString('hex')}`;
  const tempPath = path.join(dir, `.${path.basename(filePath)}.${nonce}.tmp`);
  let fd;
  let publicationStarted = false;
  fsImpl.mkdirSync(dir, { recursive: true });
  try {
    fd = fsImpl.openSync(tempPath, 'wx', 0o600);
    securePrivatePath(tempPath, {
      fs: fsImpl,
      directory: false,
      fresh: true,
      label: 'setup environment staging file',
      ownerLabel: 'setup environment staging file',
    });
    fsImpl.writeFileSync(fd, body, { encoding: 'utf8' });
    fsImpl.fsyncSync(fd);
    fsImpl.closeSync(fd);
    fd = undefined;
    publicationStarted = true;
    publishFileDurably(tempPath, filePath, {
      fs: fsImpl,
      cleanupComponent: 'setup-environment-publication',
      onCommittedCleanupWarning: deps.onCommittedCleanupWarning || committedCleanupWarning,
    });
    assertPrivatePath(filePath, {
      fs: fsImpl,
      directory: false,
      label: 'setup environment file',
      ownerLabel: 'setup environment file',
    });
  } catch (error) {
    if (fd !== undefined) try { fsImpl.closeSync(fd); } catch {}
    if (!publicationStarted) try { fsImpl.unlinkSync(tempPath); } catch {}
    throw error;
  }
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const env = deps.env || process.env;
  const checkNodeVersion = deps.assertNodeVersion || assertNodeVersion;
  const install = deps.installDependencies || installDependencies;
  const initRuntime = deps.initializeRuntime || initializeRuntime;
  const loadEffectiveEnv = deps.effectiveEnv || ((envPath) => effectiveEnv(envPath, env));
  const readEnv = deps.readEnvFile || readEnvFile;
  const build = deps.buildEnv || buildEnv;
  const merge = deps.mergeEnv || mergeEnv;
  const render = deps.renderEnv || renderEnv;
  const statusForEnv = deps.statusFromEnv || statusFromEnv;
  const writeEnvFile = deps.writeEnvFile || writeEnvAtomic;
  const opts = parseArgs(argv);
  if (opts.help) {
    printHelp(io);
    return 0;
  }
  checkNodeVersion();

  const existing = readEnv(opts.envPath);
  const requested = opts.deploymentId
    ? { REDACTWALL_CONNECTED_DEPLOYMENT_ID: opts.deploymentId }
    : {};
  const configuredDeploymentId = deploymentIdFromSources(existing, env, requested);

  if (opts.check) {
    const effective = loadEffectiveEnv(opts.envPath);
    deploymentIdFromSources(existing, env, requested, effective);
    const status = statusForEnv(effective);
    printStatus(status, io);
    return status.ready ? 0 : 1;
  }

  let generated = build(opts);
  const effectiveDeploymentId = deploymentIdFromSources(
    existing, env, generated,
  ) || configuredDeploymentId;
  if (effectiveDeploymentId) {
    generated = {
      ...generated,
      REDACTWALL_CONNECTED_DEPLOYMENT_ID: effectiveDeploymentId,
    };
  }
  const merged = merge(existing, generated, opts);
  if (!opts.skipInstall) install(opts);
  writeEnvFile(opts.envPath, render(merged, opts));

  const audit = initRuntime(opts.envPath);
  const status = statusForEnv({ ...merged, ...env });
  io.log(`Wrote ${opts.envPath}`);
  io.log(`Initialized SQLite store at ${merged.REDACTWALL_DB_PATH}`);
  io.log(`Audit chain: ${audit.ok ? 'ok' : 'failed'}`);
  printStatus(status, io);
  if (!status.ready) return 1;
  io.log('Setup complete. Start with: npm start');
  return 0;
}

if (require.main === module) { try { process.exitCode = main(); } catch (e) { console.error('Setup failed: ' + (e && e.message ? e.message : e)); process.exitCode = 1; } }

module.exports = {
  assertNodeVersion,
  buildEnv,
  effectiveEnv,
  initializeRuntime,
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
  writeEnvAtomic,
};
