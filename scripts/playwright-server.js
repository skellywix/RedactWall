'use strict';
/**
 * Isolated server for Playwright E2E. It uses temp DB/policy paths so browser
 * tests can save policy and create audit events without touching demo config.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { clearApplicationEnvironment } = require('./playwright-env');

const root = path.join(__dirname, '..');
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-e2e-'));
const policyPath = path.join(tempDir, 'policy.json');
fs.copyFileSync(path.join(root, 'config', 'policy.json'), policyPath);
// The data directory must not exist yet: private-path trust can only be
// established before the directory's first file, so the server must create and
// trust it on boot. Pre-seeding any file into it (like the copied policy, which
// therefore stays in tempDir) fails preflight with
// PRIVATE_DIRECTORY_UNTRUSTED_STATE.
const dataDir = path.join(tempDir, 'data');

const requestedPort = process.env.PORT || '4210';
clearApplicationEnvironment(process.env);
Object.assign(process.env, {
  PORT: requestedPort,
  NODE_ENV: 'test',
  ADMIN_USER: 'admin',
  ADMIN_PASSWORD: 'e2e-pass',
  OPERATOR_USER: 'e2e-operator',
  OPERATOR_PASSWORD: 'e2e-operator-pass',
  AUDITOR_USER: 'e2e-auditor',
  AUDITOR_PASSWORD: 'e2e-auditor-pass',
  REDACTWALL_SECRET: 'e2e-session-secret',
  REDACTWALL_DATA_KEY: 'e2e-data-key',
  INGEST_API_KEY: 'e2e-ingest-key',
  REDACTWALL_DB_DRIVER: 'sqlite',
  REDACTWALL_DB_PATH: path.join(dataDir, 'redactwall.db'),
  REDACTWALL_DATA_DIR: dataDir,
  REDACTWALL_AUDIT_DIR: path.join(dataDir, 'audit'),
  REDACTWALL_POLICY_PATH: policyPath,
  REDACTWALL_ENV_PATH: path.join(tempDir, 'missing.env'),
  REDACTWALL_SUBSCRIPTIONS_PATH: path.join(tempDir, 'subscriptions.json'),
  REDACTWALL_UPDATE_CONFIG_PATH: path.join(tempDir, 'update-config.json'),
  REDACTWALL_UPDATE_STATE_PATH: path.join(tempDir, 'update-state.json'),
});

const app = require('../server/app');
const server = app.startServer(Number(process.env.PORT));
// The APIRequestContext opens a connection during policy bootstrap, then may
// reuse it after a browser interaction lasting longer than Node's five-second
// default idle timeout. Keep the isolated test server alive for the complete
// scenario so Windows does not race a stale pooled socket against its FIN.
server.keepAliveTimeout = 120_000;
server.headersTimeout = 125_000;

function cleanup() {
  try { server.close(); } catch {}
  try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
}

process.on('SIGTERM', () => {
  cleanup();
  process.exit(0);
});
process.on('SIGINT', () => {
  cleanup();
  process.exit(0);
});
process.on('exit', cleanup);
