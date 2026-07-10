'use strict';
/**
 * Isolated server for Playwright E2E. It uses temp DB/policy paths so browser
 * tests can save policy and create audit events without touching demo config.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-e2e-'));
const policyPath = path.join(tempDir, 'policy.json');
fs.copyFileSync(path.join(root, 'config', 'policy.json'), policyPath);

process.env.PORT = process.env.PORT || '4210';
process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'e2e-pass';
process.env.OPERATOR_USER = process.env.OPERATOR_USER || 'e2e-operator';
process.env.OPERATOR_PASSWORD = process.env.OPERATOR_PASSWORD || 'e2e-operator-pass';
process.env.AUDITOR_USER = process.env.AUDITOR_USER || 'e2e-auditor';
process.env.AUDITOR_PASSWORD = process.env.AUDITOR_PASSWORD || 'e2e-auditor-pass';
process.env.REDACTWALL_SECRET = process.env.REDACTWALL_SECRET || 'e2e-session-secret';
process.env.REDACTWALL_DATA_KEY = process.env.REDACTWALL_DATA_KEY || 'e2e-data-key';
process.env.INGEST_API_KEY = process.env.INGEST_API_KEY || 'e2e-ingest-key';
process.env.REDACTWALL_DB_PATH = process.env.REDACTWALL_DB_PATH || path.join(tempDir, 'redactwall.db');
process.env.REDACTWALL_POLICY_PATH = process.env.REDACTWALL_POLICY_PATH || policyPath;

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
