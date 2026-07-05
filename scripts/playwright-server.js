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
process.env.REDACTWALL_SECRET = process.env.REDACTWALL_SECRET || 'e2e-session-secret';
process.env.REDACTWALL_DATA_KEY = process.env.REDACTWALL_DATA_KEY || 'e2e-data-key';
process.env.INGEST_API_KEY = process.env.INGEST_API_KEY || 'e2e-ingest-key';
process.env.REDACTWALL_DB_PATH = process.env.REDACTWALL_DB_PATH || path.join(tempDir, 'redactwall.db');
process.env.REDACTWALL_POLICY_PATH = process.env.REDACTWALL_POLICY_PATH || policyPath;

const app = require('../server/app');
const server = app.startServer(Number(process.env.PORT));

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
