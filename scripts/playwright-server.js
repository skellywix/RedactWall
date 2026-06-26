'use strict';
/**
 * Isolated server for Playwright E2E. It uses temp DB/policy paths so browser
 * tests can save policy and create audit events without touching demo config.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'promptsentinel-e2e-'));
const policyPath = path.join(tempDir, 'policy.json');
fs.copyFileSync(path.join(root, 'config', 'policy.json'), policyPath);

process.env.PORT = process.env.PORT || '4210';
process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'e2e-pass';
process.env.SENTINEL_SECRET = process.env.SENTINEL_SECRET || 'e2e-session-secret';
process.env.SENTINEL_DATA_KEY = process.env.SENTINEL_DATA_KEY || 'e2e-data-key';
process.env.INGEST_API_KEY = process.env.INGEST_API_KEY || 'e2e-ingest-key';
process.env.SENTINEL_DB_PATH = process.env.SENTINEL_DB_PATH || path.join(tempDir, 'sentinel.db');
process.env.SENTINEL_POLICY_PATH = process.env.SENTINEL_POLICY_PATH || policyPath;

const app = require('../server');
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
