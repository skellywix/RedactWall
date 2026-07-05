'use strict';
/**
 * Isolated app boot for the suite's Playwright flows. Mirrors
 * scripts/playwright-server.js but ALSO sets AUDITOR_USER/AUDITOR_PASSWORD so
 * the auditor role journey works, plus a stable secret/data key.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..', '..');
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-suite-e2e-'));
const policyPath = path.join(tempDir, 'policy.json');
fs.copyFileSync(path.join(root, 'config', 'policy.json'), policyPath);

process.env.PORT = process.env.PORT || '4310';
process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'e2e-pass';
process.env.AUDITOR_USER = process.env.AUDITOR_USER || 'auditor@example.test';
process.env.AUDITOR_PASSWORD = process.env.AUDITOR_PASSWORD || 'e2e-auditor-pass';
process.env.SENTINEL_SECRET = process.env.SENTINEL_SECRET || 'e2e-session-secret';
process.env.SENTINEL_DATA_KEY = process.env.SENTINEL_DATA_KEY || 'e2e-data-key';
process.env.INGEST_API_KEY = process.env.INGEST_API_KEY || 'e2e-ingest-key';
process.env.SENTINEL_DB_PATH = process.env.SENTINEL_DB_PATH || path.join(tempDir, 'sentinel.db');
process.env.SENTINEL_POLICY_PATH = process.env.SENTINEL_POLICY_PATH || policyPath;

const app = require(path.join(root, 'server', 'app'));
const server = app.startServer(Number(process.env.PORT));

function cleanup() {
  try { server.close(); } catch {}
  try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch {}
}

process.on('SIGTERM', () => { cleanup(); process.exit(0); });
process.on('SIGINT', () => { cleanup(); process.exit(0); });
process.on('exit', cleanup);
