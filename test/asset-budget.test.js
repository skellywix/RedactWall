'use strict';
/** Keep shipped frontend and extension assets inside lightweight transfer budgets. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { BROWSER_TARGETS, packageExtension } = require('../scripts/package-extension');

const root = path.join(__dirname, '..');

function readAsset(relPath) {
  const body = fs.readFileSync(path.join(root, relPath));
  return {
    relPath,
    rawBytes: body.length,
    gzipBytes: zlib.gzipSync(body, { level: 9 }).length,
  };
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function assertWithin(label, actual, max) {
  assert.ok(actual <= max, `${label} is ${formatBytes(actual)}, expected <= ${formatBytes(max)}`);
}

function assertAssetBudgets(assets) {
  const totals = { rawBytes: 0, gzipBytes: 0 };
  for (const asset of assets) {
    const measured = readAsset(asset.path);
    assertWithin(`${asset.path} raw size`, measured.rawBytes, asset.maxRawBytes);
    assertWithin(`${asset.path} gzip size`, measured.gzipBytes, asset.maxGzipBytes);
    totals.rawBytes += measured.rawBytes;
    totals.gzipBytes += measured.gzipBytes;
  }
  return totals;
}

function walkFiles(relDir) {
  const dir = path.join(root, relDir);
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const relPath = path.join(relDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(relPath));
    } else if (entry.isFile()) {
      files.push(relPath);
    }
  }
  return files;
}

test('admin public assets stay within transfer budgets', () => {
  const totals = assertAssetBudgets([
    { path: 'server/public/index.html', maxRawBytes: 180_000, maxGzipBytes: 32_000 },
    { path: 'server/public/dashboard.js', maxRawBytes: 255_000, maxGzipBytes: 60_000 },
    { path: 'server/public/siem-package.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/security-package.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/agentic-mcp.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/ai-threat-guardrails.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/operator-flow.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/policy-guides.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/policy-impact-preview.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/behavior-baselines.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/market-hardening.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/competitive-readiness.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/control-graph.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/coverage-file-flow.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/decision-quality.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/detector-feedback.js', maxRawBytes: 8_000, maxGzipBytes: 3_000 },
    { path: 'server/public/console-theme.css', maxRawBytes: 24_000, maxGzipBytes: 6_000 },
    { path: 'server/public/login.html', maxRawBytes: 12_000, maxGzipBytes: 5_000 },
    { path: 'server/public/login.js', maxRawBytes: 6_000, maxGzipBytes: 2_500 },
  ]);

  assertWithin('admin public assets raw total', totals.rawBytes, 525_000);
  assertWithin('admin public assets gzip total', totals.gzipBytes, 122_000);
});

test('console app bundle stays within transfer budgets', (t) => {
  // The bundle is gitignored build output; CI builds it before tests. Local
  // runs without `npm run console:build` skip rather than fail on a missing dir.
  if (!fs.existsSync(path.join(root, 'server', 'public', 'app', 'index.html'))) {
    t.skip('console bundle not built (npm run console:build)');
    return;
  }
  const totals = walkFiles(path.join('server', 'public', 'app'))
    .map(readAsset)
    .reduce((acc, asset) => ({
      rawBytes: acc.rawBytes + asset.rawBytes,
      gzipBytes: acc.gzipBytes + asset.gzipBytes,
    }), { rawBytes: 0, gzipBytes: 0 });

  assertWithin('console app bundle raw total', totals.rawBytes, 700_000);
  assertWithin('console app bundle gzip total', totals.gzipBytes, 200_000);
});

test('browser extension assets stay within install package budgets', () => {
  assertAssetBudgets([
    { path: 'sensors/browser-extension/lib/detect.js', maxRawBytes: 105_000, maxGzipBytes: 37_000 },
    { path: 'sensors/browser-extension/content.js', maxRawBytes: 60_000, maxGzipBytes: 16_000 },
    { path: 'sensors/browser-extension/background.js', maxRawBytes: 30_000, maxGzipBytes: 9_000 },
    { path: 'sensors/browser-extension/manifest.json', maxRawBytes: 14_000, maxGzipBytes: 2_500 },
  ]);

  const totals = walkFiles('sensors/browser-extension')
    .map(readAsset)
    .reduce((acc, asset) => ({
      rawBytes: acc.rawBytes + asset.rawBytes,
      gzipBytes: acc.gzipBytes + asset.gzipBytes,
    }), { rawBytes: 0, gzipBytes: 0 });

  assertWithin('browser extension assets raw total', totals.rawBytes, 220_000);
  assertWithin('browser extension assets gzip total', totals.gzipBytes, 70_000);
});

test('browser extension store packages stay within size budget', (t) => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-extension-budget-'));
  t.after(() => fs.rmSync(outDir, { recursive: true, force: true }));

  for (const target of BROWSER_TARGETS) {
    const result = packageExtension({ outDir, target, now: new Date('2026-07-01T00:00:00.000Z') });
    assertWithin(`${target} extension zip size`, result.packageManifest.sizeBytes, 80_000);
  }
});
