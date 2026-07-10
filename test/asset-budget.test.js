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
      if (relPath === path.join('sensors', 'browser-extension', '_metadata')) continue;
      files.push(...walkFiles(relPath));
    } else if (entry.isFile()) {
      files.push(relPath);
    }
  }
  return files;
}

test('shipped static frontend assets stay within transfer budgets', () => {
  // The legacy static console (index.html, dashboard.js, and the feature JS
  // bundles) was removed in favor of the built React console under
  // server/public/app (budgeted separately below). What still ships as static
  // top-level assets are the login page and the console stylesheets.
  const totals = assertAssetBudgets([
    { path: 'server/public/console-base.css', maxRawBytes: 130_000, maxGzipBytes: 24_000 },
    { path: 'server/public/console-theme.css', maxRawBytes: 24_000, maxGzipBytes: 6_000 },
    { path: 'server/public/login.html', maxRawBytes: 12_000, maxGzipBytes: 5_000 },
    { path: 'server/public/login.js', maxRawBytes: 6_000, maxGzipBytes: 2_500 },
  ]);

  assertWithin('shipped static frontend raw total', totals.rawBytes, 160_000);
  assertWithin('shipped static frontend gzip total', totals.gzipBytes, 34_000);
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
    // Bounded nested encoding/canonicalization plus the synchronous SHA-256 EDM
    // profile are required at the disconnected sensor edge. Keep less than 3KB
    // raw and 1.5KB gzip headroom so generated-model or debug-data drift fails.
    { path: 'sensors/browser-extension/lib/detect.js', maxRawBytes: 138_000, maxGzipBytes: 49_000 },
    // Managed-policy locking and immutable-send checks moved this just over the
    // prior 60KB line; retain less than 1KB of raw headroom.
    { path: 'sensors/browser-extension/content.js', maxRawBytes: 61_000, maxGzipBytes: 16_000 },
    // Exact optional-host grants, persistent runtime injection, bounded
    // control-plane reads, and fail-closed rehydration live in the worker.
    // These ceilings retain about 1.2KB raw and 0.4KB gzip headroom.
    { path: 'sensors/browser-extension/background.js', maxRawBytes: 48_000, maxGzipBytes: 12_000 },
    { path: 'sensors/browser-extension/manifest.json', maxRawBytes: 14_000, maxGzipBytes: 2_500 },
  ]);

  const totals = walkFiles('sensors/browser-extension')
    .map(readAsset)
    .reduce((acc, asset) => ({
      rawBytes: acc.rawBytes + asset.rawBytes,
      gzipBytes: acc.gzipBytes + asset.gzipBytes,
    }), { rawBytes: 0, gzipBytes: 0 });

  // Signed-policy, destination-coverage, and isolated-reveal assets are now
  // first-class shipped controls. Keep aggregate headroom below three percent.
  assertWithin('browser extension assets raw total', totals.rawBytes, 300_000);
  assertWithin('browser extension assets gzip total', totals.gzipBytes, 95_000);
});

test('browser extension store packages stay within size budget', (t) => {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-extension-budget-'));
  t.after(() => fs.rmSync(outDir, { recursive: true, force: true }));

  for (const target of BROWSER_TARGETS) {
    const result = packageExtension({ outDir, target, now: new Date('2026-07-01T00:00:00.000Z') });
    // A 97KB cap leaves less than three percent package headroom after the
    // non-shipped Chromium runtime metadata directory is excluded.
    assertWithin(`${target} extension zip size`, result.packageManifest.sizeBytes, 97_000);
  }
});
