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

function singleMatchingAsset(paths, pattern, label) {
  const matches = paths.filter((assetPath) => pattern.test(assetPath.replaceAll('\\', '/')));
  assert.strictEqual(matches.length, 1, `expected one ${label} asset, found ${matches.length}`);
  return matches[0];
}

test('shipped static frontend assets stay within transfer budgets', () => {
  // The legacy static console (index.html, dashboard.js, and the feature JS
  // bundles) was removed in favor of the built React console under
  // server/public/app (budgeted separately below). What still ships as static
  // top-level assets are the shared auth pages and the console stylesheets.
  const totals = assertAssetBudgets([
    { path: 'server/public/console-base.css', maxRawBytes: 130_000, maxGzipBytes: 24_000 },
    { path: 'server/public/console-theme.css', maxRawBytes: 24_000, maxGzipBytes: 6_000 },
    { path: 'server/public/auth-surface.css', maxRawBytes: 6_000, maxGzipBytes: 1_800 },
    { path: 'server/public/login.html', maxRawBytes: 12_000, maxGzipBytes: 5_000 },
    { path: 'server/public/auth-response.js', maxRawBytes: 4_000, maxGzipBytes: 1_500 },
    { path: 'server/public/login.js', maxRawBytes: 6_000, maxGzipBytes: 2_500 },
    { path: 'server/public/accept-invite.html', maxRawBytes: 4_000, maxGzipBytes: 1_600 },
    { path: 'server/public/accept-invite.js', maxRawBytes: 4_000, maxGzipBytes: 1_600 },
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
  const builtAssets = walkFiles(path.join('server', 'public', 'app'));
  const totals = builtAssets
    .map(readAsset)
    .reduce((acc, asset) => ({
      rawBytes: acc.rawBytes + asset.rawBytes,
      gzipBytes: acc.gzipBytes + asset.gzipBytes,
    }), { rawBytes: 0, gzipBytes: 0 });

  // The redesign adds 18 route-complete workflows, strict response decoders,
  // truthful evidence states, and the interactive exposure map; the merged
  // credit-union surfaces (FFIEC frameworks rollup, board-training attestation)
  // add a few more KB. Ceilings are re-measured against that integrated build
  // at 762,502 raw / 228,498 gzip bytes. Retain about five percent measured
  // headroom while also guarding the initial shell and the two largest lazy
  // routes so total growth cannot hide an expensive first load or route
  // regression.
  assertWithin('console app bundle raw total', totals.rawBytes, 801_000);
  assertWithin('console app bundle gzip total', totals.gzipBytes, 240_000);

  assertAssetBudgets([
    {
      path: singleMatchingAsset(builtAssets, /\/assets\/index-[^/]+\.js$/, 'console shell JavaScript'),
      maxRawBytes: 240_000,
      maxGzipBytes: 76_000,
    },
    {
      path: singleMatchingAsset(builtAssets, /\/assets\/index-[^/]+\.css$/, 'console shell stylesheet'),
      maxRawBytes: 8_500,
      maxGzipBytes: 2_200,
    },
    {
      path: singleMatchingAsset(builtAssets, /\/assets\/Monitor-[^/]+\.js$/, 'Command Center JavaScript'),
      maxRawBytes: 100_000,
      maxGzipBytes: 27_000,
    },
    {
      path: singleMatchingAsset(builtAssets, /\/assets\/Policy-[^/]+\.js$/, 'Policy JavaScript'),
      maxRawBytes: 80_000,
      maxGzipBytes: 22_000,
    },
  ]);
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
