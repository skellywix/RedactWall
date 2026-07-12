'use strict';

const fs = require('fs');
const path = require('path');
const { defineConfig, devices } = require('@playwright/test');
const { sanitizedEnvironment } = require('./scripts/playwright-env');

const port = Number(process.env.PLAYWRIGHT_PORT || 4210);
const baseURL = `http://127.0.0.1:${port}`;

// If the exact Chromium build @playwright/test resolves by default is absent
// (common when the bundled browsers under PLAYWRIGHT_BROWSERS_PATH are a
// different revision), fall back to any installed full Chromium build so the
// e2e suite runs across environments.
function resolveChromium() {
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (!root) return undefined;
  try {
    const dir = fs.readdirSync(root).find((name) => /^chromium-\d+$/.test(name));
    if (!dir) return undefined;
    for (const rel of [
      'chrome-linux/chrome',
      'chrome-linux64/chrome',
      'chrome-mac/Chromium.app/Contents/MacOS/Chromium',
      'chrome-win/chrome.exe',
      'chrome-win64/chrome.exe',
    ]) {
      const candidate = path.join(root, dir, rel);
      if (fs.existsSync(candidate)) return candidate;
    }
  } catch { /* fall back to default resolution */ }
  return undefined;
}
const chromiumPath = process.env.PLAYWRIGHT_CHROMIUM_PATH || resolveChromium();
const launchOptions = chromiumPath ? { executablePath: chromiumPath } : {};

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 30000,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node scripts/playwright-server.js',
    url: `${baseURL}/healthz`,
    // Windows first boot performs required private-state owner and ACL probes.
    // The measured initialization budget is 60 seconds; routine tests retain
    // the normal per-test timeout above.
    timeout: 60000,
    reuseExistingServer: false,
    env: {
      ...sanitizedEnvironment(process.env),
      PORT: String(port),
    },
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], launchOptions },
    },
  ],
});
