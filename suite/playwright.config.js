'use strict';

const fs = require('fs');
const path = require('path');
const { defineConfig, devices } = require('@playwright/test');

const port = Number(process.env.PLAYWRIGHT_PORT || 4310);
const baseURL = `http://127.0.0.1:${port}`;

// The bundled chromium build in this environment can differ from the revision
// @playwright/test resolves by default, so pin to the full chromium binary
// present under PLAYWRIGHT_BROWSERS_PATH when one is available.
function resolveChromium() {
  const root = process.env.PLAYWRIGHT_BROWSERS_PATH || '/opt/pw-browsers';
  try {
    const dir = fs.readdirSync(root).find((name) => /^chromium-\d+$/.test(name));
    if (!dir) return undefined;
    for (const rel of ['chrome-linux/chrome', 'chrome-linux64/chrome']) {
      const candidate = path.join(root, dir, rel);
      if (fs.existsSync(candidate)) return candidate;
    }
  } catch { /* fall back to default resolution */ }
  return undefined;
}

const chromiumPath = resolveChromium();
const launchOptions = chromiumPath ? { executablePath: chromiumPath } : {};

module.exports = defineConfig({
  testDir: path.join(__dirname, 'flows'),
  timeout: 45000,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  fullyParallel: false,
  reporter: [['list']],
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `node ${path.join(__dirname, 'support', 'playwright-server.js')}`,
    url: `${baseURL}/healthz`,
    timeout: 30000,
    reuseExistingServer: false,
    env: {
      ...process.env,
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
