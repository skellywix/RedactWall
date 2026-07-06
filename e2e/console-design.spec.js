'use strict';

/**
 * Design-parity evidence for the new React console. Proves the legacy design
 * system was fully ported: the shared base sheet loads (UI font, not serif),
 * dark is the default theme, the light/dark toggle works and persists, the
 * Overview leak-map animation fires, and native selectors carry the instrument
 * styling. Also captures a light + dark screenshot of every view for review.
 */

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

const SHOT_DIR = path.join(__dirname, 'design-evidence');
const VIEWS = [
  { hash: '/', name: 'overview' },
  { hash: '/queue', name: 'queue' },
  { hash: '/monitor', name: 'monitor' },
  { hash: '/activity', name: 'activity' },
  { hash: '/insights', name: 'insights' },
  { hash: '/coverage', name: 'coverage' },
  { hash: '/lineage', name: 'lineage' },
  { hash: '/decision-quality', name: 'decision-quality' },
  { hash: '/catalog', name: 'catalog' },
  { hash: '/compliance', name: 'compliance' },
  { hash: '/identity', name: 'identity' },
  { hash: '/policy', name: 'policy' },
  { hash: '/deploy', name: 'deploy' },
  { hash: '/integrations', name: 'integrations' },
  { hash: '/audit', name: 'audit' },
  { hash: '/updates', name: 'updates' },
];

// 16 views x 2 themes of full-page screenshots need headroom beyond the old
// five-view budget.
test.setTimeout(240000);
test.use({ viewport: { width: 1440, height: 900 } });

async function login(page) {
  await page.goto('/login.html');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/index\.html$/);
}

async function createHeldPrompt(request) {
  const response = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: 'Synthetic design-evidence SSN 524-71-4410 before submission.',
      user: 'design-evidence@example.test',
      destination: 'chat.openai.com',
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'e2e-org',
    },
  });
  expect(response.ok()).toBeTruthy();
}

async function shootAllViews(page, theme) {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  for (const view of VIEWS) {
    await page.goto(`/app/#${view.hash}`);
    // Let the view settle past its loading meta line before capturing.
    await expect(page.locator('.app-panel-meta').first()).not.toHaveText('Loading', { timeout: 10000 }).catch(() => {});
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(SHOT_DIR, `${view.name}-${theme}.png`), fullPage: true });
  }
}

test('new console ports the legacy design system (fonts, dark default, toggle, animation, selectors)', async ({ page, request }) => {
  await createHeldPrompt(request);
  await login(page);
  await page.goto('/app/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  // 1) Dark is the default theme (no stored preference yet).
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'dark');

  // 2) The shared base sheet loaded: body renders in the UI font stack, not the
  //    browser-default serif that the un-linked console fell back to.
  //    (--font-ui resolves to the -apple-system/SF Pro/Segoe stack; the
  //    un-linked console fell back to the browser default serif, which would
  //    never contain these families).
  const fontFamily = await page.evaluate(() => getComputedStyle(document.body).fontFamily);
  expect(fontFamily).toContain('-apple-system');
  expect(fontFamily).toContain('SF Pro Text');

  // 3) The Overview leak-map animation renders and its flow dashes are live.
  await expect(page.locator('#leakMapStage svg')).toBeVisible();
  await expect(page.locator('#leakMapStage .leak-wall')).toBeVisible();
  expect(await page.locator('#leakMapStage .leak-flow').count()).toBeGreaterThan(0);

  // 4) Native selectors carry the instrument styling (appearance stripped).
  await page.goto('/app/#/audit');
  const select = page.locator('.audit-view select').first();
  await expect(select).toBeVisible();
  const appearance = await select.evaluate((el) => {
    const s = getComputedStyle(el);
    return s.appearance || s.webkitAppearance;
  });
  expect(appearance).toBe('none');

  // Dark screenshots of every view.
  await shootAllViews(page, 'dark');

  // 5) The theme toggle switches to light and persists across a reload.
  await page.goto('/app/');
  const lightBtn = page.locator('.theme-toggle button[data-theme-choice="light"]');
  await expect(lightBtn).toBeVisible();
  await lightBtn.click();
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'light');
  const stored = await page.evaluate(() => localStorage.getItem('redactwall.theme'));
  expect(stored).toBe('light');

  await page.reload();
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'light');

  // Light screenshots of every view.
  await shootAllViews(page, 'light');
});
