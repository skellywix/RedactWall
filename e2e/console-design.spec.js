'use strict';

/**
 * Design-parity evidence for the new React console. Proves the legacy design
 * system was fully ported: the shared base sheet loads (UI font, not serif),
 * dark is the default theme, the light/dark toggle works and persists, the
 * Overview leak-map animation fires, and native selectors carry the instrument
 * styling. Also captures a light + dark screenshot of every view for review,
 * plus responsive shell evidence.
 */

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

const SHOT_DIR = path.join(__dirname, 'design-evidence');
const VIEWS = [
  { hash: '/', name: 'overview', heading: 'Texas FCU Overview', root: '.leak-map-section', state: 'overview' },
  { hash: '/queue', name: 'queue', heading: 'Member Data Queue', root: '.queue-view', state: 'queue' },
  { hash: '/monitor', name: 'monitor', heading: 'Texas FCU Command Center', root: '.monitor-view', state: 'monitor' },
  { hash: '/activity', name: 'activity', heading: 'Exam Activity', root: '.activity-view' },
  { hash: '/insights', name: 'insights', heading: 'Member Data Insights', root: '.insights-view' },
  { hash: '/coverage', name: 'coverage', heading: 'Texas FCU Coverage', root: '.coverage-view' },
  { hash: '/lineage', name: 'lineage', heading: 'Member Data Lineage', root: '.lineage-view' },
  { hash: '/decision-quality', name: 'decision-quality', heading: 'Reviewer Decision Quality' },
  { hash: '/catalog', name: 'catalog', heading: 'AI Vendor Catalog', root: '.catalog-view' },
  { hash: '/compliance', name: 'compliance', heading: 'NCUA / GLBA Controls', root: '.compliance-view' },
  { hash: '/ncua', name: 'ncua-readiness', heading: 'Texas FCU Readiness', root: '.ncua-view' },
  { hash: '/identity', name: 'identity', heading: 'Users & Roles', root: '.identity-view', state: 'identity' },
  { hash: '/licensing', name: 'licensing', heading: 'Licensing', root: '.licensing-view' },
  { hash: '/policy', name: 'policy', heading: 'Policy Configuration', root: '.policy-view', state: 'policy' },
  { hash: '/deploy', name: 'deploy', heading: 'Texas FCU sensor rollout', root: '.deploy-view' },
  { hash: '/integrations', name: 'integrations', heading: 'Evidence Delivery', root: '.integrations-view' },
  { hash: '/audit', name: 'audit', heading: 'Examiner Audit Chain', root: '.audit-view' },
  { hash: '/updates', name: 'updates', heading: 'Controlled Updates', root: '.updates-view' },
];

// 18 views x 2 themes of full-page screenshots need headroom beyond the old
// five-view budget.
test.setTimeout(240000);
test.use({ viewport: { width: 1440, height: 900 } });
test.beforeEach(() => fs.mkdirSync(SHOT_DIR, { recursive: true }));

async function login(page) {
  await loginAs(page, 'admin', 'e2e-pass');
}

async function loginAs(page, user, password) {
  await page.goto('/login.html');
  await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
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
  const body = await response.json();
  expect(body.status).toBe('pending');
}

async function settleLayout(page) {
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function waitForViewEvidence(page, view) {
  if (view.root) await expect(page.locator(view.root).first()).toBeVisible({ timeout: 45000 });
  await expect(page.getByRole('heading', { name: view.heading, exact: true }).first()).toBeVisible({ timeout: 45000 });
  await expect(page.locator('.app-loading')).toHaveCount(0, { timeout: 45000 });
  await expect(page.locator('.app-panel-meta').filter({ hasText: /^Loading$/ })).toHaveCount(0, { timeout: 45000 });
  if (view.state === 'overview') {
    await expect(page.locator('.leak-map-section')).toHaveAttribute('data-map-state', /^(empty|populated|unavailable)$/, { timeout: 45000 });
  } else if (view.state === 'queue') {
    await expect(page.getByText('Loading member-data queue', { exact: true })).toHaveCount(0, { timeout: 45000 });
  } else if (view.state === 'monitor') {
    await expect(page.locator('.monitor-view').getByText(/^(SYNCING|AWAITING POSTURE|Waiting for verified posture\.?|Loading action state|Loading detector feedback|Loading activity)$/)).toHaveCount(0, { timeout: 45000 });
  } else if (view.state === 'policy') {
    await expect(page.locator('.policy-head-row')).toBeVisible({ timeout: 45000 });
    await expect(page.locator('.policy-head-row')).not.toContainText('Checking readiness', { timeout: 45000 });
  } else if (view.state === 'identity') {
    await expect(page.locator('.identity-grid[data-loading-label="LOADING"]')).toHaveCount(0, { timeout: 45000 });
  }
  await settleLayout(page);
}

async function shootAllViews(page, theme) {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  for (const view of VIEWS) {
    await page.goto(`/app/#${view.hash}`);
    await waitForViewEvidence(page, view);
    await page.screenshot({
      path: path.join(SHOT_DIR, `${view.name}-${theme}.png`),
      fullPage: true,
      animations: 'disabled',
    });
  }
}

test('new console ports the legacy design system (fonts, dark default, toggle, animation, selectors)', async ({ page, request }) => {
  await createHeldPrompt(request);
  await login(page);
  await page.goto('/app/');
  await expect(page.getByRole('heading', { name: 'Texas FCU Overview' })).toBeVisible();

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

test('responsive shell contains focus, restores launchers, and preserves deep links', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 });
  await login(page);
  await page.goto('/app/#/audit?scope=recent');
  await expect(page).toHaveURL(/\/app\/#\/audit\?scope=recent$/);
  await expect(page.locator('.app-route-context strong')).toHaveText('Examiner Audit Chain');

  await page.keyboard.press('Tab');
  const skipLink = page.getByRole('link', { name: 'Skip to main content' });
  await expect(skipLink).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();
  await expect(page).toHaveURL(/\/app\/#\/audit\?scope=recent$/);

  const menuButton = page.getByRole('button', { name: 'Open navigation menu' });
  await expect(menuButton).toBeVisible();
  await menuButton.click();

  const drawer = page.getByRole('dialog', { name: 'Navigation menu' });
  const closeDrawer = drawer.getByRole('button', { name: 'Close navigation menu' });
  await expect(drawer).toBeVisible();
  await expect(closeDrawer).toBeFocused();
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  await page.screenshot({ path: path.join(SHOT_DIR, 'shell-mobile-drawer-320x568-dark.png'), animations: 'disabled' });
  await page.keyboard.press('Shift+Tab');
  expect(await drawer.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await expect(menuButton).toBeFocused();

  await menuButton.click();
  await page.locator('.app-nav-backdrop').click({ position: { x: 310, y: 300 } });
  await expect(drawer).toBeHidden();
  await expect(menuButton).toBeFocused();

  await menuButton.click();
  await drawer.getByRole('button', { name: 'Licensing' }).click();
  await expect(page).toHaveURL(/\/app\/#\/licensing$/);
  await expect(drawer).toBeHidden();

  const paletteLauncher = page.getByRole('button', { name: 'Open the command palette' });
  await paletteLauncher.click();
  const palette = page.getByRole('dialog', { name: 'Command palette' });
  await expect(palette.getByLabel('Command palette filter')).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  expect(await palette.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  await page.keyboard.press('Escape');
  await expect(palette).toHaveCount(0);
  await expect(paletteLauncher).toBeFocused();

  await expect(page.locator('.app-loading')).toHaveCount(0);
  await page.screenshot({ path: path.join(SHOT_DIR, 'shell-mobile-320x568-dark.png') });
  await page.setViewportSize({ width: 1024, height: 520 });
  await page.goto('/app/#/audit?scope=recent');
  await expect(menuButton).toBeHidden();
  await expect(page.locator('.app-rail')).toBeVisible();
  await expect(page.locator('.app-loading')).toHaveCount(0);
  await page.screenshot({ path: path.join(SHOT_DIR, 'shell-desktop-short-1024x520-dark.png') });
});

for (const account of [
  {
    role: 'security_admin',
    user: 'admin',
    password: 'e2e-pass',
    deepLink: '/updates?source=role-check',
    activeLabel: 'Controlled Updates',
    visible: ['Sensor Rollout', 'Evidence Delivery', 'Controlled Updates'],
    hidden: [],
  },
  {
    role: 'operator',
    user: 'e2e-operator',
    password: 'e2e-operator-pass',
    deepLink: '/deploy?source=role-check',
    activeLabel: 'Sensor Rollout',
    visible: ['Sensor Rollout', 'Evidence Delivery', 'Controlled Updates'],
    hidden: [],
  },
  {
    role: 'auditor',
    user: 'e2e-auditor',
    password: 'e2e-auditor-pass',
    deepLink: '/licensing?source=role-check',
    activeLabel: 'Licensing',
    visible: ['Users & Roles', 'Licensing'],
    hidden: ['Sensor Rollout', 'Evidence Delivery', 'Controlled Updates'],
  },
]) {
  test(`${account.role} drawer keeps role-scoped routes and query deep links`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 740 });
    await loginAs(page, account.user, account.password);
    await page.goto(`/app/#${account.deepLink}`);
    await expect(page).toHaveURL(new RegExp(`#${account.deepLink.replace('?', '\\?')}$`));
    await expect(page.locator('.app-route-context strong')).toHaveText(account.activeLabel);

    await page.getByRole('button', { name: 'Open navigation menu' }).click();
    const drawer = page.getByRole('dialog', { name: 'Navigation menu' });
    await expect(drawer.getByRole('button', { name: account.activeLabel })).toHaveAttribute('aria-current', 'page');
    for (const label of account.visible) await expect(drawer.getByRole('button', { name: label })).toBeVisible();
    for (const label of account.hidden) await expect(drawer.getByRole('button', { name: label })).toHaveCount(0);
    await page.screenshot({
      path: path.join(SHOT_DIR, `role-${account.role}-mobile-390x740-dark.png`),
      fullPage: true,
      animations: 'disabled',
    });
  });
}

test('forced-colors mode preserves visible navigation, focus, and evidence controls', async ({ page, request }) => {
  await page.emulateMedia({ forcedColors: 'active' });
  await page.setViewportSize({ width: 1024, height: 768 });
  await createHeldPrompt(request);
  await login(page);
  await page.goto('/app/#/');
  await waitForViewEvidence(page, VIEWS[0]);
  expect(await page.evaluate(() => matchMedia('(forced-colors: active)').matches)).toBe(true);

  const paletteLauncher = page.getByRole('button', { name: 'Open the command palette' });
  await paletteLauncher.focus();
  await expect(paletteLauncher).toBeFocused();
  const focus = await paletteLauncher.evaluate((element) => {
    const style = getComputedStyle(element);
    return { outlineStyle: style.outlineStyle, outlineWidth: style.outlineWidth };
  });
  expect(focus.outlineStyle).not.toBe('none');
  expect(Number.parseFloat(focus.outlineWidth)).toBeGreaterThanOrEqual(1);
  await expect(page.getByRole('button', { name: 'Details', exact: true })).toBeVisible();
  await page.screenshot({
    path: path.join(SHOT_DIR, 'overview-forced-colors-1024x768.png'),
    fullPage: true,
    animations: 'disabled',
  });
});
