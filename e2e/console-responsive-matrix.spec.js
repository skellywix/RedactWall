'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

const SHOT_DIR = path.join(__dirname, 'design-evidence', 'responsive');
const VIEWPORTS = [
  { name: 'mobile-320x568', width: 320, height: 568 },
  { name: 'mobile-390x844', width: 390, height: 844 },
  { name: 'tablet-768x1024', width: 768, height: 1024 },
  { name: 'short-1024x600', width: 1024, height: 600 },
  { name: 'laptop-1366x768', width: 1366, height: 768 },
  { name: 'desktop-1440x900', width: 1440, height: 900 },
  { name: 'desktop-1920x1080', width: 1920, height: 1080 },
  { name: 'wide-2560x1440', width: 2560, height: 1440 },
];
const ROUTES = [
  { hash: '/', name: 'overview', heading: 'Texas FCU Overview', root: '.leak-map-section', state: 'overview' },
  { hash: '/queue', name: 'queue', heading: 'Member Data Queue', root: '.queue-view', state: 'queue' },
  { hash: '/monitor', name: 'monitor', heading: 'Texas FCU Command Center', root: '.monitor-view', state: 'monitor' },
  { hash: '/activity', name: 'activity', heading: 'Exam Activity', root: '.activity-view' },
  { hash: '/insights', name: 'insights', heading: 'Member Data Insights', root: '.insights-view' },
  { hash: '/coverage', name: 'coverage', heading: 'Texas FCU Coverage', root: '.coverage-view' },
  { hash: '/lineage', name: 'lineage', heading: 'Member Data Lineage', root: '.lineage-view' },
  { hash: '/decision-quality', name: 'decision-quality', heading: 'Reviewer Decision Quality' },
  { hash: '/audit', name: 'audit', heading: 'Examiner Audit Chain', root: '.audit-view' },
  { hash: '/catalog', name: 'catalog', heading: 'AI Vendor Catalog', root: '.catalog-view' },
  { hash: '/compliance', name: 'compliance', heading: 'NCUA / GLBA Controls', root: '.compliance-view' },
  { hash: '/ncua', name: 'ncua', heading: 'Texas FCU Readiness', root: '.ncua-view' },
  { hash: '/policy', name: 'policy', heading: 'Policy Configuration', root: '.policy-view', state: 'policy' },
  { hash: '/identity', name: 'identity', heading: 'Users & Roles', root: '.identity-view', state: 'identity' },
  { hash: '/licensing', name: 'licensing', heading: 'Licensing', root: '.licensing-view' },
  { hash: '/deploy', name: 'deploy', heading: 'Texas FCU sensor rollout', root: '.deploy-view' },
  { hash: '/integrations', name: 'integrations', heading: 'Evidence Delivery', root: '.integrations-view' },
  { hash: '/updates', name: 'updates', heading: 'Controlled Updates', root: '.updates-view' },
];

test.beforeEach(() => {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
});

async function login(page) {
  await page.goto('/login.html');
  await page.locator('#user').fill('admin');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function settleLayout(page) {
  await page.evaluate(() => new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(resolve));
  }));
}

async function waitForSettledView(page, route) {
  if (route.root) await expect(page.locator(route.root).first()).toBeVisible({ timeout: 45000 });
  await expect(page.getByRole('heading', { name: route.heading, exact: true }).first()).toBeVisible({ timeout: 45000 });
  await expect(page.locator('.app-loading')).toHaveCount(0, { timeout: 45000 });
  await expect(page.locator('.app-panel-meta').filter({ hasText: /^Loading$/ })).toHaveCount(0, { timeout: 45000 });

  if (route.state === 'overview') {
    await expect(page.locator('.leak-map-section')).toHaveAttribute('data-map-state', /^(empty|populated|unavailable)$/, { timeout: 45000 });
    await expect(page.getByText('Loading evidence counters', { exact: true })).toHaveCount(0, { timeout: 45000 });
  } else if (route.state === 'queue') {
    await expect(page.getByText('Loading member-data queue', { exact: true })).toHaveCount(0, { timeout: 45000 });
    await expect(page.locator('.queue-view .app-panel-meta').first()).not.toContainText(/Loading|Refreshing/, { timeout: 45000 });
  } else if (route.state === 'monitor') {
    const loadingCopy = /^(SYNCING|AWAITING POSTURE|Waiting for verified posture\.?|Loading action state|Loading detector feedback|Loading activity)$/;
    await expect(page.locator('.monitor-view').getByText(loadingCopy)).toHaveCount(0, { timeout: 45000 });
  } else if (route.state === 'policy') {
    await expect(page.locator('.policy-head-row')).toBeVisible({ timeout: 45000 });
    await expect(page.locator('.policy-head-row')).not.toContainText('Checking readiness', { timeout: 45000 });
    await expect(page.locator('details[data-policy-section="templates"] .policy-disclosure-meta')).not.toHaveText('Loading', { timeout: 45000 });
  } else if (route.state === 'identity') {
    await expect(page.locator('.identity-grid[data-loading-label="LOADING"]')).toHaveCount(0, { timeout: 45000 });
    await expect(page.getByRole('heading', { name: 'Administration Overview', exact: true })).toBeVisible({ timeout: 45000 });
  }

  await settleLayout(page);
}

async function pageOverflow(page) {
  return page.evaluate(() => ({
    document: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
  }));
}

async function expectNoOverflow(page, label) {
  const overflow = await pageOverflow(page);
  expect(overflow.document, `${label} document overflow`).toBeLessThanOrEqual(1);
  expect(overflow.body, `${label} body overflow`).toBeLessThanOrEqual(1);
}

async function createHeldPrompt(request) {
  const response = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: 'Synthetic reduced-motion proof SSN 524-71-9627 before submission.',
      user: 'responsive-motion@example.test',
      destination: 'chat.openai.com',
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'responsive-motion-org',
    },
  });
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body.status).toBe('pending');
  return body.id;
}

async function denyFixture(page, id) {
  await page.evaluate(async (queryId) => {
    const csrfResponse = await fetch('/api/csrf');
    const { csrfToken } = await csrfResponse.json();
    const response = await fetch(`/api/queries/${queryId}/deny`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
      body: JSON.stringify({ note: 'responsive evidence cleanup' }),
    });
    if (!response.ok) throw new Error('responsive evidence cleanup failed');
  }, id);
}

function installLayoutZoom() {
  const apply = () => {
    const parent = document.head || document.documentElement;
    if (!parent) return false;
    const id = 'playwright-layout-zoom';
    let style = document.getElementById(id);
    if (!style) {
      style = document.createElement('style');
      style.id = id;
      parent.appendChild(style);
    }
    style.textContent = 'html { zoom: 2 !important; }';
    return true;
  };
  if (!apply()) document.addEventListener('DOMContentLoaded', apply, { once: true });
}

test.describe('authenticated responsive evidence matrix', () => {
  test.setTimeout(900000);

  test('all authenticated routes reflow across supported viewport shapes', async ({ page }) => {
    const pageErrors = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    await login(page);
    await expect(page.locator('body')).toHaveAttribute('data-theme', 'dark');

    for (const route of ROUTES) {
      await page.setViewportSize({ width: VIEWPORTS[0].width, height: VIEWPORTS[0].height });
      await page.goto(`/app/#${route.hash}`);
      await waitForSettledView(page, route);

      for (const viewport of VIEWPORTS) {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await waitForSettledView(page, route);
        await page.evaluate(() => window.scrollTo(0, 0));
        await expectNoOverflow(page, `${route.name} at ${viewport.name}`);
        await page.screenshot({
          path: path.join(SHOT_DIR, `${route.name}-${viewport.name}-dark.png`),
          fullPage: true,
          animations: 'disabled',
        });
      }
    }

    expect(pageErrors).toEqual([]);
  });

  test('seeded motion and persistent 200 percent layout zoom retain operable reflow', async ({ page, request }) => {
    const heldId = await createHeldPrompt(request);
    await page.setViewportSize({ width: 800, height: 900 });
    await login(page);

    try {
      const overview = ROUTES[0];
      await page.goto('/app/#/');
      await waitForSettledView(page, overview);
      await expect(page.locator('#leakMapStage [data-leak-edge]')).not.toHaveCount(0);
      await expect(page.locator('#leakMapStage .leak-flow')).not.toHaveCount(0);

      await page.emulateMedia({ reducedMotion: 'reduce' });
      await expect(page.getByRole('button', { name: 'Motion reduced' })).toBeDisabled();
      await expect(page.locator('#leakMapStage [data-leak-edge]')).not.toHaveCount(0);
      await expect(page.locator('#leakMapStage .leak-line')).not.toHaveCount(0);
      await expect(page.locator('#leakMapStage .leak-flow')).toHaveCount(0);
      await page.screenshot({
        path: path.join(SHOT_DIR, 'overview-reduced-motion-800x900-dark.png'),
        fullPage: true,
        animations: 'disabled',
      });

      await page.emulateMedia({ reducedMotion: 'no-preference' });
      const heading = page.getByRole('heading', { name: overview.heading, exact: true });
      const baseline = await heading.boundingBox();
      expect(baseline).not.toBeNull();
      await page.addInitScript(installLayoutZoom);
      await page.evaluate(installLayoutZoom);
      await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).zoom)).toBe('2');
      await settleLayout(page);
      const enlarged = await heading.boundingBox();
      expect(enlarged).not.toBeNull();
      expect(enlarged.height).toBeGreaterThanOrEqual(baseline.height * 1.9);

      const zoomWorkflows = [
        {
          route: overview,
          exercise: async () => {
            await page.getByRole('button', { name: 'Details', exact: true }).click();
            await expect(page.locator('#leakMapDetails')).toBeVisible();
          },
        },
        {
          route: ROUTES.find((route) => route.name === 'queue'),
          exercise: async () => {
            const search = page.getByPlaceholder('Filter by employee, AI destination, or masked text');
            await search.fill('responsive-motion');
            await expect(search).toHaveValue('responsive-motion');
          },
        },
        {
          route: ROUTES.find((route) => route.name === 'policy'),
          exercise: async () => {
            const fleet = page.locator('details[data-policy-section="fleet"]');
            await fleet.locator('summary').click();
            await expect(fleet).toHaveAttribute('open', '');
          },
        },
        {
          route: ROUTES.find((route) => route.name === 'activity'),
          exercise: async () => {
            const search = page.getByLabel('Search activity');
            await search.fill('status:pending');
            await expect(search).toHaveValue('status:pending');
          },
        },
      ];

      for (const workflow of zoomWorkflows) {
        await page.goto(`/app/#${workflow.route.hash}`);
        await waitForSettledView(page, workflow.route);
        await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).zoom)).toBe('2');
        await expectNoOverflow(page, `${workflow.route.name} at 200 percent layout zoom`);
        await workflow.exercise();
        await expectNoOverflow(page, `${workflow.route.name} controls at 200 percent layout zoom`);
        await page.screenshot({
          path: path.join(SHOT_DIR, `${workflow.route.name}-text-zoom-200-800x900-dark.png`),
          fullPage: true,
          animations: 'disabled',
        });
      }
    } finally {
      await denyFixture(page, heldId).catch(() => {});
    }
  });
});
