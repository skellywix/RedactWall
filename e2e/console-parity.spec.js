'use strict';

/**
 * Parity EVIDENCE for the new React console: every legacy capability now has a
 * route in /app, and each route renders real content — not a hung loader, not
 * console noise. Modeled on admin-console-app.spec.js (same login, same seeded
 * held prompt, same zero-console-error discipline).
 */

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

// The console bundle is gitignored build output; CI builds it before this
// suite. Skip loudly rather than fail when a local run has not built it.
const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

test.setTimeout(90000);

// The committed default policy the playwright server boots with. Earlier specs
// in the shared test:browser run (browser-extension) mutate the server policy —
// e.g. blockUnapprovedAiDestinations with a narrow governed list — and do not
// restore it, which makes the seeded chat.openai.com prompt come back
// 'destination_blocked' instead of 'pending'. Reset to the default before each
// test so this spec is independent of run order.
const DEFAULT_POLICY = require(path.join(__dirname, '..', 'config', 'policy.json'));

async function resetServerPolicy(request) {
  const loginRes = await request.post('/api/login', { data: { user: 'admin', password: 'e2e-pass' } });
  expect(loginRes.ok()).toBeTruthy();
  const { csrfToken } = await (await request.get('/api/csrf')).json();
  const putRes = await request.put('/api/policy', {
    headers: { 'x-csrf-token': csrfToken },
    data: DEFAULT_POLICY,
  });
  expect(putRes.ok()).toBeTruthy();
}

test.beforeEach(async ({ request }) => {
  await resetServerPolicy(request);
});

async function login(page) {
  await page.goto('/login.html');
  await expect(page.getByRole('heading', { name: 'RedactWall' })).toBeVisible();
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

function collectUiProblems(page) {
  const problems = [];
  page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (['error', 'warning'].includes(message.type())) {
      problems.push(`console ${message.type()}: ${message.text()}`);
    }
  });
  page.on('response', (response) => {
    const url = response.url();
    if (url.includes('/api/') && response.status() >= 400) {
      problems.push(`api ${response.status()}: ${url}`);
    }
  });
  return problems;
}

async function createHeldPrompt(request, suffix) {
  const response = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: `Synthetic parity-evidence SSN 524-71-${suffix} before submission.`,
      user: 'parity-console@example.test',
      destination: 'chat.openai.com',
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'e2e-org',
    },
  });
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body.status).toBe('pending');
  return body;
}

// One entry per route: the heading is the view's own h2 (verified against
// console/src/views/*.tsx), never a nav label, so a blank view cannot pass.
const ROUTES = {
  operate: [
    { hash: '/', heading: 'Overview' },
    { hash: '/queue', heading: 'Approval Queue' },
    { hash: '/monitor', heading: 'AI Security Command Center' },
    { hash: '/activity', heading: 'All Gated Prompts' },
  ],
  analyze: [
    { hash: '/insights', heading: 'AI Usage Insights' },
    { hash: '/coverage', heading: 'Sensor Coverage' },
    { hash: '/lineage', heading: 'Prompt And File Lineage' },
    { hash: '/decision-quality', heading: 'Decision Quality' },
  ],
  govern: [
    { hash: '/catalog', heading: 'AI App Catalog' },
    { hash: '/compliance', heading: 'Compliance Posture' },
    { hash: '/ncua', heading: 'NCUA Readiness' },
    { hash: '/identity', heading: 'Identity' },
    { hash: '/policy', heading: 'Configuration' },
  ],
  system: [
    { hash: '/deploy', heading: 'Sensor packages' },
    { hash: '/integrations', heading: 'Integrations & Delivery' },
    { hash: '/audit', heading: 'Tamper-evident Audit Log' },
    { hash: '/updates', heading: 'Updates' },
  ],
};

async function assertViewRenders(page, route) {
  await page.goto(`/app/#${route.hash}`);
  await expect(page.getByRole('heading', { name: route.heading, exact: true })).toBeVisible();
  // Every loader must resolve: Suspense fallbacks and per-view fetch loaders
  // share the .app-loading class, and Panel metas show a literal "Loading".
  await expect(page.locator('.app-loading')).toHaveCount(0, { timeout: 20000 });
  await expect(page.locator('.app-panel-meta', { hasText: /^Loading$/ })).toHaveCount(0);
}

async function assertGroupRenders(page, request, suffix, routes) {
  const problems = collectUiProblems(page);
  await createHeldPrompt(request, suffix);
  await login(page);
  for (const route of routes) {
    await assertViewRenders(page, route);
  }
  expect(problems).toEqual([]);
}

test('OPERATE views render live content without errors', async ({ page, request }) => {
  await assertGroupRenders(page, request, '8101', ROUTES.operate);
});

test('ANALYZE views render live content without errors', async ({ page, request }) => {
  await assertGroupRenders(page, request, '8102', ROUTES.analyze);
});

test('GOVERN views render live content without errors', async ({ page, request }) => {
  await assertGroupRenders(page, request, '8103', ROUTES.govern);
});

test('SYSTEM views render live content without errors', async ({ page, request }) => {
  await assertGroupRenders(page, request, '8104', ROUTES.system);
});

test('shell chrome: nav groups, queue badge, LIVE indicator, sign-out, command palette', async ({ page, request }) => {
  const problems = collectUiProblems(page);
  await createHeldPrompt(request, '8105');
  await login(page);

  await page.goto('/app/');
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();

  // All four legacy capability groups exist in the rail.
  for (const label of ['Operate', 'Analyze', 'Govern', 'System']) {
    await expect(page.locator('.app-rail-group .rail-group-label', { hasText: new RegExp(`^${label}$`) })).toBeVisible();
  }

  // The queue badge reflects the seeded held prompt.
  const queueBadge = page.locator('.app-rail .tab', { hasText: 'Approval Queue' }).locator('.badge');
  await expect(queueBadge).toBeVisible();
  await expect(queueBadge).toHaveText(/^[1-9]\d*$/);

  // Topbar telemetry + session controls, same ids the legacy console exposed.
  await expect(page.locator('#liveTxt')).toHaveText('LIVE');
  await expect(page.locator('#lastUpdated')).toContainText('LAST UPDATED');
  await expect(page.locator('#who')).toContainText('admin / Security Admin');
  await expect(page.locator('#logout')).toHaveText(/Sign out/);

  // Command palette: Ctrl+K opens, substring filter narrows, Enter navigates.
  await page.keyboard.press('Control+k');
  const palette = page.locator('.cmdk');
  await expect(palette).toBeVisible();
  await palette.getByLabel('Command palette filter').fill('lineage');
  await expect(palette.locator('.cmdk-item')).toHaveCount(1);
  await expect(palette.locator('.cmdk-item.is-selected')).toContainText('Data Lineage');
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/app\/#\/lineage$/);
  await expect(page.getByRole('heading', { name: 'Prompt And File Lineage', exact: true })).toBeVisible();
  await expect(palette).toHaveCount(0);

  expect(problems).toEqual([]);
});
