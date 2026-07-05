'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

// The console bundle is gitignored build output; CI builds it before this
// suite. Skip loudly rather than fail when a local run has not built it.
const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

test.setTimeout(90000);

async function login(page) {
  await page.goto('/login.html');
  await expect(page.getByRole('heading', { name: 'PromptWall' })).toBeVisible();
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/index\.html$/);
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
      prompt: `Synthetic new-console wiring SSN 524-71-${suffix} before submission.`,
      user: 'app-console@example.test',
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

test('unauthenticated /app is redirected to the login page', async ({ page }) => {
  await page.goto('/app/');
  await expect(page).toHaveURL(/\/login\.html$/);
});

test('console shell renders the live session and pilot view after login', async ({ page }) => {
  const problems = collectUiProblems(page);
  await login(page);

  await page.goto('/app/');
  await expect(page.locator('#who')).toContainText('admin / Security Admin');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();

  await page.getByRole('link', { name: 'Decision Quality' }).click();
  await expect(page).toHaveURL(/\/app\/#\/decision-quality$/);
  await expect(page.getByRole('heading', { name: 'Decision Quality' })).toBeVisible();
  // Renders either posture-driven rows or the explicit empty state — both are
  // healthy; a hung "Loading" meta line is not.
  await expect(page.locator('.app-panel-meta')).not.toHaveText('Loading', { timeout: 10000 });

  await expect(page.getByRole('link', { name: 'Classic console' })).toHaveAttribute('href', '/index.html');
  expect(problems).toEqual([]);
});

test('overview leak exposure map renders the sanitized department graph', async ({ page, request }) => {
  const problems = collectUiProblems(page);
  const held = await createHeldPrompt(request, '9207');
  await login(page);

  await page.goto('/app/');
  await expect(page.locator('.leak-map-section')).toContainText('AI Data Leak Exposure Map');
  await expect(page.locator('#leakMapSummary')).toContainText('prompt bodies excluded');
  await expect(page.locator('#leakMapStage svg')).toBeVisible();
  await expect(page.locator('#leakMapStage .leak-wall')).toBeVisible();
  await expect(page.locator('#leakMapStage')).toContainText('PROMPTWALL');
  await expect(page.locator('#leakMapStage [data-leak-node="segment:org:e2e-org"]')).toBeVisible();
  await expect(page.locator('#leakMapStage [data-leak-node^="destination:"]').first()).toBeVisible();

  // Inspector answers with sanitized copy only.
  await expect(page.locator('#leakMapInspector')).toContainText('What is flowing');
  await expect(page.locator('#leakMapInspector')).toContainText('masked findings only');
  expect(await page.locator('.leak-map-section').textContent()).not.toContain('524-71-');

  // Node click focuses the segment; the exposure filter narrows the graph.
  await page.locator('#leakMapStage [data-leak-node="segment:org:e2e-org"]').click();
  await expect(page.locator('#leakMapInspector')).toContainText('e2e-org');
  await page.locator('[data-leak-filter="risk"]').click();
  await expect(page.locator('[data-leak-filter="risk"]')).toHaveAttribute('aria-pressed', 'true');

  // Reduced motion strips the animated flow classes on re-render.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(page.locator('#leakMapStage')).toHaveClass(/is-static/);
  expect(await page.locator('#leakMapStage .leak-flow').count()).toBe(0);

  // Deny the fixture so later specs see a single-row approval queue.
  const denied = await page.evaluate(async (id) => {
    const { csrfToken } = await (await fetch('/api/csrf')).json();
    const res = await fetch(`/api/queries/${id}/deny`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
      body: JSON.stringify({ note: 'e2e leak-map fixture cleanup' }),
    });
    return res.status;
  }, held.id);
  expect(denied).toBe(200);

  expect(problems).toEqual([]);
});

test('approval queue releases a held prompt after password step-up', async ({ page, request }) => {
  const held = await createHeldPrompt(request, '9001');
  await login(page);

  await page.goto('/app/#/queue');
  await expect(page.getByRole('heading', { name: 'Approval Queue' })).toBeVisible();
  const heldRow = page.locator('article.q').filter({ hasText: 'app-console@example.test' }).first();
  await heldRow.click();

  await page.getByLabel('Decision note').fill('e2e release check');
  await page.getByRole('button', { name: 'Approve release' }).click();

  const dialog = page.locator('dialog.stepup-dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Account password').fill('e2e-pass');
  await dialog.getByRole('button', { name: 'Approve release' }).click();

  await expect(page.locator('#toastStack')).toContainText('Prompt approved and released.');
  const status = await request.get(`/api/v1/status/${held.id}`, {
    headers: { 'x-api-key': 'e2e-ingest-key', 'x-release-token': held.releaseToken },
  });
  expect(status.ok()).toBeTruthy();
  expect((await status.json()).status).toBe('approved');
});

test('policy and audit views render live data without errors', async ({ page }) => {
  const problems = collectUiProblems(page);
  await login(page);

  await page.goto('/app/#/policy');
  await expect(page.getByRole('heading', { name: 'Policy', exact: true })).toBeVisible();
  await expect(page.locator('.app-panel-meta').first()).not.toHaveText('Loading', { timeout: 10000 });

  await page.goto('/app/#/audit');
  await expect(page.getByRole('heading', { name: 'Tamper-evident Audit Log' })).toBeVisible();
  await expect(page.locator('.app-panel-meta').first()).not.toHaveText('Loading', { timeout: 10000 });

  expect(problems).toEqual([]);
});
