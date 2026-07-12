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
  await expect(page.getByRole('heading', { name: 'RedactWall' })).toBeVisible();
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function loginAs(page, user, password) {
  await page.goto('/login.html');
  await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
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
  await expect(page.locator('#who')).toContainText('admin / Global Administrator');
  await expect(page.getByRole('heading', { name: 'Institution Overview' })).toBeVisible();

  await page.getByRole('button', { name: 'Reviewer Decisions' }).click();
  await expect(page).toHaveURL(/\/app\/#\/decision-quality$/);
  await expect(page.getByRole('heading', { name: 'Reviewer Decision Quality' })).toBeVisible();
  // Renders either posture-driven rows or the explicit empty state — both are
  // healthy; a hung "Loading" meta line is not.
  await expect(page.locator('.app-panel-meta')).not.toHaveText('Loading', { timeout: 10000 });

  expect(problems).toEqual([]);
});

test('administration nav exposes users, roles, and licensing workflows', async ({ page }) => {
  const problems = collectUiProblems(page);
  await login(page);

  await page.goto('/app/#/identity');
  await expect(page.getByText('Administration')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Users & Roles' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Users & Roles' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Identity Setup' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Staff Directory' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Invite Staff User' })).toBeVisible();
  const roleMatrix = page.locator('.role-matrix');
  await expect(roleMatrix.getByText('Global Administrator')).toBeVisible();
  await expect(roleMatrix.getByText('Member Data Reviewer')).toBeVisible();

  const inviteEmail = `e2e-admin-${Date.now()}@example.test`;
  const inviteForm = page.locator('.invite-form');
  await inviteForm.getByLabel('Staff email').fill(inviteEmail);
  await inviteForm.getByLabel('Display name').fill('E2E Admin User');
  await inviteForm.getByLabel('Role').selectOption('auditor');
  await inviteForm.getByLabel('Reason').fill('E2E admin invite');
  await inviteForm.getByRole('button', { name: 'Create invite' }).click();
  await expect(inviteForm).toContainText('Invite link');
  const inviteUrl = await inviteForm.locator('.invite-url .mono').textContent();
  expect(inviteUrl).toContain('/accept-invite.html#token=');

  const invitationRow = page.locator('.admin-table.compact tbody tr').filter({ hasText: inviteEmail });
  await expect(invitationRow).toBeVisible();
  page.once('dialog', (dialog) => dialog.accept('E2E replacement invite link'));
  await invitationRow.getByRole('button', { name: 'Resend' }).click();
  const replacementLink = page.getByRole('status').filter({ hasText: 'Replacement invite link' });
  await expect(replacementLink).toBeVisible();
  await expect(inviteForm.locator('.invite-url')).toHaveCount(0);
  const replacementUrl = await replacementLink.locator('.mono').textContent();
  expect(replacementUrl).toContain('/accept-invite.html#token=');
  expect(replacementUrl).not.toBe(inviteUrl);

  await page.getByRole('tab', { name: 'Identity Setup' }).click();
  await expect(page.getByRole('heading', { name: 'Identity Setup' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Reviewer Groups' })).toBeVisible();

  await page.getByRole('button', { name: 'Licensing' }).click();
  await expect(page).toHaveURL(/\/app\/#\/licensing$/);
  await expect(page.getByRole('heading', { name: 'Licensing' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'License Users' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Renewal Request' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Install Signed License' })).toBeVisible();

  await page.goto(replacementUrl || '');
  await expect(page.getByRole('heading', { name: 'Set password' })).toBeVisible();
  await expect(page).toHaveURL(/\/accept-invite\.html$/);
  expect(page.url()).not.toContain('token=');
  await page.getByLabel('Display name').fill('E2E Accepted Auditor');
  await page.getByLabel('Password', { exact: true }).fill('Accepted-pass-2026');
  await page.getByLabel('Confirm password').fill('Accepted-pass-2026');
  await page.getByRole('button', { name: 'Accept invite' }).click();
  await expect(page.getByRole('heading', { name: 'Invite accepted' })).toBeVisible();
  await expect(page.locator('#acceptedUser')).toContainText(inviteEmail);

  const loginRequests = [];
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/login.html') loginRequests.push(request.url());
  });
  const loginHref = await page.locator('#loginLink').getAttribute('href');
  expect(loginHref).toContain('/login.html#user=');
  expect(loginHref).not.toContain('?user=');
  await page.locator('#loginLink').click();
  await expect(page).toHaveURL(/\/login\.html$/);
  await expect(page.locator('#user')).toHaveValue(inviteEmail);
  expect(loginRequests).toHaveLength(1);
  expect(loginRequests[0]).not.toContain(inviteEmail);
  expect(loginRequests[0]).not.toContain('user=');

  expect(problems).toEqual([]);
});

test('identity administration never renders API failures as zero-user posture', async ({ page }) => {
  await login(page);
  for (const endpoint of ['roles', 'users']) {
    await page.route(`**/api/admin/${endpoint}`, (route) => route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'temporarily_unavailable' }),
    }));
  }

  await page.goto('/app/#/identity');
  await expect(page.getByRole('heading', { name: 'Administration data unavailable' })).toBeVisible();
  await expect(page.getByText('RedactWall did not substitute zero users or unmetered seats.')).toBeVisible();
  await expect(page.getByText('Active Staff Users')).toHaveCount(0);
  await expect(page.getByText('License Seats')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible();
});

test('identity administration preserves its last verified snapshot on refresh failure', async ({ page }) => {
  await login(page);
  await page.goto('/app/#/identity');
  await expect(page.getByText('Active Staff Users')).toBeVisible();
  const before = await page.locator('.identity-summary').first().textContent();

  for (const endpoint of ['roles', 'users']) {
    await page.route(`**/api/admin/${endpoint}`, (route) => route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'temporarily_unavailable' }),
    }));
  }
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();

  await expect(page.getByRole('alert')).toContainText('Showing the last verified snapshot.');
  await expect(page.locator('.identity-summary').first()).toHaveText(before || '');
  await expect(page.getByRole('heading', { name: 'Staff Directory' })).toBeVisible();
});

for (const account of [
  { role: 'operator', user: 'e2e-operator', password: 'e2e-operator-pass' },
  { role: 'auditor', user: 'e2e-auditor', password: 'e2e-auditor-pass' },
]) {
  test(`${account.role} administration views are truthful and read-only`, async ({ page }) => {
    const problems = collectUiProblems(page);
    await loginAs(page, account.user, account.password);

    await page.goto('/app/#/identity');
    await expect(page.getByRole('heading', { name: 'Staff Directory' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Test configuration' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Create invite' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: /^(Disable|Reactivate|Resend|Revoke)$/ })).toHaveCount(0);
    await expect(page.getByRole('combobox', { name: /^Role for / })).toHaveCount(0);

    await page.goto('/app/#/licensing');
    await expect(page.getByRole('heading', { name: 'License Users' })).toBeVisible();
    await expect(page.getByRole('button', { name: /^(Release|Reassign|Request renewal|Install license)$/ })).toHaveCount(0);
    await expect(page.getByText('Global Administrator access is required to change licensing.')).toBeVisible();
    for (const navItem of ['Sensor Rollout', 'Evidence Delivery', 'Controlled Updates']) {
      if (account.role === 'operator') await expect(page.getByRole('button', { name: navItem })).toBeVisible();
      else await expect(page.getByRole('button', { name: navItem })).toHaveCount(0);
    }

    expect(problems).toEqual([]);
  });
}

test('overview leak exposure map renders the sanitized department graph', async ({ page, request }) => {
  const problems = collectUiProblems(page);
  const held = await createHeldPrompt(request, '9207');
  await login(page);

  await page.goto('/app/');
  await expect(page.locator('.leak-map-section')).toContainText('AI Exposure Map');
  await expect(page.locator('#leakMapSummary')).toContainText('prompt bodies excluded');
  await expect(page.locator('#leakMapStage svg')).toBeVisible();
  await expect(page.locator('#leakMapStage .leak-wall')).toBeVisible();
  await expect(page.locator('#leakMapStage')).toContainText('REDACTWALL');
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
  await expect(page.getByRole('heading', { name: 'Member Data Queue' })).toBeVisible();
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
  await expect(page.getByRole('heading', { name: 'Policy Configuration', exact: true })).toBeVisible();
  await expect(page.locator('.app-panel-meta').first()).not.toHaveText('Loading', { timeout: 10000 });

  await page.goto('/app/#/audit');
  await expect(page.getByRole('heading', { name: 'Examiner Audit Chain' })).toBeVisible();
  await expect(page.locator('.app-panel-meta').first()).not.toHaveText('Loading', { timeout: 10000 });

  expect(problems).toEqual([]);
});
