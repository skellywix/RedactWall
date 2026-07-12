'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
const SHOT_DIR = path.join(__dirname, 'design-evidence', 'states');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

test.setTimeout(90000);
test.beforeEach(() => fs.mkdirSync(SHOT_DIR, { recursive: true }));

async function loginAs(page, user, password) {
  await page.goto('/login.html');
  await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

function updateStatus(overrides = {}) {
  return {
    ok: true,
    inProgress: false,
    config: {
      remoteName: 'origin',
      branch: 'main',
      installMode: 'skip',
      restartCommand: 'systemctl restart redactwall',
      restartAfterUpdate: false,
      restartEnabled: true,
      restartCommandSource: 'config',
      configPath: 'synthetic-update-config.json',
      backupDir: 'synthetic-backups',
    },
    repo: {
      branch: 'main',
      head: '0123456789abcdef0123456789abcdef01234567',
      remoteUrl: 'https://github.com/example/redactwall.git',
      dirtyFiles: [],
    },
    safety: {
      backupDir: 'synthetic-backups',
      auditIntegrity: { ok: true, count: 12 },
      sourceTreeClean: true,
      configuredBranch: true,
      githubRemote: true,
    },
    lastRun: {
      status: 'updated',
      stage: 'complete',
      startedAt: '2026-07-11T12:00:00.000Z',
      completedAt: '2026-07-11T12:01:00.000Z',
      fromCommit: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      toCommit: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      restartRequired: true,
    },
    ...overrides,
  };
}

function requestBody(request) {
  if (!request.postData()) return null;
  try {
    return request.postDataJSON();
  } catch {
    return request.postData();
  }
}

function restartScheduledResponse(overrides = {}) {
  return {
    ok: true,
    scheduled: true,
    state: {
      status: 'restart-scheduled',
      restartRequired: true,
      restartScheduledAt: '2026-07-12T12:00:00.000Z',
      updatedAt: '2026-07-12T12:00:00.000Z',
      ...overrides,
    },
  };
}

async function fulfillJson(route, body, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function mockUpdateApi(page, calls, options = {}) {
  const baseStatus = options.statusBody ?? updateStatus();
  await page.route('**/api/update/**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const method = request.method();
    const body = requestBody(request);
    calls.push({ pathname, method, body });

    if (pathname === '/api/update/status') {
      return fulfillJson(route, baseStatus, options.statusCode ?? 200);
    }
    if (pathname === '/api/update/config') {
      return fulfillJson(route, updateStatus({ config: { ...baseStatus.config, ...body } }));
    }
    if (pathname === '/api/update/check') return fulfillJson(route, { ok: true, updateAvailable: false });
    if (pathname === '/api/update/apply') return fulfillJson(route, { ok: true, updated: false });
    if (pathname === '/api/update/restart') return fulfillJson(route, options.restartBody ?? restartScheduledResponse());
    return fulfillJson(route, { error: 'unexpected update route' }, 404);
  });
}

async function openUpdates(page) {
  await page.goto('/app/#/updates');
  await expect(page.getByRole('heading', { name: 'Controlled Updates', exact: true })).toBeVisible();
  await expect(page.locator('.app-loading')).toHaveCount(0);
}

test('operator server boundary allows status and action validation but rejects configuration', async ({ page }) => {
  await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
  const outcomes = await page.evaluate(async () => {
    const statusResponse = await fetch('/api/update/status');
    const csrfResponse = await fetch('/api/csrf');
    const { csrfToken } = await csrfResponse.json();
    const request = (path, body) => fetch(path, {
      method: path.endsWith('/config') ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
      body: JSON.stringify(body),
    });
    const configResponse = await request('/api/update/config', {
      remoteName: 'origin',
      branch: 'main',
      installMode: 'skip',
      restartCommand: '',
      restartAfterUpdate: false,
    });
    const applyResponse = await request('/api/update/apply', { confirmBackup: false });
    return {
      status: statusResponse.status,
      config: configResponse.status,
      configError: await configResponse.json(),
      apply: applyResponse.status,
    };
  });

  expect(outcomes.status).toBe(200);
  expect(outcomes.config).toBe(403);
  expect(outcomes.configError).toEqual({ error: 'forbidden' });
  expect(outcomes.apply).toBe(400);
});

test('operator can check, apply, and restart while configuration stays read-only', async ({ page }) => {
  const calls = [];
  await mockUpdateApi(page, calls);
  await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
  await openUpdates(page);

  await expect(page.getByTestId('update-config-permission')).toContainText('Current settings are read-only');
  for (const id of ['#updateRemoteName', '#updateBranch', '#updateInstallMode', '#updateRestartCommand', '#updateRestartAfter']) {
    await expect(page.locator(id)).toBeDisabled();
  }
  await expect(page.getByRole('button', { name: 'Save configuration', exact: true })).toBeDisabled();
  await page.screenshot({
    path: path.join(SHOT_DIR, 'updates-operator-readonly-permission.png'),
    fullPage: true,
    animations: 'disabled',
  });

  await page.getByRole('button', { name: 'Check GitHub', exact: true }).click();
  await expect.poll(() => calls.filter((call) => call.pathname === '/api/update/check').length).toBe(1);
  await expect(page.locator('.app-panel-meta')).toContainText('Current');

  await page.getByRole('button', { name: 'Update from GitHub', exact: true }).click();
  const applyDialog = page.getByRole('dialog', { name: 'Update from GitHub' });
  await expect(applyDialog).toBeVisible();
  await page.screenshot({
    path: path.join(SHOT_DIR, 'updates-destructive-confirmation.png'),
    fullPage: true,
    animations: 'disabled',
  });
  await applyDialog.getByRole('button', { name: 'Continue', exact: true }).click();
  await expect.poll(() => calls.filter((call) => call.pathname === '/api/update/apply').length).toBe(1);

  await page.getByRole('button', { name: 'Restart service', exact: true }).click();
  const restartDialog = page.getByRole('dialog', { name: 'Restart service' });
  await expect(restartDialog).toBeVisible();
  await restartDialog.getByRole('button', { name: 'Restart', exact: true }).click();
  await expect.poll(() => calls.filter((call) => call.pathname === '/api/update/restart').length).toBe(1);
  await expect(page.locator('.app-panel-meta')).toContainText('Restarting');

  expect(calls.filter((call) => call.pathname === '/api/update/config')).toEqual([]);
  expect(calls.find((call) => call.pathname === '/api/update/check')).toMatchObject({ method: 'POST', body: null });
  expect(calls.find((call) => call.pathname === '/api/update/apply')).toMatchObject({
    method: 'POST',
    body: { confirmBackup: true },
  });
  expect(calls.find((call) => call.pathname === '/api/update/restart')).toMatchObject({ method: 'POST', body: null });
});

test('operator sees an unverified restart receipt as failure and never as Restarting', async ({ page }) => {
  const calls = [];
  await mockUpdateApi(page, calls, { restartBody: { ...restartScheduledResponse(), scheduled: 'true' } });
  await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
  await openUpdates(page);

  await page.getByRole('button', { name: 'Restart service', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Restart service' });
  await dialog.getByRole('button', { name: 'Restart', exact: true }).click();

  await expect.poll(() => calls.filter((call) => call.pathname === '/api/update/restart').length).toBe(1);
  await expect(page.getByText('Restart response could not be verified. Check service status before retrying.', { exact: true })).toBeVisible();
  await expect(page.locator('.app-panel-meta')).not.toContainText('Restarting');
});

test('operator accepts the documented server-shaped restart receipt', async ({ page }) => {
  const calls = [];
  await mockUpdateApi(page, calls, { restartBody: restartScheduledResponse() });
  await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
  await openUpdates(page);

  await page.getByRole('button', { name: 'Restart service', exact: true }).click();
  await page.getByRole('dialog', { name: 'Restart service' }).getByRole('button', { name: 'Restart', exact: true }).click();

  await expect.poll(() => calls.filter((call) => call.pathname === '/api/update/restart').length).toBe(1);
  await expect(page.locator('.app-panel-meta')).toContainText('Restarting');
  await expect(page.getByText(/Restart response could not be verified/)).toHaveCount(0);
});

test('Security Admin retains mutable configuration and sends the documented payload', async ({ page }) => {
  const calls = [];
  await mockUpdateApi(page, calls);
  await loginAs(page, 'admin', 'e2e-pass');
  await openUpdates(page);

  await expect(page.getByTestId('update-config-permission')).toHaveCount(0);
  await page.locator('#updateRemoteName').fill('upstream');
  await page.locator('#updateBranch').fill('release-2026');
  await page.locator('#updateInstallMode').selectOption('npm-ci');
  await page.locator('#updateRestartCommand').fill('systemctl restart redactwall');
  await page.locator('#updateRestartAfter').check();
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();

  await expect.poll(() => calls.filter((call) => call.pathname === '/api/update/config').length).toBe(1);
  await expect(page.getByRole('status', { name: 'Update configuration status' })).toHaveText('Saved');
  expect(calls.find((call) => call.pathname === '/api/update/config')).toEqual({
    pathname: '/api/update/config',
    method: 'PUT',
    body: {
      remoteName: 'upstream',
      branch: 'release-2026',
      installMode: 'npm-ci',
      restartCommand: 'systemctl restart redactwall',
      restartAfterUpdate: true,
    },
  });
});

for (const scenario of [
  {
    name: 'malformed',
    statusCode: 200,
    statusBody: { ...updateStatus(), config: { ...updateStatus().config, branch: { invalid: true } } },
    message: 'Update status unavailable.',
  },
  {
    name: 'unavailable',
    statusCode: 503,
    statusBody: { error: 'Update service temporarily unavailable.' },
    message: 'Update service temporarily unavailable.',
  },
]) {
  test(`operator sees an explicit ${scenario.name} state instead of invented update readiness`, async ({ page }) => {
    const calls = [];
    await mockUpdateApi(page, calls, scenario);
    await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
    await openUpdates(page);

    await expect(page.locator('.app-panel-meta')).toContainText('Unavailable');
    await expect(page.locator('.readonly-note')).toHaveText(scenario.message);
    await expect(page.getByRole('heading', { name: 'GitHub Update', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Check GitHub', exact: true })).toHaveCount(0);
    expect(calls.filter((call) => call.pathname === '/api/update/status')).toHaveLength(1);
  });
}
