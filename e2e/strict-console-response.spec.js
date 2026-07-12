'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

const ISO = '2026-07-12T12:00:00.000Z';

async function fulfillJson(route, body, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function login(page) {
  await page.goto('/login.html');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

function licenseStatus(overrides = {}) {
  return {
    state: 'active',
    plan: 'standard',
    seats: 25,
    customer: 'Texas FCU',
    customerId: 'texas-fcu',
    features: ['ncua_readiness'],
    expires: '2099-01-01T00:00:00.000Z',
    graceEndsAt: '2099-01-31T00:00:00.000Z',
    daysRemaining: 26471,
    reason: null,
    ...overrides,
  };
}

function seatReport(overrides = {}) {
  return {
    license: licenseStatus(),
    tenantId: null,
    saasMode: false,
    seatLimit: 0,
    seatLimitValid: true,
    seatsUsed: 0,
    seatsRemaining: null,
    overLimit: false,
    assignedSeats: 0,
    releasedSeats: 0,
    users: [],
    ...overrides,
  };
}

test('topbar reports checking then unavailable without inventing a verified timestamp', async ({ page }) => {
  let postureRoute;
  let releaseRoute;
  const captured = new Promise((resolve) => { releaseRoute = resolve; });
  await page.route('**/api/posture?*', async (route) => {
    postureRoute = route;
    releaseRoute();
    await new Promise((resolve) => { postureRoute.release = resolve; });
  });

  await login(page);
  await captured;
  await expect(page.locator('#lastUpdated')).toHaveText('CHECKING');
  await postureRoute.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'unavailable' }) });
  postureRoute.release();
  await expect(page.locator('#lastUpdated')).toHaveText('UNAVAILABLE');
  await expect(page.locator('#lastUpdated')).not.toContainText('POSTURE VERIFIED');
});

test('HTTP 500 with {ok:true} never reports a delivered test email', async ({ page }) => {
  await page.route('**/api/notifications/test-email', (route) => fulfillJson(route, { ok: true }, 500));
  await login(page);
  await page.goto('/app/#/integrations');
  await expect(page.getByRole('heading', { name: 'Evidence Delivery', exact: true })).toBeVisible();
  await page.getByLabel('Test email recipient').fill('recipient@example.test');
  await page.getByRole('button', { name: 'Send test email', exact: true }).click();
  await expect(page.locator('.integrations-email-result')).toContainText('Failed:');
  await expect(page.locator('.integrations-email-result')).not.toContainText('Delivered');
});

test('truthy SOC receipt and incomplete SIEM package stay explicitly unavailable', async ({ page }) => {
  await page.route('**/api/integrations/siem/package**', (route) => fulfillJson(route, { summary: {} }));
  await page.route('**/api/posture/notify', (route) => fulfillJson(route, {
    sent: 'true',
    status: 204,
    posture: { generatedAt: ISO, score: 90, state: 'ready' },
  }));
  await login(page);
  await page.goto('/app/#/monitor');
  await expect(page.getByText(/Package error - unverified package/i).first()).toBeVisible();
  await page.getByRole('button', { name: /Evidence operations/ }).click();
  await expect(page.getByRole('button', { name: 'Download ZIP', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Send SOC snapshot', exact: true }).click();
  await expect(page.getByText('NOT SENT - UNVERIFIED RESPONSE', { exact: true })).toBeVisible();
  await expect(page.getByText('SENT TO SOC', { exact: true })).toHaveCount(0);
});

test('full segment state totals remain verified when the display matrix is bounded', async ({ page }) => {
  const posture = require('../server/posture');
  const rows = Array.from({ length: 20 }, (_, index) => ({
    id: `attention-segment-${index}`,
    createdAt: `2026-07-12T11:${String(index).padStart(2, '0')}:00.000Z`,
    status: 'allowed',
    user: `analyst-${index}@example.test`,
    orgId: `org-${index}`,
    destination: 'chatgpt.com',
    source: 'browser_extension',
    channel: 'submit',
    findings: [{ type: 'EMAIL', severity: 2, score: 0.9, masked: 'a***@example.test' }],
    riskScore: 50,
    maxSeverity: 2,
  }));
  const report = posture.summarize({
    rows,
    policy: {},
    auditIntegrity: { ok: true, count: rows.length },
    now: ISO,
    env: {},
  });
  expect(report.segments.summary.attention).toBeGreaterThan(report.segments.matrix.length);
  await page.route('**/api/posture?*', (route) => fulfillJson(route, report));

  await login(page);
  await page.goto('/app/#/monitor');
  const lens = page.getByLabel('Posture segment lens');
  await expect(lens).toContainText(`${report.segments.summary.attention} attention items`);
  await expect(lens).not.toContainText('Segment scope not reported');
});

test('malformed identity roles render unavailable without crashing or zero substitution', async ({ page }) => {
  await page.route('**/api/admin/roles', (route) => fulfillJson(route, { roles: [{}] }));
  await login(page);
  await page.goto('/app/#/identity');
  await expect(page.getByRole('heading', { name: 'Users & Roles', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Administration data unavailable', exact: true })).toBeVisible();
  await expect(page.getByText('Could not load users and roles', { exact: true })).toBeVisible();
});

test('unknown detector decision is shown as unverified and never green', async ({ page }) => {
  await page.route('**/api/detectors/test', (route) => fulfillJson(route, {
    decision: 'proceed',
    reasons: ['synthetic'],
    riskScore: 0,
    findings: [],
  }));
  await login(page);
  await page.goto('/app/#/policy');
  const input = page.getByLabel('Sample text to test');
  await expect(input).toBeVisible();
  await input.fill('Synthetic member SSN 123-45-6789');
  await page.getByRole('button', { name: 'Test detection', exact: true }).click();
  await expect(page.getByText('Test response could not be verified.', { exact: true })).toBeVisible();
  await expect(page.getByText('PROCEED', { exact: true })).toHaveCount(0);
});

test('malformed destination review preserves last verified coverage with an explicit warning', async ({ page }) => {
  const report = require('../server/coverage').summarize([], {});
  report.shadowDestinations = [{
    destination: 'shadow.example.test',
    policyState: 'review',
    events: 3,
    blocked: 0,
    redacted: 0,
    shadow: 3,
    users: 1,
    source: 'browser_extension',
    sources: ['browser_extension'],
    lastSeen: ISO,
    governed: false,
  }];
  await page.route('**/api/coverage', (route) => fulfillJson(route, report));
  await page.route('**/api/destinations/review', (route) => fulfillJson(route, {
    destination: 'shadow.example.test',
    decision: 'block',
    coverage: {},
  }));
  await login(page);
  await page.goto('/app/#/coverage');
  const shadow = page.locator('.shadow-row', { hasText: 'shadow.example.test' });
  await expect(shadow).toBeVisible();
  await shadow.getByRole('button', { name: 'Block', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Record destination reason' });
  await dialog.getByLabel('Admin reason').fill('Synthetic examiner review');
  await dialog.getByRole('button', { name: 'Save review', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Destination review response could not be verified. Showing the last verified coverage snapshot.');
  await expect(shadow).toBeVisible();
});

test('malformed license install and seats responses never clear input or invent seat posture', async ({ page }) => {
  const status = licenseStatus({ renewalRequests: [] });
  const seats = seatReport();
  await page.route('**/api/admin/license', (route) => fulfillJson(route, status));
  await page.route('**/api/admin/license/seats', (route) => fulfillJson(route, seats));
  await page.route('**/api/admin/license/install', (route) => fulfillJson(route, {}));
  await login(page);
  await page.goto('/app/#/licensing');
  await expect(page.getByRole('heading', { name: 'Licensing', exact: true })).toBeVisible();
  const payload = {
    customer: 'Texas FCU', customerId: 'texas-fcu', plan: 'standard', seats: 25,
    features: ['ncua_readiness'], expires: '2099-01-01T00:00:00.000Z',
  };
  const signed = `${Buffer.from(JSON.stringify(payload)).toString('base64')}.synthetic-signature`;
  const input = page.getByLabel('Signed license');
  await input.fill(signed);
  await page.getByRole('button', { name: 'Install license', exact: true }).click();
  await expect(page.getByText(/response could not be verified/i)).toBeVisible();
  await expect(input).toHaveValue(signed);
  await expect(page.getByText('Signed license installed', { exact: true })).toHaveCount(0);

  await page.unroute('**/api/admin/license/seats');
  await page.route('**/api/admin/license/seats', (route) => fulfillJson(route, { users: [{}] }));
  await page.reload();
  await expect(page.getByText('Licensing unavailable', { exact: true })).toBeVisible();
  await expect(page.getByText(/No seat totals were inferred/)).toBeVisible();
});
