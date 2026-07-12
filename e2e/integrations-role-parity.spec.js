'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

async function loginAs(page, user, password) {
  await page.goto('/login.html');
  await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function deliveryEndpointStatuses(page) {
  return page.evaluate(async () => {
    const csrf = await fetch('/api/csrf').then((response) => response.json());
    const call = async (url, options) => {
      const response = await fetch(url, options);
      await response.arrayBuffer();
      return response.status;
    };
    return {
      subscriptions: await call('/api/subscriptions'),
      deliveries: await call('/api/subscriptions/deliveries'),
      subscriptionTest: await call('/api/subscriptions/__role_parity_missing__/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
        body: '{}',
      }),
      notifications: await call('/api/notifications/status'),
      digest: await call('/api/reports/digest/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
        body: '{}',
      }),
      email: await call('/api/notifications/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
        body: JSON.stringify({ to: 'role-parity@example.test' }),
      }),
    };
  });
}

test('operator keeps evidence-route operations without requesting admin notification data', async ({ page }) => {
  await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
  const adminRequests = [];
  page.on('request', (request) => {
    const pathname = new URL(request.url()).pathname;
    if (pathname === '/api/notifications/status' || pathname === '/api/reports/digest/send' || pathname === '/api/notifications/test-email') {
      adminRequests.push(`${request.method()} ${pathname}`);
    }
  });
  const deliveriesLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/subscriptions/deliveries');
  await page.goto('/app/#/integrations');
  await deliveriesLoaded;

  await expect(page.getByRole('heading', { name: 'Evidence Delivery', exact: true })).toBeVisible();
  await expect(page.getByText('Security Admin access required', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Send digest now' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Send test email' })).toHaveCount(0);
  expect(adminRequests).toEqual([]);

  expect(await deliveryEndpointStatuses(page)).toEqual({
    subscriptions: 200,
    deliveries: 200,
    subscriptionTest: 404,
    notifications: 403,
    digest: 403,
    email: 403,
  });
});

test('Security Admin sees notification status and controls while failed delivery reads stay unknown', async ({ page }) => {
  await loginAs(page, 'admin', 'e2e-pass');
  let deliveryReadsFail = false;
  await page.route('**/api/subscriptions', (route) => route.fulfill({
    status: deliveryReadsFail ? 503 : 200,
    contentType: 'application/json',
    body: deliveryReadsFail
      ? '{"error":"unavailable"}'
      : JSON.stringify({
        destinations: [{
          id: 'synthetic-siem', name: 'Synthetic SIEM', type: 'splunk', minRisk: 0, minSeverity: 0,
          eventTypes: null, urlHost: 'siem.example.test',
        }],
        supportedTypes: ['splunk'],
      }),
  }));
  await page.route('**/api/subscriptions/deliveries', (route) => route.fulfill({
    status: deliveryReadsFail ? 503 : 200,
    contentType: 'application/json',
    body: deliveryReadsFail
      ? '{"error":"unavailable"}'
      : JSON.stringify({
        deliveries: [{
          id: 'delivery-1', ts: '2026-07-11T12:00:00.000Z', destId: 'synthetic-siem',
          destName: 'Synthetic SIEM', type: 'splunk', status: 'delivered', attempts: 1, httpStatus: 200,
        }],
      }),
  }));
  const notificationLoaded = page.waitForResponse((response) => new URL(response.url()).pathname === '/api/notifications/status');
  await page.goto('/app/#/integrations');
  await notificationLoaded;
  await expect(page.getByRole('button', { name: 'Send digest now' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Send test email' })).toBeVisible();
  await expect(page.getByText('Security Admin access required', { exact: true })).toHaveCount(0);

  deliveryReadsFail = true;
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect(page.getByText('Showing last verified evidence routes after refresh failed.')).toBeVisible();
  await expect(page.getByText('Showing last verified delivery history after refresh failed.')).toBeVisible();
  await expect(page.getByText('No subscriptions configured.')).toHaveCount(0);
  await expect(page.getByText('No deliveries yet.')).toHaveCount(0);
});

test('an older refresh cannot relabel the latest failed read as current', async ({ page }) => {
  await loginAs(page, 'admin', 'e2e-pass');
  let subscriptionCalls = 0;
  let deliveryCalls = 0;
  let releaseOlder = () => {};
  const olderGate = new Promise((resolve) => { releaseOlder = resolve; });

  await page.route('**/api/subscriptions', async (route) => {
    const sequence = ++subscriptionCalls;
    if (sequence === 2) await olderGate;
    const malformed = sequence >= 3;
    await route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/json', 'x-refresh-sequence': sequence === 2 ? 'older' : sequence >= 3 ? 'latest' : 'initial' },
      body: JSON.stringify({
        destinations: [{
          id: 'race-siem', name: sequence === 2 ? 'Older SIEM' : 'Initial SIEM', type: 'splunk',
          minRisk: malformed ? 'zero' : 0, minSeverity: 0, eventTypes: null, urlHost: 'siem.example.test',
        }],
        supportedTypes: ['splunk'],
      }),
    });
  });
  await page.route('**/api/subscriptions/deliveries', async (route) => {
    const sequence = ++deliveryCalls;
    if (sequence === 2) await olderGate;
    const malformed = sequence >= 3;
    await route.fulfill({
      status: 200,
      headers: { 'content-type': 'application/json', 'x-refresh-sequence': sequence === 2 ? 'older' : sequence >= 3 ? 'latest' : 'initial' },
      body: JSON.stringify({
        deliveries: [{
          id: 'race-delivery', ts: '2026-07-11T12:00:00.000Z', destId: 'race-siem', destName: 'Initial SIEM',
          type: 'splunk', status: malformed ? { value: 'delivered' } : 'delivered', attempts: 1, httpStatus: 200,
        }],
      }),
    });
  });
  await page.route('**/api/notifications/status', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      smtp: { configured: false, host: null, port: null, secure: 'starttls', from: null, authConfigured: false },
      emailDestinations: [],
      digest: { intervalHours: 24, last: null },
    }),
  }));

  await page.goto('/app/#/integrations');
  await expect(page.locator('.sub-row').getByText('Initial SIEM', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect.poll(() => Promise.all([subscriptionCalls, deliveryCalls])).toEqual([2, 2]);

  const latestResponses = Promise.all([
    page.waitForResponse((response) => new URL(response.url()).pathname === '/api/subscriptions'
      && response.headers()['x-refresh-sequence'] === 'latest'),
    page.waitForResponse((response) => new URL(response.url()).pathname === '/api/subscriptions/deliveries'
      && response.headers()['x-refresh-sequence'] === 'latest'),
  ]);
  await page.getByRole('button', { name: 'Refresh' }).click();
  await latestResponses;
  await expect(page.getByText('Showing last verified evidence routes after refresh failed.')).toBeVisible();

  const olderResponses = Promise.all([
    page.waitForResponse((response) => new URL(response.url()).pathname === '/api/subscriptions'
      && response.headers()['x-refresh-sequence'] === 'older'),
    page.waitForResponse((response) => new URL(response.url()).pathname === '/api/subscriptions/deliveries'
      && response.headers()['x-refresh-sequence'] === 'older'),
  ]);
  releaseOlder();
  await olderResponses;
  await expect(page.getByText('Showing last verified evidence routes after refresh failed.')).toBeVisible();
  await expect(page.locator('.sub-row').getByText('Initial SIEM', { exact: true })).toBeVisible();
  await expect(page.getByText('Older SIEM', { exact: true })).toHaveCount(0);
});

test('nested and mutation payloads must be verified before the console claims delivery', async ({ page }) => {
  await loginAs(page, 'admin', 'e2e-pass');
  let malformedReads = false;
  const validDestination = {
    id: 'synthetic-siem', name: 'Synthetic SIEM', type: 'splunk', minRisk: 0, minSeverity: 0,
    eventTypes: null, urlHost: 'siem.example.test',
  };
  const validDelivery = {
    id: 'delivery-1', ts: '2026-07-11T12:00:00.000Z', destId: 'synthetic-siem',
    destName: 'Synthetic SIEM', type: 'splunk', status: 'delivered', attempts: 1, httpStatus: 200,
  };

  await page.route('**/api/subscriptions', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      destinations: [{ ...validDestination, ...(malformedReads ? { minRisk: 'zero' } : {}) }],
      supportedTypes: ['splunk'],
    }),
  }));
  await page.route('**/api/subscriptions/deliveries', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      deliveries: [{ ...validDelivery, ...(malformedReads ? { status: { value: 'delivered' } } : {}) }],
    }),
  }));
  await page.route('**/api/notifications/status', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      smtp: {
        configured: false,
        host: malformedReads ? 'smtp.inconsistent.example.test' : null,
        port: null,
        secure: 'starttls',
        from: null,
        authConfigured: false,
      },
      emailDestinations: [],
      digest: { intervalHours: 24, last: null },
    }),
  }));
  await page.route('**/api/subscriptions/*/test', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ result: { destId: 'synthetic-siem', status: 'delivered' } }),
  }));
  await page.route('**/api/notifications/test-email', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ ok: true, error: 'smtp_error' }),
  }));
  await page.route('**/api/reports/digest/send', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ results: [{ status: { value: 'delivered' } }] }),
  }));

  await page.goto('/app/#/integrations');
  await expect(page.locator('.sub-row').getByText('Synthetic SIEM', { exact: true })).toBeVisible();

  await page.getByRole('button', { name: 'Send test', exact: true }).click();
  await expect(page.locator('.sub-test-result')).toContainText('Last test: unavailable');
  await expect(page.locator('.sub-test-result')).not.toContainText('Last test: delivered');

  await page.getByLabel('Test email recipient').fill('verified-result@example.test');
  await page.getByRole('button', { name: 'Send test email' }).click();
  await expect(page.locator('.integrations-email-result')).toContainText('Result unavailable');
  await expect(page.locator('#toastStack')).toContainText('response could not be verified');
  await expect(page.locator('#toastStack')).not.toContainText('Test email delivered');

  await page.getByRole('button', { name: 'Send digest now' }).click();
  await expect(page.locator('#toastStack')).toContainText('Digest response could not be verified');
  await expect(page.locator('#toastStack')).not.toContainText('Digest dispatch verified');

  malformedReads = true;
  await page.getByRole('button', { name: 'Refresh' }).click();
  await expect(page.getByText('Showing last verified evidence routes after refresh failed.')).toBeVisible();
  await expect(page.getByText('Showing last verified delivery history after refresh failed.')).toBeVisible();
  await expect(page.getByText('Showing the last verified notification snapshot after refresh failed.')).toBeVisible();
  await expect(page.getByText('No subscriptions configured.')).toHaveCount(0);
  await expect(page.getByText('No deliveries yet.')).toHaveCount(0);
});
