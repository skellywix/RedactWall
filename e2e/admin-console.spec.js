'use strict';

const fs = require('fs/promises');
const { test, expect } = require('@playwright/test');

async function login(page) {
  await page.goto('/login.html');
  await expect(page.getByRole('heading', { name: 'PromptWall' })).toBeVisible();
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/index\.html$/);
  await expect(page.locator('#who')).toContainText('admin / Security Admin');
}

test('admin console login, approval, policy save, and evidence export work in a browser', async ({ page, request }) => {
  const gateResponse = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: 'Member SSN 524-71-9043 is in this synthetic loan note.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    },
  });
  expect(gateResponse.ok()).toBeTruthy();
  const gated = await gateResponse.json();
  expect(gated.status).toBe('pending');

  const shadowResponse = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: '[shadow-AI] visit to ungoverned AI tool: notebooklm.google.com',
      user: 'analyst@example.test',
      destination: 'notebooklm.google.com',
      source: 'browser_extension',
      channel: 'shadow_ai',
      clientOutcome: 'shadow_ai',
    },
  });
  expect(shadowResponse.ok()).toBeTruthy();

  const heartbeatResponse = await request.post('/api/v1/heartbeat', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      user: 'analyst@example.test',
      orgId: 'cu-acme',
      destination: 'browser-install',
      source: 'browser_extension',
      sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
      checks: [
        { id: 'managed_config', ok: true, detail: 'configured' },
        { id: 'managed_identity', ok: true, detail: 'present' },
      ],
    },
  });
  expect(heartbeatResponse.ok()).toBeTruthy();

  await login(page);

  const queueItem = page.locator(`.q[data-id="${gated.id}"]`);
  await expect(queueItem).toBeVisible();
  await expect(queueItem).toContainText('US_SSN');
  await expect(queueItem).not.toContainText('524-71-9043');

  await page.locator(`#note_${gated.id}`).fill('Synthetic approval for browser E2E');
  await page.getByRole('button', { name: 'Approve release' }).click();
  await expect(page.getByRole('heading', { name: 'Confirm release' })).toBeVisible();
  await page.getByLabel('Account password').fill('e2e-pass');
  await page.locator('.stepup-dialog').getByRole('button', { name: 'Approve release' }).click();
  await expect(page.locator('#queueList')).toContainText('Queue clear');

  await page.locator('.content-tabs .tab[data-tab="activity"]').click();
  await expect(page.locator('#activityRows')).toContainText('approved');
  await expect(page.locator('#activityRows')).toContainText('analyst@example.test');
  await page.locator('#globalSearch').fill('analyst@example.test');
  await expect(page.locator('#activityRows')).toContainText('approved');
  await page.locator('#globalSearch').fill('no-such-user');
  await expect(page.locator('#activityRows')).toContainText('No matching activity');
  await page.locator('#globalSearch').fill('');

  await page.locator('.content-tabs .tab[data-tab="coverage"]').click();
  await expect(page.locator('#tab-coverage')).toBeVisible();
  await expect(page.locator('#coverageScore')).toContainText('Coverage score');
  await expect(page.locator('#shadowRows')).toContainText('notebooklm.google.com');
  await expect(page.locator('#sensorMix')).toContainText('Browser extension');
  await expect(page.locator('#fleetRows')).toContainText('analyst@example.test');
  await expect(page.locator('#fleetRows')).toContainText('cu-acme');
  await expect(page.locator('#fleetRows')).toContainText('covered');
  await expect(page.locator('#fleetRows')).toContainText('checks ok');

  await page.locator('.content-tabs .tab[data-tab="identity"]').click();
  await expect(page.locator('#tab-identity')).toBeVisible();
  await expect(page.locator('#identityScimRows')).toContainText('/scim/v2');
  await page.locator('#identityTenant').fill('contoso.onmicrosoft.com');
  await page.locator('#refreshIdentity').click();
  await expect(page.locator('#identityOidcRows')).toContainText('login.microsoftonline.com/contoso.onmicrosoft.com/v2.0');
  await page.locator('#identityProvider').selectOption('okta');
  await page.locator('#identityTenant').fill('customer.okta.com');
  await page.locator('#refreshIdentity').click();
  await expect(page.locator('#identityOidcRows')).toContainText('customer.okta.com/oauth2/default');
  await expect(page.locator('#identityEnvRows')).toContainText('OIDC_CLIENT_SECRET');
  await expect(page.locator('body')).not.toContainText('e2e-ingest-key');

  await page.locator('.content-tabs .tab[data-tab="policy"]').click();
  await expect(page.locator('#pol_desktop_destination')).toBeVisible();
  await page.locator('input[name="mode"][value="warn"]').check();
  await page.locator('#pol_risk').fill('35');
  await page.locator('#pol_desktop_destination').fill('Copilot Desktop');
  await page.locator('#pol_policy_scopes').fill(JSON.stringify([{
    id: 'legal_contract_review',
    groups: ['PromptWall Legal'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    enforcementMode: 'block',
    blockMinSeverity: 2,
  }], null, 2));
  await page.locator('#pol_policy_exceptions').fill(JSON.stringify([{
    id: 'legal_vendor_24h',
    users: ['counsel@example.test'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    expiresAt: '2030-01-01T00:00:00.000Z',
  }], null, 2));
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.locator('#polSaved')).toHaveText('Saved');
  const policy = await page.evaluate(async () => (await fetch('/api/policy')).json());
  expect(policy.enforcementMode).toBe('warn');
  expect(policy.blockRiskScore).toBe(35);
  expect(policy.desktopCollectorDestination).toBe('Copilot Desktop');
  expect(policy.policyScopes[0]).toMatchObject({
    id: 'legal_contract_review',
    groups: ['promptwall legal'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    enforcementMode: 'block',
    blockMinSeverity: 2,
  });
  expect(policy.policyExceptions[0]).toMatchObject({
    id: 'legal_vendor_24h',
    users: ['counsel@example.test'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    expiresAt: '2030-01-01T00:00:00.000Z',
  });

  await page.locator('.content-tabs .tab[data-tab="audit"]').click();
  await expect(page.locator('#integrity')).toContainText('Chain verified');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export Evidence' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^promptwall-evidence-/);
  const exportedPath = await download.path();
  const pack = JSON.parse(await fs.readFile(exportedPath, 'utf8'));
  expect(pack.auditIntegrity.ok).toBe(true);
  expect(JSON.stringify(pack)).not.toContain('524-71-9043');
  expect(pack.stats.approved).toBeGreaterThanOrEqual(1);
});

test('admin console mobile layout keeps content tabs usable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);

  await expect(page.locator('.content-tabs .tab[data-tab="queue"]')).toBeVisible();
  const railTabsDisplay = await page.locator('.rail .tabs').evaluate((el) => getComputedStyle(el).display);
  expect(railTabsDisplay).toBe('none');

  await page.locator('.content-tabs .tab[data-tab="policy"]').click();
  await expect(page.locator('#tab-policy')).toBeVisible();
  await page.locator('.content-tabs .tab[data-tab="audit"]').click();
  await expect(page.locator('#tab-audit')).toBeVisible();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});
