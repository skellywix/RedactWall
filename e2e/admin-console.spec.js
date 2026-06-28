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

  await login(page);

  const queueItem = page.locator(`.q[data-id="${gated.id}"]`);
  await expect(queueItem).toBeVisible();
  await expect(queueItem).toContainText('US_SSN');
  await expect(queueItem).not.toContainText('524-71-9043');

  await page.locator(`#note_${gated.id}`).fill('Synthetic approval for browser E2E');
  await page.getByRole('button', { name: 'Approve release' }).click();
  await expect(page.getByRole('heading', { name: 'Confirm release' })).toBeVisible();
  await page.getByLabel('Admin password').fill('e2e-pass');
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

  await page.locator('.content-tabs .tab[data-tab="policy"]').click();
  await page.locator('input[name="mode"][value="warn"]').check();
  await page.locator('#pol_risk').fill('35');
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect(page.locator('#polSaved')).toHaveText('Saved');
  const policy = await page.evaluate(async () => (await fetch('/api/policy')).json());
  expect(policy.enforcementMode).toBe('warn');
  expect(policy.blockRiskScore).toBe(35);

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
