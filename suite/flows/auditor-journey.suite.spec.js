'use strict';
/**
 * Flow 12 - Auditor journey. An auditor logs in, lands on a read-only console
 * (no mutating controls), can still export the examiner evidence pack, and a
 * direct admin write from that same session is refused with 403.
 */
const fs = require('fs/promises');
const { test, expect } = require('@playwright/test');

test.setTimeout(60000);

const AUDITOR = { user: 'auditor@example.test', password: 'e2e-auditor-pass' };

async function seedHeld(request, suffix) {
  const res = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: `Synthetic auditor-journey SSN 524-71-${suffix} in a loan note.`,
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    },
  });
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body.status).toBe('pending');
  return body;
}

async function loginAuditor(page) {
  await page.goto('/login.html');
  await page.locator('#user').fill(AUDITOR.user);
  await page.locator('#password').fill(AUDITOR.password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/index\.html$/);
  await expect(page.locator('#who')).toContainText('Auditor');
}

test('auditor sees a read-only console, exports evidence, and is blocked from writes', async ({ page, request }) => {
  const held = await seedHeld(request, '6201');
  await loginAuditor(page);

  // Queue is read-only: no approve/deny controls, but the item is visible.
  await page.locator('.rail .tab[data-tab="queue"]').click();
  await expect(page.locator('#tab-queue')).toBeVisible();
  const queueItem = page.locator(`.q[data-id="${held.id}"]`);
  await expect(queueItem).toBeVisible();
  await expect(queueItem).toContainText('US_SSN');
  await expect(queueItem).not.toContainText('524-71-6201');
  await expect(queueItem.locator('[data-act="approve"]')).toHaveCount(0);
  await expect(queueItem.locator('[data-act="deny"]')).toHaveCount(0);
  await expect(queueItem).toContainText('Read-only auditor view');

  // Policy tab renders read-only (Save changes control absent).
  await page.locator('.rail .tab[data-tab="policy"]').click();
  await expect(page.locator('#tab-policy')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);
  await expect(page.locator('#tab-policy')).toContainText('Read-only auditor view');

  // Evidence export works for the auditor and carries no raw PII.
  await page.locator('.rail .tab[data-tab="audit"]').click();
  await expect(page.locator('#integrity')).toContainText('Chain verified');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export Evidence' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^promptwall-evidence-/);
  const pack = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
  expect(pack.auditIntegrity.ok).toBe(true);
  expect(JSON.stringify(pack)).not.toContain('524-71-6201');

  // A direct admin write from the auditor's own browser session returns 403.
  const denyStatus = await page.evaluate(async (id) => {
    const csrf = await (await fetch('/api/csrf')).json();
    const res = await fetch(`/api/queries/${id}/deny`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
      body: JSON.stringify({ note: 'auditor direct write attempt' }),
    });
    return res.status;
  }, held.id);
  expect(denyStatus).toBe(403);
});
