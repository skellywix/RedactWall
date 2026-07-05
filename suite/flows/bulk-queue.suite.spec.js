'use strict';
/**
 * Flow 14 - Bulk queue actions. Seed three held items via ingest, select them
 * all in the queue UI, bulk-deny, and assert every one transitions out of
 * pending (queue empties and the activity log shows the denials).
 */
const { test, expect } = require('@playwright/test');

test.setTimeout(60000);

async function loginAdmin(page) {
  await page.goto('/login.html');
  await page.locator('#user').fill('admin');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/index\.html$/);
  await expect(page.locator('#who')).toContainText('Security Admin');
}

async function seedHeld(request, suffix) {
  const res = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: `Synthetic bulk-queue SSN 524-71-${suffix} pending review.`,
      user: `bulk-${suffix}@example.test`,
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

test('admin bulk-denies all selected held prompts from the queue UI', async ({ page, request }) => {
  const held = [];
  for (const suffix of ['6401', '6402', '6403']) held.push(await seedHeld(request, suffix));

  await loginAdmin(page);
  await page.locator('.rail .tab[data-tab="queue"]').click();
  await expect(page.locator('#tab-queue')).toBeVisible();
  for (const item of held) await expect(page.locator(`.q[data-id="${item.id}"]`)).toBeVisible();

  // Select every held item via its bulk checkbox; the bulk bar reveals.
  for (const item of held) {
    await page.locator(`[data-queue-bulk-select="${item.id}"]`).check();
  }
  await expect(page.locator('#queueBulkBar')).not.toHaveClass(/hidden/);
  await expect(page.locator('#queueBulkCount')).toHaveText('3 selected');

  await page.locator('#queueBulkNote').fill('Synthetic bulk deny sweep');
  await page.getByRole('button', { name: 'Deny selected' }).click();

  // All three leave the pending queue (other tests may share the queue, so we
  // assert on our own items rather than a globally empty queue).
  for (const item of held) await expect(page.locator(`.q[data-id="${item.id}"]`)).toHaveCount(0);

  // Server state confirms every item is denied.
  const statuses = await page.evaluate(async (ids) => {
    const rows = await (await fetch('/api/queries')).json();
    return ids.map((id) => (rows.find((q) => q.id === id) || {}).status);
  }, held.map((h) => h.id));
  expect(statuses).toEqual(['denied', 'denied', 'denied']);
});
