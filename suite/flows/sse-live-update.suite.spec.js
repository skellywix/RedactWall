'use strict';
/**
 * Flow 13 - SSE live update. With the console open (no reload), an ingest gate
 * call that holds a prompt must push the pending count up over the EventSource
 * (/api/stream) and surface the new item in the live queue.
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

test('a held prompt pushed via ingest updates the queue without a page reload', async ({ page, request }) => {
  await loginAdmin(page);
  await page.locator('.rail .tab[data-tab="queue"]').click();
  await expect(page.locator('#tab-queue')).toBeVisible();

  // Capture the load count so we can prove no navigation happened.
  const navCounter = await page.evaluate(() => {
    window.__suiteNavs = (window.__suiteNavs || 0) + 1;
    return window.__suiteNavs;
  });

  const before = await page.locator('.q').count();

  const res = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: 'Synthetic SSE member SSN 524-71-6301 awaiting approval.',
      user: 'sse-analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    },
  });
  expect(res.ok()).toBeTruthy();
  const held = await res.json();
  expect(held.status).toBe('pending');

  // The SSE 'query' event drives loadQueue()/loadStats() with no reload.
  await expect(page.locator(`.q[data-id="${held.id}"]`)).toBeVisible({ timeout: 15000 });
  await expect(page.locator('#qBadge')).not.toHaveClass(/hidden/);
  await expect.poll(async () => page.locator('.q').count()).toBeGreaterThan(before);

  // Confirm the page was never navigated/reloaded during the update.
  const stillSame = await page.evaluate(() => window.__suiteNavs);
  expect(stillSame).toBe(navCounter);
});
