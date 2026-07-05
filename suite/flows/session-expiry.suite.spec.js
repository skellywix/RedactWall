'use strict';
/**
 * Flow 15 - Session expiry / CSRF surfaced. If the session cookie disappears
 * mid-session, the next authenticated action must land the user back on the
 * login page rather than crashing the console.
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

test('clearing the session cookie mid-session bounces the next action to login', async ({ page, context }) => {
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  await loginAdmin(page);
  await page.locator('.rail .tab[data-tab="activity"]').click();
  await expect(page.locator('#tab-activity')).toBeVisible();

  // Simulate an expired/cleared session by dropping cookies for this context.
  await context.clearCookies();

  // The next data-loading action calls api(), which on 401 redirects to login.
  // Switching to the coverage tab triggers loadCoverage() -> 401 -> redirect.
  await page.locator('.rail .tab[data-tab="coverage"]').click();

  await expect(page).toHaveURL(/\/login\.html$/, { timeout: 15000 });
  await expect(page.locator('#password')).toBeVisible();
  expect(pageErrors).toEqual([]);
});
