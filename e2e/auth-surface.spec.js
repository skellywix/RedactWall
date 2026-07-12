'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const SHOT_DIR = path.join(__dirname, 'design-evidence');

test.beforeEach(() => {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
});

async function expectNoPageOverflow(page) {
  const size = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(size.scrollWidth).toBe(size.clientWidth);
}

test('sign-in surface is focused, responsive, and uses the shared instrument styling', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/login.html');

  await expect(page.locator('body')).toHaveAttribute('data-theme', 'dark');
  await expect(page.getByRole('heading', { name: 'RedactWall' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(page.getByLabel('Username')).toHaveValue('admin');
  await expect(page.getByLabel('Password')).toBeFocused();
  await expect(page.getByLabel('Authenticator or recovery code')).toHaveAttribute('maxlength', '11');
  await expect(page.getByRole('button', { name: 'Continue' })).toBeVisible();
  await expectNoPageOverflow(page);
  await page.screenshot({ path: path.join(SHOT_DIR, 'auth-sign-in-mobile-390x844.png'), fullPage: true });

  await page.setViewportSize({ width: 1440, height: 900 });
  await expectNoPageOverflow(page);
  await page.screenshot({ path: path.join(SHOT_DIR, 'auth-sign-in-desktop-1440x900.png'), fullPage: true });
});

test('sign-in keyboard submission exposes an accessible error and permits a corrected retry', async ({ page }) => {
  const attempts = [];
  await page.route('**/api/login-options', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ oidc: { enabled: false }, defaultAdminCredential: false }),
  }));
  await page.route('**/api/login', async (route) => {
    const body = route.request().postDataJSON();
    attempts.push(body);
    if (body.password === 'Corrected-passphrase') {
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'invalid credentials' }),
    });
  });
  await page.route('**/app/', (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: '<!doctype html><title>Authenticated test destination</title><h1>Authenticated</h1>',
  }));

  await page.goto('/login.html');
  const password = page.getByLabel('Password');
  await expect(password).toBeFocused();
  await password.fill('Wrong-passphrase');
  await password.press('Enter');

  const alert = page.getByRole('alert');
  await expect(alert).toHaveText('Invalid credentials. Try again.');
  await expect(page.getByLabel('Username')).toHaveAttribute('aria-invalid', 'true');
  await expect(password).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByLabel('Username')).toBeFocused();
  await page.screenshot({ path: path.join(SHOT_DIR, 'auth-invalid-credentials-desktop.png'), fullPage: true });

  await password.fill('Corrected-passphrase');
  await password.press('Enter');
  await expect(page).toHaveURL(/\/app\/$/);
  await expect(page.getByRole('heading', { name: 'Authenticated' })).toBeVisible();
  expect(attempts.map((attempt) => attempt.password)).toEqual(['Wrong-passphrase', 'Corrected-passphrase']);
});

test('MFA prompt accepts a recovery code and focuses the combined code field', async ({ page }) => {
  const attempts = [];
  await page.route('**/api/login-options', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ oidc: { enabled: false }, defaultAdminCredential: false }),
  }));
  await page.route('**/api/login', async (route) => {
    const body = route.request().postDataJSON();
    attempts.push(body);
    if (body.otp === 'ABCDE-12345') {
      await route.fulfill({ status: 204 });
      return;
    }
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'invalid mfa code', mfaRequired: true }),
    });
  });
  await page.route('**/app/', (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: '<!doctype html><title>MFA complete</title><h1>MFA complete</h1>',
  }));

  await page.goto('/login.html');
  await page.getByLabel('Password').fill('Synthetic-passphrase');
  await page.getByLabel('Password').press('Enter');

  const code = page.getByLabel('Authenticator or recovery code');
  await expect(page.getByRole('alert')).toHaveText('Enter your current authenticator or recovery code.');
  await expect(code).toHaveAttribute('aria-invalid', 'true');
  await expect(code).toBeFocused();
  await code.fill('ABCDE-12345');
  await code.press('Enter');

  await expect(page).toHaveURL(/\/app\/$/);
  expect(attempts.at(-1).otp).toBe('ABCDE-12345');
});

test('sign-in suppresses duplicate credential submissions while one attempt is pending', async ({ page }) => {
  let releaseLogin;
  const loginGate = new Promise((resolve) => { releaseLogin = resolve; });
  let loginRequests = 0;
  await page.route('**/api/login-options', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ oidc: { enabled: false }, defaultAdminCredential: false }),
  }));
  await page.route('**/api/login', async (route) => {
    loginRequests += 1;
    await loginGate;
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'invalid credentials' }),
    });
  });

  try {
    await page.goto('/login.html');
    const password = page.getByLabel('Password');
    const submit = page.getByRole('button', { name: 'Continue', exact: true });
    await password.fill('Synthetic-pending-passphrase');
    await submit.click();
    await expect(submit).toBeDisabled();
    await expect(page.locator('#f')).toHaveAttribute('aria-busy', 'true');
    await password.press('Enter');
    await password.press('Enter');
    await expect.poll(() => loginRequests).toBe(1);

    releaseLogin();
    await expect(page.getByRole('alert')).toHaveText('Invalid credentials. Try again.');
    await expect(submit).toBeEnabled();
    await expect(page.locator('#f')).not.toHaveAttribute('aria-busy', 'true');
  } finally {
    releaseLogin();
  }
});

test('invitation surface removes its token fragment before credential entry and reflows on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 });
  await page.goto('/accept-invite.html#token=synthetic-invite-token');

  await expect(page).toHaveURL(/\/accept-invite\.html$/);
  await expect(page.getByRole('heading', { name: 'Set up your account' })).toBeVisible();
  await expect(page.getByLabel('Display name')).toBeVisible();
  await expect(page.getByLabel('Password', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Confirm password')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Accept invite' })).toBeVisible();
  await expectNoPageOverflow(page);
  await page.screenshot({ path: path.join(SHOT_DIR, 'auth-invite-mobile-320x568.png'), fullPage: true });
});

test('invitation errors are explicit for missing, weak, mismatched, and expired credentials', async ({ page }) => {
  await page.goto('/accept-invite.html');
  await expect(page.getByRole('button', { name: 'Accept invite' })).toBeDisabled();
  await expect(page.getByRole('alert')).toHaveText(/missing a token/i);
  await page.screenshot({ path: path.join(SHOT_DIR, 'auth-invite-missing-token.png'), fullPage: true });

  await page.route('**/api/invitations/accept', (route) => route.fulfill({
    status: 410,
    contentType: 'application/json',
    body: JSON.stringify({ error: 'invalid_or_expired_invitation' }),
  }));
  // A fragment-only navigation reuses the missing-token document and its
  // disabled submit state. Force a new document while preserving the product's
  // fragment-only bearer-token contract; the page strips both immediately.
  await page.goto('/accept-invite.html?scenario=expired#token=expired-synthetic-token');

  const password = page.getByLabel('Password', { exact: true });
  const confirm = page.getByLabel('Confirm password');
  await password.fill('too-short');
  await confirm.fill('too-short');
  await page.getByRole('button', { name: 'Accept invite' }).click();
  await expect(page.getByRole('alert')).toHaveText('Password must be at least 12 characters.');
  await expect(password).toHaveAttribute('aria-invalid', 'true');
  await expect(password).toBeFocused();

  await password.fill('Valid-passphrase-2026');
  await confirm.fill('Different-passphrase');
  await page.getByRole('button', { name: 'Accept invite' }).click();
  await expect(page.getByRole('alert')).toHaveText('Passwords do not match.');
  await expect(confirm).toHaveAttribute('aria-invalid', 'true');
  await expect(confirm).toBeFocused();

  await confirm.fill('Valid-passphrase-2026');
  await page.getByRole('button', { name: 'Accept invite' }).click();
  await expect(page.getByRole('alert')).toHaveText('Invite is invalid, expired, already used, or revoked.');
  await page.screenshot({ path: path.join(SHOT_DIR, 'auth-invite-expired-token.png'), fullPage: true });
});

test('verified invitation success shows the assigned account without retaining the token', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/api/invitations/accept', async (route) => {
    expect(route.request().postDataJSON()).toEqual({
      token: 'valid-synthetic-token',
      password: 'Valid-passphrase-2026',
      displayName: 'Synthetic Auditor',
    });
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ user: 'synthetic-auditor', role: 'auditor', roleLabel: 'FCU Auditor' }),
    });
  });

  await page.goto('/accept-invite.html#token=valid-synthetic-token');
  await expect(page).toHaveURL(/\/accept-invite\.html$/);
  await page.getByLabel('Display name').fill('Synthetic Auditor');
  await page.getByLabel('Password', { exact: true }).fill('Valid-passphrase-2026');
  await page.getByLabel('Confirm password').fill('Valid-passphrase-2026');
  await page.getByRole('button', { name: 'Accept invite' }).click();

  await expect(page.getByRole('heading', { name: 'Invite accepted' })).toBeVisible();
  await expect(page.getByText('synthetic-auditor is ready as FCU Auditor.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/login.html#user=synthetic-auditor');
  await page.screenshot({ path: path.join(SHOT_DIR, 'auth-invite-success-mobile-390x844.png'), fullPage: true });
});
