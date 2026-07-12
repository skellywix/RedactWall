'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

const ADMIN_USER = 'admin';
const ADMIN_PASSWORD = 'e2e-pass';
const PROOF_DESTINATION = 'e2e-policy-mutation.invalid';

function requireIsolatedPlaywrightServer(baseURL) {
  if (!baseURL) throw new Error('policy mutation proof requires the Playwright base URL');
  const port = Number(process.env.PLAYWRIGHT_PORT || 4210);
  const expectedOrigin = `http://127.0.0.1:${port}`;
  const actual = new URL(baseURL);
  if (actual.origin !== expectedOrigin || actual.pathname !== '/' || actual.search || actual.hash) {
    throw new Error(`refusing policy mutation outside the isolated Playwright server at ${expectedOrigin}`);
  }
}

async function responseJson(response, description) {
  expect(response.ok(), `${description}: HTTP ${response.status()}`).toBeTruthy();
  return response.json();
}

async function authenticateAdmin(request) {
  const login = await request.post('/api/login', {
    data: { user: ADMIN_USER, password: ADMIN_PASSWORD },
  });
  const session = await responseJson(login, 'admin login');
  expect(session.role).toBe('security_admin');

  const me = await responseJson(await request.get('/api/me'), 'authenticated principal');
  expect(me).toMatchObject({ user: ADMIN_USER, role: 'security_admin' });

  const csrf = await responseJson(await request.get('/api/csrf'), 'CSRF token');
  expect(typeof csrf.csrfToken).toBe('string');
  expect(csrf.csrfToken.length).toBeGreaterThan(20);
  return csrf.csrfToken;
}

async function loginConsole(page) {
  await page.goto('/login.html');
  await page.locator('#user').fill(ADMIN_USER);
  await page.locator('#password').fill(ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function openPolicy(page) {
  await page.goto('/app/#/policy');
  await expect(page.getByRole('heading', { name: 'Policy Configuration', exact: true })).toBeVisible();
  await expect(page.locator('.app-panel-meta').first()).not.toHaveText('Loading', { timeout: 10000 });
}

function sorted(values) {
  return [...values].sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
}

async function restoreExactPolicy(request, csrfToken, originalPolicy) {
  const restored = await request.put('/api/policy', {
    headers: { 'x-csrf-token': csrfToken },
    data: originalPolicy,
  });
  const restoredBody = await responseJson(restored, 'exact policy restoration');
  expect(restoredBody).toEqual(originalPolicy);

  const verified = await responseJson(await request.get('/api/policy'), 'restored policy readback');
  expect(verified).toEqual(originalPolicy);
}

function tightenedCopy(originalPolicy) {
  expect(Array.isArray(originalPolicy.alwaysBlock)).toBe(true);
  expect(Array.isArray(originalPolicy.blockedDestinations)).toBe(true);
  expect(originalPolicy.blockedDestinations).not.toContain(PROOF_DESTINATION);
  expect(originalPolicy.allowedDestinations || []).not.toContain(PROOF_DESTINATION);
  return {
    ...originalPolicy,
    blockedDestinations: [...originalPolicy.blockedDestinations, PROOF_DESTINATION],
  };
}

async function saveTightenedPolicy(page, tightenedPolicy, markAttempted) {
  const blockedDestinations = page.getByLabel('Blocked AI destinations');
  await expect(blockedDestinations).toBeVisible();
  await blockedDestinations.fill(tightenedPolicy.blockedDestinations.join('\n'));
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();

  const saveRequestPromise = page.waitForRequest((candidate) => (
    candidate.method() === 'PUT' && new URL(candidate.url()).pathname === '/api/policy'
  ));
  markAttempted();
  await page.getByRole('button', { name: 'Save changes' }).click();
  const saveBody = (await saveRequestPromise).postDataJSON();
  expect(saveBody.blockedDestinations).toEqual(tightenedPolicy.blockedDestinations);
  expect(saveBody).not.toHaveProperty('alwaysBlock');

  await expect(page.getByText('Saved', { exact: true })).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled();
}

async function verifyPolicyReadback(page, request, originalPolicy, tightenedPolicy) {
  const apiPolicy = await responseJson(await request.get('/api/policy'), 'mutated policy readback');
  expect(apiPolicy).toEqual(tightenedPolicy);
  expect(apiPolicy.alwaysBlock).toEqual(originalPolicy.alwaysBlock);

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Policy Configuration', exact: true })).toBeVisible();
  await expect(page.getByLabel('Blocked AI destinations')).toHaveValue(
    tightenedPolicy.blockedDestinations.join('\n'),
  );
}

function policyMutationEntry(entries) {
  return entries.find((candidate) => {
    if (candidate.action !== 'POLICY_UPDATED' || candidate.actor !== ADMIN_USER) return false;
    try {
      const detail = JSON.parse(candidate.detail);
      return detail.changed?.some((change) => (
        change.field === 'blockedDestinations'
        && Array.isArray(change.after)
        && change.after.includes(PROOF_DESTINATION)
      ));
    } catch {
      return false;
    }
  });
}

async function verifyPolicyAudit(request, originalPolicy, tightenedPolicy) {
  const audit = await responseJson(await request.get('/api/audit?limit=200'), 'policy audit evidence');
  expect(audit.integrity).toMatchObject({ ok: true });
  expect(audit.window).toMatchObject({ scope: 'all' });
  const entry = policyMutationEntry(audit.entries);
  expect(entry, 'POLICY_UPDATED audit entry for the additive block').toBeTruthy();

  const detail = JSON.parse(entry.detail);
  expect(detail.type).toBe('policy_change');
  expect(detail.changed.map((change) => change.field)).toEqual(['blockedDestinations']);
  expect(detail.changed[0].before).toEqual(sorted(originalPolicy.blockedDestinations));
  expect(detail.changed[0].after).toEqual(sorted(tightenedPolicy.blockedDestinations));
}

test('admin policy save is read back by the API and UI, audited, and exactly restored', async ({ baseURL, page, request }) => {
  requireIsolatedPlaywrightServer(baseURL);
  const csrfToken = await authenticateAdmin(request);
  const originalPolicy = await responseJson(await request.get('/api/policy'), 'original policy snapshot');
  const tightenedPolicy = tightenedCopy(originalPolicy);
  let mutationAttempted = false;

  try {
    await loginConsole(page);
    await openPolicy(page);
    await saveTightenedPolicy(page, tightenedPolicy, () => { mutationAttempted = true; });
    await verifyPolicyReadback(page, request, originalPolicy, tightenedPolicy);
    await verifyPolicyAudit(request, originalPolicy, tightenedPolicy);
  } finally {
    if (mutationAttempted) await restoreExactPolicy(request, csrfToken, originalPolicy);
  }
});
