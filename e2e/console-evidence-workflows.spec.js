'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

async function loginAs(page, user = 'admin', password = 'e2e-pass') {
  await page.goto('/login.html');
  await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

async function downloadBytes(download) {
  const stream = await download.createReadStream();
  expect(stream).toBeTruthy();
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function issueReceipt(request) {
  const response = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: 'Draft a friendly reminder about the branch holiday schedule.',
      user: 'receipt-ui@example.test',
      destination: 'chat.openai.com',
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'e2e-org',
    },
  });
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body.decision).toBe('allow');
  expect(body.receipt).toBeTruthy();
  return body.receipt;
}

async function openReceiptVerifier(page) {
  await page.goto('/app/#/audit');
  const verifier = page.locator('.receipt-verifier');
  await expect(verifier.getByRole('heading', { name: 'Verify safe-to-send receipt' })).toBeVisible();
  return verifier;
}

async function submitReceipt(verifier, receipt) {
  const input = verifier.getByLabel('Receipt JSON');
  await input.fill('');
  await input.fill(JSON.stringify(receipt));
  await expect(verifier.getByRole('status')).toContainText('Receipt changed');
  await verifier.getByRole('button', { name: 'Verify receipt' }).click();
}

test('examiner audit distinguishes verified, tampered, malformed, and oversized receipts', async ({ page, request }) => {
  const receipt = await issueReceipt(request);
  await loginAs(page);
  const verifier = await openReceiptVerifier(page);
  const status = verifier.getByRole('status');

  await submitReceipt(verifier, receipt);
  await expect(status).toContainText('Receipt verified');
  await expect(verifier.getByLabel('Receipt JSON')).not.toHaveAttribute('aria-invalid', 'true');

  const last = receipt.sig.slice(-1);
  const tampered = { ...receipt, sig: `${receipt.sig.slice(0, -1)}${last === 'x' ? 'y' : 'x'}` };
  await submitReceipt(verifier, tampered);
  await expect(status).toContainText('signature does not match');
  await expect(verifier.getByLabel('Receipt JSON')).toHaveAttribute('aria-invalid', 'true');

  await submitReceipt(verifier, { ...receipt, promptSha256: 'not-a-hash' });
  await expect(status).toContainText('Receipt format is invalid');

  await submitReceipt(verifier, { ...receipt, status: 'blocked' });
  await expect(status).toContainText('Receipt format is invalid');

  const missingField = { ...receipt };
  delete missingField.policySha256;
  await submitReceipt(verifier, missingField);
  await expect(status).toContainText('Receipt format is invalid');

  await verifier.getByLabel('Receipt JSON').fill('x'.repeat(4097));
  await expect(status).toContainText('exceeds the 4,096-character verification limit');
  await expect(status).not.toContainText('unavailable');
});

test('receipt edits revoke prior success and input stays fixed while verification is pending', async ({ page, request }) => {
  const receipt = await issueReceipt(request);
  await loginAs(page);
  const verifier = await openReceiptVerifier(page);
  const input = verifier.getByLabel('Receipt JSON');
  const status = verifier.getByRole('status');

  await submitReceipt(verifier, receipt);
  await expect(status).toContainText('Receipt verified');
  await input.fill(JSON.stringify({ ...receipt, destination: 'edited.example.test' }));
  await expect(status).toContainText('Receipt changed');
  await expect(status).not.toContainText('Receipt verified');

  const verificationGate = deferred();
  const verificationStarted = deferred();
  const verificationCompleted = deferred();
  await page.route('**/api/receipts/verify', async (route) => {
    verificationStarted.resolve();
    try {
      await verificationGate.promise;
      await route.continue();
    } finally {
      verificationCompleted.resolve();
    }
  });
  const submitted = JSON.stringify(receipt);
  try {
    await input.fill(submitted);
    await verifier.getByRole('button', { name: 'Verify receipt' }).click();
    await verificationStarted.promise;
    await expect(input).toBeDisabled();
    await expect(verifier.getByRole('button', { name: 'Clear' })).toBeDisabled();
    await expect(input).toHaveValue(submitted);
  } finally {
    verificationGate.resolve();
  }
  await verificationCompleted.promise;
  await expect(status).toContainText('Receipt verified');
  await expect(input).toBeEnabled();
});

test('receipt verification reports unavailable, forbidden, and expired-session outcomes truthfully', async ({ page, request }) => {
  const receipt = await issueReceipt(request);
  await loginAs(page);
  const verifier = await openReceiptVerifier(page);
  let responseStatus = 503;
  await page.route('**/api/receipts/verify', async (route) => {
    await route.fulfill({
      status: responseStatus,
      contentType: 'application/json',
      body: JSON.stringify({ error: responseStatus === 401 ? 'unauthenticated' : 'request_rejected' }),
    });
  });

  await submitReceipt(verifier, receipt);
  await expect(verifier.getByRole('status')).toContainText('verification is unavailable');

  responseStatus = 403;
  await submitReceipt(verifier, receipt);
  await expect(verifier.getByRole('status')).toContainText('not permitted to verify');

  responseStatus = 401;
  await submitReceipt(verifier, receipt);
  await expect(page).toHaveURL(/\/login\.html$/);
});

test('receipt verification rejects an oversized success response without trusting its content', async ({ page, request }) => {
  const receipt = await issueReceipt(request);
  await loginAs(page);
  const verifier = await openReceiptVerifier(page);
  await page.route('**/api/receipts/verify', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true, padding: 'x'.repeat(9 * 1024) }),
    });
  });

  await submitReceipt(verifier, receipt);
  await expect(verifier.getByRole('status')).toContainText('verification is unavailable');
  await expect(verifier.getByRole('status')).not.toContainText('Receipt verified');
});

test('examiner auditor can verify a receipt without mutation privileges', async ({ page, request }) => {
  const receipt = await issueReceipt(request);
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  const verifier = await openReceiptVerifier(page);
  await submitReceipt(verifier, receipt);
  await expect(verifier.getByRole('status')).toContainText('Receipt verified');
});

test('auditor can export evidence and download bounded JSON and ZIP trust packages', async ({ page }) => {
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  await page.goto('/app/#/compliance');

  await expect(page.getByRole('link', { name: 'Export evidence pack' })).toBeVisible();
  const jsonButton = page.getByTestId('trust-package-json');
  const zipButton = page.getByTestId('trust-package-zip');
  const status = page.locator('#trustPackageDownloadStatus');

  const [jsonDownload] = await Promise.all([page.waitForEvent('download'), jsonButton.click()]);
  expect(jsonDownload.suggestedFilename()).toBe('redactwall-security-trust-package.json');
  const json = JSON.parse((await downloadBytes(jsonDownload)).toString('utf8'));
  expect(json.schemaVersion).toBe('redactwall.security-trust-package.v1');
  expect(Array.isArray(json.controls)).toBe(true);
  expect(Array.isArray(json.documents)).toBe(true);
  await expect(status).toContainText('JSON security trust package download started');

  const [zipDownload] = await Promise.all([page.waitForEvent('download'), zipButton.click()]);
  expect(zipDownload.suggestedFilename()).toBe('redactwall-security-trust-package.zip');
  const zip = await downloadBytes(zipDownload);
  expect(zip.subarray(0, 2).toString('ascii')).toBe('PK');
  expect(zip.includes(Buffer.from([0x50, 0x4b, 0x05, 0x06]))).toBe(true);
  await expect(status).toContainText('ZIP security trust package download started');
});

test('trust-package actions stay locked while a bounded download is pending', async ({ page }) => {
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  await page.goto('/app/#/compliance');
  const jsonButton = page.getByTestId('trust-package-json');
  const zipButton = page.getByTestId('trust-package-zip');
  const started = deferred();
  const gate = deferred();
  const completed = deferred();
  await page.route('**/api/security/package?format=json', async (route) => {
    started.resolve();
    try {
      await gate.promise;
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          schemaVersion: 'redactwall.security-trust-package.v1',
          generatedAt: '2026-07-10T12:00:00.000Z',
          product: {},
          summary: {},
          privacyContract: {},
          controls: [],
          sbom: {},
          documents: [],
        }),
      });
    } finally {
      completed.resolve();
    }
  });

  const pendingDownload = page.waitForEvent('download');
  try {
    await jsonButton.click();
    await started.promise;
    await expect(page.getByTestId('trust-package-json')).toBeDisabled();
    await expect(page.getByTestId('trust-package-json')).toHaveText('Preparing JSON…');
    await expect(zipButton).toBeDisabled();
  } finally {
    gate.resolve();
  }
  await completed.promise;
  await pendingDownload;
});

test('trust-package download reports malformed, oversized, unavailable, forbidden, and expired-session outcomes', async ({ page }) => {
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  await page.goto('/app/#/compliance');
  const button = page.getByRole('button', { name: 'Download JSON' });
  const status = page.locator('#trustPackageDownloadStatus');
  let outcome = 'malformed';
  await page.route('**/api/security/package?format=json', async (route) => {
    if (outcome === 'oversize') {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: Buffer.alloc((8 * 1024 * 1024) + 1, 0x20),
      });
    }
    if (outcome === 'unavailable') {
      return route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"unavailable"}' });
    }
    if (outcome === 'forbidden') {
      return route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'forbidden', padding: 'x'.repeat(9 * 1024) }),
      });
    }
    if (outcome === 'session') {
      return route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"unauthenticated"}' });
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });

  await button.click();
  await expect(status).toContainText('response was malformed');

  outcome = 'oversize';
  await button.click();
  await expect(status).toContainText('exceeded the safe download limit');

  outcome = 'unavailable';
  await button.click();
  await expect(status).toContainText('package is unavailable');

  outcome = 'forbidden';
  await button.click();
  await expect(status).toContainText('not permitted to download');

  outcome = 'session';
  await button.click();
  await expect(page).toHaveURL(/\/login\.html$/);
});

test('operator sees a truthful trust-package permission state', async ({ page }) => {
  await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
  await page.goto('/app/#/compliance');

  await expect(page.getByRole('button', { name: 'Export evidence pack' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Download JSON' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Download ZIP' })).toBeDisabled();
  await expect(page.locator('#complianceExportPermission')).toContainText('Global Administrator or Examiner/Auditor');
  await expect(page.locator('#trustPackagePermission')).toContainText('Global Administrator or Examiner/Auditor');
});

test('ticket synchronization rejects malformed summaries and accepts only bounded count evidence', async ({ page }) => {
  await loginAs(page);
  await page.goto('/app/#/activity');
  const button = page.getByRole('button', { name: 'Sync Jira / Linear' });
  const status = page.locator('.ticket-sync-status');
  let response = {};
  let responseStatus = 200;
  await page.route('**/api/tickets/sync', async (route) => {
    await route.fulfill({ status: responseStatus, contentType: 'application/json', body: JSON.stringify(response) });
  });

  await button.click();
  await expect(status).toContainText('synchronization is unavailable');
  await expect(status).not.toContainText('complete');

  response = {
    checked: 1,
    updated: 2,
    succeeded: 1,
    failed: 0,
    generatedAt: '2026-07-10T12:00:00.000Z',
  };
  await button.click();
  await expect(status).toContainText('synchronization is unavailable');

  responseStatus = 409;
  response = { status: 'busy', reason: 'ticket_sync_in_progress' };
  await button.click();
  await expect(status).toContainText('synchronization is already running');

  responseStatus = 200;
  response = {
    status: 'complete',
    checked: 3,
    matched: 3,
    checksAttempted: 3,
    updated: 1,
    succeeded: 3,
    failed: 0,
    generatedAt: '2026-07-10T12:00:00.000Z',
  };
  await button.click();
  await expect(status).toContainText('Ticket synchronization complete: 3 status checks completed across 3 matching records; 1 updated');
  await expect(status).not.toContainText(/description|comment|summary/i);

  response = {
    status: 'partial',
    checked: 2,
    matched: 2,
    checksAttempted: 2,
    updated: 1,
    succeeded: 1,
    failed: 1,
    generatedAt: '2026-07-10T12:01:00.000Z',
    reason: 'provider_failures',
  };
  await button.click();
  await expect(status).toContainText('Ticket synchronization partial (one or more provider checks failed): 2 status checks attempted');
  await expect(status).not.toContainText('synchronization complete');
});

test('real ticket synchronization reports an isolated server with no configured channels', async ({ page }) => {
  await loginAs(page);
  await page.goto('/app/#/activity');
  await page.getByRole('button', { name: 'Sync Jira / Linear' }).click();
  await expect(page.locator('.ticket-sync-status')).toContainText('No Jira or Linear ticket channels are configured');
  await expect(page.locator('.ticket-sync-status')).toContainText('No records were changed');
});

test('activity saved views stay in memory and never persist or echo free-form search content', async ({ page }) => {
  const regulatedSearch = 'member 524-71-9043 sk-proj-secret-search raw prompt';
  const sensitiveParts = ['524-71-9043', 'sk-proj-secret-search', 'raw prompt'];
  await page.addInitScript((value) => {
    localStorage.setItem('redactwall.savedViews', JSON.stringify([{ name: value, search: value }]));
  }, regulatedSearch);
  await loginAs(page);
  await expect.poll(() => page.evaluate(() => localStorage.getItem('redactwall.savedViews'))).toBeNull();
  await page.goto('/app/#/activity');
  await page.getByRole('searchbox', { name: 'Search activity' }).fill(regulatedSearch);
  await page.getByRole('button', { name: 'Save session view' }).click();
  await expect(page.locator('.toast')).toContainText('Session view saved in memory');
  await expect(page.locator('.toast')).not.toContainText(regulatedSearch);
  await expect(page.getByRole('combobox', { name: 'Session activity views' })).toContainText('Session view 1');
  await expect(page.getByRole('combobox', { name: 'Session activity views' })).not.toContainText(regulatedSearch);

  const browserStorage = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
  }));
  for (const sensitive of sensitiveParts) expect(JSON.stringify(browserStorage)).not.toContain(sensitive);

  await page.reload();
  const sessionViews = page.getByRole('combobox', { name: 'Session activity views' });
  await expect(sessionViews).not.toContainText('Session view 1');
  await expect(page.getByRole('searchbox', { name: 'Search activity' })).toHaveValue('');
  await expect.poll(() => page.evaluate(() => localStorage.getItem('redactwall.savedViews'))).toBeNull();
  const refreshedState = await page.evaluate(() => ({
    local: Object.entries(localStorage),
    session: Object.entries(sessionStorage),
    sessionSavedViewsGlobal: window.sessionSavedViews,
    redactwallSavedViewsGlobal: window.redactwallSavedViews,
  }));
  expect(refreshedState.sessionSavedViewsGlobal).toBeUndefined();
  expect(refreshedState.redactwallSavedViewsGlobal).toBeUndefined();
  for (const sensitive of sensitiveParts) {
    expect(JSON.stringify(refreshedState)).not.toContain(sensitive);
    await expect(sessionViews).not.toContainText(sensitive);
  }
});

test('topbar and command-palette sign out revoke the active session', async ({ page }) => {
  await loginAs(page);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login\.html$/);
  expect((await page.context().request.get('/api/me')).status()).toBe(401);
  await page.goto('/app/');
  await expect(page).toHaveURL(/\/login\.html$/);

  await loginAs(page);
  await page.getByRole('button', { name: 'Open the command palette' }).click();
  const palette = page.getByRole('dialog', { name: 'Command palette' });
  await palette.getByRole('option', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/login\.html$/);
  expect((await page.context().request.get('/api/me')).status()).toBe(401);
});

test('failed sign out keeps the authenticated session visible and retryable', async ({ page }) => {
  await loginAs(page);
  await page.route('**/api/logout', (route) => route.fulfill({
    status: 503,
    contentType: 'application/json',
    body: JSON.stringify({ error: 'temporary_failure', padding: 'x'.repeat(9 * 1024) }),
  }));

  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/app\/?(?:#.*)?$/);
  await expect(page.locator('.toast')).toContainText('Sign out failed. Your current session remains open.');
  expect((await page.context().request.get('/api/me')).status()).toBe(200);
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
});
