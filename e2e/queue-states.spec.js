'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { test, expect } = require('@playwright/test');
const { createDeferred } = require('./helpers/deferred');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

test.setTimeout(90000);

const VERIFIED_ROW = {
  id: 'queue-state-e2e',
  createdAt: '2026-07-10T12:00:00.000Z',
  status: 'pending',
  user: 'queue-reviewer@example.test',
  destination: 'approved-ai.example.test',
  source: 'browser_extension',
  channel: 'submit',
  redactedPrompt: 'Masked member-data context: [REDACTED].',
  findings: [{ type: 'MEMBER_ID', masked: 'redacted', severity: 4 }],
  categories: [],
  entityCounts: { MEMBER_ID: 1 },
  reasons: ['synthetic queue state fixture'],
  riskScore: 84,
  maxSeverity: 4,
  maxSeverityLabel: 'high',
  rawRetained: false,
};

const SECOND_VERIFIED_ROW = {
  ...VERIFIED_ROW,
  id: 'queue-state-e2e-secondary',
  user: 'second-reviewer@example.test',
  createdAt: '2026-07-10T12:01:00.000Z',
};

const JUSTIFICATION_ROW = {
  ...VERIFIED_ROW,
  id: 'queue-state-e2e-justification',
  status: 'pending_justification',
  user: 'justification-reviewer@example.test',
  createdAt: '2026-07-10T12:02:00.000Z',
};

const SYNTHETIC_APPROVAL_PROMPT = 'This confidential merger contract should be reviewed.';
const AUDIT_PRIVATE_FIELDS = new Set([
  'rawPrompt',
  'redactedPrompt',
  'findings',
  'decisionNote',
  'user',
  'assignedUser',
]);

function safeIdentityNonce() {
  return `r${randomBytes(8).toString('hex')}`;
}

async function login(page, user = '', password = 'e2e-pass') {
  await page.goto('/login.html');
  if (user) await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function routeQueue(page, response) {
  await page.route('**/api/queries?*', async (route) => {
    const current = typeof response === 'function' ? response() : response;
    if (current === 'unavailable') {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'temporarily_unavailable' }),
      });
      return;
    }
    if (current === 'forbidden') {
      await route.fulfill({
        status: 403,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'forbidden' }),
      });
      return;
    }
    const requestedStatus = new URL(route.request().url()).searchParams.get('status');
    const body = Array.isArray(current) && requestedStatus
      ? current.filter((row) => row.status === requestedStatus)
      : current;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body),
    });
  });
}

async function fetchQueryAudit(page, queryId) {
  const response = await page.evaluate(async (id) => {
    const current = await fetch(`/api/audit?queryId=${encodeURIComponent(id)}&limit=50`);
    return { status: current.status, body: current.ok ? await current.json() : null };
  }, queryId);
  expect(response.status).toBe(200);
  expect(response.body).not.toBeNull();
  return response.body;
}

function assertAuditWindow(audit) {
  expect(audit).toEqual(expect.objectContaining({
    entries: expect.any(Array),
    integrity: expect.objectContaining({ ok: true, count: expect.any(Number) }),
    window: expect.objectContaining({ scope: 'query', complete: expect.any(Boolean) }),
    retention: expect.any(String),
  }));
  const counts = ['scannedEntries', 'totalEntries', 'matchedEntries', 'returnedEntries'];
  expect(Number.isSafeInteger(audit.integrity.count)).toBe(true);
  expect(audit.integrity.count).toBeGreaterThanOrEqual(0);
  for (const key of counts) {
    expect(Number.isSafeInteger(audit.window[key])).toBe(true);
    expect(audit.window[key]).toBeGreaterThanOrEqual(0);
  }
  expect(audit.window.totalEntries).toBe(audit.integrity.count);
  expect(audit.window.scannedEntries).toBeLessThanOrEqual(audit.window.totalEntries);
  expect(audit.window.returnedEntries).toBe(audit.entries.length);
  expect(audit.window.returnedEntries).toBeLessThanOrEqual(audit.window.matchedEntries);
  expect(audit.window.complete).toBe(audit.window.scannedEntries === audit.window.totalEntries);
}

function assertApprovalAudit(audit, queryId) {
  assertAuditWindow(audit);
  expect(audit.window.matchedEntries).toBeGreaterThanOrEqual(2);
  expect(audit.entries.every((entry) => entry.queryId === queryId)).toBe(true);
  expect(audit.entries.every((entry) => /^[0-9a-f]{64}$/.test(entry.prevHash) && /^[0-9a-f]{64}$/.test(entry.hash))).toBe(true);
  const actions = audit.entries.map((entry) => entry.action);
  expect(actions.filter((action) => action === 'FLAGGED')).toHaveLength(1);
  expect(actions.filter((action) => action === 'APPROVED')).toHaveLength(1);
  expect(actions.indexOf('APPROVED')).toBeLessThan(actions.indexOf('FLAGGED'));
  expect(audit.entries.every((entry) => Object.keys(entry).every((key) => !AUDIT_PRIVATE_FIELDS.has(key)))).toBe(true);
  expect(JSON.stringify(audit.entries)).not.toContain(SYNTHETIC_APPROVAL_PROMPT);
}

async function captureApprovedAuditTrail(page, fixture, testInfo) {
  await page.getByLabel('Status').selectOption('approved');
  const approvedRow = page.locator('article.q').filter({ hasText: fixture.user });
  await expect(approvedRow).toHaveCount(1);
  await approvedRow.getByRole('button', { name: `Review incident for ${fixture.user}` }).click();
  const verifiedTrail = page.getByLabel('Verified audit trail');
  await expect(verifiedTrail).toContainText('FLAGGED');
  await expect(verifiedTrail).toContainText('APPROVED');
  await verifiedTrail.screenshot({
    path: testInfo.outputPath('queue-approved-audit-trail.png'),
    animations: 'disabled',
    mask: [verifiedTrail.locator('li span')],
    maskColor: '#64748b',
  });
}

test('queue never presents an initial fetch failure as a clear queue', async ({ page }) => {
  await login(page);
  const fetchGate = createDeferred();
  const fetchCompleted = createDeferred();
  let fetchStarted = 0;
  let completedFetches = 0;
  await page.route('**/api/queries?*', async (route) => {
    fetchStarted += 1;
    await fetchGate.promise;
    try {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'temporarily_unavailable' }),
      });
    } finally {
      completedFetches += 1;
      if (completedFetches === 2) fetchCompleted.release();
    }
  });

  try {
    await page.goto('/app/#/queue');

    await expect(page.getByText('Loading member-data queue')).toBeVisible();
    await expect.poll(() => fetchStarted).toBe(2);
    fetchGate.release();
    await fetchCompleted.promise;
    await expect(page.getByRole('alert').filter({ hasText: 'Member-data queue unavailable' })).toBeVisible();
    await expect(page.getByText('No clear-queue claim has been made.')).toBeVisible();
    await expect(page.getByText('Member-data queue clear')).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Retry', exact: true })).toBeVisible();
  } finally {
    fetchGate.release();
    if (fetchStarted >= 2) await fetchCompleted.promise;
  }
});

test('queue presents an authenticated 403 as access denied, never as clear', async ({ page }) => {
  await login(page, 'e2e-auditor', 'e2e-auditor-pass');
  await routeQueue(page, 'forbidden');
  await page.goto('/app/#/queue');

  await expect(page.getByRole('alert').filter({ hasText: 'Queue access denied' })).toBeVisible();
  await expect(page.getByText('This signed-in role cannot view member-data incidents.')).toBeVisible();
  await expect(page.getByText('Member-data queue clear')).toHaveCount(0);
  await expect(page.getByRole('checkbox', { name: /Select incident .* for bulk decision/ })).toHaveCount(0);
});

test('held view fetches and combines both exact statuses while keeping justification holds actionable', async ({ page }) => {
  await login(page);
  const requestedStatuses = [];
  const requestedLimits = [];
  await page.route('**/api/queries?*', async (route) => {
    const url = new URL(route.request().url());
    const status = url.searchParams.get('status');
    requestedStatuses.push(status);
    requestedLimits.push(url.searchParams.get('limit'));
    const rows = status === 'pending'
      ? [VERIFIED_ROW]
      : status === 'pending_justification'
        ? [JUSTIFICATION_ROW]
        : [];
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(rows) });
  });

  await page.goto('/app/#/queue');

  await expect(page.locator('article.q')).toHaveCount(2);
  expect(new Set(requestedStatuses)).toEqual(new Set(['pending', 'pending_justification']));
  expect(requestedStatuses.every((status) => status !== null)).toBe(true);
  expect(requestedLimits.every((limit) => limit === '200')).toBe(true);
  await expect(page.locator('.app-panel-meta').first()).toContainText('2 held');
  await expect(page.getByText('Member-data queue clear')).toHaveCount(0);

  const row = page.locator('article.q').filter({ hasText: JUSTIFICATION_ROW.user });
  const rowButton = row.getByRole('button', { name: `Review incident for ${JUSTIFICATION_ROW.user}` });
  await expect(rowButton).toHaveAttribute('aria-pressed', 'true');
  const approvalRowButton = page.locator('article.q').filter({ hasText: VERIFIED_ROW.user })
    .getByRole('button', { name: `Review incident for ${VERIFIED_ROW.user}` });
  await expect(approvalRowButton).toHaveAttribute('aria-pressed', 'false');
  await approvalRowButton.click();
  await expect(approvalRowButton).toHaveAttribute('aria-pressed', 'true');
  await rowButton.click();
  await expect(rowButton).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.queue-detail-pane')).toContainText('pending justification');
  await expect(page.getByRole('button', { name: 'Approve release' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Deny', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Raw not retained' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Update assignment' })).toBeVisible();

  const checkbox = row.getByRole('checkbox', { name: /Select incident .* for bulk decision/ });
  await checkbox.check();
  await expect(page.locator('.queue-bulk-bar')).toContainText('1 selected');
});

test('held view never claims clear when either exact-status request fails', async ({ page }) => {
  await login(page);
  await page.route('**/api/queries?*', async (route) => {
    const status = new URL(route.request().url()).searchParams.get('status');
    if (status === 'pending_justification') {
      await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'temporarily_unavailable' }) });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
  });
  await page.goto('/app/#/queue');

  await expect(page.getByRole('alert').filter({ hasText: 'Member-data queue unavailable' })).toBeVisible();
  await expect(page.getByText('Member-data queue clear')).toHaveCount(0);
});

test('queue distinguishes verified empty, search-filtered empty, and stale snapshot states', async ({ page }) => {
  await login(page);
  await page.setViewportSize({ width: 390, height: 844 });
  let response = [];
  await routeQueue(page, () => response);
  await page.goto('/app/#/queue');

  await expect(page.getByText('Member-data queue clear')).toBeVisible();

  response = [VERIFIED_ROW];
  await page.getByRole('button', { name: 'Refresh queue' }).click();
  await expect(page.locator('article.q').filter({ hasText: VERIFIED_ROW.user })).toBeVisible();

  await page.getByRole('searchbox', { name: 'Search' }).fill('no matching incident');
  await expect(page.getByText('No search matches')).toBeVisible();
  await expect(page.getByText('Member-data queue clear')).toHaveCount(0);
  await page.getByRole('button', { name: 'Clear search' }).click();
  await expect(page.locator('article.q').filter({ hasText: VERIFIED_ROW.user })).toBeVisible();

  response = 'unavailable';
  await page.getByRole('button', { name: 'Refresh queue' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Queue refresh failed' })).toContainText(
    'Showing the last verified snapshot',
  );
  await expect(page.locator('article.q').filter({ hasText: VERIFIED_ROW.user })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Review selected incident' })).toBeVisible();
  await expect(page.getByText('Member-data queue clear')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('password step-up contains keyboard focus and restores the opener on Escape', async ({ page }) => {
  await login(page);
  await routeQueue(page, [VERIFIED_ROW]);
  await page.goto('/app/#/queue');

  const approve = page.getByRole('button', { name: 'Approve release' });
  await expect(approve).toBeVisible();
  await approve.focus();
  await approve.click();

  const dialog = page.getByRole('dialog', { name: 'Confirm release' });
  const password = dialog.getByLabel('Account password');
  const confirm = dialog.getByRole('button', { name: 'Approve release' });
  await expect(password).toBeFocused();

  await page.keyboard.press('Shift+Tab');
  await expect(confirm).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(password).toBeFocused();

  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0);
  await expect(approve).toBeFocused();
});

test('nested bulk checkbox toggles with Space without selecting its row', async ({ page }) => {
  await login(page);
  await routeQueue(page, [VERIFIED_ROW, SECOND_VERIFIED_ROW]);
  await page.goto('/app/#/queue');

  const selectedRow = page.locator('article.q').filter({ hasText: SECOND_VERIFIED_ROW.user });
  const olderRow = page.locator('article.q').filter({ hasText: VERIFIED_ROW.user });
  const checkbox = olderRow.getByRole('checkbox', { name: /Select incident .* for bulk decision/ });
  const checkboxTarget = olderRow.locator('.queue-bulk-target');
  const rowButton = olderRow.getByRole('button', { name: `Review incident for ${VERIFIED_ROW.user}` });
  const [targetBox, buttonBox] = await Promise.all([checkboxTarget.boundingBox(), rowButton.boundingBox()]);
  expect(targetBox).not.toBeNull();
  expect(buttonBox).not.toBeNull();
  expect(targetBox.width).toBeGreaterThanOrEqual(24);
  expect(targetBox.height).toBeGreaterThanOrEqual(24);
  expect(targetBox.x + targetBox.width).toBeLessThanOrEqual(buttonBox.x);
  await expect(page.locator('.queue-detail-pane')).toContainText(SECOND_VERIFIED_ROW.user);
  await checkbox.focus();
  await page.keyboard.press('Space');

  await expect(checkbox).toBeChecked();
  await expect(page.locator('.queue-bulk-bar')).toContainText('1 selected');
  await expect(selectedRow.getByRole('button', { name: `Review incident for ${SECOND_VERIFIED_ROW.user}` })).toHaveAttribute('aria-pressed', 'true');
  await expect(rowButton).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('.queue-detail-pane')).toContainText(SECOND_VERIFIED_ROW.user);

  await page.keyboard.press('Space');
  await expect(checkbox).not.toBeChecked();
  await expect(page.locator('.queue-bulk-bar')).toHaveCount(0);
});

test('real backend justification hold appears once and can be approved from the default held view', async ({ page }, testInfo) => {
  await login(page);
  const fixture = await page.evaluate(async ({ prompt, nonce }) => {
    const csrf = await (await fetch('/api/csrf')).json();
    const original = await (await fetch('/api/policy')).json();
    const headers = { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken };
    const restore = {
      enforcementMode: original.enforcementMode,
      blockMinSeverity: original.blockMinSeverity,
      blockRiskScore: original.blockRiskScore,
    };
    try {
      const policyResponse = await fetch('/api/policy', {
        method: 'PUT',
        headers,
        body: JSON.stringify({ enforcementMode: 'justify', blockMinSeverity: 2, blockRiskScore: 10 }),
      });
      if (!policyResponse.ok) throw new Error(`policy setup failed: ${policyResponse.status}`);
      const user = `queue-justify-${nonce}@example.test`;
      const gateResponse = await fetch('/api/v1/gate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': 'e2e-ingest-key' },
        body: JSON.stringify({
          prompt,
          user,
          destination: 'approved-ai.example.test',
          source: 'browser_extension',
          channel: 'submit',
          orgId: 'e2e-org',
        }),
      });
      const body = await gateResponse.json();
      if (!gateResponse.ok) throw new Error(`gate setup failed: ${gateResponse.status}`);
      return { ...body, user };
    } finally {
      const restoreResponse = await fetch('/api/policy', { method: 'PUT', headers, body: JSON.stringify(restore) });
      if (!restoreResponse.ok) throw new Error(`policy restore failed: ${restoreResponse.status}`);
    }
  }, { prompt: SYNTHETIC_APPROVAL_PROMPT, nonce: safeIdentityNonce() });

  expect(fixture.status).toBe('pending_justification');
  const exactStatusRows = await page.evaluate(async () => {
    const [pendingResponse, justificationResponse] = await Promise.all([
      fetch('/api/queries?status=pending&limit=200'),
      fetch('/api/queries?status=pending_justification&limit=200'),
    ]);
    return {
      pending: (await pendingResponse.json()).map((row) => row.id),
      justification: (await justificationResponse.json()).map((row) => row.id),
    };
  });
  expect(exactStatusRows.pending).not.toContain(fixture.id);
  expect(exactStatusRows.justification.filter((id) => id === fixture.id)).toHaveLength(1);
  await page.goto('/app/#/queue');
  const row = page.locator('article.q').filter({ hasText: fixture.user });
  await expect(row).toHaveCount(1);
  await expect(row.getByRole('checkbox', { name: /Select incident .* for bulk decision/ })).toBeVisible();
  await expect(page.getByText('Member-data queue clear')).toHaveCount(0);
  await row.click();

  await page.getByLabel('Decision note').fill('E2E justification hold approval');
  await page.getByRole('button', { name: 'Approve release' }).click();
  const dialog = page.getByRole('dialog', { name: 'Confirm release' });
  await dialog.getByLabel('Account password').fill('e2e-pass');
  await dialog.getByRole('button', { name: 'Approve release' }).click();
  await expect(page.locator('#toastStack')).toContainText('Prompt approved and released.');

  await expect.poll(async () => page.evaluate(async (id) => {
    const response = await fetch(`/api/queries/${encodeURIComponent(id)}`);
    return response.ok ? (await response.json()).status : `http-${response.status}`;
  }, fixture.id)).toBe('approved');

  assertApprovalAudit(await fetchQueryAudit(page, fixture.id), fixture.id);
  await captureApprovedAuditTrail(page, fixture, testInfo);
});

test('real backend justification holds support single and bulk denial', async ({ page }) => {
  await login(page);
  const fixtures = await page.evaluate(async (nonce) => {
    const csrf = await (await fetch('/api/csrf')).json();
    const original = await (await fetch('/api/policy')).json();
    const headers = { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken };
    const restore = {
      enforcementMode: original.enforcementMode,
      blockMinSeverity: original.blockMinSeverity,
      blockRiskScore: original.blockRiskScore,
    };
    try {
      const policyResponse = await fetch('/api/policy', {
        method: 'PUT',
        headers,
        body: JSON.stringify({ enforcementMode: 'justify', blockMinSeverity: 2, blockRiskScore: 10 }),
      });
      if (!policyResponse.ok) throw new Error(`policy setup failed: ${policyResponse.status}`);
      const created = [];
      for (let index = 0; index < 3; index += 1) {
        const user = `queue-deny-${nonce}-${index}@example.test`;
        const response = await fetch('/api/v1/gate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': 'e2e-ingest-key' },
          body: JSON.stringify({
            prompt: 'This confidential merger contract should be reviewed.',
            user,
            destination: 'approved-ai.example.test',
            source: 'browser_extension',
            channel: 'submit',
            orgId: 'e2e-org',
          }),
        });
        const body = await response.json();
        if (!response.ok) throw new Error(`gate setup failed: ${response.status}`);
        created.push({ id: body.id, status: body.status, user });
      }
      return created;
    } finally {
      const restoreResponse = await fetch('/api/policy', { method: 'PUT', headers, body: JSON.stringify(restore) });
      if (!restoreResponse.ok) throw new Error(`policy restore failed: ${restoreResponse.status}`);
    }
  }, safeIdentityNonce());

  expect(fixtures.every((fixture) => fixture.status === 'pending_justification')).toBe(true);
  await page.goto('/app/#/queue');
  const firstRow = page.locator('article.q').filter({ hasText: fixtures[0].user });
  await firstRow.getByRole('button', { name: `Review incident for ${fixtures[0].user}` }).click();
  await page.getByLabel('Decision note').fill('E2E single justification denial');
  await page.getByRole('button', { name: 'Deny', exact: true }).click();
  await expect(page.locator('#toastStack')).toContainText('Prompt denied.');

  for (const fixture of fixtures.slice(1)) {
    await page.locator('article.q').filter({ hasText: fixture.user }).getByRole('checkbox', { name: /Select incident .* for bulk decision/ }).check();
  }
  await page.getByLabel('Bulk decision note').fill('E2E bulk justification denial');
  await page.getByRole('button', { name: 'Deny selected' }).click();
  await expect(page.locator('#toastStack')).toContainText('2 prompt(s) denied.');

  await expect.poll(async () => page.evaluate(async (items) => Promise.all(items.map(async ({ id }) => {
    const response = await fetch(`/api/queries/${encodeURIComponent(id)}`);
    return response.ok ? (await response.json()).status : `http-${response.status}`;
  })), fixtures)).toEqual(['denied', 'denied', 'denied']);
});
