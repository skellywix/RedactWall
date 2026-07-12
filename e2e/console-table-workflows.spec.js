'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

const HASH_ZERO = '0'.repeat(64);

async function login(page) {
  await page.goto('/login.html');
  await page.locator('#user').fill('admin');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
  await expect(page.getByRole('heading', { name: 'Texas FCU Overview', exact: true })).toBeVisible();
}

async function openView(page, hash, heading) {
  await page.goto(`/app/#/${hash}`);
  await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
  await expect(page.locator('.app-loading')).toHaveCount(0);
}

function catalogApp({ id, name, provider, riskScore, status, events }) {
  return {
    id,
    destination: `${name.toLowerCase()}.ai.example.test`,
    appName: name,
    provider,
    region: 'US',
    riskScore,
    riskTier: riskScore >= 80 ? 'high' : riskScore >= 40 ? 'moderate' : 'low',
    baseRiskScore: riskScore,
    riskOverride: null,
    overrideNote: null,
    overriddenBy: null,
    riskAttributes: { trainsOnData: 'no', personalTier: false, flags: [] },
    sanctionedStatus: status,
    knownAiHost: true,
    owner: null,
    notes: null,
    eventCount: events,
    sources: { browser_extension: events },
    firstSeen: '2026-07-01T12:00:00.000Z',
    lastSeen: '2026-07-11T12:00:00.000Z',
  };
}

const CATALOG_RESPONSE = {
  apps: [
    catalogApp({ id: 1, name: 'Alpha', provider: 'Zeta Labs', riskScore: 10, status: 'sanctioned', events: 3 }),
    catalogApp({ id: 2, name: 'Bravo', provider: 'Alpha Labs', riskScore: 90, status: 'blocked', events: 30 }),
    catalogApp({ id: 3, name: 'Charlie', provider: 'Mu Labs', riskScore: 50, status: 'under_review', events: 12 }),
  ],
};

async function mockCatalog(page) {
  await page.route(/\/api\/catalog$/, async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(CATALOG_RESPONSE) });
  });
}

function catalogNames(page) {
  return page.locator('.catalog-view tbody .catalog-app-link');
}

test('Catalog exposes accurate aria-sort while changing the visible row order', async ({ page }) => {
  await login(page);
  await mockCatalog(page);
  await openView(page, 'catalog', 'AI Vendor Catalog');

  const events = page.getByRole('columnheader', { name: 'Events', exact: true });
  const apps = page.getByRole('columnheader', { name: 'App', exact: true });
  const appSort = apps.getByRole('button', { name: 'App', exact: true });
  await expect(events).toHaveAttribute('aria-sort', 'descending');
  await expect(apps).not.toHaveAttribute('aria-sort');
  await expect(catalogNames(page)).toHaveText(['Bravo', 'Charlie', 'Alpha']);

  await appSort.click();
  await expect(apps).toHaveAttribute('aria-sort', 'ascending');
  await expect(events).not.toHaveAttribute('aria-sort');
  await expect(catalogNames(page)).toHaveText(['Alpha', 'Bravo', 'Charlie']);

  await appSort.click();
  await expect(apps).toHaveAttribute('aria-sort', 'descending');
  await expect(catalogNames(page)).toHaveText(['Charlie', 'Bravo', 'Alpha']);
});

test('Catalog sort controls are operable from the keyboard', async ({ page }) => {
  await login(page);
  await mockCatalog(page);
  await openView(page, 'catalog', 'AI Vendor Catalog');

  const header = page.getByRole('columnheader', { name: 'App', exact: true });
  const target = header.getByRole('button', { name: 'App', exact: true });
  await page.getByRole('checkbox', { name: 'Select all apps' }).focus();
  await page.keyboard.press('Tab');
  await expect(target).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(header).toHaveAttribute('aria-sort', 'ascending');
  await expect(catalogNames(page)).toHaveText(['Alpha', 'Bravo', 'Charlie']);
  await page.keyboard.press('Space');
  await expect(header).toHaveAttribute('aria-sort', 'descending');
  await expect(catalogNames(page)).toHaveText(['Charlie', 'Bravo', 'Alpha']);
});

function auditEntry(index) {
  const suffix = String(index).padStart(2, '0');
  const minute = String(60 - index).padStart(2, '0');
  return {
    id: `audit-${suffix}`,
    ts: `2026-07-11T12:${minute}:00.000Z`,
    action: index % 2 ? 'allowed' : 'denied',
    queryId: `audit-query-${suffix}`,
    actor: `reviewer-${suffix}@example.test`,
    detail: `Metadata-only audit event ${suffix}`,
    prevHash: HASH_ZERO,
    hash: index.toString(16).padStart(64, '0'),
  };
}

function auditResponse(count) {
  const entries = Array.from({ length: count }, (_, index) => auditEntry(index + 1));
  return {
    entries,
    integrity: { ok: true, count },
    window: {
      scope: 'all',
      scannedEntries: count,
      totalEntries: count,
      matchedEntries: count,
      returnedEntries: count,
      complete: true,
    },
    retention: 'Synthetic metadata-only audit fixture retained for this browser test.',
  };
}

test('Audit pagination and page-size changes preserve the correct row window', async ({ page }) => {
  await login(page);
  await page.route(/\/api\/audit\?limit=500$/, (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(auditResponse(26)),
  }));
  await openView(page, 'audit', 'Examiner Audit Chain');

  const table = page.locator('.audit-table');
  const rows = table.locator('tbody tr');
  const pager = page.locator('.audit-pager');
  const previous = pager.getByRole('button', { name: 'Previous page' });
  const next = pager.getByRole('button', { name: 'Next page' });
  await expect(rows).toHaveCount(10);
  await expect(rows.first()).toContainText('audit-query-01');
  await expect(rows.last()).toContainText('audit-query-10');
  await expect(pager).toContainText('Showing 1-10 of 26');
  await expect(previous).toBeDisabled();
  await expect(next).toBeEnabled();

  await next.click();
  await expect(rows.first()).toContainText('audit-query-11');
  await expect(rows.last()).toContainText('audit-query-20');
  await expect(pager).toContainText('Showing 11-20 of 26');
  await expect(previous).toBeEnabled();

  await page.getByLabel('Rows', { exact: true }).selectOption('25');
  await expect(rows).toHaveCount(25);
  await expect(rows.first()).toContainText('audit-query-01');
  await expect(rows.last()).toContainText('audit-query-25');
  await expect(pager).toContainText('Showing 1-25 of 26');
  await expect(previous).toBeDisabled();

  await next.click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('audit-query-26');
  await expect(pager).toContainText('Showing 26-26 of 26');
  await expect(previous).toBeEnabled();
  await expect(next).toBeDisabled();
});

function activityRow(index) {
  const suffix = String(index).padStart(2, '0');
  const minute = String(60 - index).padStart(2, '0');
  const createdAt = `2026-07-11T11:${minute}:00.000Z`;
  return {
    id: `activity-${suffix}`,
    createdAt,
    status: index % 2 ? 'allowed' : 'denied',
    user: `operator-${suffix}@example.test`,
    actor: `operator-${suffix}@example.test`,
    action: 'submit',
    destination: `vendor-${suffix}.ai.example.test`,
    source: 'browser_extension',
    channel: 'submit',
    findings: [],
    categories: [],
    entityCounts: {},
    reasons: [],
    riskScore: index,
    maxSeverity: 1,
    maxSeverityLabel: 'low',
    rawRetained: false,
    assignedRole: 'operator',
    assignedUser: `operator-${suffix}`,
    assignedGroup: 'member-operations',
    decidedBy: 'policy-engine',
    decidedAt: createdAt,
    decisionNote: 'Synthetic metadata-only policy outcome.',
    workflowReason: 'Automated enforcement',
    escalationReason: '',
    notificationStatus: 'not_configured',
    notificationChannels: [],
    scoreBreakdown: [],
  };
}

test('Activity pagination reports disabled states and renders the correct row window', async ({ page }) => {
  await login(page);
  const payload = Array.from({ length: 26 }, (_, index) => activityRow(index + 1));
  await page.route(/\/api\/queries\?limit=200$/, (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(payload),
  }));
  await openView(page, 'activity', 'Gated Member-Data Events');

  const rows = page.locator('.activity-table-wrap tbody .activity-row');
  const pager = page.locator('.table-pager');
  const previous = pager.getByRole('button', { name: 'Previous page' });
  const next = pager.getByRole('button', { name: 'Next page' });
  await expect(rows).toHaveCount(10);
  await expect(rows.first()).toContainText('vendor-01.ai.example.test');
  await expect(rows.last()).toContainText('vendor-10.ai.example.test');
  await expect(pager).toContainText('Showing 1-10 of 26');
  await expect(previous).toBeDisabled();
  await expect(next).toBeEnabled();

  await next.click();
  await expect(rows.first()).toContainText('vendor-11.ai.example.test');
  await expect(rows.last()).toContainText('vendor-20.ai.example.test');
  await expect(pager).toContainText('Showing 11-20 of 26');
  await expect(previous).toBeEnabled();
  await expect(next).toBeEnabled();

  await page.getByLabel('Rows per page').selectOption('25');
  await expect(rows).toHaveCount(25);
  await expect(rows.first()).toContainText('vendor-01.ai.example.test');
  await expect(rows.last()).toContainText('vendor-25.ai.example.test');
  await expect(pager).toContainText('Showing 1-25 of 26');
  await expect(previous).toBeDisabled();

  await next.click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('vendor-26.ai.example.test');
  await expect(pager).toContainText('Showing 26-26 of 26');
  await expect(previous).toBeEnabled();
  await expect(next).toBeDisabled();
});

function lineageBucket(index) {
  const suffix = String(index).padStart(2, '0');
  return {
    key: `employee-${suffix}`,
    events: 100 - index,
    blocked: index % 3,
    redacted: index % 2,
    allowed: 90 - index,
    warned: index % 4,
    maxRiskScore: 50 + index,
    users: 1,
    destinations: 1,
    sources: 1,
    categories: ['MEMBER_ID'],
    lastSeen: `2026-07-11T10:${suffix}:00.000Z`,
  };
}

function summaryBucket(key, events) {
  return {
    ...lineageBucket(1),
    key,
    events,
    blocked: key === 'blocked' ? events : 0,
    redacted: key === 'redacted' ? events : 0,
    allowed: key === 'allowed' ? events : 0,
  };
}

function lineageResponse() {
  return {
    limit: 1000,
    lineage: {
      byUser: Array.from({ length: 12 }, (_, index) => lineageBucket(index + 1)),
      byDestination: [summaryBucket('governed.ai.example.test', 12)],
      bySensor: [summaryBucket('browser_extension', 12)],
      byCategory: [summaryBucket('MEMBER_ID', 12)],
      byChannel: [summaryBucket('submit', 12)],
      byDecision: [summaryBucket('allowed', 5), summaryBucket('blocked', 4), summaryBucket('redacted', 3)],
      byAccountType: [summaryBucket('managed', 12)],
      byOriginApp: [summaryBucket('browser', 12)],
    },
  };
}

test('Lineage paginates each aggregate table independently', async ({ page }) => {
  await login(page);
  await page.route(/\/api\/lineage\?limit=1000$/, (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(lineageResponse()),
  }));
  await openView(page, 'lineage', 'Member Data Lineage');

  const employees = page.locator('.app-panel').filter({
    has: page.getByRole('heading', { name: 'Employees', exact: true }),
  });
  const rows = employees.locator('tbody tr');
  const pager = employees.locator('.table-pager');
  const previous = pager.getByRole('button', { name: 'Previous page' });
  const next = pager.getByRole('button', { name: 'Next page' });
  await expect(rows).toHaveCount(10);
  await expect(rows.first()).toContainText('employee-01');
  await expect(rows.last()).toContainText('employee-10');
  await expect(pager).toContainText('Showing 1-10 of 12');
  await expect(previous).toBeDisabled();
  await expect(next).toBeEnabled();

  await next.click();
  await expect(rows).toHaveCount(2);
  await expect(rows.first()).toContainText('employee-11');
  await expect(rows.last()).toContainText('employee-12');
  await expect(pager).toContainText('Showing 11-12 of 12');
  await expect(previous).toBeEnabled();
  await expect(next).toBeDisabled();

  const destinations = page.locator('.app-panel').filter({
    has: page.getByRole('heading', { name: 'AI Destinations', exact: true }),
  });
  await expect(destinations.locator('tbody tr')).toHaveCount(1);
  await expect(destinations.locator('tbody tr')).toContainText('governed.ai.example.test');
  await expect(destinations.locator('.table-pager')).toContainText('Showing 1-1 of 1');
});
