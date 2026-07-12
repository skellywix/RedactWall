'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

const EXAMINER_PATH = '/api/export/evidence?examinerProfile=federal_credit_union';
const CONTROL_IDS = [
  'ai_prompt_dlp',
  'local_detection_minimization',
  'approval_workflow',
  'tamper_evident_audit',
  'fleet_sensor_coverage',
  'backup_recoverability',
  'ai_usage_governance',
  'prompt_threat_defense',
  'ai_activity_recordkeeping',
  'member_information_safeguards',
  'ai_use_inventory',
  'vendor_service_provider_oversight',
  'incident_readiness',
  'board_reporting',
  'ai_acceptable_use',
];

async function loginAs(page, user = 'admin', password = 'e2e-pass') {
  await page.goto('/login.html');
  await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function openNcua(page) {
  await page.goto('/app/#/ncua');
  await expect(page.getByRole('heading', { name: 'Texas FCU Readiness' })).toBeVisible();
  await expect(page.getByText('Scoring NCUA readiness…')).toHaveCount(0);
}

async function responseText(download) {
  const stream = await download.createReadStream();
  expect(stream).toBeTruthy();
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
}

function promptFreeFamilies() {
  return {
    memberData: {
      identifiers: ['US_SSN', 'MEMBER_ID', 'LOAN_NUMBER', 'BANK_ACCOUNT', 'ROUTING_NUMBER'],
      events: 10,
      prevented: 8,
      redacted: 1,
      released: 1,
    },
    shadowAi: {
      totalApps: 5,
      sanctioned: 2,
      underReview: 1,
      tolerated: 1,
      unsanctioned: 1,
      blocked: 0,
      unreviewedEvents: 3,
    },
    useCases: {
      total: 4,
      approved: 2,
      underReview: 1,
      restricted: 0,
      retired: 1,
      overdue: 1,
      activeTotal: 3,
      vendorReviewed: 2,
      vendorPending: 1,
      vendorNotReviewed: 0,
    },
    incidents: { total: 3, open: 1, underReview: 0, reported: 1, closed: 1, overdue: 1, reportedLate: 1 },
    exceptions: { total: 2, active: 1, expiringSoon: 1, reviewDue: 0, expired: 0, disabled: 1 },
    exportHealth: {
      scheduled: true,
      cadence: 'monthly',
      nextRunAt: '2026-08-01T12:00:00.000Z',
      retentionDays: 365,
    },
    audit: { verified: true, count: 100 },
  };
}

function validReadinessResponse() {
  const families = promptFreeFamilies();
  return {
    entitled: true,
    report: {
      profile: 'federal_credit_union',
      generatedAt: '2026-07-11T12:00:00.000Z',
      score: 100,
      state: 'ready',
      controls: CONTROL_IDS.map((id) => ({
        id,
        title: `Verified ${id}`,
        state: 'covered',
        controlFamilies: ['NCUA evidence'],
        summary: 'Verified prompt-free evidence is available.',
      })),
      panels: { ...families, edm: { configured: true, enabled: true, active: true, fingerprints: 12, minLength: 16, severity: 4 } },
      nextActions: [],
    },
  };
}

function validBoardPacket() {
  return {
    generatedAt: '2026-07-11T12:00:00.000Z',
    profile: 'federal_credit_union',
    readiness: { score: 97, state: 'ready' },
    ...promptFreeFamilies(),
    seats: {
      tenantId: 'tenant-1',
      saasMode: true,
      seatLimit: 25,
      seatsUsed: 12,
      seatsRemaining: 13,
      overLimit: false,
      trueUp: { licensedSeats: 25, configuredLimit: 25, seatsUsed: 12, mismatch: false },
      users: [{ user: 'must-not-leave-the-console' }],
    },
    license: { state: 'active', plan: 'enterprise', expires: '2027-07-11T12:00:00.000Z' },
    secret: 'must-not-be-saved',
  };
}

for (const account of [
  { label: 'security admin', user: 'admin', password: 'e2e-pass' },
  { label: 'auditor', user: 'e2e-auditor', password: 'e2e-auditor-pass' },
]) {
  test(`${account.label} receives both export controls and examiner endpoint access`, async ({ page }) => {
    await loginAs(page, account.user, account.password);
    await openNcua(page);

    const examiner = page.getByRole('link', { name: 'Export examiner pack' });
    await expect(examiner).toHaveAttribute('href', EXAMINER_PATH);
    await expect(page.getByRole('button', { name: 'Board packet', exact: true })).toBeEnabled();
    await expect(page.locator('#ncuaExaminerPermission')).toHaveCount(0);
    await expect(page.locator('#ncuaBoardPermission')).toHaveCount(0);

    const endpoint = await page.context().request.get(EXAMINER_PATH);
    expect(endpoint.status()).toBe(200);
    await endpoint.dispose();
  });
}

test('operator can read readiness but cannot invoke either restricted export', async ({ page }) => {
  await loginAs(page, 'e2e-operator', 'e2e-operator-pass');
  let boardRequests = 0;
  await page.route('**/api/ncua/board-packet', async (route) => {
    boardRequests += 1;
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  await openNcua(page);

  await expect(page.getByRole('button', { name: 'Export examiner pack' })).toBeDisabled();
  await expect(page.getByRole('link', { name: 'Export examiner pack' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Board packet', exact: true })).toBeDisabled();
  await expect(page.locator('#ncuaExaminerPermission')).toContainText('Global Administrator or Examiner/Auditor');
  await expect(page.locator('#ncuaBoardPermission')).toContainText('Global Administrator or Examiner/Auditor');
  expect(boardRequests).toBe(0);

  const endpoint = await page.context().request.get(EXAMINER_PATH);
  expect(endpoint.status()).toBe(403);
  await endpoint.dispose();
});

test('approver role simulation keeps readiness readable and both exports disabled', async ({ page }) => {
  await loginAs(page);
  await page.route('**/api/me', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      user: 'simulated-approver',
      role: 'approver',
      authProvider: 'local',
      defaultPassword: false,
    }),
  }));
  await page.goto('/app/?role=approver#/ncua');
  await expect(page.getByRole('heading', { name: 'Texas FCU Readiness' })).toBeVisible();

  await expect(page.getByRole('button', { name: 'Export examiner pack' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Board packet', exact: true })).toBeDisabled();
  await expect(page.locator('#ncuaExaminerPermission')).toContainText('Global Administrator or Examiner/Auditor');
  await expect(page.locator('#ncuaBoardPermission')).toContainText('Global Administrator or Examiner/Auditor');
});

test('unentitled auditor retains examiner export but receives an explicit board-packet license state', async ({ page }) => {
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  let boardRequests = 0;
  await page.route('**/api/ncua/readiness', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ entitled: false, report: null }),
  }));
  await page.route('**/api/ncua/board-packet', async (route) => {
    boardRequests += 1;
    await route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  await openNcua(page);

  await expect(page.getByRole('heading', { name: 'Not included in this license' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Export examiner pack' })).toHaveAttribute('href', EXAMINER_PATH);
  await expect(page.getByRole('button', { name: 'Board packet', exact: true })).toBeDisabled();
  await expect(page.locator('#ncuaBoardPermission')).toContainText('NCUA Readiness add-on');
  expect(boardRequests).toBe(0);
});

test('malformed nested readiness evidence is rejected without rendering a score or enabling board export', async ({ page }) => {
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  const response = validReadinessResponse();
  response.report.panels.audit = { verified: 'yes', count: 100 };
  response.report.controls[0].summary = '<img src=x onerror=alert(1)>';
  await page.route('**/api/ncua/readiness', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(response),
  }));
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  await openNcua(page);

  await expect(page.getByText('Readiness report malformed', { exact: true })).toBeVisible();
  await expect(page.getByText('No score, controls, or export entitlement was trusted.')).toBeVisible();
  await expect(page.getByText('100/100')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Board packet', exact: true })).toBeDisabled();
  await expect(page.locator('#ncuaBoardPermission')).toContainText('cannot be verified');
  expect(pageErrors).toEqual([]);
});

test('board packet reports authoritative 403, 503, and successful download outcomes', async ({ page }) => {
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  let outcome = 'denied';
  const requests = [];
  await page.route('**/api/ncua/board-packet', async (route) => {
    requests.push({ method: route.request().method(), csrf: route.request().headers()['x-csrf-token'] || '' });
    if (outcome === 'denied') {
      await route.fulfill({ status: 403, contentType: 'application/json', body: '{"error":"not_entitled"}' });
      return;
    }
    if (outcome === 'unavailable') {
      await route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"temporarily_unavailable"}' });
      return;
    }
    const packet = validBoardPacket();
    if (outcome === 'incomplete') delete packet.seats.trueUp;
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(packet) });
  });
  await openNcua(page);

  const button = page.getByRole('button', { name: 'Board packet', exact: true });
  const status = page.locator('#ncuaBoardStatus');
  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  await button.click();
  await expect(status).toContainText('export was denied');

  outcome = 'unavailable';
  await button.click();
  await expect(status).toContainText('export is unavailable');

  outcome = 'incomplete';
  await button.click();
  await expect(status).toContainText('response was malformed and was not saved');
  expect(downloads).toBe(0);

  outcome = 'success';
  const pendingDownload = page.waitForEvent('download');
  await button.click();
  const download = await pendingDownload;
  expect(download.suggestedFilename()).toMatch(/^redactwall-board-packet-\d{4}-\d{2}-\d{2}\.json$/);
  const packet = JSON.parse(await responseText(download));
  expect(packet.profile).toBe('federal_credit_union');
  expect(packet.readiness).toEqual({ score: 97, state: 'ready' });
  expect(packet.seats.users).toBeUndefined();
  expect(packet.secret).toBeUndefined();
  await expect(status).toContainText('download started');

  expect(requests).toHaveLength(4);
  expect(requests.every((request) => request.method === 'POST')).toBe(true);
  expect(requests.every((request) => request.csrf.length > 0)).toBe(true);
});
