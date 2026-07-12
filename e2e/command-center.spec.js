'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');
const serverPosture = require('../server/posture');
const { createDeferred } = require('./helpers/deferred');

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

function commandCenterPosture(overrides = {}) {
  const generatedAt = new Date().toISOString();
  return {
    generatedAt,
    metrics: [
      { id: 'active-sensors', label: 'Active sensors', value: '2/3', status: 'warning', lastUpdated: generatedAt },
      { id: 'controlled-sensitive', label: 'Control rate', value: 97, unit: '%', status: 'warning', lastUpdated: generatedAt },
    ],
    objectives: [],
    hardening: {
      score: 78,
      state: 'attention',
      areas: [],
      proofLedger: { verified: 4, attention: 1, missing: 1, total: 6 },
      mission: {
        title: 'Close current enforcement gaps',
        state: 'attention',
        status: '2 proof gaps',
        progress: { percent: 78 },
        proofLedger: { verified: 4, attention: 1, missing: 1, total: 6 },
        lanes: [],
      },
    },
    segments: {
      active: null,
      filters: [
        { id: 'all', typeLabel: 'All', label: 'All segments' },
        { id: 'lending', typeLabel: 'Team', label: 'Lending' },
      ],
      matrix: [],
      summary: { selectedId: 'all', visibleEvents: 12, attention: 2, privacy: 'metadata only; prompt bodies excluded' },
    },
    actionQueue: [
      {
        id: 'gap-1',
        severity: 'critical',
        category: 'Sensor coverage',
        label: 'Restore endpoint enforcement',
        detail: 'Sanitized control metadata only.',
        action: 'Open coverage',
        targetTab: 'coverage',
      },
    ],
    aiInventory: { summary: { activeDestinations: 0 }, apps: [], tools: [] },
    threatGuardrails: { summary: { events: 0, activeRules: 0, privacy: 'prompt bodies excluded' }, rules: [], controls: [], recent: [] },
    agenticMcp: { summary: { activeAgents: 0, activeTools: 0, controlled: 0, privacy: 'prompt bodies excluded' } },
    controlGraph: { summary: { nodes: 0, edges: 0, privacy: 'prompt bodies excluded' }, lanes: [], nodes: [], edges: [] },
    behaviorBaselines: { summary: { anomalies: 0, critical: 0, warning: 0 }, dimensions: [] },
    decisionQuality: { summary: { pendingReviews: 0 }, cards: [], hotspots: [] },
    surfaces: [
      { id: 'browser', name: 'Browser enforcement', source: 'browser_extension', status: 'online', health: 100, confidence: 99 },
      { id: 'endpoint', name: 'Endpoint enforcement', source: 'endpoint_agent', status: 'warning', health: 62, confidence: 95 },
    ],
    events: [],
    trend: [],
    controls: [],
    ...overrides,
  };
}

function completeCommandCenterPosture() {
  return serverPosture.summarize({
    rows: [],
    policy: {},
    auditIntegrity: { ok: true, count: 0 },
    now: '2026-07-11T12:00:00.000Z',
    env: {},
  });
}

async function mockPosture(page, posture) {
  await page.route(/\/api\/posture\?/, (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(posture),
  }));
}

async function mockFeedback(page, reviewQueue = [
  { queryId: 'query-1', detectorId: 'US_SSN', detectorIds: ['US_SSN'], destination: 'chat.example.test', status: 'pending', riskScore: 90, canFeedback: true },
]) {
  await page.route('**/api/detector-feedback/report?**', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      summary: { valid: 1, noisy: 0, reviewCandidates: reviewQueue.length, privacy: 'metadata only; prompt bodies excluded' },
      detectors: [],
      reviewQueue,
    }),
  }));
}

function scopedPosture(id, label, visibleEvents) {
  const report = commandCenterPosture();
  return {
    ...report,
    segments: {
      ...report.segments,
      active: id === 'all' ? null : { id, typeLabel: 'Team', label, state: 'attention', score: 78 },
      summary: { ...report.segments.summary, selectedId: id, visibleEvents },
    },
  };
}

function isZipArchive(bytes) {
  if (bytes.length < 22 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) return false;
  const searchStart = Math.max(0, bytes.length - 65_557);
  for (let index = bytes.length - 22; index >= searchStart; index -= 1) {
    if (bytes[index] !== 0x50 || bytes[index + 1] !== 0x4b || bytes[index + 2] !== 0x05 || bytes[index + 3] !== 0x06) continue;
    const commentLength = bytes[index + 20] | (bytes[index + 21] << 8);
    return index + 22 + commentLength === bytes.length;
  }
  return false;
}

async function createApprover(page) {
  const user = `command-center-approver-${Date.now()}@example.test`;
  const password = 'Command-Center-Approver-2026!';
  const result = await page.evaluate(async ({ userName, nextPassword }) => {
    const csrf = await fetch('/api/csrf').then((response) => response.json());
    const inviteResponse = await fetch('/api/admin/users/invitations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
      body: JSON.stringify({ userName, displayName: 'Command Center Approver', role: 'approver', reason: 'Command Center role matrix test' }),
    });
    const invite = await inviteResponse.json();
    const token = new URL(invite.inviteUrl, location.origin).hash.slice('#token='.length);
    const acceptResponse = await fetch('/api/invitations/accept', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, password: nextPassword, displayName: 'Command Center Approver' }),
    });
    return { inviteStatus: inviteResponse.status, acceptStatus: acceptResponse.status };
  }, { userName: user, nextPassword: password });
  expect(result).toEqual({ inviteStatus: 201, acceptStatus: 200 });
  await page.context().clearCookies();
  return { user, password };
}

async function endpointOutcomes(page) {
  return page.evaluate(async () => {
    const csrf = await fetch('/api/csrf').then((response) => response.json());
    const call = async (path, method = 'GET', body) => {
      const response = await fetch(path, {
        method,
        headers: method === 'GET' ? undefined : { 'Content-Type': 'application/json', 'x-csrf-token': csrf.csrfToken },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      await response.arrayBuffer();
      return response.status;
    };
    return {
      postureAction: await call('/api/posture/actions', 'POST', { id: 'command-center-role-check', status: 'resolved', note: 'role_matrix_test' }),
      detectorFeedback: await call('/api/queries/not-found/detector-feedback', 'POST', { detectorId: 'US_SSN', verdict: 'valid', reason: 'role_matrix_test' }),
      socSnapshot: await call('/api/posture/notify', 'POST'),
      siem: await call('/api/integrations/siem/package?profile=all'),
    };
  });
}

test('Command Center starts with operator answers and preserves live task contracts', async ({ page }) => {
  await loginAs(page);
  await mockPosture(page, commandCenterPosture());
  let actionPayload = null;
  await page.route('**/api/posture/actions', (route) => {
    actionPayload = route.request().postDataJSON();
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });

  await page.goto('/app/#/monitor');
  await expect(page.getByRole('heading', { name: 'Texas FCU Command Center' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'What needs attention now' })).toBeVisible();
  for (const label of ['Enforcement health', 'Urgent actions', 'Active scope', 'Sensor coverage', 'Evidence freshness']) {
    const brief = page.getByRole('article', { name: label });
    await expect(brief.getByText(label, { exact: true })).toBeVisible();
    await expect(brief).toBeVisible();
  }
  const briefLinks = page.locator('.command-brief-link');
  await expect(briefLinks).toHaveCount(5);
  for (const link of await briefLinks.all()) {
    const box = await link.boundingBox();
    expect(box?.height || 0).toBeGreaterThanOrEqual(24);
  }
  await expect(page.getByText('prompt bodies, finding values, and token-vault data stay excluded', { exact: false })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Urgent Action Queue' })).toBeVisible();
  await expect(page.getByText('Restore endpoint enforcement')).toBeVisible();

  for (const workspace of await page.locator('.monitor-workspace').all()) {
    await expect(workspace).toHaveJSProperty('open', false);
  }
  await page.getByRole('button', { name: 'Review enforcement' }).click();
  await expect(page.locator('#workspace-enforcement')).toHaveJSProperty('open', true);
  await expect(page.locator('#workspace-enforcement > summary')).toBeFocused();
  await page.locator('#workspace-enforcement > summary').click();
  await expect(page.getByRole('heading', { name: 'AI Vendor Inventory' })).toBeHidden();
  await page.getByRole('button', { name: /AI estate & guardrails/ }).click();
  await expect(page.locator('#workspace-estate')).toHaveJSProperty('open', true);
  await expect(page.getByRole('heading', { name: 'AI Vendor Inventory' })).toBeVisible();

  await page.getByRole('button', { name: 'Assign to me' }).click();
  await expect.poll(() => actionPayload).toEqual({
    id: 'gap-1',
    status: 'assigned',
    owner: 'admin',
    note: 'assigned_from_command_center',
  });
});

test('resolved actions with pending proof remain urgent until evidence lands', async ({ page }) => {
  await loginAs(page);
  await mockPosture(page, commandCenterPosture({
    actionQueue: [{
      id: 'proof-gap',
      severity: 'info',
      category: 'Examiner evidence',
      label: 'Attach remediation proof',
      detail: 'Resolution recorded; proof has not been verified.',
      workflowStatus: 'resolved',
      workflowProofState: 'proof_pending',
    }],
  }));
  await page.goto('/app/#/monitor');

  const urgent = page.getByRole('article', { name: 'Urgent actions' });
  await expect(urgent).toContainText('1 open');
  await expect(urgent).toContainText('1 proof pending');
  await expect(urgent).not.toContainText('Clear');
  await expect(urgent).toHaveClass(/tone-attention/);
});

test('scope label changes only after a verified response and survives a failed switch', async ({ page }) => {
  await loginAs(page);
  const lendingGate = createDeferred();
  const failureGate = createDeferred();
  let lendingVerified = false;
  await page.route(/\/api\/posture\?/, async (route) => {
    const segment = new URL(route.request().url()).searchParams.get('segment') || 'all';
    if (segment === 'lending') {
      await lendingGate.promise;
      lendingVerified = true;
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(scopedPosture('lending', 'Lending', 4)) });
    }
    if (lendingVerified) {
      await failureGate.promise;
      return route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"temporarily_unavailable"}' });
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(scopedPosture('all', 'All activity', 12)) });
  });
  try {
    await page.goto('/app/#/monitor');

    const scope = page.getByRole('article', { name: 'Active scope' });
    await expect(scope.locator('strong')).toHaveText('All activity');
    await page.getByLabel('Command center scope').selectOption('lending');
    await expect(scope.locator('strong')).toHaveText('All activity');
    await expect(scope).toContainText('Switching to Lending; showing verified All activity');

    lendingGate.release();
    await expect(scope.locator('strong')).toHaveText('Lending');
    await expect(scope).toContainText('Showing verified Lending');

    await page.getByLabel('Command center scope').selectOption('all');
    await expect(scope.locator('strong')).toHaveText('Lending');
    await expect(scope).toContainText('Switching to All activity; showing verified Lending');
    failureGate.release();
    await expect(page.getByRole('alert')).toContainText('last verified snapshot');
    await expect(scope.locator('strong')).toHaveText('Lending');
    await expect(scope).toContainText('Switch failed; showing last verified Lending');
  } finally {
    lendingGate.release();
    failureGate.release();
  }
});

for (const bindingCase of ['missing', 'active-only', 'conflicting', 'mismatched']) {
  test(`${bindingCase} scope binding cannot replace the verified scope`, async ({ page }) => {
    await loginAs(page);
    await page.route(/\/api\/posture\?/, (route) => {
      const segment = new URL(route.request().url()).searchParams.get('segment') || 'all';
      if (segment !== 'lending') {
        return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(scopedPosture('all', 'All activity', 12)) });
      }
      const lending = scopedPosture('lending', 'Lending', 4);
      const invalid = bindingCase === 'missing' || bindingCase === 'active-only'
        ? {
            ...lending,
            segments: {
              ...lending.segments,
              active: bindingCase === 'missing' ? null : lending.segments.active,
              summary: { visibleEvents: 4, attention: 1, privacy: 'metadata only; prompt bodies excluded' },
            },
          }
        : bindingCase === 'conflicting'
          ? {
              ...lending,
              segments: {
                ...lending.segments,
                active: { id: 'all', typeLabel: 'All', label: 'All activity', state: 'ready', score: 100 },
              },
            }
          : scopedPosture('all', 'All activity', 12);
      return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(invalid) });
    });
    await page.goto('/app/#/monitor');

    const scope = page.getByRole('article', { name: 'Active scope' });
    await expect(scope.locator('strong')).toHaveText('All activity');
    await page.getByLabel('Command center scope').selectOption('lending');

    await expect(page.getByRole('alert')).toContainText('last verified snapshot');
    await expect(scope.locator('strong')).toHaveText('All activity');
    await expect(scope).toContainText('Switch failed; showing last verified All activity');
  });
}

test('failed refresh of the current scope identifies the last verified snapshot', async ({ page }) => {
  await loginAs(page);
  let failRefresh = false;
  await page.route(/\/api\/posture\?/, (route) => {
    if (failRefresh) {
      return route.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"temporarily_unavailable"}' });
    }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(scopedPosture('all', 'All activity', 12)) });
  });
  await page.goto('/app/#/monitor');

  const scope = page.getByRole('article', { name: 'Active scope' });
  await expect(scope).toContainText('Showing verified All activity');
  failRefresh = true;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();

  await expect(page.getByRole('alert')).toContainText('last verified snapshot');
  await expect(scope.locator('strong')).toHaveText('All activity');
  await expect(scope).toContainText('Refresh failed; showing last verified All activity');
});

test('partial posture is explicit, compact, and responsive instead of a false all-clear', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 740 });
  await loginAs(page);
  const partial = commandCenterPosture({
    metrics: undefined,
    actionQueue: undefined,
    hardening: undefined,
    surfaces: [],
  });
  await mockPosture(page, partial);

  await page.goto('/app/#/monitor');
  await expect(page.getByRole('heading', { name: 'What needs attention now' })).toBeVisible();
  await expect(page.getByText('Action status not reported')).toBeVisible();
  await expect(page.getByText('All clear', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Not reported', { exact: true }).first()).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  await page.screenshot({ path: testInfo.outputPath('command-center-partial-mobile.png'), fullPage: true });
});

test('a complete server-shaped posture reaches a current ready or attention state', async ({ page }) => {
  await loginAs(page);
  await mockPosture(page, completeCommandCenterPosture());
  await page.goto('/app/#/monitor');

  await expect(page.locator('.signal-live-summary')).toContainText(/LIVE|ATTENTION/);
  await expect(page.locator('.signal-live-summary')).not.toContainText('PARTIAL');
  await expect(page.locator('.signal-console-header .signal-updated')).toContainText('UPDATED');
  await expect(page.getByText(/scope-verified but incomplete/i)).toHaveCount(0);
});

for (const incompleteFamily of [
  {
    name: 'mission progress',
    mutate(report) { report.hardening.mission.progress = { percent: 50 }; },
  },
  {
    name: 'hardening proof rows',
    mutate(report) { delete report.hardening.areas[0].proofs; },
  },
  {
    name: 'action workflow proof state',
    mutate(report) { delete report.actionQueue[0].workflowProofState; },
  },
  {
    name: 'scoped active segment',
    segment: 'group:no-current-evidence',
    build() {
      const report = serverPosture.summarize({
        rows: [], policy: {}, auditIntegrity: { ok: true, count: 0 },
        segmentId: 'group:no-current-evidence', now: '2026-07-11T12:00:00.000Z', env: {},
      });
      report.segments.active = null;
      return report;
    },
  },
  {
    name: 'selected segment filter',
    segment: 'group:no-current-evidence',
    build() {
      const report = serverPosture.summarize({
        rows: [], policy: {}, auditIntegrity: { ok: true, count: 0 },
        segmentId: 'group:no-current-evidence', now: '2026-07-11T12:00:00.000Z', env: {},
      });
      report.segments.filters = report.segments.filters.filter((item) => item.id !== report.segments.summary.selectedId);
      return report;
    },
  },
  {
    name: 'valid segment state',
    mutate(report) { report.segments.matrix[0].state = 'unexpected_green_state'; },
  },
]) {
  test(`missing ${incompleteFamily.name} keeps a scope-verified snapshot PARTIAL`, async ({ page }) => {
    await loginAs(page);
    const report = incompleteFamily.build
      ? incompleteFamily.build()
      : JSON.parse(JSON.stringify(completeCommandCenterPosture()));
    incompleteFamily.mutate?.(report);
    if (incompleteFamily.segment) {
      const initial = completeCommandCenterPosture();
      const selected = report.segments.filters.find((item) => item.id === incompleteFamily.segment)
        || report.segments.matrix.find((item) => item.id === incompleteFamily.segment);
      initial.segments.filters.push({
        id: selected.id,
        typeLabel: selected.typeLabel,
        label: selected.label,
        state: selected.state,
        events: selected.events,
        controlRate: selected.controlRate,
      });
      await page.route(/\/api\/posture\?/, (route) => {
        const segment = new URL(route.request().url()).searchParams.get('segment') || 'all';
        return route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(segment === incompleteFamily.segment ? report : initial),
        });
      });
    } else {
      await mockPosture(page, report);
    }
    await page.goto('/app/#/monitor');
    if (incompleteFamily.segment) {
      await page.getByLabel('Command center scope').selectOption(incompleteFamily.segment);
    }

    await expect(page.locator('.signal-live-summary')).toContainText('PARTIAL');
    await expect(page.locator('.signal-live-summary')).not.toContainText('LIVE');
    await expect(page.getByRole('alert')).toContainText('scope-verified but incomplete');
  });
}

test('incomplete and contradictory workspace fields never become zero or complete claims', async ({ page }) => {
  await loginAs(page);
  await mockPosture(page, commandCenterPosture({
    metrics: undefined,
    objectives: undefined,
    actionQueue: [{
      id: 'resolution-without-proof-state',
      severity: 'info',
      label: 'Resolution awaiting proof state',
      workflowStatus: 'resolved',
    }],
    hardening: {
      mission: { title: 'Incomplete mission payload' },
      areas: [{ id: 'incomplete-area', label: 'Incomplete hardening area' }],
    },
    aiInventory: {
      summary: { sanctioned: 1, shadow: 0, highRiskAssets: 0, unapprovedLocalTools: 0, activeDestinations: 0 },
      apps: [],
      tools: [],
    },
    agenticMcp: {
      summary: { events: 1, activeAgents: 1, activeTools: 0, controlled: 0, blocked: 0, registryMode: 'observe_with_blocks' },
      agents: [{ id: 'partial-agent', name: 'Partial agent' }],
      tools: [],
      connectorRegistry: {
        summary: { shipped: 0, profiles: 0, profileTemplates: 0, shippedRuntimePresent: 0, installProof: false, nextConnector: 'none' },
        profiles: [],
      },
      requests: [],
      policy: {
        registryMode: 'observe_with_blocks',
        allowed: { count: 0, examples: [] },
        blocked: { count: 0, examples: [] },
        approvalRequired: { count: 0, examples: [] },
      },
    },
    threatGuardrails: {
      summary: { events: 0, detections: 0, activeRules: 1, blocked: 0, critical: 0, promptInjection: 0, unsafeOutput: 0 },
      rules: [],
      controls: [],
      recent: [],
    },
    controlGraph: {
      summary: { nodes: 1, edges: 0, highRiskAssets: 0, shadowAssets: 0, mcpLinks: 0, controlledLinks: 0 },
      lanes: [],
      nodes: [],
      edges: [],
    },
    behaviorBaselines: { summary: { activeEvents: 1, anomalies: 1, critical: 0, warning: 0 }, dimensions: [] },
    decisionQuality: {
      summary: { controlRate: 100, pendingReviews: 0, overrideWatch: 0 },
      cards: [{ id: 'partial-card', label: 'Partial score card' }],
      hotspots: [],
    },
    trend: [{ date: '2026-07-11' }],
    controls: [{ label: 'Partial control' }],
    surfaces: [{ id: 'partial-surface', name: 'Partial surface' }],
    events: [{ id: 'partial-event', title: 'Partial event' }],
  }));
  await page.goto('/app/#/monitor');

  await expect(page.locator('.signal-live-summary')).toContainText('PARTIAL');
  await expect(page.locator('.signal-live-summary')).not.toContainText('LIVE');
  await expect(page.getByRole('alert')).toContainText('scope-verified but incomplete');

  const urgent = page.getByRole('article', { name: 'Urgent actions' });
  await expect(urgent).toContainText('1 open');
  await expect(urgent).toContainText('proof status not reported');
  await expect(urgent).not.toContainText('Clear');

  const enforcementSummary = page.locator('#workspace-enforcement > summary');
  await expect(enforcementSummary).toContainText('metrics not reported');
  await expect(enforcementSummary).toContainText('objectives not reported');
  await enforcementSummary.click();
  await expect(page.getByText('Posture metrics not reported', { exact: true })).toBeVisible();
  await expect(page.getByText('Posture objectives not reported', { exact: true })).toBeVisible();
  await expect(page.getByText('Operator flow not reported', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('Progress not reported', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Current mission step not reported' })).toBeVisible();
  await expect(page.locator('#workspace-enforcement').getByText('Proof ledger not reported', { exact: true })).toBeVisible();
  await expect(page.getByText('Deployment proof complete', { exact: true })).toHaveCount(0);
  await expect(page.getByText('All proof rows are verified.', { exact: true })).toHaveCount(0);

  await expect(page.locator('#workspace-estate > summary')).toContainText('assets not reported');
  await expect(page.locator('#workspace-estate > summary')).toContainText('threat events not reported');
  await expect(page.locator('#workspace-estate > summary')).toContainText('graph nodes not reported');
  await expect(page.locator('#workspace-intelligence > summary')).toContainText('trend days not reported');
  await expect(page.locator('#workspace-intelligence > summary')).toContainText('control paths not reported');
  await expect(page.locator('#workspace-live > summary')).toContainText('surfaces not reported');
  await expect(page.locator('#workspace-live > summary')).toContainText('recent events not reported');

  await page.getByRole('button', { name: /AI estate & guardrails/ }).click();
  const estate = page.locator('#workspace-estate');
  for (const message of [
    'AI inventory not reported',
    'MCP control details not reported',
    'AI threat guardrails not reported',
    'AI control graph not reported',
  ]) {
    await expect(estate.getByText(message, { exact: true }).first()).toBeVisible();
  }
  await expect(estate).not.toContainText('No AI inventory');
  await expect(estate).not.toContainText('No agents');
  await expect(estate).not.toContainText('No active rules');
  await expect(estate).not.toContainText('No graph');

  await page.getByRole('button', { name: /Decision intelligence/ }).click();
  const intelligence = page.locator('#workspace-intelligence');
  for (const message of [
    'Risk trend not reported',
    'Control outcomes not reported',
    'Behavior baselines not reported',
    'Reviewer decision quality not reported',
  ]) {
    await expect(intelligence.getByText(message, { exact: true }).first()).toBeVisible();
  }
  await expect(intelligence).not.toContainText('No behavior anomalies');
  await expect(intelligence).not.toContainText('No reviewer decision hotspots');

  await page.getByRole('button', { name: /Live signals/ }).click();
  const live = page.locator('#workspace-live');
  await expect(live.getByText('Surfaces not reported', { exact: true }).first()).toBeVisible();
  await expect(live.getByText('Activity events not reported', { exact: true }).first()).toBeVisible();
  await expect(live).not.toContainText('No events');
  await expect(live.locator('.signal-toolbar .signal-chip b')).toHaveText(['—', '—', '—', '—', '—', '—', '—']);
  await expect(live.locator('.signal-toolbar .signal-chip')).toHaveCount(7);
  for (const chip of await live.locator('.signal-toolbar .signal-chip').all()) await expect(chip).toBeDisabled();

  await page.getByRole('button', { name: /Evidence operations/ }).click();
  const area = page.getByRole('article').filter({ hasText: 'Incomplete hardening area' });
  await expect(area).toContainText('Not reported');
  await expect(area).toContainText('Proof state not reported');
  await expect(area).toContainText('Gap state not reported');
  await expect(area).toContainText('Proof rows not reported.');
  await expect(area).toContainText('Runbook steps not reported.');
  await expect(area).not.toContainText('No open gaps');
  await expect(area).not.toContainText('No remediation steps published.');
});

test('auxiliary API failures do not render invented zero activity or feedback counts', async ({ page }) => {
  await loginAs(page);
  await mockPosture(page, commandCenterPosture());
  for (const pattern of ['**/api/queries?**', '**/api/detector-feedback/report?**']) {
    await page.route(pattern, (route) => route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: '{"error":"temporarily_unavailable"}',
    }));
  }
  await page.goto('/app/#/monitor');
  await page.getByRole('button', { name: /Decision intelligence/ }).click();

  await expect(page.getByText('Activity unavailable', { exact: true })).toBeVisible();
  await expect(page.locator('.decision-pivots b')).toHaveText([
    'Not reported',
    'Not reported',
    'Not reported',
    'Not reported',
    'Not reported',
    'Not reported',
    'Not reported',
  ]);
  await expect(page.locator('#detectorFeedbackRows').getByText('Detector feedback unavailable', { exact: true })).toBeVisible();
  await expect(page.locator('#workspace-intelligence > summary')).toContainText('Activity unavailable');
  await expect(page.locator('#workspace-intelligence > summary')).toContainText('Detector feedback unavailable');
});

test('SOC snapshot preserves a cached license denial instead of reporting not configured', async ({ page }) => {
  await loginAs(page);
  await mockPosture(page, commandCenterPosture());
  await page.route('**/api/posture/notify', (route) => route.fulfill({
    status: 403,
    contentType: 'application/json',
    body: '{"error":"license_readonly"}',
  }));
  await page.goto('/app/#/monitor');
  await page.getByRole('button', { name: /Evidence operations/ }).click();

  const workbench = page.locator('.signal-section').filter({ hasText: 'Hardening Workbench' });
  await workbench.getByRole('button', { name: 'Send SOC snapshot' }).click();
  await expect(workbench.locator('.signal-updated')).toHaveText('NOT SENT - request failed: license readonly');
  await expect(workbench.locator('.signal-updated')).not.toContainText('not configured');
});

test('approver detector feedback controls honor candidate-specific authority', async ({ page }) => {
  await loginAs(page);
  const approver = await createApprover(page);
  await loginAs(page, approver.user, approver.password);
  await mockPosture(page, commandCenterPosture());
  await mockFeedback(page, [
    { queryId: 'owned-query', detectorId: 'US_SSN', detectorIds: ['US_SSN'], destination: 'owned.example.test', status: 'pending', riskScore: 90, canFeedback: true },
    { queryId: 'other-query', detectorId: 'SECRET_KEY', detectorIds: ['SECRET_KEY'], destination: 'other.example.test', status: 'pending', riskScore: 80, canFeedback: false },
  ]);
  await page.goto('/app/#/monitor');
  await page.getByRole('button', { name: /Decision intelligence/ }).click();

  const owned = page.locator('#detectorFeedbackRows .control-row').filter({ hasText: 'owned.example.test' });
  const other = page.locator('#detectorFeedbackRows .control-row').filter({ hasText: 'other.example.test' });
  await expect(owned.getByRole('button', { name: 'Valid' })).toBeEnabled();
  await expect(owned.getByRole('button', { name: 'Noisy' })).toBeEnabled();
  await expect(other.getByRole('button', { name: 'Valid' })).toBeDisabled();
  await expect(other.getByRole('button', { name: 'Noisy' })).toBeDisabled();
  await expect(other).toContainText('Assigned to another reviewer or role.');
});

test('Security Admin downloads a real, valid SIEM integration archive', async ({ page }) => {
  await loginAs(page);
  await mockPosture(page, commandCenterPosture());
  await mockFeedback(page);
  await page.goto('/app/#/monitor');
  await page.getByRole('button', { name: /Evidence operations/ }).click();

  const downloadButton = page.getByRole('button', { name: 'Download ZIP' });
  await expect(downloadButton).toBeEnabled();
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    downloadButton.click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^redactwall-siem-(all|[a-z0-9_-]+)-package\.zip$/);
  const downloadPath = await download.path();
  expect(downloadPath).toBeTruthy();
  const bytes = fs.readFileSync(downloadPath);
  expect(isZipArchive(bytes)).toBe(true);
});

async function assertCapabilityMatrix(page, expected) {
  await mockPosture(page, commandCenterPosture());
  await mockFeedback(page);
  await page.goto('/app/#/monitor');

  const postureAction = page.getByRole('button', { name: 'Assign to me' });
  if (expected.postureActions) await expect(postureAction).toBeEnabled();
  else await expect(postureAction).toBeDisabled();

  await page.getByRole('button', { name: /Decision intelligence/ }).click();
  const detectorFeedback = page.getByRole('button', { name: 'Valid' });
  if (expected.detectorFeedback) await expect(detectorFeedback).toBeEnabled();
  else await expect(detectorFeedback).toBeDisabled();

  await page.getByRole('button', { name: /Evidence operations/ }).click();
  const snapshot = page.getByRole('button', { name: 'Send SOC snapshot' });
  const siem = page.getByLabel('SIEM package profile');
  if (expected.socSnapshot) await expect(snapshot).toBeEnabled();
  else await expect(snapshot).toBeDisabled();
  if (expected.siem) await expect(siem).toBeEnabled();
  else await expect(siem).toBeDisabled();

  const permissionNotes = page.locator('.monitor-permission-note');
  await expect(permissionNotes).toHaveCount(expected.permissionCopy.length);
  for (const copy of expected.permissionCopy) {
    const note = permissionNotes.filter({ hasText: copy });
    await expect(note).toBeVisible();
    await expect(note).toHaveAttribute('tabindex', '0');
    await note.focus();
    await expect(note).toBeFocused();
  }

  const outcomes = await endpointOutcomes(page);
  expect(outcomes.postureAction).toBe(expected.postureEndpoint);
  expect(outcomes.detectorFeedback).toBe(expected.detectorEndpoint);
  expect(expected.snapshotEndpoints).toContain(outcomes.socSnapshot);
  expect(outcomes.siem).toBe(expected.siemEndpoint);
}

for (const account of [
  {
    role: 'security_admin', user: 'admin', password: 'e2e-pass',
    postureActions: true, detectorFeedback: true, socSnapshot: true, siem: true,
    permissionCopy: [],
    postureEndpoint: 200, detectorEndpoint: 404, snapshotEndpoints: [200, 202], siemEndpoint: 200,
  },
  {
    role: 'operator', user: 'e2e-operator', password: 'e2e-operator-pass',
    postureActions: true, detectorFeedback: false, socSnapshot: false, siem: false,
    permissionCopy: [
      'Security Admin or Member Data Reviewer access is required to submit detector feedback.',
      'Security Admin access is required to send SOC snapshots.',
      'Security Admin or Auditor access is required to prepare or download SIEM packages.',
    ],
    postureEndpoint: 200, detectorEndpoint: 403, snapshotEndpoints: [403], siemEndpoint: 403,
  },
  {
    role: 'auditor', user: 'e2e-auditor', password: 'e2e-auditor-pass',
    postureActions: false, detectorFeedback: false, socSnapshot: false, siem: true,
    permissionCopy: [
      'Security Admin or Operations Administrator access is required to update posture actions.',
      'Security Admin or Member Data Reviewer access is required to submit detector feedback.',
      'Security Admin access is required to send SOC snapshots.',
    ],
    postureEndpoint: 403, detectorEndpoint: 403, snapshotEndpoints: [403], siemEndpoint: 200,
  },
]) {
  test(`${account.role} Command Center capabilities match real route outcomes`, async ({ page }) => {
    await loginAs(page, account.user, account.password);
    await assertCapabilityMatrix(page, account);
  });
}

test('approver Command Center capabilities match real decision route outcomes', async ({ page }) => {
  await loginAs(page);
  const approver = await createApprover(page);
  await loginAs(page, approver.user, approver.password);
  await assertCapabilityMatrix(page, {
    postureActions: false,
    detectorFeedback: true,
    socSnapshot: false,
    siem: false,
    permissionCopy: [
      'Security Admin or Operations Administrator access is required to update posture actions.',
      'Security Admin access is required to send SOC snapshots.',
      'Security Admin or Auditor access is required to prepare or download SIEM packages.',
    ],
    postureEndpoint: 403,
    detectorEndpoint: 404,
    snapshotEndpoints: [403],
    siemEndpoint: 403,
  });
});
