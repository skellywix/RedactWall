'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');
const { createDeferred } = require('./helpers/deferred');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

async function login(page) {
  await page.goto('/login.html');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function createHeldPrompt(request) {
  const response = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: 'Synthetic overview-map wiring SSN 524-71-9613 before submission.',
      user: 'overview-map@example.test',
      destination: 'chat.openai.com',
      source: 'browser_extension',
      channel: 'submit',
      orgId: 'overview-map-org',
    },
  });
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body.status).toBe('pending');
  return body.id;
}

async function denyFixture(page, id) {
  await page.evaluate(async (queryId) => {
    const { csrfToken } = await (await fetch('/api/csrf')).json();
    await fetch(`/api/queries/${queryId}/deny`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
      body: JSON.stringify({ note: 'overview map test cleanup' }),
    });
  }, id);
}

function mapNode(id, label, overrides = {}) {
  const node = {
    id,
    label,
    status: 'online',
    events: 1,
    sensitive: 0,
    controlled: 0,
    blocked: 0,
    redacted: 0,
    coached: 0,
    pending: 0,
    shadow: 0,
    uncontrolled: 0,
    continued: 0,
    uncontrolledContinued: 0,
    users: 0,
    controlRate: 100,
    lastSeen: null,
    ...overrides,
  };
  if (!Object.prototype.hasOwnProperty.call(overrides, 'controlRate')) {
    node.controlRate = node.sensitive ? Math.round((node.controlled / node.sensitive) * 100) : 100;
  }
  if (!Object.prototype.hasOwnProperty.call(overrides, 'status')) {
    node.status = node.uncontrolled || node.shadow
      ? 'error'
      : node.pending
        ? 'warning'
        : node.events
          ? 'online'
          : 'idle';
  }
  return node;
}

function mapEdge(id, to, overrides) {
  return {
    ...mapNode(id, id, overrides),
    from: overrides?.from || 'org:texas-fcu',
    to,
    via: overrides?.via || 'browser_extension',
    viaLabel: overrides?.viaLabel || 'Browser',
    categories: [],
  };
}

function aggregateMapNodes(edges, key, typeLabel) {
  const byId = new Map();
  for (const edge of edges) {
    const id = edge[key];
    const counts = byId.get(id) || {
      events: 0, sensitive: 0, controlled: 0, blocked: 0, redacted: 0,
      coached: 0, pending: 0, shadow: 0, uncontrolled: 0, continued: 0,
      uncontrolledContinued: 0,
    };
    for (const count of Object.keys(counts)) counts[count] += edge[count];
    byId.set(id, counts);
  }
  return [...byId.entries()].map(([id, counts]) => mapNode(
    id,
    key === 'via' ? (edges.find((edge) => edge.via === id)?.viaLabel || id) : id,
    { ...counts, ...(typeLabel ? { typeLabel } : {}), ...(key === 'to' ? { state: 'observed' } : {}) },
  ));
}

function mapReport(edges = []) {
  const segments = aggregateMapNodes(edges, 'from', 'Organization');
  const channels = aggregateMapNodes(edges, 'via');
  const destinations = aggregateMapNodes(edges, 'to');
  const total = (key) => edges.reduce((sum, edge) => sum + edge[key], 0);
  const sensitive = total('sensitive');
  return {
    segments,
    channels,
    destinations,
    edges,
    categories: [],
    summary: {
      segments: segments.length,
      destinations: destinations.length,
      edges: edges.length,
      shownEdges: edges.length,
      events: total('events'),
      sensitive,
      controlled: total('controlled'),
      uncontrolled: total('uncontrolled'),
      continued: total('continued'),
      uncontrolledContinued: total('uncontrolledContinued'),
      pending: total('pending'),
      shadow: total('shadow'),
      controlRate: sensitive
        ? Math.round((total('controlled') / sensitive) * 100)
        : 100,
      status: edges.some((edge) => edge.uncontrolled || edge.shadow)
        ? 'error'
        : edges.some((edge) => edge.pending)
          ? 'warning'
          : edges.length
            ? 'online'
            : 'idle',
      privacy: 'prompt bodies excluded',
    },
  };
}

function postureBody(map) {
  return { leakMap: map, surfaces: [{ id: 'surface-audit-evidence', status: 'online', description: 'linked entries verified' }] };
}

async function mockPosture(page, body, status = 200) {
  await page.route('**/api/posture?*', (route) => route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  }));
}

function statsBody(overrides = {}) {
  return {
    total: 12,
    pending: 2,
    held: 3,
    approved: 3,
    denied: 1,
    allowed: 6,
    todayBlocked: 3,
    topEntities: [['US_SSN', 2]],
    ...overrides,
  };
}

async function mockStats(page, readResponse) {
  await page.route('**/api/stats', (route) => {
    const response = typeof readResponse === 'function' ? readResponse() : readResponse;
    return route.fulfill({
      status: response.status,
      contentType: 'application/json',
      body: JSON.stringify(response.body),
    });
  });
}

async function installControllableEventSource(page) {
  await page.addInitScript(() => {
    const sources = new Set();
    class ControllableEventSource extends EventTarget {
      constructor(url) {
        super();
        this.url = String(url);
        this.readyState = 1;
        sources.add(this);
      }

      close() {
        this.readyState = 2;
        sources.delete(this);
      }
    }
    window.EventSource = ControllableEventSource;
    window.__emitRedactWallEvent = (name, data) => {
      for (const source of sources) {
        source.dispatchEvent(new MessageEvent(name, { data: JSON.stringify(data) }));
      }
    };
  });
}

async function emitLiveEvent(page, name, data = {}) {
  await page.evaluate(({ eventName, eventData }) => {
    window.__emitRedactWallEvent(eventName, eventData);
  }, { eventName: name, eventData: data });
}

async function expectMapEdgeRendered(page, id) {
  const edge = page.locator(`[data-leak-edge="${id}"]`);
  await expect(edge).toHaveCount(1);
  await expect(edge.locator('[data-leak-leg="ingress"]')).toHaveAttribute('d', /^M /);
}

async function selectMapEdge(page, id) {
  const edge = page.locator(`[data-leak-edge="${id}"]`);
  await edge.focus();
  await edge.press('Enter');
}

test('overview map provides equivalent keyboard, details, viewport, and motion controls', async ({ page, request }, testInfo) => {
  const heldId = await createHeldPrompt(request);
  await login(page);
  try {
    await page.goto('/app/');
    const map = page.locator('.leak-map-section');
    await expect(map.getByRole('heading', { name: 'Texas FCU AI Exposure Map' })).toBeVisible();

    const edge = page.locator('#leakMapStage [data-leak-edge]').first();
    await edge.focus();
    await edge.press('Enter');
    await expect(edge).toHaveAttribute('aria-pressed', 'true');
    const node = page.locator('#leakMapStage [data-leak-node]').first();
    await node.focus();
    await node.press('Space');
    await expect(node).toHaveAttribute('aria-pressed', 'true');

    const viewport = page.locator('.leak-map-viewport');
    for (let step = 0; step < 4; step += 1) await page.getByRole('button', { name: 'Zoom in' }).click();
    await expect(page.getByLabel('Map zoom')).toHaveText('180%');
    await expect(page.getByRole('button', { name: 'Zoom in' })).toBeDisabled();
    const beforePan = await viewport.getAttribute('transform');
    await page.getByRole('button', { name: 'Pan map right' }).click();
    expect(await viewport.getAttribute('transform')).not.toBe(beforePan);
    await page.getByRole('button', { name: 'Pan map left' }).click();
    await expect(viewport).toHaveAttribute('transform', beforePan);
    await page.getByRole('button', { name: 'Pan map up' }).click();
    expect(await viewport.getAttribute('transform')).not.toBe(beforePan);
    await page.getByRole('button', { name: 'Pan map down' }).click();
    await expect(viewport).toHaveAttribute('transform', beforePan);

    for (let step = 0; step < 4; step += 1) await page.getByRole('button', { name: 'Zoom out' }).click();
    await expect(page.getByLabel('Map zoom')).toHaveText('100%');
    await expect(page.getByRole('button', { name: 'Zoom out' })).toBeDisabled();

    await page.getByRole('button', { name: 'At-risk' }).click();
    await expect(page.getByRole('button', { name: 'At-risk' })).toHaveAttribute('aria-pressed', 'true');
    await page.getByRole('button', { name: 'Zoom in' }).click();
    await page.getByRole('button', { name: 'Pan map left' }).click();
    await page.getByRole('button', { name: 'Fit' }).click();
    await expect(page.getByLabel('Map zoom')).toHaveText('100%');
    await expect(page.getByRole('button', { name: 'At-risk' })).toHaveAttribute('aria-pressed', 'true');

    await page.getByRole('button', { name: 'Reset' }).click();
    await expect(page.getByRole('button', { name: 'All FCU flows' })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByLabel('Map zoom')).toHaveText('100%');
    await expect(page.locator('#leakMapInspector')).toHaveCount(0);

    await page.getByRole('button', { name: 'Pause flow' }).click();
    await expect(page.locator('#leakMapStage')).toHaveClass(/is-static/);
    await expect(page.locator('#leakMapStage .leak-flow')).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath('overview-map-desktop.png'), fullPage: true });

    await page.getByRole('button', { name: 'Details', exact: true }).click();
    await expect(page.locator('#leakMapDetails')).toBeVisible();
    await expect(page.locator('.leak-relationship-list li').first()).toBeVisible();
    await expect(map).not.toContainText('524-71-');

    await page.setViewportSize({ width: 390, height: 844 });
    await page.reload();
    await expect(page.locator('[data-map-view="details"]')).toHaveAttribute('aria-pressed', 'true');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    await page.screenshot({ path: testInfo.outputPath('overview-details-mobile.png'), fullPage: true });

    await page.setViewportSize({ width: 1280, height: 900 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.reload();
    await expect(page.getByRole('button', { name: 'Motion reduced' })).toBeDisabled();
    await expect(page.locator('#leakMapStage .leak-flow')).toHaveCount(0);
  } finally {
    await denyFixture(page, heldId).catch(() => {});
  }
});

test('overview map renders outbound legs only for policy-authorized continuation', async ({ page }) => {
  const edges = [
    mapEdge('pending-only', 'pending.example', { events: 1, blocked: 0, pending: 1, sensitive: 1 }),
    mapEdge('mixed', 'mixed.example', { events: 2, blocked: 1, pending: 1, continued: 1, sensitive: 1, controlled: 1 }),
    mapEdge('blocked', 'blocked.example', { events: 1, blocked: 1, sensitive: 1, controlled: 1 }),
    mapEdge('redacted', 'redacted.example', { events: 1, redacted: 1, continued: 1, sensitive: 1, controlled: 1 }),
    mapEdge('paste', 'paste.example', { events: 1, coached: 1, sensitive: 1, controlled: 1 }),
    mapEdge('warning', 'warning.example', { events: 1, coached: 1, sensitive: 1, controlled: 1 }),
    mapEdge('shadow', 'shadow.example', { events: 1, shadow: 1 }),
    mapEdge('unknown', 'unknown.example', { events: 1, sensitive: 1, uncontrolled: 1 }),
    mapEdge('aggregate-mixed', 'unknown.example', { from: 'org:aggregate-review', events: 2, sensitive: 1, uncontrolled: 1, continued: 1, uncontrolledContinued: 0 }),
    mapEdge('sensitive-allowed', 'unknown.example', { from: 'org:sensitive-review', events: 1, sensitive: 1, uncontrolled: 1, continued: 1, uncontrolledContinued: 1 }),
  ];
  await mockPosture(page, postureBody(mapReport(edges)));
  await login(page);

  const pending = page.locator('[data-leak-edge="pending-only"]');
  await expect(pending).toHaveAttribute('data-continuation-events', '0');
  await expect(pending.locator('[data-leak-leg="outbound"]')).toHaveCount(0);
  await expect(pending.locator('.leak-stop')).toHaveCount(1);

  const mixed = page.locator('[data-leak-edge="mixed"]');
  await expect(mixed).toHaveAttribute('data-continuation-events', '1');
  await expect(mixed.locator('[data-leak-leg="ingress"]')).toHaveClass(/is-held/);
  await expect(mixed.locator('[data-leak-leg="outbound"]')).toHaveClass(/is-clean/);

  const blocked = page.locator('[data-leak-edge="blocked"]');
  await expect(blocked).toHaveAttribute('data-continuation-events', '0');
  await expect(blocked.locator('[data-leak-leg="outbound"]')).toHaveCount(0);

  const redacted = page.locator('[data-leak-edge="redacted"]');
  await expect(redacted).toHaveAttribute('data-continuation-events', '1');
  await expect(redacted.locator('[data-leak-leg="outbound"]')).toHaveCount(1);
  await expect(redacted).toHaveAttribute('aria-label', /Redacted for safe continuation/);

  for (const id of ['paste', 'warning', 'shadow', 'unknown']) {
    const observational = page.locator(`[data-leak-edge="${id}"]`);
    await expect(observational).toHaveAttribute('data-continuation-events', '0');
    await expect(observational.locator('[data-leak-leg="outbound"]')).toHaveCount(0);
  }

  await selectMapEdge(page, 'unknown');
  await expect(page.locator('#leakMapInspector')).toContainText(/uncontrolled observations; continuation relationship not inferred/i);
  await expect(page.locator('#leakMapInspector')).not.toContainText(/reached the destination|events left/i);

  await selectMapEdge(page, 'paste');
  await expect(page.locator('#leakMapInspector')).toContainText('No uncontrolled observation recorded');

  await selectMapEdge(page, 'shadow');
  await expect(page.locator('#leakMapInspector')).toContainText('sightings of ungoverned AI');

  const aggregateMixed = page.locator('[data-leak-edge="aggregate-mixed"]');
  await expect(aggregateMixed.locator('[data-leak-leg="outbound"]')).toHaveClass(/is-clean/);
  await aggregateMixed.focus();
  await aggregateMixed.press('Enter');
  await expect(page.locator('#leakMapInspector')).toContainText('continuation relationship not inferred');
  await expect(page.locator('#leakMapInspector')).toContainText('1 policy-authorized continuation decision; delivery not confirmed');

  const sensitiveAllowed = page.locator('[data-leak-edge="sensitive-allowed"]');
  await expect(sensitiveAllowed.locator('[data-leak-leg="outbound"]')).toHaveClass(/is-leak/);
  await expect(sensitiveAllowed).toHaveAttribute('aria-label', /Includes policy-authorized sensitive continuation/);
});

test('overview map render and animation remain bounded at representative density', async ({ page }, testInfo) => {
  const edges = Array.from({ length: 18 }, (_, index) => mapEdge(
    `performance-path-${index}`,
    `ai-destination-${index % 6}.example`,
    {
      from: `org:team-${Math.floor(index / 6)}`,
      events: (index % 5) + 1,
      sensitive: index % 3 === 0 ? 1 : 0,
      controlled: index % 3 === 0 ? 1 : 0,
      redacted: index % 3 === 0 ? 1 : 0,
      continued: index % 3 === 0 ? 1 : 0,
    },
  ));
  await mockPosture(page, postureBody(mapReport(edges)));
  await mockStats(page, { status: 200, body: statsBody({ total: 18 }) });
  await login(page);
  await page.goto('/app/#/activity');

  // Change only the hash and take the mark in that same document. Comparing
  // performance.now() values across navigations would mix time origins and
  // could make a slow render look negative.
  const startedAt = await page.evaluate(() => {
    location.hash = '/';
    return performance.now();
  });
  await expect(page).toHaveURL(/\/app\/#\/$/);
  await expect(page.locator('#leakMapStage [data-leak-edge]')).toHaveCount(18);
  const result = await page.evaluate(async (start) => {
    const renderedAt = performance.now();
    const intervals = await new Promise((resolve) => {
      const samples = [];
      let previous = performance.now();
      const sample = (now) => {
        samples.push(now - previous);
        previous = now;
        if (samples.length === 30) resolve(samples);
        else requestAnimationFrame(sample);
      };
      requestAnimationFrame(sample);
    });
    const sorted = [...intervals].sort((a, b) => a - b);
    return {
      renderMs: Number((renderedAt - start).toFixed(1)),
      frameP95Ms: Number(sorted[Math.floor(sorted.length * 0.95)].toFixed(1)),
      mapDomNodes: document.querySelectorAll('#leakMapStage *').length,
      paths: document.querySelectorAll('#leakMapStage [data-leak-edge]').length,
    };
  }, startedAt);

  await testInfo.attach('overview-map-performance.json', {
    body: Buffer.from(`${JSON.stringify(result, null, 2)}\n`),
    contentType: 'application/json',
  });
  expect(result.renderMs).toBeLessThan(5000);
  expect(result.frameP95Ms).toBeLessThan(100);
  expect(result.mapDomNodes).toBeLessThan(2000);
  expect(result.paths).toBe(18);
});

test('newer live stats cannot be overwritten by an older HTTP response', async ({ page, request }) => {
  const oldStatsGate = createDeferred();
  const oldStatsCompleted = createDeferred();
  let statsRequests = 0;
  let completedOldStats = 0;
  await page.route('**/api/stats', async (route) => {
    statsRequests += 1;
    if (statsRequests <= 2) {
      await oldStatsGate.promise;
      try {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(statsBody({ held: 99 })) });
      } finally {
        completedOldStats += 1;
        if (completedOldStats === 2) oldStatsCompleted.release();
      }
      return;
    }
    await route.continue();
  });
  await mockPosture(page, postureBody(mapReport()));
  await installControllableEventSource(page);
  await login(page);
  let heldId = '';
  try {
    await expect.poll(() => statsRequests).toBeGreaterThanOrEqual(2);
    heldId = await createHeldPrompt(request);
    const currentResponse = await page.evaluate(async () => {
      const response = await fetch('/api/stats');
      return { status: response.status, body: response.ok ? await response.json() : null };
    });
    expect(currentResponse.status).toBe(200);
    const currentStats = currentResponse.body;
    expect(currentStats.held).toBeGreaterThan(0);
    await emitLiveEvent(page, 'stats', currentStats);

    const queueValue = page.locator('.overview-stat').filter({ hasText: 'Member-data queue' }).locator('.overview-stat-value');
    const queueBadge = page.locator('.app-rail .tab').filter({ hasText: 'Queue' }).locator('.badge');
    await expect(queueValue).toHaveText(String(currentStats.held));
    await expect(queueBadge).toHaveText(String(currentStats.held));

    oldStatsGate.release();
    await oldStatsCompleted.promise;
    await expect(queueValue).toHaveText(String(currentStats.held));
    await expect(queueBadge).toHaveText(String(currentStats.held));
  } finally {
    oldStatsGate.release();
    if (statsRequests >= 2) await oldStatsCompleted.promise;
    if (heldId) await denyFixture(page, heldId).catch(() => {});
  }
});

test('newer posture evidence cannot be overwritten by older overlapping requests', async ({ page }) => {
  const oldPostureGate = createDeferred();
  const oldPostureCompleted = createDeferred();
  let postureRequests = 0;
  let completedOldPosture = 0;
  const oldReport = postureBody(mapReport([mapEdge('old-path', 'old.example', { events: 1, continued: 1 })]));
  const newReport = postureBody(mapReport([mapEdge('new-path', 'new.example', { events: 1, continued: 1 })]));
  oldReport.surfaces = [{ id: 'surface-audit-evidence', status: 'error', description: 'old audit state' }];
  newReport.surfaces = [{ id: 'surface-audit-evidence', status: 'online', description: 'new audit state' }];
  await page.route('**/api/posture?*', async (route) => {
    postureRequests += 1;
    if (postureRequests <= 2) {
      await oldPostureGate.promise;
      try {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(oldReport) });
      } finally {
        completedOldPosture += 1;
        if (completedOldPosture === 2) oldPostureCompleted.release();
      }
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(newReport) });
  });
  await mockStats(page, { status: 200, body: statsBody() });
  await installControllableEventSource(page);
  await login(page);
  try {
    await expect.poll(() => postureRequests).toBeGreaterThanOrEqual(2);
    await emitLiveEvent(page, 'query', { type: 'synthetic_refresh' });
    await expectMapEdgeRendered(page, 'new-path');
    await expect(page.locator('.rail-status')).toContainText('SECURE');

    oldPostureGate.release();
    await oldPostureCompleted.promise;
    await expectMapEdgeRendered(page, 'new-path');
    await expect(page.locator('[data-leak-edge="old-path"]')).toHaveCount(0);
    await expect(page.locator('.rail-status')).toContainText('SECURE');
    await expect(page.locator('.rail-status')).not.toContainText('REVIEW');
  } finally {
    oldPostureGate.release();
    if (postureRequests >= 2) await oldPostureCompleted.promise;
  }
});

test('overview map distinguishes loading, verified empty, and fetch failure', async ({ page }) => {
  const postureGate = createDeferred();
  const postureCompleted = createDeferred();
  let postureStarted = 0;
  let completedPosture = 0;
  await page.route('**/api/posture?*', async (route) => {
    postureStarted += 1;
    await postureGate.promise;
    try {
      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(postureBody(mapReport())) });
    } finally {
      completedPosture += 1;
      if (completedPosture === 2) postureCompleted.release();
    }
  });
  await login(page);

  const map = page.locator('.leak-map-section');
  try {
    await expect(map).toHaveAttribute('data-map-state', 'loading');
    await expect(map).toContainText('Loading exposure evidence');
    await expect.poll(() => postureStarted).toBeGreaterThanOrEqual(2);
    postureGate.release();
    await postureCompleted.promise;
    await expect(map).toHaveAttribute('data-map-state', 'empty');
    await expect(map).toContainText('No exposure paths in the verified snapshot');
    await expect(map).not.toContainText('Exposure evidence unavailable');

    await page.unroute('**/api/posture?*');
    await mockPosture(page, { error: 'unavailable' }, 503);
    await page.reload();
    await expect(map).toHaveAttribute('data-map-state', 'unavailable');
    await expect(map).toContainText('Exposure evidence unavailable');
    await expect(map).not.toContainText('No exposure paths in the verified snapshot');
  } finally {
    postureGate.release();
    if (postureStarted >= 2) await postureCompleted.promise;
  }
});

test('overview rejects malformed continuation evidence instead of drawing a green path', async ({ page }) => {
  const malformed = mapReport([
    mapEdge('malformed-path', 'malformed.example', {
      events: 1,
      sensitive: 1,
      controlled: 0,
      uncontrolled: 1,
      continued: true,
      uncontrolledContinued: '1',
    }),
  ]);
  await mockPosture(page, postureBody(malformed));
  await mockStats(page, { status: 200, body: statsBody() });
  await login(page);

  const map = page.locator('.leak-map-section');
  await expect(map).toHaveAttribute('data-map-state', 'unavailable');
  await expect(map).toContainText('Exposure evidence unavailable');
  await expect(page.locator('[data-leak-edge="malformed-path"]')).toHaveCount(0);
});

test('overview counters distinguish unavailable, malformed, and verified-zero responses', async ({ page }) => {
  let response = { status: 503, body: { error: 'unavailable' } };
  await mockStats(page, () => response);
  await mockPosture(page, postureBody(mapReport()));
  await installControllableEventSource(page);
  await login(page);

  await expect(page.getByRole('alert').filter({ hasText: 'Evidence counters unavailable' })).toBeVisible();
  await expect(page.getByText('No FCU evidence in the verified snapshot')).toHaveCount(0);

  response = { status: 200, body: { total: 0 } };
  await page.getByRole('button', { name: 'Retry counters' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Evidence counters unavailable' })).toBeVisible();
  await expect(page.getByText('No FCU evidence in the verified snapshot')).toHaveCount(0);

  const legacyStats = statsBody({ pending: 2 });
  delete legacyStats.held;
  response = { status: 200, body: legacyStats };
  await page.getByRole('button', { name: 'Retry counters' }).click();
  const queueCard = page.locator('.overview-stat').filter({ hasText: 'Member-data queue' });
  await expect(queueCard.locator('.overview-stat-value')).toHaveText('Not reported');
  await expect(queueCard).toContainText('2 approval holds reported; justification total unavailable');
  await expect(page.locator('.app-rail .tab').filter({ hasText: 'Queue' }).locator('.badge')).toHaveCount(0);

  response = {
    status: 200,
    body: statsBody({
      total: 0,
      pending: 0,
      held: 0,
      approved: 0,
      denied: 0,
      allowed: 0,
      todayBlocked: 0,
      topEntities: [],
    }),
  };
  await emitLiveEvent(page, 'query', { type: 'synthetic_refresh' });
  await expect(page.getByText('No FCU evidence in the verified snapshot')).toBeVisible();
  await expect(page.getByText('Evidence counters unavailable')).toHaveCount(0);
});

test('overview retains and labels the last verified counters after refresh failure', async ({ page }) => {
  let response = { status: 200, body: statsBody() };
  await mockStats(page, () => response);
  await mockPosture(page, postureBody(mapReport()));
  await installControllableEventSource(page);
  await login(page);

  await expect(page.getByText('Sanitized live counters')).toBeVisible();
  await expect(page.getByText('Showing last verified counters')).toHaveCount(0);
  response = { status: 503, body: { error: 'unavailable' } };
  await emitLiveEvent(page, 'query', { type: 'synthetic_refresh' });

  await expect(page.getByText('Showing last verified counters')).toBeVisible();
  await expect(page.getByText('Last verified counters', { exact: true })).toBeVisible();
  await expect(page.getByText('No FCU evidence in the verified snapshot')).toHaveCount(0);
});

test('overview retains and labels a populated map after refresh failure', async ({ page }) => {
  const snapshot = postureBody(mapReport([
    mapEdge('verified-path', 'verified.example', { events: 1, continued: 1 }),
  ]));
  let response = { status: 200, body: snapshot };
  await page.route('**/api/posture?*', (route) => route.fulfill({
    status: response.status,
    contentType: 'application/json',
    body: JSON.stringify(response.body),
  }));
  await mockStats(page, { status: 200, body: statsBody() });
  await installControllableEventSource(page);
  await login(page);

  const map = page.locator('.leak-map-section');
  await expect(map).toHaveAttribute('data-map-state', 'populated');
  await expectMapEdgeRendered(page, 'verified-path');
  response = { status: 503, body: { error: 'unavailable' } };
  await emitLiveEvent(page, 'query', { type: 'synthetic_refresh' });

  await expect(map).toHaveAttribute('data-map-state', 'unavailable');
  await expect(map).toContainText('last verified snapshot remains visible');
  await expectMapEdgeRendered(page, 'verified-path');
});
