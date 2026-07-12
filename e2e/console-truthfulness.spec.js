'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');
const { createDeferred } = require('./helpers/deferred');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
const STATE_SHOT_DIR = path.join(__dirname, 'design-evidence', 'states');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);
test.beforeEach(() => fs.mkdirSync(STATE_SHOT_DIR, { recursive: true }));

async function captureState(page, name) {
  await page.screenshot({
    path: path.join(STATE_SHOT_DIR, `${name}.png`),
    fullPage: true,
    animations: 'disabled',
  });
}

function activityRow(id, user, destination, createdAt) {
  return {
    id,
    createdAt,
    status: 'pending',
    user,
    destination,
    source: 'browser_extension',
    channel: 'submit',
    redactedPrompt: 'Synthetic masked member-data context: [REDACTED].',
    findings: [{ type: 'MEMBER_ID', masked: 'redacted', severity: 4 }],
    categories: [],
    entityCounts: { MEMBER_ID: 1 },
    reasons: ['synthetic truthfulness fixture'],
    riskScore: 84,
    maxSeverity: 4,
    maxSeverityLabel: 'high',
    rawRetained: false,
  };
}

const OLDER_ACTIVITY = activityRow(
  'activity-older-snapshot',
  'older-snapshot@example.test',
  'older.example.test',
  '2026-07-11T12:00:00.000Z',
);
const NEWER_ACTIVITY = activityRow(
  'activity-newer-snapshot',
  'newer-snapshot@example.test',
  'newer.example.test',
  '2026-07-11T12:01:00.000Z',
);
const STREAM_ACTIVITY = activityRow(
  'activity-live-event',
  'live-event@example.test',
  'live.example.test',
  '2026-07-11T12:02:00.000Z',
);

const AUDIT_EMPTY = activityRow(
  'audit-verified-empty',
  'audit-empty@example.test',
  'empty-audit.example.test',
  '2026-07-11T12:03:00.000Z',
);
const AUDIT_MALFORMED = activityRow(
  'audit-malformed',
  'audit-malformed@example.test',
  'malformed-audit.example.test',
  '2026-07-11T12:02:00.000Z',
);
const AUDIT_INTEGRITY = activityRow(
  'audit-integrity-failure',
  'audit-integrity@example.test',
  'integrity-audit.example.test',
  '2026-07-11T12:01:00.000Z',
);
const AUDIT_WINDOWED = activityRow(
  'audit-incomplete-window',
  'audit-window@example.test',
  'windowed-audit.example.test',
  '2026-07-11T12:00:00.000Z',
);

async function login(page) {
  await page.goto('/login.html');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function installSyntheticEventStream(page) {
  await page.addInitScript(() => {
    const streams = new Set();
    class SyntheticEventSource extends EventTarget {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSED = 2;

      constructor(url) {
        super();
        this.url = new URL(String(url), location.href).href;
        this.withCredentials = false;
        this.readyState = SyntheticEventSource.CONNECTING;
        this.onopen = null;
        this.onerror = null;
        streams.add(this);
        queueMicrotask(() => {
          if (this.readyState === SyntheticEventSource.CLOSED) return;
          this.readyState = SyntheticEventSource.OPEN;
          const event = new Event('open');
          this.dispatchEvent(event);
          if (typeof this.onopen === 'function') this.onopen(event);
        });
      }

      close() {
        this.readyState = SyntheticEventSource.CLOSED;
        streams.delete(this);
      }
    }

    Object.defineProperty(window, 'EventSource', {
      configurable: true,
      writable: true,
      value: SyntheticEventSource,
    });
    Object.defineProperty(window, '__redactwallEmitSyntheticEvent', {
      configurable: true,
      value(name, data) {
        const payload = JSON.stringify(data);
        for (const stream of streams) {
          stream.dispatchEvent(new MessageEvent(name, { data: payload }));
        }
        return streams.size;
      },
    });
  });
}

async function emitSyntheticEvent(page, name, data) {
  const listeners = await page.evaluate(
    ([eventName, eventData]) => window.__redactwallEmitSyntheticEvent(eventName, eventData),
    [name, data],
  );
  expect(listeners).toBeGreaterThan(0);
}

function postureReport(surfaces) {
  return {
    surfaces,
    leakMap: {
      segments: [],
      channels: [],
      destinations: [],
      edges: [],
      categories: [],
      summary: {
        segments: 0,
        destinations: 0,
        edges: 0,
        shownEdges: 0,
        events: 0,
        sensitive: 0,
        controlled: 0,
        uncontrolled: 0,
        continued: 0,
        uncontrolledContinued: 0,
        pending: 0,
        shadow: 0,
        controlRate: 100,
        status: 'idle',
        privacy: 'prompt bodies excluded',
      },
    },
  };
}

test('rail posture labels become stale, unavailable, and not reported without retaining secure claims', async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await installSyntheticEventStream(page);
  let postureMode = 'ready';
  await page.route('**/api/posture?*', async (route) => {
    if (postureMode === 'unavailable') {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'posture_temporarily_unavailable' }),
      });
      return;
    }
    if (postureMode === 'malformed') {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          surfaces: [{ id: 'surface-audit-evidence', status: 'online', description: 'Unverified partial response.' }],
        }),
      });
      return;
    }
    const surfaces = postureMode === 'omitted'
      ? []
      : [
        { id: 'surface-audit-evidence', status: 'online', description: 'Synthetic audit chain verified.' },
        { id: 'surface-browser_extension', status: 'online', description: 'Synthetic browser sensor online.' },
      ];
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(postureReport(surfaces)),
    });
  });

  await login(page);
  const rail = page.locator('.rail-status');
  await expect(rail.getByText('SECURE', { exact: true })).toBeVisible();
  await expect(rail.getByText('MONITORING', { exact: true })).toBeVisible();

  postureMode = 'unavailable';
  await emitSyntheticEvent(page, 'decision', { id: 'synthetic-refresh', status: 'denied' });
  await expect(rail.getByText('LAST VERIFIED', { exact: true })).toHaveCount(2);
  await expect(rail.getByText('SECURE', { exact: true })).toHaveCount(0);
  await expect(rail.getByText('MONITORING', { exact: true })).toHaveCount(0);
  await expect(rail.locator('.status-chip').first()).toHaveAttribute('aria-label', /current status is unknown/i);
  await captureState(page, 'shell-last-verified-posture-1024x768');

  await page.reload();
  await expect(rail.getByText('UNAVAILABLE', { exact: true })).toHaveCount(2);
  await expect(rail.getByText('SECURE', { exact: true })).toHaveCount(0);
  await expect(rail.getByText('MONITORING', { exact: true })).toHaveCount(0);
  await captureState(page, 'shell-posture-unavailable-1024x768');

  postureMode = 'omitted';
  await page.reload();
  await expect(rail.getByText('NOT REPORTED', { exact: true })).toHaveCount(2);
  await expect(rail.getByText('SECURE', { exact: true })).toHaveCount(0);
  await expect(rail.getByText('MONITORING', { exact: true })).toHaveCount(0);
  await captureState(page, 'shell-posture-not-reported-1024x768');

  postureMode = 'malformed';
  await page.reload();
  await expect(rail.getByText('UNAVAILABLE', { exact: true })).toHaveCount(2);
  await expect(rail.getByText('SECURE', { exact: true })).toHaveCount(0);
  await expect(rail.getByText('MONITORING', { exact: true })).toHaveCount(0);
  await captureState(page, 'shell-posture-malformed-partial-1024x768');
});

test('activity keeps newer HTTP and SSE evidence when an older request finishes last', async ({ page }) => {
  await installSyntheticEventStream(page);
  await login(page);
  const olderGate = createDeferred();
  const olderCompleted = createDeferred();
  let requestCount = 0;
  await page.route('**/api/queries?limit=200', async (route) => {
    requestCount += 1;
    if (requestCount === 1) {
      await olderGate.promise;
      try {
        await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([OLDER_ACTIVITY]) });
      } finally {
        olderCompleted.release();
      }
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify([NEWER_ACTIVITY]) });
  });

  try {
    await page.goto('/app/#/activity');
    await expect(page.getByText('Loading activity…')).toBeVisible();
    await expect.poll(() => requestCount).toBe(1);

    await emitSyntheticEvent(page, 'decision', { id: NEWER_ACTIVITY.id, status: 'pending' });
    await expect.poll(() => requestCount).toBe(2);
    await expect(page.getByText(NEWER_ACTIVITY.destination, { exact: true })).toBeVisible();

    await emitSyntheticEvent(page, 'query', { query: STREAM_ACTIVITY });
    await expect(page.getByText(STREAM_ACTIVITY.destination, { exact: true })).toBeVisible();

    olderGate.release();
    await olderCompleted.promise;
    await expect(page.getByText(NEWER_ACTIVITY.destination, { exact: true })).toBeVisible();
    await expect(page.getByText(STREAM_ACTIVITY.destination, { exact: true })).toBeVisible();
    await expect(page.getByText(OLDER_ACTIVITY.destination, { exact: true })).toHaveCount(0);
  } finally {
    olderGate.release();
    if (requestCount >= 1) await olderCompleted.promise;
  }
});

test('activity failure states never present an unverified empty snapshot as verified', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await installSyntheticEventStream(page);
  await login(page);
  let activityMode = 'verified-empty';
  await page.route('**/api/queries?limit=200', async (route) => {
    if (activityMode === 'unavailable') {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'activity_temporarily_unavailable' }),
      });
      return;
    }
    await route.fulfill({ status: 200, contentType: 'application/json', body: '[]' });
  });

  await page.goto('/app/#/activity');
  await expect(page.getByText('No gated member-data events yet')).toBeVisible();
  await expect(page.getByText('The current verified snapshot contains no activity events.')).toBeVisible();
  await captureState(page, 'activity-verified-empty-mobile-390x844');

  activityMode = 'unavailable';
  await emitSyntheticEvent(page, 'decision', { id: 'synthetic-stale-activity', status: 'denied' });
  await expect(page.getByText('Activity snapshot stale')).toBeVisible();
  await expect(page.getByText(/No current empty-state conclusion can be drawn/i)).toBeVisible();
  await expect(page.getByText('No gated member-data events yet')).toHaveCount(0);
  await captureState(page, 'activity-stale-empty-mobile-390x844');

  await page.reload();
  await expect(page.getByText('Activity unavailable')).toBeVisible();
  await expect(page.getByText(/No verified activity snapshot is available/i)).toBeVisible();
  await expect(page.getByText('No gated member-data events yet')).toHaveCount(0);
  await captureState(page, 'activity-unavailable-mobile-390x844');

  await emitSyntheticEvent(page, 'query', { query: STREAM_ACTIVITY });
  await expect(page.getByText(STREAM_ACTIVITY.destination, { exact: true })).toBeVisible();
  await expect(page.getByText(/Showing verified activity received so far; current events may be missing/i)).toBeVisible();
  await expect(page.getByText('Activity unavailable')).toHaveCount(0);
  await captureState(page, 'activity-partial-live-mobile-390x844');
});

test('incident audit trail distinguishes loading, complete empty, bounded empty, malformed, and integrity failure', async ({ page }) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await login(page);
  const emptyAuditGate = createDeferred();
  const emptyAuditCompleted = createDeferred();
  let emptyAuditStarted = 0;
  await page.route('**/api/queries?*', async (route) => {
    const status = new URL(route.request().url()).searchParams.get('status');
    const rows = status === 'pending' ? [AUDIT_EMPTY, AUDIT_MALFORMED, AUDIT_INTEGRITY, AUDIT_WINDOWED] : [];
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(rows) });
  });
  await page.route('**/api/audit?*', async (route) => {
    const queryId = new URL(route.request().url()).searchParams.get('queryId');
    if (queryId === AUDIT_EMPTY.id) {
      emptyAuditStarted += 1;
      await emptyAuditGate.promise;
      try {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            entries: [],
            integrity: { ok: true, count: 0 },
            window: { scope: 'query', scannedEntries: 0, totalEntries: 0, matchedEntries: 0, returnedEntries: 0, complete: true },
            retention: 'Synthetic retention policy.',
          }),
        });
      } finally {
        emptyAuditCompleted.release();
      }
      return;
    }
    if (queryId === AUDIT_MALFORMED.id) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ entries: [], integrity: { ok: true, count: 0 } }),
      });
      return;
    }
    if (queryId === AUDIT_WINDOWED.id) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          entries: [],
          integrity: { ok: true, count: 2500 },
          window: { scope: 'query', scannedEntries: 2000, totalEntries: 2500, matchedEntries: 0, returnedEntries: 0, complete: false },
          retention: 'Synthetic retention policy.',
        }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        entries: [],
        integrity: { ok: false, count: 0, reason: 'chain', brokenAt: 'synthetic-audit-entry' },
        window: { scope: 'query', scannedEntries: 0, totalEntries: 0, matchedEntries: 0, returnedEntries: 0, complete: false },
        retention: 'Synthetic retention policy.',
      }),
    });
  });

  try {
    await page.goto('/app/#/queue');
    const auditTrail = page.locator('.query-audit');
    await expect(auditTrail).toContainText('Loading verified audit history…');
    await expect.poll(() => emptyAuditStarted).toBe(1);
    await captureState(page, 'queue-audit-loading-1366x768');

    emptyAuditGate.release();
    await emptyAuditCompleted.promise;
    await expect(auditTrail).toContainText('Audit chain verified. The complete retained audit set has no entries for this incident.');
    await captureState(page, 'queue-audit-verified-empty-1366x768');

    await page.getByRole('button', { name: `Review incident for ${AUDIT_MALFORMED.user}` }).click();
    await expect(auditTrail).toContainText('Audit history is unavailable or malformed. No empty-history conclusion can be drawn.');
    await expect(auditTrail).not.toContainText('No entries were recorded');

    await page.getByRole('button', { name: `Review incident for ${AUDIT_INTEGRITY.user}` }).click();
    await expect(auditTrail).toContainText('Audit history integrity could not be verified. Entries are withheld.');
    await expect(auditTrail).not.toContainText('No entries were recorded');
    await captureState(page, 'queue-audit-integrity-failure-1366x768');

    await page.getByRole('button', { name: `Review incident for ${AUDIT_WINDOWED.user}` }).click();
    await expect(auditTrail).toContainText('No entries were found in the verified recent window; older entries may exist.');
    await expect(auditTrail).not.toContainText('complete retained audit set has no entries');
    await captureState(page, 'queue-audit-bounded-empty-1366x768');
  } finally {
    emptyAuditGate.release();
    if (emptyAuditStarted > 0) await emptyAuditCompleted.promise;
  }
});
