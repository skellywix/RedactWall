'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');
test.setTimeout(90000);

async function login(page) {
  await page.goto('/login.html');
  await page.locator('#user').fill('admin');
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

function mapNode(id, label, overrides = {}) {
  return {
    id,
    label,
    status: 'online',
    events: 4,
    sensitive: 2,
    controlled: 2,
    blocked: 1,
    redacted: 1,
    coached: 0,
    pending: 0,
    shadow: 0,
    uncontrolled: 0,
    continued: 2,
    uncontrolledContinued: 0,
    users: 1,
    controlRate: 100,
    lastSeen: null,
    ...overrides,
  };
}

function overviewPosture() {
  const segment = mapNode('org:texas-fcu', 'Texas FCU', { typeLabel: 'Organization' });
  const channel = mapNode('browser_extension', 'Browser extension');
  const destination = mapNode('chat.example.test', 'Approved AI assistant', { state: 'sanctioned' });
  const edge = {
    ...mapNode('edge-accessibility', 'Protected route'),
    from: segment.id,
    to: destination.id,
    via: channel.id,
    viaLabel: 'Browser extension',
    categories: [{ label: 'US_SSN', events: 2 }],
  };
  return {
    leakMap: {
      segments: [segment],
      channels: [channel],
      destinations: [destination],
      edges: [edge],
      categories: [{ label: 'US_SSN', events: 2 }],
      summary: {
        segments: 1,
        destinations: 1,
        edges: 1,
        shownEdges: 1,
        events: 4,
        sensitive: 2,
        controlled: 2,
        uncontrolled: 0,
        continued: 2,
        uncontrolledContinued: 0,
        pending: 0,
        shadow: 0,
        controlRate: 100,
        status: 'online',
        privacy: 'prompt bodies excluded',
      },
    },
    surfaces: [{ id: 'surface-audit-evidence', status: 'online', description: 'Linked entries verified' }],
  };
}

async function mockOverview(page) {
  await page.route(/\/api\/posture\?/, (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(overviewPosture()),
  }));
  await page.route('**/api/stats', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      total: 12,
      pending: 1,
      held: 1,
      approved: 4,
      denied: 2,
      allowed: 5,
      todayBlocked: 3,
      topEntities: [['US_SSN', 2]],
    }),
  }));
}

async function waitForOverview(page) {
  await expect(page.getByRole('heading', { name: 'Texas FCU Overview', exact: true })).toBeVisible();
  await expect(page.locator('.leak-map-section')).toHaveAttribute('data-map-state', 'populated');
  await expect(page.locator('.overview-evidence')).toBeVisible();
}

function parseCssColor(value) {
  const match = String(value).match(/^rgba?\(([^)]+)\)$/i);
  if (!match) throw new Error(`Unsupported computed color: ${value}`);
  const parts = match[1].replace('/', ' ').split(/[\s,]+/).filter(Boolean).map(Number);
  if (parts.length < 3 || parts.some((part) => !Number.isFinite(part))) {
    throw new Error(`Invalid computed color: ${value}`);
  }
  return { r: parts[0], g: parts[1], b: parts[2], a: parts[3] === undefined ? 1 : parts[3] };
}

function composite(foreground, background) {
  const alpha = foreground.a + background.a * (1 - foreground.a);
  if (!alpha) return { r: 255, g: 255, b: 255, a: 1 };
  const channel = (key) => (
    (foreground[key] * foreground.a + background[key] * background.a * (1 - foreground.a)) / alpha
  );
  return { r: channel('r'), g: channel('g'), b: channel('b'), a: alpha };
}

function luminance(color) {
  const linear = (channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b);
}

function contrastRatio(first, second) {
  const [lighter, darker] = [luminance(first), luminance(second)].sort((a, b) => b - a);
  return (lighter + 0.05) / (darker + 0.05);
}

async function paintEvidence(locator, foregroundProperty, includeElementBackground) {
  return locator.evaluate((element, options) => {
    const backgrounds = [];
    let current = options.includeElementBackground ? element : element.parentElement;
    while (current) {
      backgrounds.push(getComputedStyle(current).backgroundColor);
      current = current.parentElement;
    }
    return {
      foreground: getComputedStyle(element)[options.foregroundProperty],
      backgrounds,
    };
  }, { foregroundProperty, includeElementBackground });
}

function contrastFromPaint(paint) {
  const background = paint.backgrounds
    .map(parseCssColor)
    .reverse()
    .reduce((result, layer) => composite(layer, result), { r: 255, g: 255, b: 255, a: 1 });
  const foreground = composite(parseCssColor(paint.foreground), background);
  return { ratio: contrastRatio(foreground, background), foreground: paint.foreground, background };
}

async function expectContrast(locator, label, minimum, options = {}) {
  await expect(locator, `${label} must be visible before contrast is measured`).toBeVisible();
  const paint = await paintEvidence(
    locator,
    options.foregroundProperty || 'color',
    options.includeElementBackground !== false,
  );
  const result = contrastFromPaint(paint);
  expect(
    result.ratio,
    `${label} contrast ${result.ratio.toFixed(2)}:1 from ${result.foreground}; expected at least ${minimum}:1`,
  ).toBeGreaterThanOrEqual(minimum);
}

async function expectKeyboardFocusEvidence(locator, label) {
  await expect(locator, `${label} should receive keyboard focus`).toBeFocused();
  const evidence = await locator.evaluate((element) => {
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
    return {
      outlineStyle: style.outlineStyle,
      outlineWidth: Number.parseFloat(style.outlineWidth) || 0,
      boxShadow: style.boxShadow,
      withinViewport: rect.top >= 0 && rect.left >= 0
        && rect.bottom <= window.innerHeight && rect.right <= window.innerWidth,
      centerExposed: Boolean(hit && (element === hit || element.contains(hit))),
    };
  });
  const visibleRing = evidence.outlineStyle !== 'none' && evidence.outlineWidth >= 2;
  expect(visibleRing || evidence.boxShadow !== 'none', `${label} needs a visible focus indicator`).toBe(true);
  expect(evidence.withinViewport, `${label} focus must not be clipped outside the viewport`).toBe(true);
  expect(evidence.centerExposed, `${label} focus must not be covered by sticky or modal content`).toBe(true);
}

async function expectTouchTarget(locator, label) {
  await expect(locator, `${label} must be visible at the representative mobile viewport`).toBeVisible();
  const box = await locator.boundingBox();
  expect(box, `${label} must have a measurable target`).not.toBeNull();
  expect(box.width, `${label} width must be at least 44 CSS pixels`).toBeGreaterThanOrEqual(44);
  expect(box.height, `${label} height must be at least 44 CSS pixels`).toBeGreaterThanOrEqual(44);
}

test('representative dark and light routes retain computed text and graphic contrast', async ({ page }) => {
  await mockOverview(page);
  await login(page);
  await waitForOverview(page);
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'dark');

  await expectContrast(page.getByRole('heading', { name: 'Texas FCU Overview', exact: true }), 'dark overview heading', 4.5);
  await expectContrast(page.locator('.leak-map-title h3'), 'dark exposure-map heading', 4.5);
  await expectContrast(page.locator('.overview-section-head p').first(), 'dark overview supporting text', 4.5);
  await expectContrast(page.locator('.app-topbar .status-light'), 'dark stream-status marker', 3, {
    foregroundProperty: 'backgroundColor',
    includeElementBackground: false,
  });

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'light');
  await page.goto('/app/#/audit');
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'light');
  await expect(page.getByRole('heading', { name: 'Examiner Audit Chain', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Verify safe-to-send receipt', exact: true })).toBeVisible();

  await expectContrast(page.getByRole('heading', { name: 'Examiner Audit Chain', exact: true }), 'light audit heading', 4.5);
  await expectContrast(page.locator('.receipt-verifier-copy p'), 'light receipt guidance', 4.5);
  await expectContrast(page.getByRole('button', { name: 'Examiner Audit Chain', exact: true }).locator('.tab-icon'), 'light active-navigation icon', 3);
  await expectContrast(page.getByRole('button', { name: 'Switch to dark theme' }).locator('svg'), 'light theme-toggle icon', 3);
});

test('keyboard focus remains visibly indicated, in view, and above sticky layers', async ({ page }) => {
  await login(page);
  await page.goto('/app/#/audit');
  await expect(page.getByRole('heading', { name: 'Examiner Audit Chain', exact: true })).toBeVisible();

  await page.keyboard.press('Tab');
  const skipLink = page.getByRole('link', { name: 'Skip to main content' });
  await expectKeyboardFocusEvidence(skipLink, 'skip link');
  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();

  await page.keyboard.press('Control+K');
  const paletteFilter = page.getByLabel('Command palette filter');
  await expectKeyboardFocusEvidence(paletteFilter, 'command-palette filter');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'Command palette' })).toHaveCount(0);
  await expectKeyboardFocusEvidence(page.getByRole('button', { name: 'Open the command palette' }), 'restored palette launcher');
});

test('dynamic route, status, and failure messages expose semantic announcement roles', async ({ page }) => {
  let unavailable = true;
  await page.route('**/api/queries?*', (route) => route.fulfill({
    status: unavailable ? 503 : 200,
    contentType: 'application/json',
    body: JSON.stringify(unavailable ? { error: 'queue_temporarily_unavailable' } : []),
  }));
  await login(page);
  await page.goto('/app/#/queue');

  const routeContext = page.locator('.app-route-context');
  await expect(routeContext).toHaveAttribute('aria-live', 'polite');
  await expect(routeContext).toContainText('Member Data Queue');
  const failure = page.getByRole('alert').filter({ hasText: 'Member-data queue unavailable' });
  await expect(failure).toHaveAttribute('aria-live', 'assertive');
  await expect(failure).toContainText('No clear-queue claim has been made');

  unavailable = false;
  await failure.getByRole('button', { name: 'Retry' }).click();
  const verifiedEmpty = page.getByRole('status').filter({ hasText: 'Member-data queue clear' });
  await expect(verifiedEmpty).toHaveAttribute('aria-live', 'polite');
  await expect(verifiedEmpty).toContainText('No held member-data prompts');

  await page.goto('/app/#/audit');
  await expect(routeContext).toContainText('Examiner Audit Chain');
  const verifier = page.locator('.receipt-verifier');
  const receiptStatus = verifier.getByRole('status');
  await expect(receiptStatus).toHaveAttribute('aria-live', 'polite');
  await verifier.getByLabel('Receipt JSON').fill('{not complete json');
  await verifier.getByRole('button', { name: 'Verify receipt' }).click();
  await expect(receiptStatus).toHaveText('Enter one complete RedactWall receipt as a JSON object.');
  await expect(verifier.getByLabel('Receipt JSON')).toHaveAttribute('aria-invalid', 'true');
});

test('forced-colors mode keeps current navigation, status, focus, and map paths distinguishable', async ({ page }, testInfo) => {
  await page.emulateMedia({ forcedColors: 'active' });
  await page.setViewportSize({ width: 1024, height: 768 });
  await mockOverview(page);
  await login(page);
  await waitForOverview(page);
  expect(await page.evaluate(() => matchMedia('(forced-colors: active)').matches)).toBe(true);

  const activeNavigation = page.getByRole('button', { name: 'Texas FCU Overview', exact: true });
  await expect(activeNavigation).toHaveAttribute('aria-current', 'page');
  const navigationPaint = await activeNavigation.evaluate((element) => {
    const style = getComputedStyle(element);
    return { width: Number.parseFloat(style.borderTopWidth), style: style.borderTopStyle, color: style.borderTopColor };
  });
  expect(navigationPaint.width, 'current navigation needs a forced-colors boundary').toBeGreaterThanOrEqual(1);
  expect(navigationPaint.style).not.toBe('none');
  expect(navigationPaint.color).not.toBe('rgba(0, 0, 0, 0)');

  const mapChoice = page.getByRole('button', { name: 'Map', exact: true });
  await expect(mapChoice).toHaveAttribute('aria-pressed', 'true');
  const selectedPaint = await mapChoice.evaluate((element) => {
    const style = getComputedStyle(element);
    return { width: Number.parseFloat(style.outlineWidth), style: style.outlineStyle };
  });
  expect(selectedPaint.width, 'selected map view needs a non-color outline').toBeGreaterThanOrEqual(2);
  expect(selectedPaint.style).not.toBe('none');

  const statusMarker = page.locator('.app-topbar .status-light');
  await expect(statusMarker).toBeVisible();
  const markerPaint = await statusMarker.evaluate((element) => {
    const style = getComputedStyle(element);
    return { background: style.backgroundColor, forcedColorAdjust: style.forcedColorAdjust };
  });
  expect(markerPaint.forcedColorAdjust).toBe('none');
  expect(markerPaint.background).not.toBe('rgba(0, 0, 0, 0)');

  const mapEdge = page.locator('.leak-edge .leak-line').first();
  // A horizontal SVG path can have a zero-height DOM rectangle even while its
  // stroke is painted. Assert the rendered path exists, then inspect its paint.
  await expect(mapEdge).toHaveCount(1);
  const edgePaint = await mapEdge.evaluate((element) => {
    const style = getComputedStyle(element);
    return { stroke: style.stroke, width: Number.parseFloat(style.strokeWidth), forcedColorAdjust: style.forcedColorAdjust };
  });
  expect(edgePaint.stroke).not.toBe('none');
  expect(edgePaint.stroke).not.toBe('rgba(0, 0, 0, 0)');
  expect(edgePaint.width).toBeGreaterThan(0);
  expect(edgePaint.forcedColorAdjust).toBe('auto');

  await mapChoice.focus();
  await page.keyboard.press('Tab');
  await page.keyboard.press('Shift+Tab');
  await expectKeyboardFocusEvidence(mapChoice, 'forced-colors selected map view');
  await page.screenshot({
    path: testInfo.outputPath('accessibility-forced-colors.png'),
    fullPage: true,
    animations: 'disabled',
  });
});

test('representative mobile console controls expose at least 44 by 44 CSS pixel targets', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockOverview(page);
  await page.route('**/api/catalog', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ apps: [] }),
  }));
  await login(page);
  await waitForOverview(page);

  const controls = [
    [page.getByRole('button', { name: 'Open navigation menu' }), 'navigation-menu launcher'],
    [page.getByRole('button', { name: 'Open the command palette' }), 'command-palette launcher'],
    [page.getByRole('button', { name: 'Switch to light theme' }), 'theme toggle'],
    [page.getByRole('button', { name: 'Sign out' }), 'sign-out control'],
  ];
  for (const [control, label] of controls) await expectTouchTarget(control, label);
  await expect(page.getByRole('status', { name: /^(LIVE|SYNCING)$/ })).toBeVisible();

  await page.getByRole('button', { name: 'Open navigation menu' }).click();
  const drawer = page.getByRole('dialog', { name: 'Navigation menu' });
  await expect(drawer).toBeVisible();
  await expectTouchTarget(drawer.getByRole('button', { name: 'Close navigation menu' }), 'navigation close control');
  await expectTouchTarget(drawer.getByRole('button', { name: 'Texas FCU Overview', exact: true }), 'current mobile navigation item');
  await expectTouchTarget(drawer.getByRole('button', { name: /^Member Data Queue/ }), 'mobile navigation destination');

  await page.screenshot({
    path: testInfo.outputPath('accessibility-mobile-targets-390x844.png'),
    fullPage: true,
    animations: 'disabled',
  });

  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  await page.goto('/app/#/catalog');
  await expect(page.getByRole('heading', { name: 'AI Vendor Catalog', exact: true })).toBeVisible();
  await expectTouchTarget(page.getByRole('button', { name: 'App', exact: true }), 'catalog App sort control');
  await expectTouchTarget(page.getByRole('button', { name: 'Risk', exact: true }), 'catalog Risk sort control');
});
