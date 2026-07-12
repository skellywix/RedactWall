'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { test, expect } = require('@playwright/test');
const { createDeferred } = require('./helpers/deferred');

const appIndexPath = path.join(__dirname, '..', 'server', 'public', 'app', 'index.html');
test.skip(!fs.existsSync(appIndexPath), 'console bundle not built (npm run console:build)');

const EXPECTED_PREFLIGHT_CHECK_IDS = [
  'admin_password',
  'admin_password_strength',
  'admin_mfa',
  'admin_mfa_secret',
  'operator_credentials',
  'operator_user_distinct',
  'operator_password_strength',
  'approver_credentials',
  'approver_user_distinct',
  'approver_password_strength',
  'auditor_credentials',
  'auditor_user_distinct',
  'auditor_password_strength',
  'ingest_key',
  'ingest_key_strength',
  'scim_bearer_token_strength',
  'oidc_config',
  'oidc_client_secret_strength',
  'oidc_scim_users',
  'oidc_endpoints',
  'oidc_https',
  'session_secret',
  'session_secret_strength',
  'raw_prompt_encryption',
  'data_key_strength',
  'secure_cookie',
  'db_driver',
  'sqlite_local_disk',
  'postgres_tls',
  'postgres_tenant_context',
  'public_url',
  'connected_license_url',
  'connected_license_auth',
  'connected_license_verdict_key',
  'custom_detectors',
  'policy_file',
  'policy_signing_key',
  'exact_match',
  'license_customer_binding',
  'saas_tenant_id',
  'saas_seat_limit',
  'saas_tenant_context',
  'saas_user_identity',
];

const VERIFIED_PREFLIGHT = {
  production: true,
  level: 'ok',
  checks: EXPECTED_PREFLIGHT_CHECK_IDS.map((id) => ({ id, ok: true })),
};

const VERIFIED_COVERAGE = {
  totals: { fleetAttention: 0 },
  sensors: [
    { source: 'browser_extension', required: true, events: 12, latestVersion: '0.3.0', lastSeen: '2030-01-02T03:04:05.000Z' },
    { source: 'endpoint_agent', required: true, events: 4, latestVersion: '0.3.0', lastSeen: '2030-01-02T03:04:05.000Z' },
    { source: 'mcp_guard', required: true, events: 2, latestVersion: '0.3.0', lastSeen: '2030-01-02T03:04:05.000Z' },
  ],
};

const VERIFIED_IMPACT = {
  generatedAt: '2030-01-02T03:04:05.000Z',
  privacy: { mode: 'metadata_only', promptBodiesIncluded: false, excludedFields: ['prompt'] },
  summary: {
    sampleSize: 10,
    changed: 1,
    newlyBlocked: 1,
    newlyAllowed: 0,
    moreRestrictive: 1,
    lessRestrictive: 0,
    current: { blocked: 2, approval_required: 1, justification_required: 0, redacted: 1, warned: 2, allowed: 4, observed: 0 },
    proposed: { blocked: 3, approval_required: 1, justification_required: 0, redacted: 1, warned: 1, allowed: 4, observed: 0 },
  },
  topDeltas: { destinations: [], categories: [], sources: [], reasons: [] },
};

function fulfillJson(route, body, status = 200) {
  return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

async function loginAs(page, user = 'admin', password = 'e2e-pass') {
  await page.goto('/login.html');
  await page.locator('#user').fill(user);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/app\/?$/);
}

async function openPolicy(page, route = '/policy') {
  await page.goto(`/app/#${route}`);
  await expect(page.getByRole('heading', { name: 'Policy Configuration', exact: true })).toBeVisible();
  await expect(page.locator('.app-panel-meta').first()).not.toHaveText('Loading', { timeout: 10000 });
}

test('policy prioritizes the decision workflow and keeps bulk controls collapsed', async ({ page }) => {
  await loginAs(page);
  await openPolicy(page);

  await expect(page.getByRole('heading', { name: 'Enforcement essentials' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Texas FCU policy mode' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Member-data blocking thresholds' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'AI vendor governance' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Approval routing' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Member Data Test Bench' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Impact preview' })).toBeVisible();
  expect(await page.locator('.policy-chip.static').count()).toBeGreaterThanOrEqual(21);

  const disclosures = page.locator('details[data-policy-section]');
  await expect(disclosures).toHaveCount(7);
  for (const section of ['fleet', 'templates', 'browser-actions', 'mcp', 'scopes', 'advanced', 'retention']) {
    await expect(page.locator(`details[data-policy-section="${section}"]`)).not.toHaveAttribute('open', '');
  }
  await expect(page.getByRole('button', { name: 'Run retention purge' })).toBeHidden();

  const save = page.getByRole('button', { name: 'Save changes' });
  await expect(save).toBeDisabled();
  await expect(page.getByText('No pending changes', { exact: true })).toBeVisible();

  const risk = page.locator('#pol-risk');
  const initialRisk = await risk.inputValue();
  await risk.fill(initialRisk === '70' ? '71' : '70');
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
  await expect(save).toBeEnabled();
  const impactRequestPromise = page.waitForRequest((request) => request.url().includes('/api/policy/impact') && request.method() === 'POST');
  await page.getByRole('button', { name: 'Test configuration' }).click();
  const impactBody = (await impactRequestPromise).postDataJSON();
  expect(impactBody.blockRiskScore).toBe(Number(initialRisk === '70' ? '71' : '70'));
  expect(Array.isArray(impactBody.approvalRoutingRules)).toBe(true);
  expect(Array.isArray(impactBody.policyScopes)).toBe(true);
  await page.getByRole('button', { name: 'Discard changes' }).click();
  await expect(risk).toHaveValue(initialRisk);
  await expect(page.getByText('No pending changes', { exact: true })).toBeVisible();
  await expect(save).toBeDisabled();

  const synthetic = 'Synthetic policy test SSN 123-45-6789';
  const detectorRequestPromise = page.waitForRequest((request) => request.url().endsWith('/api/detectors/test') && request.method() === 'POST');
  await page.getByLabel('Sample text to test').fill(synthetic);
  await page.getByRole('button', { name: 'Test detection' }).click();
  expect((await detectorRequestPromise).postDataJSON()).toEqual({ text: synthetic });
  await expect(page.getByText('BLOCK', { exact: true }).last()).toBeVisible();
});

test('editing a tested draft invalidates the prior impact preview', async ({ page }) => {
  await loginAs(page);
  await page.route('**/api/preflight', (route) => fulfillJson(route, VERIFIED_PREFLIGHT));
  await page.route('**/api/coverage', (route) => fulfillJson(route, VERIFIED_COVERAGE));
  await page.route('**/api/policy/impact?**', (route) => fulfillJson(route, VERIFIED_IMPACT));
  await openPolicy(page);

  const risk = page.locator('#pol-risk');
  const initialRisk = Number(await risk.inputValue());
  await risk.fill(String(initialRisk === 99 ? 98 : initialRisk + 1));
  await page.getByRole('button', { name: 'Test configuration' }).click();

  const preview = page.locator('.policy-impact');
  await expect(preview).toContainText('Draft policy replayed against 10 recent events');
  await expect(preview).toContainText('1');

  await risk.fill(String(initialRisk === 99 ? 97 : initialRisk + 2));
  await expect(preview).toHaveCount(0);
  await expect(page.getByText('Not run', { exact: true })).toBeVisible();
});

test('malformed policy and template success bodies remain unavailable instead of rendering invented configuration', async ({ page }) => {
  await loginAs(page);
  await page.route('**/api/policy', (route) => route.request().method() === 'GET'
    ? fulfillJson(route, {
      enforcementMode: 'block',
      blockMinSeverity: 2,
      blockRiskScore: 25,
      alwaysBlock: ['US_SSN'],
    })
    : route.continue());
  await openPolicy(page);
  await expect(page.getByText('Policy unavailable', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);

  await page.unroute('**/api/policy');
  await page.route('**/api/policy/templates', (route) => fulfillJson(route, [{
    id: 'unsafe-template',
    label: 'Malformed template',
    description: 'Nested policy field has the wrong type',
    policy: { blockRiskScore: 'high' },
  }]));
  await page.reload();
  const templates = page.locator('details[data-policy-section="templates"]');
  await templates.locator('summary').click();
  await expect(templates.getByText('Policy templates unavailable', { exact: true })).toBeVisible();
  await expect(templates).not.toContainText('Malformed template');
});

test('malformed nested impact success body is rejected without an impact claim', async ({ page }) => {
  await loginAs(page);
  await page.route('**/api/preflight', (route) => fulfillJson(route, VERIFIED_PREFLIGHT));
  await page.route('**/api/coverage', (route) => fulfillJson(route, VERIFIED_COVERAGE));
  await page.route('**/api/policy/impact?**', (route) => fulfillJson(route, {
    ...VERIFIED_IMPACT,
    summary: {
      ...VERIFIED_IMPACT.summary,
      proposed: { ...VERIFIED_IMPACT.summary.proposed, observed: 'zero' },
    },
  }));
  await openPolicy(page);

  const risk = page.locator('#pol-risk');
  const initialRisk = Number(await risk.inputValue());
  await risk.fill(String(initialRisk === 99 ? 98 : initialRisk + 1));
  await page.getByRole('button', { name: 'Test configuration' }).click();

  await expect(page.getByText('Policy impact response could not be verified. Retry the configuration test.', { exact: true })).toBeVisible();
  await expect(page.locator('.policy-impact')).toHaveCount(0);
  await expect(page.getByText('Not run', { exact: true })).toBeVisible();
});

test('malformed or mismatched save success bodies keep the draft unsaved', async ({ page }) => {
  await loginAs(page);
  await openPolicy(page);
  const activePolicy = await page.evaluate(() => fetch('/api/policy').then((response) => response.json()));
  const risk = page.locator('#pol-risk');
  const initialRisk = Number(await risk.inputValue());
  const requestedRisk = initialRisk === 99 ? 98 : initialRisk + 1;
  await risk.fill(String(requestedRisk));

  await page.route('**/api/policy', (route) => route.request().method() === 'PUT'
    ? fulfillJson(route, { ...activePolicy, summary: { saved: true }, blockRiskScore: 'high' })
    : route.continue());
  await page.getByRole('button', { name: 'Save changes' }).click();
  const unverified = 'Save response could not be verified. Reload policy before making another change.';
  await expect(page.getByText(unverified, { exact: true })).toBeVisible();
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
  await expect(risk).toHaveValue(String(requestedRisk));
  await expect(page.getByText('Saved', { exact: true })).toHaveCount(0);

  await page.unroute('**/api/policy');
  await page.route('**/api/policy', (route) => route.request().method() === 'PUT'
    ? fulfillJson(route, activePolicy)
    : route.continue());
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText(unverified, { exact: true })).toBeVisible();
  await expect(page.getByText('Unsaved changes', { exact: true })).toBeVisible();
  await expect(page.getByText('Saved', { exact: true })).toHaveCount(0);
});

test('server-normalized guided approval route is accepted as the saved policy', async ({ page }) => {
  await loginAs(page);
  await openPolicy(page);
  const activePolicy = await page.evaluate(() => fetch('/api/policy').then((response) => response.json()));
  const { normalizePolicy } = require('../server/policy');
  let saveBody = null;

  await page.route('**/api/policy', async (route) => {
    if (route.request().method() !== 'PUT') return route.continue();
    saveBody = route.request().postDataJSON();
    return fulfillJson(route, normalizePolicy({ ...activePolicy, ...saveBody }));
  });

  const disclosure = page.locator('details.policy-inline-disclosure').filter({ hasText: 'Configure approval routes' });
  await disclosure.locator('summary').click();
  await disclosure.getByLabel('Route id').fill('Lending_High_Risk');
  await disclosure.getByLabel('Assigned group').fill('LENDING');
  await disclosure.getByLabel('SCIM groups').fill('RedactWall Lending');
  await disclosure.getByLabel('Detectors').fill('secret_key');
  await disclosure.getByLabel('Reason').fill('Lending_Review');
  await disclosure.getByRole('button', { name: 'Add route' }).click();
  await page.getByRole('button', { name: 'Save changes' }).click();

  await expect.poll(() => saveBody).not.toBeNull();
  expect(saveBody.approvalRoutingRules).toEqual([expect.objectContaining({
    id: 'lending_high_risk',
    assignedGroup: 'lending',
    assignedRole: 'approver',
    groups: ['RedactWall Lending'],
    detectors: ['secret_key'],
    minSeverity: 3,
    reason: 'lending_review',
    slaMinutes: 60,
  })]);
  await expect(page.getByText('Saved', { exact: true })).toBeVisible();
  await expect(page.getByText('No pending changes', { exact: true })).toBeVisible();
  await expect(page.getByText('Save response could not be verified.', { exact: false })).toHaveCount(0);
});

test('malformed or mismatched template success body never claims the template was applied', async ({ page }) => {
  await loginAs(page);
  const activePolicy = await page.evaluate(() => fetch('/api/policy').then((response) => response.json()));
  const requestedRisk = activePolicy.blockRiskScore === 99 ? 98 : activePolicy.blockRiskScore + 1;
  await page.route('**/api/policy/templates', (route) => fulfillJson(route, [{
    id: 'verified-template',
    label: 'Verified template',
    description: 'Changes the risk threshold',
    policy: { blockRiskScore: requestedRisk },
  }]));
  await page.route('**/api/policy/apply-template', (route) => fulfillJson(route, {
    ...activePolicy,
    alwaysBlock: activePolicy.alwaysBlock.filter((type) => type !== 'US_SSN'),
  }));
  await openPolicy(page, '/policy?section=templates');

  const templates = page.locator('details[data-policy-section="templates"]');
  await templates.getByRole('button', { name: 'Verified template' }).click();
  await templates.getByRole('button', { name: 'Apply template' }).click();
  const unverified = 'Template may have been applied, but the response could not be verified. Reload policy before retrying.';
  await expect(page.locator('#toastStack').getByText(unverified, { exact: true }).last()).toBeVisible();
  await expect(page.getByText('Template applied.', { exact: true })).toHaveCount(0);

  await page.unroute('**/api/policy/apply-template');
  await page.route('**/api/policy/apply-template', (route) => fulfillJson(route, activePolicy));
  await templates.getByRole('button', { name: 'Verified template' }).click();
  await templates.getByRole('button', { name: 'Apply template' }).click();
  await expect(page.locator('#toastStack').getByText(unverified, { exact: true }).last()).toBeVisible();
  await expect(page.getByText('Template applied.', { exact: true })).toHaveCount(0);
});

test('readiness and fleet evidence render explicit loading states before verification', async ({ page }) => {
  const preflightGate = createDeferred();
  const coverageGate = createDeferred();
  const preflightCompleted = createDeferred();
  const coverageCompleted = createDeferred();
  let preflightStarted = false;
  let coverageStarted = false;
  await loginAs(page);
  await page.route('**/api/preflight', async (route) => {
    preflightStarted = true;
    await preflightGate.promise;
    try {
      await fulfillJson(route, VERIFIED_PREFLIGHT);
    } finally {
      preflightCompleted.release();
    }
  });
  await page.route('**/api/coverage', async (route) => {
    coverageStarted = true;
    await coverageGate.promise;
    try {
      await fulfillJson(route, VERIFIED_COVERAGE);
    } finally {
      coverageCompleted.release();
    }
  });
  try {
    await openPolicy(page, '/policy?section=fleet');

    const header = page.locator('.policy-head-row');
    await expect(header.getByText('Checking readiness', { exact: true })).toBeVisible();
    await expect(page.locator('.policy-head-metrics > div').filter({ hasText: 'Fleet attention' }).locator('dd')).toHaveText('Loading');
    const fleet = page.locator('details[data-policy-section="fleet"]');
    await expect(fleet.getByText('Loading readiness checks', { exact: true })).toBeVisible();
    await expect(fleet.getByText('Loading fleet coverage', { exact: true })).toBeVisible();
    await expect(fleet.locator('.sensor-card').first().locator('dd').nth(1)).toHaveText('Loading');
    await expect.poll(() => preflightStarted).toBe(true);
    await expect.poll(() => coverageStarted).toBe(true);
    preflightGate.release();
    coverageGate.release();
    await Promise.all([preflightCompleted.promise, coverageCompleted.promise]);
    await expect(header.getByText('100/100 ready', { exact: true })).toBeVisible();
    await expect(page.locator('.policy-head-metrics > div').filter({ hasText: 'Fleet attention' }).locator('dd')).toHaveText('0');
  } finally {
    preflightGate.release();
    coverageGate.release();
    await Promise.all([
      preflightStarted ? preflightCompleted.promise : Promise.resolve(),
      coverageStarted ? coverageCompleted.promise : Promise.resolve(),
    ]);
  }
});

test('failed readiness and coverage requests never render a current all-clear or synthetic zero', async ({ page }) => {
  await loginAs(page);
  await page.route('**/api/preflight', (route) => fulfillJson(route, { error: 'unavailable' }, 503));
  await page.route('**/api/coverage', (route) => fulfillJson(route, { error: 'unavailable' }, 503));
  await openPolicy(page, '/policy?section=fleet');

  const header = page.locator('.policy-head-row');
  await expect(header.getByText('Readiness unavailable', { exact: true })).toBeVisible();
  await expect(header).toContainText('No verified readiness evidence is available');
  const fleetMetric = page.locator('.policy-head-metrics > div').filter({ hasText: 'Fleet attention' });
  await expect(fleetMetric.locator('dd')).toHaveText('Unavailable');
  await expect(header).not.toContainText('All reported checks ready');

  const fleet = page.locator('details[data-policy-section="fleet"]');
  await expect(fleet).toHaveAttribute('open', '');
  await expect(fleet.getByRole('alert').filter({ hasText: 'Readiness checks unavailable' })).toBeVisible();
  await expect(fleet.getByRole('alert').filter({ hasText: 'Fleet coverage unavailable' })).toBeVisible();
  await expect(fleet.locator('.health-score')).toContainText('not verified');
  await expect(fleet.locator('.sensor-card').first().locator('dd').nth(1)).toHaveText('Unavailable');
  await expect(fleet).not.toContainText('0 observed');
  await expect(fleet).not.toContainText('No events observed');
});

test('verified partial evidence reports missing fields instead of inventing readiness or fleet values', async ({ page }) => {
  await loginAs(page);
  await page.route('**/api/preflight', (route) => fulfillJson(route, { production: true, level: 'ready' }));
  await page.route('**/api/coverage', (route) => fulfillJson(route, {}));
  await openPolicy(page, '/policy?section=fleet');

  const header = page.locator('.policy-head-row');
  await expect(header.getByText('Readiness incomplete', { exact: true })).toBeVisible();
  await expect(header).toContainText('did not report any checks');
  await expect(page.locator('.policy-head-metrics > div').filter({ hasText: 'Fleet attention' }).locator('dd')).toHaveText('Not reported');
  await expect(header).not.toContainText('All reported checks ready');

  const fleet = page.locator('details[data-policy-section="fleet"]');
  await expect(fleet.locator('.health-score')).toContainText('not verified');
  await expect(fleet.locator('.sensor-card').first().locator('dd').nth(1)).toHaveText('Not reported');
  await expect(fleet.getByText('Not reported', { exact: true }).first()).toBeVisible();
  await expect(fleet).not.toContainText('0 observed');
});

test('successful but incomplete preflight arrays cannot claim complete groups or full readiness', async ({ page }) => {
  const omitted = new Set(['admin_mfa', 'oidc_scim_users']);
  const partialChecks = VERIFIED_PREFLIGHT.checks.filter((check) => !omitted.has(check.id));
  await loginAs(page);
  await page.route('**/api/preflight', (route) => fulfillJson(route, { ...VERIFIED_PREFLIGHT, checks: partialChecks }));
  await page.route('**/api/coverage', (route) => fulfillJson(route, VERIFIED_COVERAGE));
  await openPolicy(page, '/policy?section=fleet');

  const header = page.locator('.policy-head-row');
  await expect(header.getByText('Readiness incomplete', { exact: true })).toBeVisible();
  await expect(header).toContainText('41/43 expected checks reported; 2 missing');
  await expect(header).not.toContainText('100/100 ready');
  await expect(header).not.toContainText('All expected checks ready');

  const fleet = page.locator('details[data-policy-section="fleet"]');
  const admin = fleet.locator('.setup-item').filter({ hasText: 'Admin access' });
  const identity = fleet.locator('.setup-item').filter({ hasText: 'Identity provider' });
  await expect(admin).toContainText('6/7 checks reported');
  await expect(identity).toContainText('5/6 checks reported');
  await expect(admin.locator('.setup-dot')).toHaveClass(/warn/);
  await expect(identity.locator('.setup-dot')).toHaveClass(/warn/);
  await expect(fleet.locator('.health-score')).toContainText('not verified');
});

test('every readiness area exposes representative missing or failed evidence without claiming Ready', async ({ page }) => {
  const omitted = new Set(['admin_mfa_secret', 'approver_user_distinct', 'session_secret_strength', 'oidc_endpoints']);
  const failed = new Set([
    'operator_credentials',
    'auditor_password_strength',
    'secure_cookie',
    'oidc_client_secret_strength',
    'oidc_https',
    'public_url',
    'connected_license_auth',
    'custom_detectors',
    'policy_signing_key',
    'license_customer_binding',
  ]);
  const checks = VERIFIED_PREFLIGHT.checks
    .filter((check) => !omitted.has(check.id))
    .map((check) => failed.has(check.id) ? { ...check, ok: false, severity: 'error' } : check);
  await loginAs(page);
  await page.route('**/api/preflight', (route) => fulfillJson(route, { ...VERIFIED_PREFLIGHT, level: 'blocked', checks }));
  await page.route('**/api/coverage', (route) => fulfillJson(route, VERIFIED_COVERAGE));
  await openPolicy(page, '/policy?section=fleet');

  const fleet = page.locator('details[data-policy-section="fleet"]');
  const adminSetup = fleet.locator('.setup-item').filter({ hasText: 'Admin access' });
  const identitySetup = fleet.locator('.setup-item').filter({ hasText: 'Identity provider' });
  await expect(adminSetup.locator('.setup-dot')).toHaveClass(/bad/);
  await expect(adminSetup).toContainText('5/7 checks reported');
  await expect(adminSetup).not.toContainText('Ready');
  await expect(identitySetup.locator('.setup-dot')).toHaveClass(/bad/);
  await expect(identitySetup).toContainText('5/6 checks reported');
  await expect(identitySetup).not.toContainText('Ready');

  const settings = fleet.locator('.settings-list');
  const groupRows = settings.locator('[data-readiness-group]');
  await expect(groupRows).toHaveCount(14);
  const expectations = [
    ['admin-auth', '3/4 checks reported'],
    ['operator-access', 'Blocked'],
    ['approver-access', '2/3 checks reported'],
    ['auditor-access', 'Blocked'],
    ['identity-provider', '5/6 checks reported'],
    ['session-cookies', '2/3 checks reported'],
    ['public-url', 'Blocked'],
    ['connected-license', 'Blocked'],
    ['policy-integrity', 'Blocked'],
    ['license-binding', 'Blocked'],
  ];
  for (const [key, status] of expectations) {
    const row = settings.locator(`[data-readiness-group="${key}"]`);
    await expect(row).toBeVisible();
    await expect(row).toContainText(status);
    await expect(row).not.toContainText('Ready');
  }
  await expect(page.locator('.policy-head-row')).not.toContainText('100/100 ready');
});

test('failed evidence refresh retains an explicitly stale snapshot instead of a current all-clear', async ({ page }) => {
  let failRefresh = false;
  await loginAs(page);
  await page.route('**/api/preflight', (route) => failRefresh
    ? fulfillJson(route, { error: 'unavailable' }, 503)
    : fulfillJson(route, VERIFIED_PREFLIGHT));
  await page.route('**/api/coverage', (route) => failRefresh
    ? fulfillJson(route, { error: 'unavailable' }, 503)
    : fulfillJson(route, VERIFIED_COVERAGE));
  await openPolicy(page, '/policy?section=fleet');

  await expect(page.locator('.policy-head-row')).toContainText('100/100 ready');
  failRefresh = true;
  await page.getByRole('button', { name: 'Test configuration' }).click();

  const header = page.locator('.policy-head-row');
  await expect(header.getByText('Readiness stale', { exact: true })).toBeVisible();
  await expect(header).toContainText('Last verified: 100/100; latest refresh failed');
  await expect(page.locator('.policy-head-metrics > div').filter({ hasText: 'Fleet attention' }).locator('dd')).toHaveText('Last verified: 0');
  await expect(header).not.toContainText('All reported checks ready');

  const fleet = page.locator('details[data-policy-section="fleet"]');
  await expect(fleet.getByRole('alert').filter({ hasText: 'Showing last verified readiness checks' })).toBeVisible();
  await expect(fleet.getByRole('alert').filter({ hasText: 'Showing last verified fleet coverage' })).toBeVisible();
  await expect(fleet.locator('.sensor-card').first().locator('dd').nth(1)).toHaveText('12 (last verified)');
});

test('template catalog distinguishes loading, verified empty, and unavailable', async ({ page }) => {
  const templatesGate = createDeferred();
  const templatesCompleted = createDeferred();
  let templatesStarted = false;
  await loginAs(page);
  await page.route('**/api/policy/templates', async (route) => {
    templatesStarted = true;
    await templatesGate.promise;
    try {
      await fulfillJson(route, []);
    } finally {
      templatesCompleted.release();
    }
  });
  try {
    await openPolicy(page, '/policy?section=templates');

    const templates = page.locator('details[data-policy-section="templates"]');
    await expect(templates).toHaveAttribute('open', '');
    await expect(templates.getByText('Loading policy templates', { exact: true })).toBeVisible();
    await expect(templates.locator('.policy-disclosure-meta')).toHaveText('Loading');
    await expect.poll(() => templatesStarted).toBe(true);
    templatesGate.release();
    await templatesCompleted.promise;
    await expect(templates.getByText('No policy templates configured', { exact: true })).toBeVisible();
    await expect(templates.locator('.policy-disclosure-meta')).toHaveText('0 available');

    await page.unroute('**/api/policy/templates');
    await page.route('**/api/policy/templates', (route) => fulfillJson(route, { error: 'unavailable' }, 503));
    await page.reload();
    await expect(templates.getByText('Policy templates unavailable', { exact: true })).toBeVisible();
    await expect(templates.locator('.policy-disclosure-meta')).toHaveText('Unavailable');
    await expect(templates).not.toContainText('No policy templates configured');
  } finally {
    templatesGate.release();
    if (templatesStarted) await templatesCompleted.promise;
  }
});

test('template refresh failure labels retained templates as last verified', async ({ page }) => {
  const template = { id: 'verified-template', label: 'Verified baseline', description: 'Known test template', policy: {} };
  let templateRefreshes = 0;
  await loginAs(page);
  const activePolicy = await page.evaluate(() => fetch('/api/policy').then((response) => response.json()));
  await page.route('**/api/policy/templates', (route) => {
    templateRefreshes += 1;
    return templateRefreshes === 1 ? fulfillJson(route, [template]) : fulfillJson(route, { error: 'unavailable' }, 503);
  });
  await page.route('**/api/policy/apply-template', (route) => fulfillJson(route, activePolicy));
  await openPolicy(page, '/policy?section=templates');

  const templates = page.locator('details[data-policy-section="templates"]');
  await templates.getByRole('button', { name: 'Verified baseline' }).click();
  await templates.getByRole('button', { name: 'Apply template' }).click();
  await expect(templates.getByRole('alert').filter({ hasText: 'Showing last verified policy templates' })).toBeVisible();
  await expect(templates.locator('.policy-disclosure-meta')).toHaveText('1 available · last verified');
  await expect(templates.getByRole('button', { name: 'Verified baseline' })).toBeVisible();
});

test('save, template, and purge controls retain their endpoint contracts', async ({ page }) => {
  await loginAs(page);
  await openPolicy(page);
  const activePolicy = await page.evaluate(() => fetch('/api/policy').then((response) => response.json()));
  let saveBody = null;
  let templateBody = null;
  let purgeCalls = 0;

  await page.route('**/api/policy', async (route) => {
    if (route.request().method() !== 'PUT') return route.continue();
    saveBody = route.request().postDataJSON();
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...activePolicy, ...saveBody }) });
  });
  await page.route('**/api/policy/apply-template', async (route) => {
    templateBody = route.request().postDataJSON();
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(activePolicy) });
  });
  await page.route('**/api/retention/purge', async (route) => {
    purgeCalls += 1;
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ purged: 3 }) });
  });

  const risk = page.locator('#pol-risk');
  const initialRisk = await risk.inputValue();
  await risk.fill(initialRisk === '70' ? '71' : '70');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect.poll(() => saveBody).not.toBeNull();
  expect(Object.keys(saveBody).sort()).toEqual([
    'allowedDestinations',
    'approvalRoutingRules',
    'blockMinSeverity',
    'blockRiskScore',
    'blockUnapprovedAiDestinations',
    'blockedBrowserActions',
    'blockedDestinations',
    'blockedFileUploadDestinations',
    'desiredSensorVersions',
    'desktopCollectorDestination',
    'enforcementMode',
    'governedDestinations',
    'mcpAllowedTools',
    'mcpApprovalRequiredTools',
    'mcpBlockedTools',
    'policyExceptions',
    'policyScopes',
    'rawRetentionDays',
    'requiredSensors',
    'responseScanMode',
    'storeRawForApproval',
  ]);
  expect(saveBody.blockRiskScore).toBe(Number(initialRisk === '70' ? '71' : '70'));
  await expect(page.getByText('No pending changes', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled();

  const templates = page.locator('details[data-policy-section="templates"]');
  await templates.locator('summary').click();
  const templateButton = templates.locator('button.policy-chip').first();
  await expect(templateButton).toBeVisible();
  await templateButton.click();
  await templates.getByRole('button', { name: 'Apply template' }).click();
  await expect.poll(() => templateBody).not.toBeNull();
  expect(Object.keys(templateBody)).toEqual(['id']);

  const retention = page.locator('details[data-policy-section="retention"]');
  await retention.locator('summary').click();
  await retention.getByRole('button', { name: 'Run retention purge' }).click();
  await expect.poll(() => purgeCalls).toBe(1);
  await expect(page.getByText('Purged 3 record(s)', { exact: true })).toBeVisible();
});

test('policy disclosures support keyboard use and safe query deep links', async ({ page }) => {
  await loginAs(page);
  await openPolicy(page, '/policy?section=mcp&source=e2e');

  await expect(page).toHaveURL(/#\/policy\?section=mcp&source=e2e$/);
  const mcp = page.locator('details[data-policy-section="mcp"]');
  await expect(mcp).toHaveAttribute('open', '');
  await expect(mcp.getByRole('heading', { name: 'MCP tool governance' })).toBeVisible();

  const summary = mcp.locator('summary');
  await summary.focus();
  await expect(summary).toBeFocused();
  await page.keyboard.press('Space');
  await expect(mcp).not.toHaveAttribute('open', '');
  await page.keyboard.press('Enter');
  await expect(mcp).toHaveAttribute('open', '');
  await expect(page).toHaveURL(/#\/policy\?section=mcp&source=e2e$/);

  await page.setViewportSize({ width: 360, height: 740 });
  await expect(summary).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('read-only roles keep edit and destructive controls gated inside disclosures', async ({ page }) => {
  await loginAs(page, 'e2e-auditor', 'e2e-auditor-pass');
  await openPolicy(page, '/policy?section=retention');

  await expect(page.getByRole('button', { name: 'Save changes' })).toHaveCount(0);
  await expect(page.locator('input[name="policy-mode"]').first()).toBeDisabled();
  await expect(page.getByText('Read-only view', { exact: true }).first()).toBeVisible();
  await expect(page.locator('.policy-view')).not.toContainText('Read-only auditor view');
  const retention = page.locator('details[data-policy-section="retention"]');
  await expect(retention).toHaveAttribute('open', '');
  await expect(retention.getByText('Security Admin required to run retention purge')).toBeVisible();
  await expect(retention.getByRole('button', { name: 'Run retention purge' })).toHaveCount(0);
});
