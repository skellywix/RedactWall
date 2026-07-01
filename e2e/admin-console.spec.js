'use strict';

const fs = require('fs/promises');
const { test, expect } = require('@playwright/test');

test.setTimeout(90000);

async function login(page) {
  await page.goto('/login.html');
  await expect(page.getByRole('heading', { name: 'PromptWall' })).toBeVisible();
  await page.locator('#password').fill('e2e-pass');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/index\.html$/);
  await expect(page.locator('#who')).toContainText('admin / Security Admin');
}

function collectUiProblems(page) {
  const problems = [];
  page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (['error', 'warning'].includes(message.type())) {
      problems.push(`console ${message.type()}: ${message.text()}`);
    }
  });
  page.on('response', (response) => {
    const url = response.url();
    if (url.includes('/api/') && response.status() >= 400) {
      problems.push(`api ${response.status()}: ${url}`);
    }
  });
  page.on('dialog', async (dialog) => {
    problems.push(`unexpected ${dialog.type()} dialog: ${dialog.message()}`);
    await dialog.dismiss();
  });
  return problems;
}

async function createHeldPrompt(request, { suffix, user, destination, source = 'browser_extension', channel = 'submit' }) {
  const response = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: `Synthetic dashboard wiring SSN 524-71-${suffix} before submission.`,
      user,
      destination,
      source,
      channel,
      orgId: 'e2e-org',
    },
  });
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body.status).toBe('pending');
  return body;
}

async function createShadowAi(request, destination) {
  const response = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: `[shadow-AI] visit to ungoverned AI tool: ${destination}`,
      user: 'shadow-ui@example.test',
      destination,
      source: 'browser_extension',
      channel: 'shadow_ai',
      clientOutcome: 'shadow_ai',
      orgId: 'e2e-org',
    },
  });
  expect(response.ok()).toBeTruthy();
}

async function recordHeartbeat(request, { user, source, destination, sensor }) {
  const response = await request.post('/api/v1/heartbeat', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      user,
      orgId: 'e2e-org',
      destination,
      source,
      sensor,
      checks: [
        { id: 'managed_config', ok: true, detail: 'configured' },
        { id: 'managed_identity', ok: true, detail: 'present' },
      ],
    },
  });
  expect(response.ok()).toBeTruthy();
}

async function setStoreRawForApproval(page, enabled) {
  await page.evaluate(async (storeRawForApproval) => {
    const csrfResponse = await fetch('/api/csrf');
    if (!csrfResponse.ok) throw new Error(`csrf failed: ${csrfResponse.status}`);
    const { csrfToken } = await csrfResponse.json();
    const response = await fetch('/api/policy', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken,
      },
      body: JSON.stringify({ storeRawForApproval }),
    });
    if (!response.ok) throw new Error(`policy update failed: ${response.status}`);
  }, enabled);
}

test('admin console theme toggle defaults light and persists dark mode', async ({ page }) => {
  const problems = collectUiProblems(page);
  await login(page);

  await expect(page.locator('body')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('#themeLight')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#themeDark')).toHaveAttribute('aria-pressed', 'false');
  const lightTheme = await page.evaluate(() => {
    const styles = getComputedStyle(document.body);
    return {
      bg: styles.getPropertyValue('--bg').trim(),
      glow: styles.getPropertyValue('--glow').trim(),
      panel: styles.getPropertyValue('--panel').trim(),
      colorScheme: styles.colorScheme,
    };
  });
  expect(lightTheme).toMatchObject({
    bg: '#fff8ed',
    panel: '#fffbf4',
    colorScheme: 'light',
  });
  expect(lightTheme.glow).toContain('245,158,11');

  await page.locator('#themeDark').click();
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'dark');
  await expect(page.locator('#themeDark')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#themeLight')).toHaveAttribute('aria-pressed', 'false');
  const darkTheme = await page.evaluate(() => {
    const styles = getComputedStyle(document.body);
    return {
      bg: styles.getPropertyValue('--bg').trim(),
      glow: styles.getPropertyValue('--glow').trim(),
      panel: styles.getPropertyValue('--panel').trim(),
      stored: localStorage.getItem('promptwall.theme'),
      colorScheme: styles.colorScheme,
    };
  });
  expect(darkTheme).toMatchObject({
    bg: '#150f0a',
    panel: '#20150c',
    stored: 'dark',
    colorScheme: 'dark',
  });
  expect(darkTheme.glow).toContain('255,178,74');

  await page.reload();
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'dark');
  await expect(page.locator('#themeDark')).toHaveAttribute('aria-pressed', 'true');

  await page.locator('#themeLight').click();
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('#themeLight')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#themeDark')).toHaveAttribute('aria-pressed', 'false');
  await expect.poll(() => page.evaluate(() => localStorage.getItem('promptwall.theme'))).toBe('light');
  expect(problems).toEqual([]);
});

test('admin console login, approval, policy save, and evidence export work in a browser', async ({ page, request }) => {
  const problems = collectUiProblems(page);
  const gateResponse = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: 'Member SSN 524-71-9043 is in this synthetic loan note.',
      user: 'analyst@example.test',
      destination: 'chatgpt.com',
      source: 'browser_extension',
      channel: 'submit',
    },
  });
  expect(gateResponse.ok()).toBeTruthy();
  const gated = await gateResponse.json();
  expect(gated.status).toBe('pending');

  const shadowResponse = await request.post('/api/v1/gate', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      prompt: '[shadow-AI] visit to ungoverned AI tool: notebooklm.google.com',
      user: 'analyst@example.test',
      destination: 'notebooklm.google.com',
      source: 'browser_extension',
      channel: 'shadow_ai',
      clientOutcome: 'shadow_ai',
    },
  });
  expect(shadowResponse.ok()).toBeTruthy();

  const heartbeatResponse = await request.post('/api/v1/heartbeat', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
    data: {
      user: 'analyst@example.test',
      orgId: 'cu-acme',
      destination: 'browser-install',
      source: 'browser_extension',
      sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
      checks: [
        { id: 'managed_config', ok: true, detail: 'configured' },
        { id: 'managed_identity', ok: true, detail: 'present' },
      ],
    },
  });
  expect(heartbeatResponse.ok()).toBeTruthy();

  await login(page);

  await expect(page.locator('.live .status-chip')).toContainText('LIVE');
  await expect(page.locator('#lastUpdated')).toContainText('LAST UPDATED');
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(page.locator('.live .status-light')).toHaveCSS('animation-name', 'none');
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.locator('.live').click();
  await expect(page.locator('.meta-popover')).toContainText('session telemetry stream');
  await page.keyboard.press('Escape');

  const topPiiPanel = page.locator('.panel', { has: page.getByRole('heading', { name: 'Top PII Detected' }) });
  await expect(topPiiPanel.getByRole('button', { name: 'HIDE' })).toBeVisible();
  await topPiiPanel.getByRole('button', { name: 'HIDE' }).click();
  await expect(topPiiPanel).toHaveClass(/collapsed/);
  await topPiiPanel.getByRole('button', { name: 'DETAILS' }).click();
  await expect(topPiiPanel).not.toHaveClass(/collapsed/);

  const queueItem = page.locator(`.q[data-id="${gated.id}"]`);
  await expect(queueItem).toBeVisible();
  await expect(queueItem).toContainText('US_SSN');
  await expect(queueItem).not.toContainText('524-71-9043');

  await page.locator(`#note_${gated.id}`).fill('Synthetic approval for browser E2E');
  await page.getByRole('button', { name: 'Approve release' }).click();
  await expect(page.getByRole('heading', { name: 'Confirm release' })).toBeVisible();
  await page.getByLabel('Account password').fill('e2e-pass');
  await page.locator('.stepup-dialog').getByRole('button', { name: 'Approve release' }).click();
  await expect(page.locator('#queueList')).toContainText('Queue clear');

  await page.locator('.content-tabs .tab[data-tab="activity"]').click();
  await expect(page.locator('#activityRows')).toContainText('approved');
  await expect(page.locator('#activityRows')).toContainText('analyst@example.test');
  const activityRow = page.locator(`tr.activity-row[data-activity-id="${gated.id}"]`);
  await activityRow.hover();
  await expect(activityRow.locator('.row-affordance')).toHaveCSS('opacity', '1');
  await activityRow.click();
  await expect(page.locator(`.activity-detail-row:has-text("${gated.id}")`)).toBeVisible();
  await activityRow.locator('.status-chip').click();
  await expect(page.locator('.meta-popover')).toContainText(`Session ID: ${gated.id}`);
  await page.keyboard.press('Escape');
  await page.locator('#globalSearch').fill('analyst@example.test');
  await expect(page.locator('#activityRows')).toContainText('approved');
  await page.locator('#globalSearch').fill('no-such-user');
  await expect(page.locator('#activityRows')).toContainText('No matching activity');
  await page.locator('#globalSearch').fill('');

  await page.locator('.content-tabs .tab[data-tab="coverage"]').click();
  await expect(page.locator('#tab-coverage')).toBeVisible();
  await expect(page.locator('#coverageScore')).toContainText('Coverage score');
  await expect(page.locator('#shadowRows')).toContainText('notebooklm.google.com');
  await expect(page.locator('#sensorMix')).toContainText('Browser extension');
  await expect(page.locator('#fleetRows')).toContainText('analyst@example.test');
  await expect(page.locator('#fleetRows')).toContainText('cu-acme');
  await expect(page.locator('#fleetRows')).toContainText('covered');
  await expect(page.locator('#fleetRows')).toContainText('checks ok');

  await page.locator('.content-tabs .tab[data-tab="identity"]').click();
  await expect(page.locator('#tab-identity')).toBeVisible();
  await expect(page.locator('#identityScimRows')).toContainText('/scim/v2');
  await page.locator('#identityTenant').fill('contoso.onmicrosoft.com');
  await page.locator('#refreshIdentity').click();
  await expect(page.locator('#identityOidcRows')).toContainText('login.microsoftonline.com/contoso.onmicrosoft.com/v2.0');
  await page.locator('#identityProvider').selectOption('okta');
  await page.locator('#identityTenant').fill('customer.okta.com');
  await page.locator('#refreshIdentity').click();
  await expect(page.locator('#identityOidcRows')).toContainText('customer.okta.com/oauth2/default');
  await expect(page.locator('#identityEnvRows')).toContainText('OIDC_CLIENT_SECRET');
  await expect(page.locator('body')).not.toContainText('e2e-ingest-key');

  await page.locator('.content-tabs .tab[data-tab="policy"]').click();
  await expect(page.locator('#pol_desktop_destination')).toBeVisible();
  await page.locator('input[name="mode"][value="warn"]').check();
  await page.locator('#pol_risk').fill('35');
  await page.locator('#pol_desktop_destination').fill('Copilot Desktop');
  await page.locator('#pol_policy_scopes').fill(JSON.stringify([{
    id: 'legal_contract_review',
    groups: ['PromptWall Legal'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    enforcementMode: 'block',
    blockMinSeverity: 2,
  }], null, 2));
  await page.locator('#pol_policy_exceptions').fill(JSON.stringify([{
    id: 'legal_vendor_24h',
    users: ['counsel@example.test'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    expiresAt: '2030-01-01T00:00:00.000Z',
  }], null, 2));
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.locator('#polSaved')).toHaveText('Saved');
  const policy = await page.evaluate(async () => (await fetch('/api/policy')).json());
  expect(policy.enforcementMode).toBe('warn');
  expect(policy.blockRiskScore).toBe(35);
  expect(policy.desktopCollectorDestination).toBe('Copilot Desktop');
  expect(policy.policyScopes[0]).toMatchObject({
    id: 'legal_contract_review',
    groups: ['promptwall legal'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    enforcementMode: 'block',
    blockMinSeverity: 2,
  });
  expect(policy.policyExceptions[0]).toMatchObject({
    id: 'legal_vendor_24h',
    users: ['counsel@example.test'],
    destinations: ['claude.ai'],
    categories: ['LEGAL_CONTRACT'],
    expiresAt: '2030-01-01T00:00:00.000Z',
  });

  await page.locator('.content-tabs .tab[data-tab="audit"]').click();
  await expect(page.locator('#integrity')).toContainText('Chain verified');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export Evidence' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^promptwall-evidence-/);
  const exportedPath = await download.path();
  const pack = JSON.parse(await fs.readFile(exportedPath, 'utf8'));
  expect(pack.auditIntegrity.ok).toBe(true);
  expect(JSON.stringify(pack)).not.toContain('524-71-9043');
  expect(pack.stats.approved).toBeGreaterThanOrEqual(1);
  expect(problems).toEqual([]);
});

test('admin console controls and forms are wired end to end', async ({ page, request }) => {
  const problems = collectUiProblems(page);
  const reveal = await createHeldPrompt(request, {
    suffix: '9101',
    user: 'reveal-ui@example.test',
    destination: 'chatgpt.com',
  });
  const approve = await createHeldPrompt(request, {
    suffix: '9102',
    user: 'approve-ui@example.test',
    destination: 'claude.ai',
  });
  const deny = await createHeldPrompt(request, {
    suffix: '9103',
    user: 'deny-ui@example.test',
    destination: 'gemini.google.com',
  });
  const shadowDestination = 'shadow-ui.example';
  await createShadowAi(request, shadowDestination);
  await recordHeartbeat(request, {
    user: 'browser-health@example.test',
    source: 'browser_extension',
    destination: 'browser-install',
    sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
  });
  await recordHeartbeat(request, {
    user: 'endpoint-health@example.test',
    source: 'endpoint_agent',
    destination: 'endpoint-install',
    sensor: { name: 'endpoint_agent', version: '0.3.0', platform: 'win32' },
  });

  await login(page);
  await expect(page.locator('#queueList')).toContainText('approve-ui@example.test');

  await page.locator('[data-tab-jump="audit"]').click();
  await expect(page.locator('#tab-audit')).toBeVisible();
  await page.locator('.content-tabs .tab[data-tab="queue"]').click();
  await page.locator('[data-tab-jump="policy"]').click();
  await expect(page.locator('#tab-policy')).toBeVisible();

  for (const tabName of ['queue', 'activity', 'coverage', 'identity', 'lineage', 'audit', 'policy']) {
    await page.locator(`.content-tabs .tab[data-tab="${tabName}"]`).click();
    await expect(page.locator(`#tab-${tabName}`)).toBeVisible();
  }

  await page.locator('.content-tabs .tab[data-tab="queue"]').click();
  await page.locator('#refreshQueue').click();
  await expect(page.locator(`.q[data-id="${approve.id}"]`)).toBeVisible();
  await page.locator('[data-queue-filter="mine"]').click();
  await expect(page.locator('[data-queue-filter="mine"]')).toHaveClass(/active/);
  await page.locator('[data-queue-filter="unassigned"]').click();
  await expect(page.locator('[data-queue-filter="unassigned"]')).toHaveClass(/active/);
  await page.locator('[data-queue-filter="escalated"]').click();
  await expect(page.locator('[data-queue-filter="escalated"]')).toHaveClass(/active/);
  await page.locator('[data-queue-filter="all"]').click();
  await expect(page.locator('[data-queue-filter="all"]')).toHaveClass(/active/);
  await page.locator('#queueCategoryFilter').selectOption('us_ssn');
  await expect(page.locator(`.q[data-id="${approve.id}"]`)).toBeVisible();
  await page.locator('#queueDestinationFilter').selectOption('claude.ai');
  await expect(page.locator(`.q[data-id="${approve.id}"]`)).toBeVisible();
  await expect(page.locator(`.q[data-id="${deny.id}"]`)).toHaveCount(0);
  await page.locator('#queueDestinationFilter').selectOption('all');
  await page.locator('#queueCategoryFilter').selectOption('all');
  await page.locator('#toggleQueueDensity').click();
  await expect(page.locator('body')).toHaveClass(/queue-density-compact/);
  await expect(page.locator('#toggleQueueDensity')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#toggleQueueDensity')).toContainText('Comfort view');
  await page.locator('#toggleQueueDensity').click();
  await expect(page.locator('body')).not.toHaveClass(/queue-density-compact/);
  await expect(page.locator('#toggleQueueDensity')).toHaveAttribute('aria-pressed', 'false');

  const revealRow = page.locator(`.q[data-id="${reveal.id}"]`);
  await revealRow.click();
  await expect(revealRow).toHaveClass(/selected/);
  await revealRow.locator('[data-act="reveal"]').click();
  await expect(page.getByRole('heading', { name: 'Confirm raw reveal' })).toBeVisible();
  await page.getByLabel('Account password').fill('e2e-pass');
  await page.locator('.stepup-dialog').getByRole('button', { name: 'Reveal' }).click();
  await expect(page.locator(`#p_${reveal.id}`)).toContainText('524-71-9101');
  await expect(revealRow.locator('[data-act="reveal"]')).toHaveText('Raw shown and logged');
  await expect(revealRow.locator('.prompt-reveal-status.raw')).toContainText('Raw prompt revealed');

  await setStoreRawForApproval(page, false);
  const noRaw = await createHeldPrompt(request, {
    suffix: '9104',
    user: 'no-raw-ui@example.test',
    destination: 'claude.ai',
  });
  await page.locator('#refreshQueue').click();
  const noRawRow = page.locator(`.q[data-id="${noRaw.id}"]`);
  await expect(noRawRow).toBeVisible();
  await expect(noRawRow).not.toContainText('524-71-9104');
  await expect(noRawRow.locator('[data-act="reveal"]')).toHaveText('Raw not retained');
  await expect(noRawRow.locator('[data-act="reveal"]')).toBeDisabled();
  await setStoreRawForApproval(page, true);
  await noRawRow.locator('textarea.note').fill('Cleanup non-retained raw UI check');
  await noRawRow.locator('[data-act="deny"]').click();
  await expect(noRawRow).toHaveCount(0);

  const denyRow = page.locator(`.q[data-id="${deny.id}"]`);
  await denyRow.locator('textarea.note').fill('Deny from full UI wiring sweep');
  await denyRow.locator('[data-act="deny"]').click();
  await expect(denyRow).toHaveCount(0);

  const approveRow = page.locator(`.q[data-id="${approve.id}"]`);
  await approveRow.locator('textarea.note').fill('Approve from full UI wiring sweep');
  await approveRow.locator('[data-act="approve"]').click();
  await expect(page.getByRole('heading', { name: 'Confirm release' })).toBeVisible();
  await page.getByLabel('Account password').fill('e2e-pass');
  await page.locator('.stepup-dialog').getByRole('button', { name: 'Approve release' }).click();
  await expect(approveRow).toHaveCount(0);

  await page.locator('.content-tabs .tab[data-tab="activity"]').click();
  await expect(page.locator('#activityRows')).toContainText('approved');
  await expect(page.locator('#activityRows')).toContainText('denied');
  await page.locator('#globalSearch').fill('approve-ui@example.test');
  await expect(page.locator('#activityRows')).toContainText('approve-ui@example.test');
  await page.locator('#globalSearch').fill('no-user-for-ui-wiring');
  await expect(page.locator('#activityRows')).toContainText('No matching activity');
  await page.locator('#globalSearch').fill('');

  await page.locator('.content-tabs .tab[data-tab="coverage"]').click();
  await page.locator('#refreshCoverage').click();
  await expect(page.locator('#coverageScore')).toContainText('Coverage score');
  await expect(page.locator('#sensorMix')).toContainText('Browser extension');
  await expect(page.locator('#fleetRows')).toContainText('endpoint-health@example.test');
  await expect(page.locator('#shadowRows')).toContainText(shadowDestination);
  await page.locator(`[data-destination-review="block"][data-destination="${shadowDestination}"]`).click();
  await expect(page.getByRole('heading', { name: 'Record destination reason' })).toBeVisible();
  await page.locator('.stepup-dialog textarea[name="reason"]').fill('full_ui_wiring_review');
  await page.locator('.stepup-dialog').getByRole('button', { name: 'Save review' }).click();
  await expect(page.locator('#shadowRows')).toContainText('Blocked');

  await page.locator('.content-tabs .tab[data-tab="identity"]').click();
  await page.locator('#identityProvider').selectOption('okta');
  await page.locator('#identityTenant').fill('customer.okta.com');
  await page.locator('#refreshIdentity').click();
  await expect(page.locator('#identityOidcRows')).toContainText('customer.okta.com/oauth2/default');
  await expect(page.locator('#identityEnvRows')).toContainText('OIDC_CLIENT_SECRET');

  await page.locator('.content-tabs .tab[data-tab="lineage"]').click();
  await page.locator('#refreshLineage').click();
  await expect(page.locator('#lineageSummary')).toContainText('Events');
  await expect(page.locator('#lineageUsers')).toContainText('approve-ui@example.test');
  await page.locator('#globalSearch').fill('claude.ai');
  await expect(page.locator('#lineageDestinations')).toContainText('claude.ai');
  await page.locator('#globalSearch').fill('');

  await page.locator('.content-tabs .tab[data-tab="policy"]').click();
  await expect(page.locator('#pol_desktop_destination')).toBeVisible();
  const originalRisk = await page.locator('#pol_risk').inputValue();
  await page.locator('#testConfiguration').click();
  await expect(page.locator('#polSaved')).toContainText(/check|warning|ready/);
  await page.locator('#pol_risk').fill(String(Number(originalRisk || 20) + 1));
  await page.locator('#discardPolicy').click();
  await expect(page.locator('#pol_risk')).toHaveValue(originalRisk);

  await page.locator('#scope_builder_id').fill('ui_scope_rule');
  await page.locator('#scope_builder_groups').fill('PromptWall Legal');
  await page.locator('#scope_builder_destinations').fill('claude.ai');
  await page.locator('#scope_builder_categories').fill('LEGAL_CONTRACT');
  await page.locator('#scope_builder_mode').selectOption('block');
  await page.locator('#scope_builder_risk').fill('42');
  await page.locator('#scope_builder_reason').fill('full_ui_wiring_scope');
  await page.locator('#addScopeRule').click();
  await expect(page.locator('#pol_policy_scopes')).toHaveValue(/ui_scope_rule/);

  await page.locator('#exception_builder_id').fill('ui_exception_rule');
  await page.locator('#exception_builder_users').fill('counsel@example.test');
  await page.locator('#exception_builder_destinations').fill('claude.ai');
  await page.locator('#exception_builder_categories').fill('LEGAL_CONTRACT');
  await page.locator('#exception_builder_hours').fill('48');
  await page.locator('#exception_builder_owner_group').fill('legal');
  await page.locator('#exception_builder_reviewer_role').selectOption('security_admin');
  await page.locator('#exception_builder_review_hours').fill('24');
  await page.locator('#exception_builder_reason').fill('full_ui_wiring_exception');
  await page.locator('#addExceptionRule').click();
  await expect(page.locator('#pol_policy_exceptions')).toHaveValue(/ui_exception_rule/);

  await page.locator('input[name="mode"][value="justify"]').check();
  await page.locator('#pol_sev').selectOption('3');
  await page.locator('#pol_risk').fill('42');
  await page.locator('#pol_retention').fill('14');
  await page.locator('#pol_desktop_destination').fill('Desktop AI QA');
  await page.locator('#pol_response_scan_mode').selectOption('block');
  await page.locator('#pol_allowed_destinations').fill('claude.ai');
  await page.locator('#pol_blocked_destinations').fill('shadow-ui.example');
  await page.locator('#pol_blocked_file_upload_destinations').fill('chatgpt.com');
  await page.locator('#pol_blocked_browser_actions').fill(JSON.stringify([{
    id: 'ui_block_paste',
    action: 'paste',
    destinations: ['chatgpt.com'],
    reason: 'full_ui_wiring_paste',
  }], null, 2));
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.locator('#polSaved')).toHaveText('Saved');
  const savedPolicy = await page.evaluate(async () => (await fetch('/api/policy')).json());
  expect(savedPolicy.enforcementMode).toBe('justify');
  expect(savedPolicy.blockMinSeverity).toBe(3);
  expect(savedPolicy.blockRiskScore).toBe(42);
  expect(savedPolicy.rawRetentionDays).toBe(14);
  expect(savedPolicy.desktopCollectorDestination).toBe('Desktop AI QA');
  expect(savedPolicy.responseScanMode).toBe('block');
  expect(savedPolicy.policyScopes.some((rule) => rule.id === 'ui_scope_rule')).toBe(true);
  expect(savedPolicy.policyExceptions.some((rule) => rule.id === 'ui_exception_rule')).toBe(true);
  expect(savedPolicy.blockedBrowserActions.some((rule) => rule.id === 'ui_block_paste')).toBe(true);

  await page.locator('.ps-tpl[data-tpl="baseline"]').click();
  await expect(page.locator('input[name="mode"][value="block"]')).toBeChecked();
  await page.locator('#runRetentionPurge').click();
  await expect(page.locator('#polSaved')).toContainText('Purged');

  await page.locator('.content-tabs .tab[data-tab="audit"]').click();
  await expect(page.locator('#integrity')).toContainText('Chain verified');
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export Evidence' }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^promptwall-evidence-/);
  const pack = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
  expect(pack.auditIntegrity.ok).toBe(true);
  expect(JSON.stringify(pack)).not.toContain('524-71-9101');

  await page.locator('#logout').click();
  await expect(page).toHaveURL(/\/login\.html$/);
  await expect(page.locator('#password')).toBeVisible();

  expect(problems).toEqual([]);
});

test('admin console secondary controls and dialog cancels are wired end to end', async ({ page, request }) => {
  const problems = collectUiProblems(page);
  const reveal = await createHeldPrompt(request, {
    suffix: '9201',
    user: 'cancel-reveal-ui@example.test',
    destination: 'chatgpt.com',
  });
  const approve = await createHeldPrompt(request, {
    suffix: '9202',
    user: 'cancel-approve-ui@example.test',
    destination: 'claude.ai',
  });
  const destinations = {
    govern: 'govern-secondary.example',
    allow: 'allow-secondary.example',
    block: 'block-secondary.example',
  };
  for (const destination of Object.values(destinations)) {
    await createShadowAi(request, destination);
  }

  await login(page);

  for (const tabName of ['activity', 'coverage', 'identity', 'lineage', 'audit', 'policy', 'queue']) {
    await page.locator(`.rail .tab[data-tab="${tabName}"]`).click();
    await expect(page.locator(`#tab-${tabName}`)).toBeVisible();
  }

  await page.locator('.content-tabs .tab[data-tab="queue"]').click();
  const revealRow = page.locator(`.q[data-id="${reveal.id}"]`);
  await revealRow.click();
  await revealRow.locator('[data-act="reveal"]').click();
  await expect(page.getByRole('heading', { name: 'Confirm raw reveal' })).toBeVisible();
  await page.locator('.stepup-dialog').getByRole('button', { name: 'Cancel' }).click();
  await expect(page.locator('.stepup-dialog')).toHaveCount(0);
  await expect(page.locator(`#p_${reveal.id}`)).not.toContainText('524-71-9201');
  await expect(revealRow.locator('[data-act="reveal"]')).toBeEnabled();

  const approveRow = page.locator(`.q[data-id="${approve.id}"]`);
  await approveRow.locator('textarea.note').fill('Cancel path should keep the item queued');
  await approveRow.locator('[data-act="approve"]').click();
  await expect(page.getByRole('heading', { name: 'Confirm release' })).toBeVisible();
  await page.locator('.stepup-dialog').getByRole('button', { name: 'Cancel' }).click();
  await expect(page.locator('.stepup-dialog')).toHaveCount(0);
  await expect(approveRow).toBeVisible();
  await expect(approveRow.locator('[data-act="approve"]')).toBeEnabled();

  await page.locator('.content-tabs .tab[data-tab="coverage"]').click();
  await page.locator('#refreshCoverage').click();
  for (const [decision, destination] of Object.entries(destinations)) {
    await page.locator(`[data-destination-review="${decision}"][data-destination="${destination}"]`).click();
    await expect(page.getByRole('heading', { name: 'Record destination reason' })).toBeVisible();
    await page.locator('.stepup-dialog textarea[name="reason"]').fill(`secondary_${decision}_review`);
    await page.locator('.stepup-dialog').getByRole('button', { name: 'Save review' }).click();
    await expect(page.locator('#shadowRows')).toContainText(destination);
  }
  await expect(page.locator('#shadowRows')).toContainText('Governed');
  await expect(page.locator('#shadowRows')).toContainText('Allowed');
  await expect(page.locator('#shadowRows')).toContainText('Blocked');
  const destinationPolicy = await page.evaluate(async () => (await fetch('/api/policy')).json());
  expect(destinationPolicy.governedDestinations).toContain(destinations.govern);
  expect(destinationPolicy.allowedDestinations).toContain(destinations.allow);
  expect(destinationPolicy.blockedDestinations).toContain(destinations.block);

  await page.locator('.content-tabs .tab[data-tab="policy"]').click();
  for (const [mode, label] of [
    ['warn', 'Monitor'],
    ['justify', 'Justify'],
    ['redact', 'Redact'],
    ['block', 'Enforce'],
  ]) {
    await page.locator(`input[name="mode"][value="${mode}"]`).check();
    await expect(page.locator(`label.policy-option:has(input[name="mode"][value="${mode}"])`)).toHaveClass(/selected/);
    await expect(page.locator(`label.policy-option:has(input[name="mode"][value="${mode}"])`)).toContainText(label);
  }

  const originalBlockUnapproved = await page.locator('#pol_block_unapproved_ai').isChecked();
  await page.locator('#pol_block_unapproved_ai').setChecked(!originalBlockUnapproved);
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.locator('#polSaved')).toHaveText('Saved');
  let savedPolicy = await page.evaluate(async () => (await fetch('/api/policy')).json());
  expect(savedPolicy.blockUnapprovedAiDestinations).toBe(!originalBlockUnapproved);
  await page.locator('#pol_block_unapproved_ai').setChecked(originalBlockUnapproved);
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.locator('#polSaved')).toHaveText('Saved');

  const templates = [
    ['baseline', 'block'],
    ['ncua_glba', 'block'],
    ['pci_dss', 'block'],
    ['hipaa', 'block'],
    ['redact_first', 'redact'],
  ];
  for (const [templateId, expectedMode] of templates) {
    await page.locator(`.ps-tpl[data-tpl="${templateId}"]`).click();
    await expect(page.locator(`input[name="mode"][value="${expectedMode}"]`)).toBeChecked();
    savedPolicy = await page.evaluate(async () => (await fetch('/api/policy')).json());
    expect(savedPolicy.enforcementMode).toBe(expectedMode);
  }

  await page.getByRole('button', { name: 'View coverage' }).click();
  await expect(page.locator('#tab-coverage')).toBeVisible();

  expect(problems).toEqual([]);
});

test('signal operations monitoring console supports adaptive states', async ({ page }) => {
  const problems = collectUiProblems(page);
  await login(page);

  await page.locator('.content-tabs .tab[data-tab="monitor"]').click();
  await expect(page.locator('#tab-monitor')).toBeVisible();
  await expect(page.locator('.signal-console')).toContainText('Signal Monitor');
  await expect(page.locator('#monitorInspector')).toContainText('No selection');

  await page.locator('#monitorSearch').focus();
  await expect(page.locator('#monitorSearchWrap')).toHaveAttribute('data-state', 'focus');
  await page.locator('#monitorSearch').fill('a');
  await expect(page.locator('#monitorSearchWrap')).toHaveAttribute('data-state', 'warning');
  await expect(page.locator('#monitorSearchHelp')).toContainText('Too broad.');
  await page.locator('#monitorSearch').fill('<bad');
  await expect(page.locator('#monitorSearchWrap')).toHaveAttribute('data-state', 'error');
  await expect(page.locator('#monitorSearch')).toHaveAttribute('aria-invalid', 'true');
  await page.locator('#monitorSearch').fill('audit');
  await expect(page.locator('#monitorSearchWrap')).toHaveAttribute('data-state', 'valid');

  await page.locator('[data-monitor-status="error"]').click();
  await expect(page.locator('[data-monitor-status="error"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#monitorPanelGrid')).toContainText('Audit Chain Verifier');
  await expect(page.locator('#monitorPanelGrid')).not.toContainText('Browser Chat Sensor');

  await page.locator('[data-monitor-select="item"][data-monitor-id="node-audit-verifier"]').click();
  await expect(page.locator('#monitorInspector')).toContainText('Audit Chain Verifier');
  await page.locator('[data-monitor-expand="node-audit-verifier"]').click();
  await expect(page.locator('[data-monitor-panel="node-audit-verifier"]')).toHaveClass(/is-expanded/);
  await expect(page.locator('[data-monitor-panel="node-audit-verifier"]')).toContainText('97% confidence');
  await page.locator('[data-monitor-close-inspector]').click();
  await expect(page.locator('#monitorInspector')).toContainText('No selection');

  await page.locator('#monitorSearch').fill('');
  await page.locator('[data-monitor-status="all"]').click();
  const eventRow = page.locator('.activity-feed-row[data-monitor-event-id="evt-7902"]');
  await eventRow.click();
  await expect(page.locator('#monitorInspector')).toContainText('SSN paste blocked before egress');
  await eventRow.locator('[data-monitor-event-expand="evt-7902"]').click();
  await expect(page.locator('.activity-detail-block:has-text("hard-stop identifier")')).toBeVisible();

  await page.locator('#monitorRefresh').click();
  await expect(page.locator('#monitorRefresh')).toBeDisabled();
  await expect(page.locator('#monitorRefresh')).toContainText('Refreshing');
  await expect(page.locator('#monitorSearch')).toBeDisabled();
  await expect(page.locator('#monitorRefresh')).toBeEnabled();
  await expect(page.locator('#monitorActivityFeed')).toContainText('Signal refresh completed');

  await page.emulateMedia({ reducedMotion: 'reduce' });
  await expect(page.locator('.signal-dot.is-pulsing').first()).toHaveCSS('animation-name', 'none');
  expect(problems).toEqual([]);
});

test('admin console mobile layout keeps content tabs usable', async ({ page }) => {
  const problems = collectUiProblems(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);

  await expect(page.locator('.content-tabs .tab[data-tab="queue"]')).toBeVisible();
  const railTabsDisplay = await page.locator('.rail .tabs').evaluate((el) => getComputedStyle(el).display);
  expect(railTabsDisplay).toBe('none');

  await page.locator('.content-tabs .tab[data-tab="policy"]').click();
  await expect(page.locator('#tab-policy')).toBeVisible();
  await page.locator('.content-tabs .tab[data-tab="audit"]').click();
  await expect(page.locator('#tab-audit')).toBeVisible();

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(1);
  expect(problems).toEqual([]);
});
