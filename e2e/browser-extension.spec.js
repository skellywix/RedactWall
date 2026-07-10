'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { test, expect, chromium } = require('@playwright/test');
const pkg = require('../package.json');

const root = path.join(__dirname, '..');
const extensionDir = path.join(root, 'sensors', 'browser-extension');

// Extensions need a full (non-headless-shell) Chromium. If the exact build
// @playwright/test resolves by default is absent (common when the bundled
// browsers under PLAYWRIGHT_BROWSERS_PATH are a different revision), fall back
// to any installed full chromium build so the suite runs across environments.
function resolveChromiumExecutable() {
  const browsersRoot = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (!browsersRoot) return undefined;
  try {
    const dirs = fs.readdirSync(browsersRoot).filter((n) => /^chromium-\d+$/.test(n));
    for (const dir of dirs) {
      for (const rel of ['chrome-linux/chrome', 'chrome-linux64/chrome', 'chrome-mac/Chromium.app/Contents/MacOS/Chromium']) {
        const candidate = path.join(browsersRoot, dir, rel);
        if (fs.existsSync(candidate)) return candidate;
      }
    }
  } catch { /* fall through to default resolution */ }
  return undefined;
}
const chromiumExecutablePath = resolveChromiumExecutable();
const artifactDir = path.join(root, 'test-results', 'browser-extension');
const fixturePolicy = {
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 20,
  governedDestinations: ['chatgpt.com', 'poe.com'],
  allowedDestinations: [],
  blockedDestinations: [],
  blockedFileUploadDestinations: [],
  blockedBrowserActions: [],
  blockUnapprovedAiDestinations: true,
  alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'],
};
const E2E_POLICY_KEYS = crypto.generateKeyPairSync('ed25519');
const E2E_POLICY_PUBLIC_KEY = E2E_POLICY_KEYS.publicKey.export({ type: 'spki', format: 'pem' }).toString();
let e2ePolicySequence = Date.now();

function arrayIndexKey(value) {
  if (!/^(0|[1-9]\d*)$/.test(value)) return false;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 && parsed < 4294967295 && String(parsed) === value;
}

function orderedPolicyKeys(value) {
  const keys = Object.keys(value);
  return [
    ...keys.filter(arrayIndexKey).sort((left, right) => Number(left) - Number(right)),
    ...keys.filter((key) => !arrayIndexKey(key)).sort(),
  ];
}

function canonicalPolicyJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalPolicyJson).join(',')}]`;
  return `{${orderedPolicyKeys(value).map((key) => (
    `${JSON.stringify(key)}:${canonicalPolicyJson(value[key])}`
  )).join(',')}}`;
}

function signedFixturePolicy(policy) {
  e2ePolicySequence = Math.max(Date.now(), e2ePolicySequence + 1);
  const issuedAt = new Date(e2ePolicySequence).toISOString();
  const expiresAt = new Date(e2ePolicySequence + (30 * 60 * 1000)).toISOString();
  const canonicalPolicy = JSON.parse(canonicalPolicyJson(policy));
  const policyHash = crypto.createHash('sha256').update(canonicalPolicyJson(canonicalPolicy)).digest('hex');
  const input = JSON.stringify({ version: 1, issuedAt, expiresAt, policyHash });
  return {
    version: 1,
    issuedAt,
    expiresAt,
    policy: canonicalPolicy,
    signature: crypto.sign(null, Buffer.from(input), E2E_POLICY_KEYS.privateKey).toString('base64'),
  };
}

function serverPolicyFromFixture(policy) {
  return {
    enforcementMode: policy.enforcementMode,
    blockMinSeverity: policy.blockMinSeverity,
    blockRiskScore: policy.blockRiskScore,
    alwaysBlock: policy.alwaysBlock || [],
    governedDestinations: policy.governedDestinations || [],
    allowedDestinations: policy.allowedDestinations || [],
    blockedDestinations: policy.blockedDestinations || [],
    blockedFileUploadDestinations: policy.blockedFileUploadDestinations || [],
    blockedBrowserActions: policy.blockedBrowserActions || [],
    blockUnapprovedAiDestinations: policy.blockUnapprovedAiDestinations !== false,
    ...(policy.corporateAiAccounts ? { corporateAiAccounts: policy.corporateAiAccounts } : {}),
    storeRawForApproval: true,
    rawRetentionDays: 30,
    ignore: [],
    disabledDetectors: [],
    responseScanMode: 'flag',
    desktopCollectorDestination: 'Desktop AI',
    approvalRoutingRules: [],
    policyScopes: [],
    policyExceptions: [],
    requiredSensors: ['browser_extension', 'endpoint_agent', 'mcp_guard'],
    desiredSensorVersions: {
      browser_extension: pkg.version,
      endpoint_agent: pkg.version,
      mcp_guard: pkg.version,
    },
  };
}

function serverScopedJustificationPolicies() {
  const serverPolicy = {
    ...fixturePolicy,
    enforcementMode: 'justify',
    blockMinSeverity: 1,
    blockRiskScore: 1,
  };
  return {
    serverPolicy,
    locallyPermissivePolicy: {
      ...serverPolicy,
      enforcementMode: 'block',
      blockMinSeverity: 99,
      blockRiskScore: 999,
    },
  };
}

function comparableBrowserActions(rules) {
  return (rules || []).map((rule) => ({
    id: rule.id,
    action: rule.action,
    destinations: rule.destinations || [],
    reason: rule.reason,
  }));
}

function chatFixture({ host, sendButton, accountRegion = '', contenteditable = false }) {
  const composerMarkup = contenteditable
    ? '<div id="prompt-textarea" role="textbox" aria-label="Message" contenteditable="true"></div>'
    : '<textarea id="prompt-textarea" aria-label="Message"></textarea>';
  return `<!doctype html>
<html>
  <head>
    <title>${host} fixture</title>
    <style>
      body { font: 14px system-ui, sans-serif; margin: 24px; }
      *, *::before, *::after { box-sizing: border-box; }
      main { max-width: 760px; margin: 0 auto; }
      textarea, [contenteditable="true"] {
        display: block; width: 100%; min-height: 120px; margin: 16px 0;
        border: 1px solid #999; padding: 12px; white-space: pre-wrap;
      }
      button { padding: 8px 12px; }
      #sent { margin-top: 20px; border-top: 1px solid #ddd; padding-top: 12px; }
    </style>
  </head>
  <body>
    <main>
      <h1>${host} controlled chat fixture</h1>
      ${accountRegion}
      ${composerMarkup}
      ${sendButton}
      <input id="file-upload" type="file" aria-label="Attach file">
      <section id="uploads" aria-label="Uploaded files"></section>
      <section id="sent" aria-label="Sent messages"></section>
    </main>
    <script>
      window.__sent = [];
      window.__uploaded = [];
      const composer = document.querySelector('#prompt-textarea');
      const sent = document.querySelector('#sent');
      const button = document.querySelector('button');
      const upload = document.querySelector('#file-upload');
      function send() {
        const value = (('value' in composer ? composer.value : composer.textContent) || '').trim();
        if (!value) return;
        window.__sent.push(value);
        sent.insertAdjacentHTML('beforeend', '<p data-sent></p>');
        sent.lastElementChild.textContent = value;
        if ('value' in composer) composer.value = '';
        else composer.textContent = '';
      }
      button.addEventListener('click', send);
      composer.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey) {
          event.preventDefault();
          send();
        }
      });
      upload.addEventListener('change', async () => {
        const files = [...upload.files];
        for (const file of files) {
          const body = await file.text();
          window.__uploaded.push({ name: file.name, body });
          const row = document.createElement('p');
          row.setAttribute('data-uploaded', '');
          row.textContent = file.name + ': ' + body;
          document.querySelector('#uploads').appendChild(row);
        }
      });
    </script>
  </body>
</html>`;
}

function twoComposerFixture() {
  return `<!doctype html>
<html>
<head><meta charset="utf-8"><title>two composer fixture</title></head>
<body>
  <main>
    <h1>controlled chat fixture: two composers</h1>
    <form id="form-a"><textarea id="composer-a" aria-label="Composer A"></textarea></form>
    <button id="send-b" type="button" form="form-b" data-testid="send-button" aria-label="Send B">Send B</button>
    <button id="send-a" type="button" form="form-a" data-testid="send-button" aria-label="Send A">Send A</button>
    <form id="form-b"><textarea id="composer-b" aria-label="Composer B"></textarea></form>
    <section id="sent-a"></section>
    <section id="sent-b"></section>
  </main>
  <script>
    window.__sentA = [];
    window.__sentB = [];
    function send(composerId, sentId, bucket, marker) {
      const composer = document.querySelector(composerId);
      const value = composer.value.trim();
      if (!value) return;
      bucket.push(value);
      const row = document.createElement('p');
      row.setAttribute(marker, '');
      row.textContent = value;
      document.querySelector(sentId).appendChild(row);
      composer.value = '';
    }
    document.querySelector('#send-a').addEventListener('click', () => send('#composer-a', '#sent-a', window.__sentA, 'data-sent-a'));
    document.querySelector('#send-b').addEventListener('click', () => send('#composer-b', '#sent-b', window.__sentB, 'data-sent-b'));
  </script>
</body>
</html>`;
}

// The serviceworker reference can resolve before the extension's chrome.*
// runtime APIs finish initializing, so a first `chrome.storage.local.set`
// occasionally throws "Cannot read properties of undefined (reading 'local')".
// Poll until chrome.storage.local exists before handing the worker back.
async function readyExtensionServiceWorker(context) {
  const serviceWorker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await expect.poll(
    () => serviceWorker.evaluate(() => Boolean(globalThis.chrome && chrome.storage && chrome.storage.local)),
    { timeout: 10000 },
  ).toBe(true);
  return serviceWorker;
}

async function launchExtensionContext(baseURL, testInfo, policy = fixturePolicy, request = null, extensionPath = extensionDir) {
  if (request) await syncServerPolicy(request, policy);
  const policyBundle = signedFixturePolicy(policy);
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-extension-e2e-'));
  await testInfo.attach('user-data-dir', { body: userDataDir, contentType: 'text/plain' });
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    ...(chromiumExecutablePath ? { executablePath: chromiumExecutablePath } : {}),
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
    ],
  });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://chatgpt.com' });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://poe.com' });
  await testInfo.attach('extension-dir', { body: extensionPath, contentType: 'text/plain' });
  await testInfo.attach('test-policy', {
    body: JSON.stringify({
      serverUrl: baseURL,
      ingestKey: 'e2e-ingest-key',
      enabled: true,
      policy,
      policyBundle,
      policyPublicKey: E2E_POLICY_PUBLIC_KEY,
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
    }, null, 2),
    contentType: 'application/json',
  });

  const serviceWorker = await readyExtensionServiceWorker(context);
  await serviceWorker.evaluate(async ({ serverUrl, policy, policyBundle, policyPublicKey }) => {
    await chrome.storage.local.set({
      serverUrl,
      ingestKey: 'e2e-ingest-key',
      enabled: true,
      requestTimeoutMs: 10000,
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
      policy,
      policyBundle,
      policyPublicKey,
    });
  }, { serverUrl: baseURL, policy, policyBundle, policyPublicKey: E2E_POLICY_PUBLIC_KEY });

  const expectedPolicyJson = JSON.stringify(policy);
  const expectedPolicyHash = crypto.createHash('sha256').update(expectedPolicyJson).digest('hex');
  const policyTrust = await serviceWorker.evaluate(async ({ expectedPolicyJson, expectedPolicyHash }) => {
    const local = await chrome.storage.local.get(['serverUrl', 'policyBundle', 'policyPublicKey']);
    const config = await cfg();
    const storedPolicyJson = JSON.stringify(local.policyBundle.policy);
    const storedDigest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(storedPolicyJson));
    const storedPolicyHash = [...new Uint8Array(storedDigest)]
      .map((value) => value.toString(16).padStart(2, '0')).join('');
    const verification = await self.RedactWallPolicyTrust.verifyBundle(
      local.policyBundle,
      local.policyPublicKey,
    );
    return {
      verification,
      policyTrusted: config.policyTrusted,
      policyExpiresAt: config.policyExpiresAt,
      serverUrl: config.serverUrl,
      localPinPresent: !!local.policyPublicKey,
      policyJsonPreserved: storedPolicyJson === expectedPolicyJson,
      expectedPolicyHash,
      storedPolicyHash,
    };
  }, { expectedPolicyJson, expectedPolicyHash });
  await testInfo.attach('policy-trust', {
    body: JSON.stringify(policyTrust, null, 2),
    contentType: 'application/json',
  });
  expect(policyTrust, `policy trust bootstrap failed: ${JSON.stringify(policyTrust)}`).toMatchObject({
    verification: { ok: true },
    policyTrusted: true,
    serverUrl: baseURL,
    localPinPresent: true,
  });

  return { context, userDataDir };
}

async function applyFixturePolicyToPage(context, page, baseURL, governedHost, policy = fixturePolicy) {
  const serviceWorker = await readyExtensionServiceWorker(context);
  const policyBundle = signedFixturePolicy(policy);
  const expectedRules = (policy.blockedBrowserActions || []).map((rule) => ({
    id: rule.id,
    action: rule.action,
  }));
  await serviceWorker.evaluate(async ({ serverUrl, policy, policyBundle, policyPublicKey }) => {
    await chrome.storage.local.set({
      serverUrl,
      ingestKey: 'e2e-ingest-key',
      enabled: true,
      requestTimeoutMs: 10000,
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
      policy,
      policyBundle,
      policyPublicKey,
    });
  }, { serverUrl: baseURL, policy, policyBundle, policyPublicKey: E2E_POLICY_PUBLIC_KEY });

  await page.reload({ waitUntil: 'domcontentloaded' });
  await expect(page.locator('h1')).toContainText('controlled chat fixture');
  await expect(page.locator('[data-sent]')).toHaveCount(0);

  await expect.poll(async () => serviceWorker.evaluate(async ({ url, host, expectedRules }) => {
    const tabs = await chrome.tabs.query({});
    const normalizedUrl = String(url || '').replace(/\/$/, '');
    const tab = tabs.find((candidate) => String(candidate.url || '').replace(/\/$/, '') === normalizedUrl);
    if (!tab || !tab.id) return false;
    try {
      const state = await chrome.tabs.sendMessage(tab.id, { type: 'getPolicyState' });
      return !!(
        state
        && state.enabled
        && state.policyTrusted
        && state.policy
        && state.policy.blockUnapprovedAiDestinations === true
        && (state.policy.governedDestinations || []).includes(host)
        && expectedRules.every((expected) => (state.policy.blockedBrowserActions || []).some((actual) => (
          actual && actual.id === expected.id && actual.action === expected.action
        )))
      );
    } catch (_) {
      return false;
    }
  }, { url: page.url(), host: governedHost, expectedRules }), {
    timeout: 15000,
    intervals: [100, 250, 500, 1000],
  }).toBe(true);
}

async function openControlledAiPage(context, url, html) {
  await context.route(url + '**', (route) => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: html,
  }));
  const page = await context.newPage();
  await page.goto(url);
  await expect(page.locator('h1')).toContainText('controlled chat fixture');
  await expect(page.locator('[data-sent]')).toHaveCount(0);
  return page;
}

async function syntheticPaste(page, value) {
  return page.locator('#prompt-textarea').evaluate((composer, text) => {
    composer.focus();
    const data = new DataTransfer();
    data.setData('text/plain', text);
    data.setData('text', text);
    const event = new ClipboardEvent('paste', {
      bubbles: true,
      cancelable: true,
      clipboardData: data,
    });
    const defaultAllowed = composer.dispatchEvent(event);
    if (!defaultAllowed) return true;
    if ('value' in composer) {
      composer.value += text;
    } else {
      composer.textContent = `${composer.textContent || ''}${text}`;
    }
    composer.dispatchEvent(new InputEvent('input', {
      bubbles: true,
      cancelable: true,
      data: text,
      inputType: 'insertFromPaste',
    }));
    return false;
  }, value);
}

async function installDraftSyncRecorder(page) {
  await page.evaluate(() => {
    const composer = document.querySelector('#prompt-textarea');
    window.__draftSync = [];
    composer.addEventListener('input', () => {
      window.__draftSync.push(composer.value || composer.innerText || composer.textContent || '');
    });
  });
}

async function syntheticFileDrop(page, { name, body }) {
  return page.evaluate(({ name, body }) => {
    const data = new DataTransfer();
    data.items.add(new File([body], name, { type: 'text/plain' }));
    const event = new DragEvent('drop', { bubbles: true, cancelable: true, dataTransfer: data });
    document.querySelector('#prompt-textarea').dispatchEvent(event);
    return event.defaultPrevented;
  }, { name, body });
}

async function syntheticCopyFromResponse(page, value) {
  return page.evaluate((text) => {
    const sent = document.querySelector('#sent');
    sent.insertAdjacentHTML('beforeend', '<p data-response></p>');
    const response = sent.lastElementChild;
    response.textContent = text;
    const range = document.createRange();
    range.selectNodeContents(response);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    const event = new Event('copy', { bubbles: true, cancelable: true });
    response.dispatchEvent(event);
    selection.removeAllRanges();
    return event.defaultPrevented;
  }, value);
}

async function loginAdminApi(request) {
  const response = await request.post('/api/login', {
    data: { user: 'admin', password: 'e2e-pass' },
  });
  expect(response.ok()).toBeTruthy();
  const csrf = await request.get('/api/csrf');
  expect(csrf.ok()).toBeTruthy();
  const { csrfToken } = await csrf.json();
  return csrfToken;
}

async function syncServerPolicy(request, policy) {
  const csrfToken = await loginAdminApi(request);
  const response = await request.put('/api/policy', {
    headers: { 'x-csrf-token': csrfToken },
    data: serverPolicyFromFixture(policy),
  });
  expect(response.ok()).toBeTruthy();
  const sensorPolicy = await request.get('/api/v1/policy', {
    headers: { 'x-api-key': 'e2e-ingest-key' },
  });
  expect(sensorPolicy.ok()).toBeTruthy();
  const body = await sensorPolicy.json();
  expect(body.enforcementMode).toBe(policy.enforcementMode);
  expect(body.blockUnapprovedAiDestinations).toBe(policy.blockUnapprovedAiDestinations !== false);
  expect(body.governedDestinations || []).toEqual(policy.governedDestinations || []);
  expect(comparableBrowserActions(body.blockedBrowserActions)).toEqual(comparableBrowserActions(policy.blockedBrowserActions));
}

async function queryStatusesFor(request, status) {
  const response = await request.get('/api/queries?limit=100');
  expect(response.ok()).toBeTruthy();
  const rows = await response.json();
  return rows.filter((row) => row.user === 'browser-smoke@example.test' && row.status === status).length;
}

async function browserRowsFor(request) {
  const response = await request.get('/api/queries?limit=100');
  expect(response.ok()).toBeTruthy();
  const rows = await response.json();
  return rows.filter((row) => row.user === 'browser-smoke@example.test');
}

async function expectNoHorizontalOverflow(page, allowance = 1) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(allowance);
}

async function expectElementInsideViewport(page, locator) {
  const box = await locator.boundingBox();
  const viewport = page.viewportSize();
  expect(box).toBeTruthy();
  expect(viewport).toBeTruthy();
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
}

test.describe('browser extension live smoke', () => {
  test.setTimeout(90000);

  test('blocks a synthetic SSN, polls its approval, and resumes only after release', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await syntheticPaste(page, 'Member test SSN 123-45-6789');
      await expect(page.locator('.ps-toast')).toContainText('Social Security number');
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');

      await page.locator('#prompt-textarea').fill('Member test SSN 123-45-6789 needs a payoff letter.');
      await page.locator('button[data-testid="send-button"]').click();

      const blockBanner = page.getByRole('alertdialog', { name: 'Sensitive data blocked' });
      await expect(blockBanner).toBeVisible();
      await expect(page.locator('.ps-title')).toContainText('Sensitive data blocked');
      await expect(blockBanner).toContainText('before it could leave this browser');
      await expect(page.locator('.ps-chip')).toContainText('Social Security number');
      await expect(blockBanner).not.toContainText('US_SSN');
      await expect(page.locator('.ps-coach')).toContainText('member ID');
      await page.getByRole('button', { name: 'Edit prompt' }).click();
      await expect(page.locator('.ps-banner')).toHaveCount(0);
      await expect(page.locator('[data-sent]')).toHaveCount(0);

      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.locator('.ps-banner')).toBeVisible();
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await page.waitForTimeout(200);
      fs.mkdirSync(artifactDir, { recursive: true });
      await page.screenshot({ path: path.join(artifactDir, 'chatgpt-blocked.png'), fullPage: true });

      await page.getByRole('button', { name: 'Request approval' }).click();
      await expect(page.locator('.ps-toast')).toContainText('Sent to your Security Admin for approval.');
      await expect(page.locator('[data-sent]')).toHaveCount(0);

      const csrfToken = await loginAdminApi(request);
      const rows = await (await request.get('/api/queries?limit=100')).json();
      const held = rows.find((row) => row.user === 'browser-smoke@example.test'
        && row.source === 'browser_extension' && row.status === 'pending');
      expect(held).toBeTruthy();
      const approved = await request.post(`/api/queries/${encodeURIComponent(held.id)}/approve`, {
        headers: { 'x-csrf-token': csrfToken },
        data: { note: 'Synthetic browser release', password: 'e2e-pass' },
      });
      expect(approved.ok()).toBeTruthy();

      await expect(page.locator('[data-sent]')).toHaveCount(1, { timeout: 10000 });
      await expect(page.locator('[data-sent]')).toContainText('123-45-6789 needs a payoff letter');
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('coaches on a personal AI account and records the account type (N4)', async ({ baseURL, request }, testInfo) => {
    const coachPolicy = { ...fixturePolicy, corporateAiAccounts: { orgEmailDomains: ['examplecu.org'], personalAccountAction: 'coach' } };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, coachPolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
          accountRegion: '<button data-testid="accounts-profile-button" aria-label="Google Account: Jane Roe (jane.roe@gmail.com)">Account</button>',
        }),
      );

      // The probe runs on load + retries; the coach toast appears for a personal account.
      await expect(page.locator('.ps-account-coach')).toContainText('personal account', { timeout: 20000 });

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');
      await page.locator('#prompt-textarea').fill('What are our branch hours this week?');
      await page.locator('button[data-testid="send-button"]').click();
      await page.waitForTimeout(400);

      const rows = await (await request.get('/api/queries?limit=100')).json();
      const personal = rows.filter((r) => r.accountType === 'personal');
      expect(personal.length).toBeGreaterThan(0);
      // No raw account email is ever stored.
      expect(JSON.stringify(rows)).not.toContain('jane.roe@gmail.com');
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('prevents hard-stop paste before a live page can draft-sync it', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');
      await installDraftSyncRecorder(page);
      await syntheticPaste(page, 'Member test SSN 123-45-6789');

      await expect(page.locator('.ps-toast')).toContainText('blocked sensitive paste');
      await expect(page.locator('#prompt-textarea')).toHaveValue('');
      const drafts = await page.evaluate(() => window.__draftSync || []);
      expect(drafts.join('\n')).not.toContain('123-45-6789');
      await expect(page.locator('[data-sent]')).toHaveCount(0);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('block banner fits narrow AI pages without horizontal overflow', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await page.setViewportSize({ width: 360, height: 740 });
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');
      await page.locator('#prompt-textarea').fill('Member test SSN 123-45-6789 needs a payoff letter.');
      await page.locator('button[data-testid="send-button"]').click();

      const blockBanner = page.getByRole('alertdialog', { name: 'Sensitive data blocked' });
      await expect(blockBanner).toBeVisible();
      await expectElementInsideViewport(page, blockBanner);
      await expect(page.getByRole('button', { name: 'Edit prompt' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Request approval' })).toBeVisible();
      await expectNoHorizontalOverflow(page);
      await expect(page.locator('[data-sent]')).toHaveCount(0);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('block and paste notices honor reduced motion preference', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await page.emulateMedia({ reducedMotion: 'reduce' });
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');
      await syntheticPaste(page, 'Member test SSN 123-45-6789');
      const pasteToast = page.locator('.ps-toast');
      await expect(pasteToast).toContainText('blocked sensitive paste');
      await expect(pasteToast).toHaveCSS('animation-name', 'none');

      await page.locator('#prompt-textarea').fill('Member test SSN 123-45-6789 needs a payoff letter.');
      await page.locator('button[data-testid="send-button"]').click();
      const blockBanner = page.getByRole('alertdialog', { name: 'Sensitive data blocked' });
      await expect(blockBanner).toBeVisible();
      await expect(blockBanner).toHaveCSS('animation-name', 'none');
      await expect(page.locator('[data-sent]')).toHaveCount(0);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('uses adapter send-button selectors on Poe-style click targets', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://poe.com/',
        chatFixture({
          host: 'poe.com',
          sendButton: '<button class="sendButton_demo">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'poe.com');
      await page.locator('#prompt-textarea').fill('Member test SSN 123-45-6789 needs a payoff letter.');
      await page.locator('button.sendButton_demo').click();

      await expect(page.locator('.ps-banner')).toBeVisible();
      await expect(page.locator('.ps-title')).toContainText('Sensitive data blocked');
      await expect(page.locator('.ps-chip')).toContainText('Social Security number');
      await expect(page.locator('.ps-banner')).not.toContainText('US_SSN');
      await expect(page.locator('.ps-coach')).toContainText('member ID');
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await page.waitForTimeout(200);
      fs.mkdirSync(artifactDir, { recursive: true });
      await page.screenshot({ path: path.join(artifactDir, 'poe-blocked.png'), fullPage: true });
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('blocks configured file drops before browser upload scanning', async ({ baseURL, request }, testInfo) => {
    const policy = {
      ...fixturePolicy,
      blockedBrowserActions: [{
        id: 'block_drop_chatgpt',
        action: 'drop',
        destinations: ['chatgpt.com'],
        reason: 'file_drop_blocked',
      }],
    };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      const prevented = await syntheticFileDrop(page, {
        name: 'member-loan.txt',
        body: 'Synthetic member SSN 123-45-6789',
      });

      expect(prevented).toBe(true);
      await expect(page.locator('.ps-toast')).toContainText('blocked file drops');
      await expect(page.locator('.ps-toast')).not.toContainText('member-loan.txt');
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await page.waitForTimeout(200);
      fs.mkdirSync(artifactDir, { recursive: true });
      await page.screenshot({ path: path.join(artifactDir, 'chatgpt-drop-blocked.png'), fullPage: true });
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('verified clean file input is replayed to the page after recorded evidence', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');
      await page.locator('#file-upload').setInputFiles({
        name: 'branch-hours.txt',
        mimeType: 'text/plain',
        buffer: Buffer.from('Lobby opens at nine.'),
      });

      await expect(page.locator('[data-uploaded]')).toHaveCount(1, { timeout: 15000 });
      await expect(page.locator('[data-uploaded]')).toContainText('branch-hours.txt: Lobby opens at nine.');
      expect(await page.evaluate(() => window.__uploaded)).toEqual([
        { name: 'branch-hours.txt', body: 'Lobby opens at nine.' },
      ]);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('async allow resumes only the exact composer and never the first global send button', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(context, 'https://chatgpt.com/', twoComposerFixture());
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');
      await page.locator('#composer-a').fill('Summarize the public quarterly update.');
      await page.locator('#composer-b').fill('Composer B must remain unsent.');

      await page.locator('#send-a').click();

      await expect(page.locator('[data-sent-a]')).toHaveCount(1, { timeout: 10000 });
      await expect(page.locator('[data-sent-a]')).toContainText('Summarize the public quarterly update.');
      await expect(page.locator('[data-sent-b]')).toHaveCount(0);
      expect(await page.evaluate(() => ({ sentA: window.__sentA, sentB: window.__sentB }))).toEqual({
        sentA: ['Summarize the public quarterly update.'],
        sentB: [],
      });
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('rapid redact clicks send once and reveal originals only in the extension tab', async ({ baseURL, request }, testInfo) => {
    const policy = {
      ...fixturePolicy,
      enforcementMode: 'redact',
      blockMinSeverity: 1,
      blockRiskScore: 1,
    };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      const rawValue = 'alex.member@example.com';
      await page.locator('#prompt-textarea').fill('Contact ' + rawValue + ' about public branch hours.');
      const revealPagePromise = context.waitForEvent('page', {
        predicate: (candidate) => candidate.url().includes('/rehydrate.html'),
      });

      await page.evaluate(() => {
        const send = document.querySelector('button[data-testid="send-button"]');
        send.click();
        send.click();
      });

      await expect(page.locator('[data-sent]')).toHaveCount(1, { timeout: 10000 });
      await expect(page.locator('[data-sent]')).toContainText('[[EMAIL_ADDRESS_1]]');
      await expect(page.locator('[data-sent]')).not.toContainText(rawValue);

      const revealPage = await revealPagePromise;
      await revealPage.waitForLoadState('domcontentloaded');
      await expect(revealPage.getByRole('heading', { name: /Sensitive values stay outside/ })).toBeVisible();
      await expect(revealPage.locator('body')).not.toContainText(rawValue);
      await revealPage.getByRole('button', { name: 'Reveal once' }).click();
      await expect(revealPage.locator('output')).toHaveText(rawValue);
      await expect(page.locator('[data-sent]')).not.toContainText(rawValue);

      fs.mkdirSync(artifactDir, { recursive: true });
      await revealPage.screenshot({ path: path.join(artifactDir, 'redactwall-isolated-reveal.png'), fullPage: true });
      await revealPage.getByRole('button', { name: 'Copy and hide' }).click();
      await expect(revealPage.locator('#status')).toContainText('Copied by your explicit request');
      await expect(revealPage.locator('output')).toHaveCount(0);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('identical approval holds poll and release only their exact composers', async ({ baseURL, request }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, fixturePolicy, request);
    try {
      const page = await openControlledAiPage(context, 'https://chatgpt.com/', twoComposerFixture());
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com');
      const existingIds = new Set((await browserRowsFor(request)).map((row) => row.id));
      const prompt = 'Member test SSN 123-45-6789 needs a payoff letter.';
      await page.locator('#composer-a').fill(prompt);
      await page.locator('#composer-b').fill(prompt);

      await page.getByRole('button', { name: 'Send A' }).click();
      await page.getByRole('button', { name: 'Request approval' }).click();
      let holdA;
      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        holdA = created.find((row) => row.status === 'pending');
        return created.length === 1 && Boolean(holdA);
      }).toBe(true);

      await page.getByRole('button', { name: 'Send B' }).click();
      await expect(page.getByRole('alertdialog', { name: 'Sensitive data blocked' })).toBeVisible();
      await page.getByRole('button', { name: 'Request approval' }).click();
      let holdB;
      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        holdB = created.find((row) => row.id !== holdA.id);
        return created.length === 2 && Boolean(holdB && holdB.status === 'pending');
      }).toBe(true);

      const csrfToken = await loginAdminApi(request);
      const approveA = await request.post(`/api/queries/${encodeURIComponent(holdA.id)}/approve`, {
        headers: { 'x-csrf-token': csrfToken },
        data: { note: 'Release exact composer A', password: 'e2e-pass' },
      });
      expect(approveA.ok()).toBeTruthy();
      await expect(page.locator('[data-sent-a]')).toHaveCount(1, { timeout: 10000 });
      await expect(page.locator('[data-sent-b]')).toHaveCount(0);

      const approveB = await request.post(`/api/queries/${encodeURIComponent(holdB.id)}/approve`, {
        headers: { 'x-csrf-token': csrfToken },
        data: { note: 'Release exact composer B', password: 'e2e-pass' },
      });
      expect(approveB.ok()).toBeTruthy();
      await expect(page.locator('[data-sent-b]')).toHaveCount(1, { timeout: 10000 });
      expect(await page.evaluate(() => ({ sentA: window.__sentA, sentB: window.__sentB }))).toEqual({
        sentA: [prompt],
        sentB: [prompt],
      });
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('blocks configured response copies without reading selected text', async ({ baseURL, request }, testInfo) => {
    const policy = {
      ...fixturePolicy,
      blockedBrowserActions: [{
        id: 'block_copy_chatgpt',
        action: 'copy',
        destinations: ['chatgpt.com'],
        reason: 'response_copy_blocked',
      }],
    };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      const prevented = await syntheticCopyFromResponse(page, 'Synthetic response contains member SSN 123-45-6789');

      expect(prevented).toBe(true);
      await expect(page.locator('.ps-toast')).toContainText('blocked copy');
      await expect(page.locator('.ps-toast')).not.toContainText('123-45-6789');
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await page.waitForTimeout(200);
      fs.mkdirSync(artifactDir, { recursive: true });
      await page.screenshot({ path: path.join(artifactDir, 'chatgpt-copy-blocked.png'), fullPage: true });
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('warn banner buttons dismiss, edit, and send after backend recording', async ({ baseURL, request }, testInfo) => {
    const policy = { ...fixturePolicy, enforcementMode: 'warn' };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      await page.locator('#prompt-textarea').fill('Email qa-warning@example.test about the account update.');
      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.getByRole('alertdialog', { name: 'Review before sending' })).toBeVisible();
      await expect(page.locator('.ps-title')).toContainText('Review before sending');
      await page.getByRole('button', { name: 'Dismiss' }).click();
      await expect(page.locator('.ps-banner')).toHaveCount(0);
      await expect(page.locator('[data-sent]')).toHaveCount(0);

      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.locator('.ps-title')).toContainText('Review before sending');
      await page.getByRole('button', { name: 'Edit prompt' }).click();
      await expect(page.locator('.ps-banner')).toHaveCount(0);
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await expect(page.locator('#prompt-textarea')).toHaveValue('Email qa-warning@example.test about the account update.');

      await loginAdminApi(request);
      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.locator('.ps-title')).toContainText('Review before sending');
      await page.getByRole('button', { name: 'Send anyway' }).click();
      await expect(page.locator('[data-sent]')).toContainText('qa-warning@example.test');
      await expect.poll(() => queryStatusesFor(request, 'warned_sent')).toBeGreaterThan(0);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('normalizes zero-width text in a live contenteditable before authorized resend', async ({ baseURL, request }, testInfo) => {
    const policy = { ...fixturePolicy, enforcementMode: 'warn' };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
          contenteditable: true,
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      await loginAdminApi(request);
      const obfuscated = 'Email qa-warning@example.test about zero\u200bwidth cleanup.';
      const normalized = 'Email qa-warning@example.test about zerowidth cleanup.';
      await page.locator('#prompt-textarea').evaluate((composer, text) => {
        composer.textContent = text;
        composer.dispatchEvent(new InputEvent('input', {
          bubbles: true,
          data: text,
          inputType: 'insertText',
        }));
      }, obfuscated);

      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.getByRole('alertdialog', { name: 'Review before sending' })).toBeVisible();
      await expect(page.locator('#prompt-textarea')).toHaveText(normalized);
      await page.getByRole('button', { name: 'Send anyway' }).click();
      await expect(page.locator('[data-sent]')).toHaveText(normalized);
      await expect.poll(() => page.evaluate(() => window.__sent)).toEqual([normalized]);
      await expect.poll(() => queryStatusesFor(request, 'warned_sent')).toBeGreaterThan(0);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('justify banner buttons validate, cancel, and submit reasons to the backend', async ({ baseURL, request }, testInfo) => {
    const policy = { ...fixturePolicy, enforcementMode: 'justify' };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      await loginAdminApi(request);
      await page.locator('#prompt-textarea').fill('Email qa-justify@example.test about the account update.');
      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.getByRole('alertdialog', { name: 'Business reason required' })).toBeVisible();
      await expect(page.locator('.ps-title')).toContainText('Business reason required');
      await page.getByRole('button', { name: 'Submit reason' }).click();
      await expect(page.locator('.ps-banner')).toBeVisible();
      await expect(page.getByRole('textbox', { name: 'Business reason' })).toHaveAttribute('aria-invalid', 'true');
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await page.getByRole('button', { name: 'Cancel' }).click();
      await expect(page.locator('.ps-banner')).toHaveCount(0);
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await expect.poll(() => queryStatusesFor(request, 'blocked_by_user')).toBeGreaterThan(0);

      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.locator('.ps-title')).toContainText('Business reason required');
      const reasonBox = page.getByRole('textbox', { name: 'Business reason' });
      await reasonBox.fill('Member support follow-up');
      await expect(reasonBox).toHaveAttribute('aria-invalid', 'false');
      await page.getByRole('button', { name: 'Submit reason' }).click();
      await expect(page.locator('[data-sent]')).toContainText('qa-justify@example.test');
      await expect.poll(() => queryStatusesFor(request, 'justified')).toBeGreaterThan(0);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('server-scoped justification submit and dismiss resolve their original holds in place', async ({ baseURL, request }, testInfo) => {
    const { serverPolicy, locallyPermissivePolicy } = serverScopedJustificationPolicies();
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, serverPolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', locallyPermissivePolicy);
      await loginAdminApi(request);
      const existingIds = new Set((await browserRowsFor(request)).map((row) => row.id));
      await page.locator('#prompt-textarea').fill('Email qa-server-justify@example.test about the account update.');
      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.getByRole('alertdialog', { name: 'Business reason required' })).toBeVisible();

      let held;
      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        held = created.find((row) => row.status === 'pending_justification');
        return created.length === 1 && Boolean(held && held.rawRetained === true);
      }).toBe(true);

      await page.getByRole('textbox', { name: 'Business reason' }).fill('Member support follow-up');
      await page.getByRole('button', { name: 'Submit reason' }).click();
      await expect(page.locator('[data-sent]')).toContainText('qa-server-justify@example.test');

      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        return created.length === 1
          && created[0].id === held.id
          && created[0].status === 'justified'
          && created[0].rawRetained === false;
      }).toBe(true);
      const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
      expect(created).toHaveLength(1);
      expect(created[0]).toMatchObject({ id: held.id, status: 'justified', rawRetained: false });
      expect(created.some((row) => row.status === 'pending_justification')).toBe(false);

      const afterSubmitIds = new Set((await browserRowsFor(request)).map((row) => row.id));
      await page.locator('#prompt-textarea').fill('Email qa-server-dismiss@example.test about the account update.');
      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.getByRole('alertdialog', { name: 'Business reason required' })).toBeVisible();
      let cancelledHold;
      await expect.poll(async () => {
        const next = (await browserRowsFor(request)).filter((row) => !afterSubmitIds.has(row.id));
        cancelledHold = next.find((row) => row.status === 'pending_justification');
        return next.length === 1 && Boolean(cancelledHold && cancelledHold.rawRetained === true);
      }).toBe(true);

      await page.getByRole('button', { name: 'Dismiss' }).click();
      await expect(page.locator('[data-sent]')).toHaveCount(1);
      await expect(page.locator('[data-sent]')).not.toContainText('qa-server-dismiss@example.test');
      await expect.poll(async () => {
        const next = (await browserRowsFor(request)).filter((row) => !afterSubmitIds.has(row.id));
        return next.length === 1
          && next[0].id === cancelledHold.id
          && next[0].status === 'blocked_by_user'
          && next[0].rawRetained === false;
      }).toBe(true);
      const cancelledRows = (await browserRowsFor(request)).filter((row) => !afterSubmitIds.has(row.id));
      expect(cancelledRows).toHaveLength(1);
      expect(cancelledRows[0]).toMatchObject({ id: cancelledHold.id, status: 'blocked_by_user', rawRetained: false });
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('a second composer challenge terminalizes the first hold before it becomes active', async ({ baseURL, request }, testInfo) => {
    const { serverPolicy, locallyPermissivePolicy } = serverScopedJustificationPolicies();
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, serverPolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        twoComposerFixture(),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', locallyPermissivePolicy);
      await loginAdminApi(request);
      const existingIds = new Set((await browserRowsFor(request)).map((row) => row.id));

      await page.locator('#composer-a').fill('Email qa-hold-a@example.test about the account update.');
      await page.locator('#composer-b').fill('Email qa-hold-b@example.test about the account update.');
      await page.getByRole('button', { name: 'Send A' }).click();
      await expect(page.getByRole('alertdialog', { name: 'Business reason required' })).toBeVisible();

      let holdA;
      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        holdA = created.find((row) => row.status === 'pending_justification');
        return created.length === 1 && Boolean(holdA && holdA.rawRetained === true);
      }).toBe(true);

      await page.getByRole('button', { name: 'Send B' }).click();
      let holdB;
      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        const first = created.find((row) => row.id === holdA.id);
        holdB = created.find((row) => row.id !== holdA.id);
        return created.length === 2
          && first && first.status === 'blocked_by_user' && first.rawRetained === false
          && holdB && holdB.status === 'pending_justification' && holdB.rawRetained === true;
      }).toBe(true);

      await expect(page.locator('.ps-banner')).toHaveCount(1);
      await page.getByRole('textbox', { name: 'Business reason' }).fill('Composer B support workflow');
      await page.getByRole('button', { name: 'Submit reason' }).click();
      await expect(page.locator('[data-sent-a]')).toHaveCount(0);
      await expect(page.locator('[data-sent-b]')).toHaveCount(1);
      await expect(page.locator('[data-sent-b]')).toContainText('qa-hold-b@example.test');

      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        const first = created.find((row) => row.id === holdA.id);
        const second = created.find((row) => row.id === holdB.id);
        return created.length === 2
          && first && first.status === 'blocked_by_user' && first.rawRetained === false
          && second && second.status === 'justified' && second.rawRetained === false;
      }).toBe(true);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('a failed justification resolution keeps the same banner and retries safely', async ({ baseURL, request }, testInfo) => {
    const { serverPolicy, locallyPermissivePolicy } = serverScopedJustificationPolicies();
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, serverPolicy, request);
    try {
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );

      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', locallyPermissivePolicy);
      await loginAdminApi(request);
      const existingIds = new Set((await browserRowsFor(request)).map((row) => row.id));
      const prompt = 'Email qa-retry-justify@example.test about the account update.';
      await page.locator('#prompt-textarea').fill(prompt);
      await page.locator('button[data-testid="send-button"]').click();
      const banner = page.getByRole('alertdialog', { name: 'Business reason required' });
      const reason = page.getByRole('textbox', { name: 'Business reason' });
      await expect(banner).toBeVisible();
      await reason.fill('Retry after control-plane outage');

      let held;
      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        held = created.find((row) => row.status === 'pending_justification');
        return created.length === 1 && Boolean(held && held.rawRetained === true);
      }).toBe(true);

      const serviceWorker = await readyExtensionServiceWorker(context);
      await serviceWorker.evaluate(async () => {
        await chrome.storage.local.set({ serverUrl: 'http://127.0.0.1:1', requestTimeoutMs: 100 });
      });
      await page.getByRole('button', { name: 'Submit reason' }).click();
      await expect(page.locator('.ps-toast').last()).toContainText('could not record this justification decision');
      await expect(banner).toBeVisible();
      await expect(reason).toHaveValue('Retry after control-plane outage');
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      const stillHeld = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
      expect(stillHeld).toHaveLength(1);
      expect(stillHeld[0]).toMatchObject({ id: held.id, status: 'pending_justification', rawRetained: true });

      fs.mkdirSync(artifactDir, { recursive: true });
      await page.screenshot({ path: path.join(artifactDir, 'server-justify-retry.png'), fullPage: true });
      await serviceWorker.evaluate(async (serverUrl) => {
        await chrome.storage.local.set({ serverUrl, requestTimeoutMs: 3000 });
      }, baseURL);
      await page.getByRole('button', { name: 'Submit reason' }).click();
      await expect(page.locator('[data-sent]')).toHaveCount(1);
      await expect(page.locator('[data-sent]')).toContainText('qa-retry-justify@example.test');
      await expect(page.locator('.ps-banner')).toHaveCount(0);

      await expect.poll(async () => {
        const created = (await browserRowsFor(request)).filter((row) => !existingIds.has(row.id));
        return created.length === 1
          && created[0].id === held.id
          && created[0].status === 'justified'
          && created[0].rawRetained === false;
      }).toBe(true);
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('remote HTTPS control-plane access is exact-origin and fail-closed without a grant', async ({ baseURL, request }, testInfo) => {
    const policy = { ...fixturePolicy, allowedDestinations: ['chatgpt.com'] };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    const remoteOrigin = 'https://control.example.test';
    const remotePattern = remoteOrigin + '/*';
    let remoteGateCalls = 0;
    try {
      await context.route(remoteOrigin + '/**', async (route) => {
        if (new URL(route.request().url()).pathname === '/api/v1/gate') remoteGateCalls += 1;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ id: 'q_remote_permission', decision: 'allow', status: 'allowed' }),
        });
      });
      const worker = await readyExtensionServiceWorker(context);
      expect(await worker.evaluate((pattern) => chrome.permissions.contains({ origins: [pattern] }), remotePattern)).toBe(false);
      expect(await worker.evaluate((pattern) => chrome.permissions.contains({ origins: [pattern] }), baseURL + '/*')).toBe(true);
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      await worker.evaluate(async ({ serverUrl, policy }) => {
        await chrome.storage.local.set({
          serverUrl,
          ingestKey: 'remote-e2e-ingest-key',
          requestTimeoutMs: 1000,
          policy,
        });
      }, { serverUrl: remoteOrigin, policy });
      await page.locator('#prompt-textarea').fill('Summarize the public quarterly update.');
      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.locator('[data-sent]')).toHaveCount(0);
      await expect(page.locator('.ps-toast')).toContainText('Send not confirmed; blocked.');
      expect(remoteGateCalls).toBe(0);

      const extensionId = new URL(worker.url()).host;
      const popup = await context.newPage();
      await popup.goto(`chrome-extension://${extensionId}/popup.html`);
      await expect(popup.locator('#serverAccess')).toBeVisible();
      await expect(popup.locator('#serverAccessText')).toContainText('control.example.test');
      const permissions = await worker.evaluate(() => chrome.permissions.getAll());
      expect(permissions.origins).not.toContain(remotePattern);
      expect(permissions.origins).not.toContain('https://*/*');
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });

  test('an exact remote HTTPS host grant enables real control-plane fetch', async ({ baseURL, request }, testInfo) => {
    const remoteOrigin = 'https://control.example.test';
    const remotePattern = remoteOrigin + '/*';
    const grantedExtension = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-extension-granted-'));
    fs.cpSync(extensionDir, grantedExtension, { recursive: true });
    const grantedManifestPath = path.join(grantedExtension, 'manifest.json');
    const grantedManifest = JSON.parse(fs.readFileSync(grantedManifestPath, 'utf8'));
    grantedManifest.host_permissions.push(remotePattern);
    fs.writeFileSync(grantedManifestPath, JSON.stringify(grantedManifest, null, 2));
    const policy = { ...fixturePolicy, allowedDestinations: ['chatgpt.com'] };
    let context;
    let userDataDir;
    let remoteGateCalls = 0;
    try {
      ({ context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request, grantedExtension));
      await context.route(remoteOrigin + '/**', async (route) => {
        remoteGateCalls += 1;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ id: 'q_remote_granted', decision: 'allow', status: 'allowed' }),
        });
      });
      const worker = await readyExtensionServiceWorker(context);
      expect(await worker.evaluate((pattern) => chrome.permissions.contains({ origins: [pattern] }), remotePattern)).toBe(true);
      const page = await openControlledAiPage(
        context,
        'https://chatgpt.com/',
        chatFixture({
          host: 'chatgpt.com',
          sendButton: '<button data-testid="send-button" aria-label="Send prompt">Send</button>',
        }),
      );
      await applyFixturePolicyToPage(context, page, baseURL, 'chatgpt.com', policy);
      await worker.evaluate(async ({ serverUrl, policy }) => {
        await chrome.storage.local.set({
          serverUrl,
          ingestKey: 'remote-e2e-ingest-key',
          requestTimeoutMs: 1000,
          policy,
        });
      }, { serverUrl: remoteOrigin, policy });
      await page.locator('#prompt-textarea').fill('Summarize the public quarterly update.');
      await page.locator('button[data-testid="send-button"]').click();
      await expect(page.locator('[data-sent]')).toHaveCount(1, { timeout: 10000 });
      await expect(page.locator('[data-sent]')).toContainText('public quarterly update');
      expect(remoteGateCalls).toBe(1);
    } finally {
      if (context) await context.close();
      if (userDataDir) fs.rmSync(userDataDir, { recursive: true, force: true });
      fs.rmSync(grantedExtension, { recursive: true, force: true });
    }
  });

  test('popup toggle and dashboard link are wired to extension storage and backend', async ({ baseURL, request }, testInfo) => {
    const policy = { ...fixturePolicy, enforcementMode: 'redact' };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy, request);
    try {
      const serviceWorker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
      const extensionId = new URL(serviceWorker.url()).host;
      const popup = await context.newPage();
      await popup.goto(`chrome-extension://${extensionId}/popup.html`);

      await expect(popup.locator('#state')).toHaveText('Protecting this browser');
      await expect(popup.locator('#mode')).toHaveText('redact');
      await expect(popup.locator('#dash')).toHaveAttribute('href', `${baseURL}/app/`);

      await popup.locator('.switch .slider').click();
      await expect(popup.locator('#state')).toHaveText('Paused');
      await expect.poll(() => serviceWorker.evaluate(() => chrome.storage.local.get('enabled'))).toEqual({ enabled: false });

      await popup.locator('.switch .slider').click();
      await expect(popup.locator('#state')).toHaveText('Protecting this browser');
      await expect.poll(() => serviceWorker.evaluate(() => chrome.storage.local.get('enabled'))).toEqual({ enabled: true });

      const dashboardPromise = context.waitForEvent('page');
      await popup.locator('#dash').click();
      const dashboard = await dashboardPromise;
      await dashboard.waitForLoadState('domcontentloaded');
      await expect(dashboard).toHaveURL(`${baseURL}/login.html`);
      await expect(dashboard.getByRole('heading', { name: 'RedactWall' })).toBeVisible();
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });
});
