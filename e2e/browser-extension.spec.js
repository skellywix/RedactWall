'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect, chromium } = require('@playwright/test');
const pkg = require('../package.json');

const root = path.join(__dirname, '..');
const extensionDir = path.join(root, 'sensors', 'browser-extension');
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

function comparableBrowserActions(rules) {
  return (rules || []).map((rule) => ({
    id: rule.id,
    action: rule.action,
    destinations: rule.destinations || [],
    reason: rule.reason,
  }));
}

function chatFixture({ host, sendButton }) {
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
      <textarea id="prompt-textarea" aria-label="Message"></textarea>
      ${sendButton}
      <section id="sent" aria-label="Sent messages"></section>
    </main>
    <script>
      window.__sent = [];
      const composer = document.querySelector('#prompt-textarea');
      const sent = document.querySelector('#sent');
      const button = document.querySelector('button');
      function send() {
        const value = composer.value.trim();
        if (!value) return;
        window.__sent.push(value);
        sent.insertAdjacentHTML('beforeend', '<p data-sent></p>');
        sent.lastElementChild.textContent = value;
        composer.value = '';
      }
      button.addEventListener('click', send);
      composer.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' && !event.shiftKey) {
          event.preventDefault();
          send();
        }
      });
    </script>
  </body>
</html>`;
}

async function launchExtensionContext(baseURL, testInfo, policy = fixturePolicy, request = null) {
  if (request) await syncServerPolicy(request, policy);
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'promptwall-extension-e2e-'));
  await testInfo.attach('user-data-dir', { body: userDataDir, contentType: 'text/plain' });
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    args: [
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`,
    ],
  });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://chatgpt.com' });
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: 'https://poe.com' });
  await testInfo.attach('extension-dir', { body: extensionDir, contentType: 'text/plain' });
  await testInfo.attach('test-policy', {
    body: JSON.stringify({
      serverUrl: baseURL,
      ingestKey: 'e2e-ingest-key',
      enabled: true,
      policy,
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
    }, null, 2),
    contentType: 'application/json',
  });

  const serviceWorker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await serviceWorker.evaluate(async ({ serverUrl, policy }) => {
    await chrome.storage.local.set({
      serverUrl,
      ingestKey: 'e2e-ingest-key',
      enabled: true,
      requestTimeoutMs: 3000,
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
      policy,
    });
  }, { serverUrl: baseURL, policy });

  return { context, userDataDir };
}

async function applyFixturePolicyToPage(context, page, baseURL, governedHost, policy = fixturePolicy) {
  const serviceWorker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  const expectedRules = (policy.blockedBrowserActions || []).map((rule) => ({
    id: rule.id,
    action: rule.action,
  }));
  await serviceWorker.evaluate(async ({ serverUrl, policy }) => {
    await chrome.storage.local.set({
      serverUrl,
      ingestKey: 'e2e-ingest-key',
      enabled: true,
      requestTimeoutMs: 3000,
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
      policy,
    });
  }, { serverUrl: baseURL, policy });

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

  test('blocks a synthetic SSN before ChatGPT fixture send and records approval request', async ({ baseURL, request }, testInfo) => {
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
      await expect(popup.locator('#dash')).toHaveAttribute('href', `${baseURL}/index.html`);

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
      await expect(dashboard.getByRole('heading', { name: 'PromptWall' })).toBeVisible();
    } finally {
      await context.close();
      fs.rmSync(userDataDir, { recursive: true, force: true });
    }
  });
});
