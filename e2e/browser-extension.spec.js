'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect, chromium } = require('@playwright/test');

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

function chatFixture({ host, sendButton }) {
  return `<!doctype html>
<html>
  <head>
    <title>${host} fixture</title>
    <style>
      body { font: 14px system-ui, sans-serif; margin: 24px; }
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

async function launchExtensionContext(baseURL, testInfo, policy = fixturePolicy) {
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
  await page.evaluate((text) => navigator.clipboard.writeText(text), value);
  await page.locator('#prompt-textarea').focus();
  await page.keyboard.press('ControlOrMeta+V');
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

test.describe('browser extension live smoke', () => {
  test.setTimeout(90000);

  test('blocks a synthetic SSN before ChatGPT fixture send and records approval request', async ({ baseURL }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo);
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

      await expect(page.locator('.ps-banner')).toBeVisible();
      await expect(page.locator('.ps-title')).toContainText('Sensitive data blocked');
      await expect(page.locator('.ps-banner')).toContainText('before it could leave this browser');
      await expect(page.locator('.ps-chip')).toContainText('Social Security number');
      await expect(page.locator('.ps-banner')).not.toContainText('US_SSN');
      await expect(page.locator('.ps-coach')).toContainText('member ID');
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

  test('prevents hard-stop paste before a live page can draft-sync it', async ({ baseURL }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo);
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

  test('uses adapter send-button selectors on Poe-style click targets', async ({ baseURL }, testInfo) => {
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo);
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

  test('blocks configured file drops before browser upload scanning', async ({ baseURL }, testInfo) => {
    const policy = {
      ...fixturePolicy,
      blockedBrowserActions: [{
        id: 'block_drop_chatgpt',
        action: 'drop',
        destinations: ['chatgpt.com'],
        reason: 'file_drop_blocked',
      }],
    };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy);
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

  test('blocks configured response copies without reading selected text', async ({ baseURL }, testInfo) => {
    const policy = {
      ...fixturePolicy,
      blockedBrowserActions: [{
        id: 'block_copy_chatgpt',
        action: 'copy',
        destinations: ['chatgpt.com'],
        reason: 'response_copy_blocked',
      }],
    };
    const { context, userDataDir } = await launchExtensionContext(baseURL, testInfo, policy);
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
});
