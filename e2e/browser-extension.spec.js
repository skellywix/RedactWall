'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { test, expect, chromium } = require('@playwright/test');

const root = path.join(__dirname, '..');
const extensionDir = path.join(root, 'sensors', 'browser-extension');
const artifactDir = path.join(root, 'test-results', 'browser-extension');

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

async function launchExtensionContext(baseURL, testInfo) {
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
      policy: {
        enforcementMode: 'block',
        blockMinSeverity: 2,
        blockRiskScore: 20,
        governedDestinations: ['chatgpt.com', 'poe.com'],
        blockedDestinations: [],
        blockedFileUploadDestinations: [],
        alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'],
      },
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
    }, null, 2),
    contentType: 'application/json',
  });

  const serviceWorker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  await serviceWorker.evaluate(async ({ serverUrl }) => {
    await chrome.storage.local.set({
      serverUrl,
      ingestKey: 'e2e-ingest-key',
      enabled: true,
      requestTimeoutMs: 3000,
      user: 'browser-smoke@example.test',
      orgId: 'e2e-org',
      policy: {
        enforcementMode: 'block',
        blockMinSeverity: 2,
        blockRiskScore: 20,
        governedDestinations: ['chatgpt.com', 'poe.com'],
        blockedDestinations: [],
        blockedFileUploadDestinations: [],
        alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'],
      },
    });
  }, { serverUrl: baseURL });

  return { context, userDataDir };
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
});
