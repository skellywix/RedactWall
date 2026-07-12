'use strict';

const assert = require('node:assert');
const test = require('node:test');
const { clearApplicationEnvironment, sanitizedEnvironment } = require('../scripts/playwright-env');

test('Playwright server environment strips application authority and outbound connectors', () => {
  const source = {
    PATH: 'tooling',
    TEMP: 'temp',
    CI: 'true',
    PLAYWRIGHT_BROWSERS_PATH: 'browsers',
    PORT: '4310',
    REDACTWALL_DATABASE_URL: 'postgres://production',
    REDACTWALL_APPROVAL_JIRA_API_TOKEN: 'jira-secret',
    APPROVAL_LINEAR_API_KEY: 'linear-secret',
    SIEM_WEBHOOK_URL: 'https://siem.example.test',
    SMTP_PASS: 'mail-secret',
    DATABASE_URL: 'postgres://fallback',
    ADMIN_PASSWORD: 'production-password',
    AWS_SECRET_ACCESS_KEY: 'cloud-secret',
  };

  assert.deepStrictEqual(sanitizedEnvironment(source), {
    PATH: 'tooling',
    TEMP: 'temp',
    CI: 'true',
    PLAYWRIGHT_BROWSERS_PATH: 'browsers',
    PORT: '4310',
  });

  const mutable = { ...source };
  clearApplicationEnvironment(mutable);
  assert.deepStrictEqual(mutable, sanitizedEnvironment(source));
});
