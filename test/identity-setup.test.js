'use strict';
/** Provider setup guides must stay secret-free and aligned with the console. */
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const {
  buildIdentitySetupGuide,
  normalizeProvider,
  renderTextGuide,
} = require('../server/identity-setup');

const root = path.join(__dirname, '..');

test('identity setup guide renders Microsoft Entra SCIM and OIDC values', () => {
  const guide = buildIdentitySetupGuide({
    provider: 'entra',
    baseUrl: 'https://promptwall.cu.example/',
    tenantId: '11111111-2222-3333-4444-555555555555',
    token: 'should-not-appear',
    clientSecret: 'should-not-appear',
  });

  const wire = JSON.stringify(guide);
  assert.strictEqual(guide.label, 'Microsoft Entra ID');
  assert.strictEqual(guide.scim.tenantUrl, 'https://promptwall.cu.example/scim/v2');
  assert.strictEqual(guide.oidc.redirectUri, 'https://promptwall.cu.example/auth/oidc/callback');
  assert.strictEqual(guide.oidc.issuer, 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0');
  assert.ok(guide.env.some((row) => row.key === 'OIDC_CLIENT_SECRET' && row.value === '<32-plus-random-characters>'));
  assert.ok(guide.roleGroups.some((row) => row.role === 'approver' && row.groups.includes('PromptWall Approvers')));
  assert.ok(guide.preflightChecks.includes('oidc_scim_users'));
  assert.doesNotMatch(wire, /should-not-appear/);
});

test('identity setup guide renders Okta issuer and callback values', () => {
  const guide = buildIdentitySetupGuide({
    provider: 'okta',
    baseUrl: 'https://promptwall.okta-pilot.example',
    tenantId: 'customer.okta.com',
  });

  assert.strictEqual(guide.label, 'Okta');
  assert.strictEqual(guide.scim.baseUrl, 'https://promptwall.okta-pilot.example/scim/v2');
  assert.strictEqual(guide.oidc.issuer, 'https://customer.okta.com/oauth2/default');
  assert.strictEqual(guide.oidc.discovery, 'https://customer.okta.com/oauth2/default/.well-known/openid-configuration');
});

test('identity setup guide accepts provider aliases and rejects invalid base urls', () => {
  assert.strictEqual(normalizeProvider('microsoft'), 'entra');
  assert.strictEqual(normalizeProvider('azuread'), 'entra');
  assert.strictEqual(normalizeProvider('okta'), 'okta');
  assert.throws(() => buildIdentitySetupGuide({ provider: 'entra', baseUrl: 'promptwall.example.test' }), /baseUrl/);
});

test('identity setup CLI prints text and json without secrets', () => {
  const text = execFileSync(process.execPath, [
    path.join(root, 'scripts', 'identity-setup.js'),
    '--provider',
    'okta',
    '--base-url',
    'https://promptwall.customer.example',
    '--tenant-id',
    'customer.okta.com',
  ], { cwd: root, encoding: 'utf8' });
  assert.match(text, /Okta setup for PromptWall/);
  assert.match(text, /SCIM_BEARER_TOKEN=<32-plus-random-characters>/);
  assert.doesNotMatch(text, /client-secret-[a-z0-9]/i);

  const json = execFileSync(process.execPath, [
    path.join(root, 'scripts', 'identity-setup.js'),
    '--provider',
    'entra',
    '--base-url',
    'https://promptwall.customer.example',
    '--tenant-id',
    'contoso.onmicrosoft.com',
    '--json',
  ], { cwd: root, encoding: 'utf8' });
  const parsed = JSON.parse(json);
  assert.strictEqual(parsed.provider, 'entra');
  assert.strictEqual(parsed.oidc.issuer, 'https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0');
});

test('dashboard and server expose authenticated identity setup UX', () => {
  const server = fs.readFileSync(path.join(root, 'server', 'app.js'), 'utf8');
  const index = fs.readFileSync(path.join(root, 'server', 'public', 'index.html'), 'utf8');
  const dashboard = fs.readFileSync(path.join(root, 'server', 'public', 'dashboard.js'), 'utf8');
  const packageJson = fs.readFileSync(path.join(root, 'package.json'), 'utf8');
  const envExample = fs.readFileSync(path.join(root, '.env.example'), 'utf8');

  assert.match(server, /app\.get\('\/api\/identity\/setup-guide', auth\.requireAuth/);
  assert.match(server, /identitySetup\.buildIdentitySetupGuide/);
  assert.match(index, /data-tab="identity"/);
  assert.match(index, /id="identityProvider"/);
  assert.match(dashboard, /async function loadIdentitySetup\(\)/);
  assert.match(dashboard, /api\(`\/api\/identity\/setup-guide\?\$\{params\.toString\(\)\}`\)/);
  assert.match(dashboard, /if \(targetName === 'identity'\) loadIdentitySetup\(\)/);
  assert.match(packageJson, /"identity:setup": "node scripts\/identity-setup\.js"/);
  assert.match(envExample, /OIDC_ISSUER=/);
  assert.match(envExample, /npm run identity:setup/);
});

test('text renderer summarizes without live token material', () => {
  const guide = buildIdentitySetupGuide({
    provider: 'entra',
    baseUrl: 'https://promptwall.customer.example',
    tenantId: 'contoso.onmicrosoft.com',
  });
  const text = renderTextGuide(guide);
  assert.match(text, /Microsoft Entra ID setup for PromptWall/);
  assert.match(text, /OIDC_CLIENT_SECRET=<32-plus-random-characters>/);
  assert.doesNotMatch(text, /SCIM bearer token value/i);
});
