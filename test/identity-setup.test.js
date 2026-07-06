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
  _internal,
} = require('../server/identity-setup');
const identityCli = require('../scripts/identity-setup');

const root = path.join(__dirname, '..');

function captureOutput() {
  const logs = [];
  const writes = [];
  return {
    logs,
    writes,
    console: {
      log(message) { logs.push(message); },
      error(message) { logs.push(message); },
    },
    stdout: { write(message) { writes.push(message); } },
  };
}

test('identity setup guide renders Microsoft Entra SCIM and OIDC values', () => {
  const guide = buildIdentitySetupGuide({
    provider: 'entra',
    baseUrl: 'https://redactwall.cu.example/',
    tenantId: '11111111-2222-3333-4444-555555555555',
    token: 'should-not-appear',
    clientSecret: 'should-not-appear',
  });

  const wire = JSON.stringify(guide);
  assert.strictEqual(guide.label, 'Microsoft Entra ID');
  assert.strictEqual(guide.scim.tenantUrl, 'https://redactwall.cu.example/scim/v2');
  assert.strictEqual(guide.oidc.redirectUri, 'https://redactwall.cu.example/auth/oidc/callback');
  assert.strictEqual(guide.oidc.issuer, 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0');
  assert.ok(guide.env.some((row) => row.key === 'OIDC_CLIENT_SECRET' && row.value === '<32-plus-random-characters>'));
  assert.ok(guide.roleGroups.some((row) => row.role === 'approver' && row.groups.includes('RedactWall Approvers')));
  assert.ok(guide.preflightChecks.includes('oidc_scim_users'));
  assert.doesNotMatch(wire, /should-not-appear/);
});

test('identity setup guide renders Okta issuer and callback values', () => {
  const guide = buildIdentitySetupGuide({
    provider: 'okta',
    baseUrl: 'https://redactwall.okta-pilot.example',
    tenantId: 'customer.okta.com',
  });

  assert.strictEqual(guide.label, 'Okta');
  assert.strictEqual(guide.scim.baseUrl, 'https://redactwall.okta-pilot.example/scim/v2');
  assert.strictEqual(guide.oidc.issuer, 'https://customer.okta.com/oauth2/default');
  assert.strictEqual(guide.oidc.discovery, 'https://customer.okta.com/oauth2/default/.well-known/openid-configuration');
});

test('identity setup guide accepts provider aliases and rejects invalid base urls', () => {
  assert.strictEqual(normalizeProvider('microsoft'), 'entra');
  assert.strictEqual(normalizeProvider('azuread'), 'entra');
  assert.strictEqual(normalizeProvider('okta'), 'okta');
  assert.throws(() => normalizeProvider('github'), /unsupported identity provider/);
  assert.throws(() => _internal.providerIssuer('github', 'tenant'), /unsupported identity provider/);
  assert.throws(() => buildIdentitySetupGuide({ provider: 'entra', baseUrl: 'redactwall.example.test' }), /baseUrl/);
});

test('identity setup CLI prints text and json without secrets', () => {
  const text = execFileSync(process.execPath, [
    path.join(root, 'scripts', 'identity-setup.js'),
    '--provider',
    'okta',
    '--base-url',
    'https://redactwall.customer.example',
    '--tenant-id',
    'customer.okta.com',
  ], { cwd: root, encoding: 'utf8' });
  assert.match(text, /Okta setup for RedactWall/);
  assert.match(text, /SCIM_BEARER_TOKEN=<32-plus-random-characters>/);
  assert.doesNotMatch(text, /client-secret-[a-z0-9]/i);

  const json = execFileSync(process.execPath, [
    path.join(root, 'scripts', 'identity-setup.js'),
    '--provider',
    'entra',
    '--base-url',
    'https://redactwall.customer.example',
    '--tenant-id',
    'contoso.onmicrosoft.com',
    '--json',
  ], { cwd: root, encoding: 'utf8' });
  const parsed = JSON.parse(json);
  assert.strictEqual(parsed.provider, 'entra');
  assert.strictEqual(parsed.oidc.issuer, 'https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0');
});

test('identity setup CLI parser and injectable main cover help, text, json, and errors', () => {
  assert.deepStrictEqual(identityCli.parseArgs([
    '--provider', 'okta',
    '--base-url', 'https://redactwall.customer.example',
    '--okta-domain', 'customer.okta.com',
    '--format', 'json',
  ]), {
    provider: 'okta',
    baseUrl: 'https://redactwall.customer.example',
    tenantId: 'customer.okta.com',
    format: 'json',
  });
  assert.strictEqual(identityCli.parseArgs(['--tenant', 'contoso.onmicrosoft.com']).tenantId, 'contoso.onmicrosoft.com');
  assert.strictEqual(identityCli.parseArgs(['--json']).format, 'json');
  assert.strictEqual(identityCli.parseArgs(['--help']).help, true);
  assert.throws(() => identityCli.parseArgs(['--format', 'xml']), /text or json/);
  assert.throws(() => identityCli.parseArgs(['--unknown']), /Unknown option/);

  const help = captureOutput();
  assert.strictEqual(identityCli.main(['--help'], { console: help.console, stdout: help.stdout }), 0);
  assert.match(help.logs[0], /Usage: npm run identity:setup/);

  const text = captureOutput();
  assert.strictEqual(identityCli.main([
    '--provider', 'entra',
    '--base-url', 'https://redactwall.customer.example',
    '--tenant-id', 'contoso.onmicrosoft.com',
  ], { console: text.console, stdout: text.stdout }), 0);
  assert.match(text.writes.join(''), /Microsoft Entra ID setup for RedactWall/);

  const json = captureOutput();
  assert.strictEqual(identityCli.main([
    '--provider', 'okta',
    '--base-url', 'https://redactwall.customer.example',
    '--tenant-id', 'customer.okta.com',
    '--json',
  ], { console: json.console, stdout: json.stdout }), 0);
  assert.strictEqual(JSON.parse(json.logs[0]).provider, 'okta');
  assert.strictEqual(json.writes.length, 0);

  const failure = captureOutput();
  let exitCode = 0;
  assert.strictEqual(identityCli.cli(['--format', 'xml'], {
    console: failure.console,
    stdout: failure.stdout,
    setExitCode(code) { exitCode = code; },
  }), 1);
  assert.strictEqual(exitCode, 1);
  assert.match(failure.logs[0], /Identity setup failed: --format must be text or json/);
});

test('console and server expose authenticated identity setup UX', () => {
  const server = fs.readFileSync(path.join(root, 'server', 'app.js'), 'utf8');
  const identityView = fs.readFileSync(path.join(root, 'console', 'src', 'views', 'Identity.tsx'), 'utf8');
  const packageJson = fs.readFileSync(path.join(root, 'package.json'), 'utf8');
  const envExample = fs.readFileSync(path.join(root, '.env.example'), 'utf8');

  assert.match(server, /app\.get\('\/api\/identity\/setup-guide', auth\.requireAuth/);
  assert.match(server, /identitySetup\.buildIdentitySetupGuide/);
  // The identity setup guide UI now lives in the React console; it renders the
  // guide fetched from the authenticated setup-guide route.
  assert.match(identityView, /export default function Identity/);
  assert.match(identityView, /api\(`\/api\/identity\/setup-guide\?\$\{params\.toString\(\)\}`\)/);
  assert.match(identityView, /<option value="entra">Microsoft Entra ID<\/option>/);
  assert.match(packageJson, /"identity:setup": "node scripts\/identity-setup\.js"/);
  assert.match(envExample, /OIDC_ISSUER=/);
  assert.match(envExample, /npm run identity:setup/);
});

test('text renderer summarizes without live token material', () => {
  const guide = buildIdentitySetupGuide({
    provider: 'entra',
    baseUrl: 'https://redactwall.customer.example',
    tenantId: 'contoso.onmicrosoft.com',
  });
  const text = renderTextGuide(guide);
  assert.match(text, /Microsoft Entra ID setup for RedactWall/);
  assert.match(text, /OIDC_CLIENT_SECRET=<32-plus-random-characters>/);
  assert.doesNotMatch(text, /SCIM bearer token value/i);
});
