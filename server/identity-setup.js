'use strict';
/**
 * Provider-specific SCIM and OIDC setup handoff. This must never include live
 * secret values; it only names the environment variables operators should fill.
 */

const ROLE_GROUPS = [
  { role: 'security_admin', groups: ['RedactWall Security Admins', 'Security Admins', 'Admins'] },
  { role: 'approver', groups: ['RedactWall Approvers', 'RedactWall Reviewers', 'Approvers', 'Reviewers'] },
  { role: 'auditor', groups: ['RedactWall Auditors', 'RedactWall Read-only', 'Auditors', 'Read-only'] },
  { role: 'operator', groups: ['RedactWall Operators', 'RedactWall Ops', 'Operators', 'Ops'] },
];

const PROVIDERS = {
  entra: {
    id: 'entra',
    label: 'Microsoft Entra ID',
    tenantLabel: 'Tenant ID or tenant domain',
    tenantPlaceholder: '<tenant-id-or-domain>',
    docs: [
      'https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups',
      'https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc',
    ],
    scimSteps: [
      'Create a non-gallery enterprise application.',
      'Set Provisioning mode to Automatic.',
      'Use the RedactWall SCIM tenant URL and the SCIM bearer token from the customer vault.',
      'Provision assigned users and groups, including the RedactWall role groups.',
      'Run Test Connection, then start provisioning only after the test succeeds.',
    ],
    oidcSteps: [
      'Register a web app for the RedactWall console.',
      'Add the RedactWall callback URL as the web redirect URI.',
      'Use a tenant-specific authority rather than common or consumers.',
      'Create a client secret and store it only in the customer secret manager.',
      'Assign only RedactWall administrators, reviewers, operators, and auditors.',
    ],
  },
  okta: {
    id: 'okta',
    label: 'Okta',
    tenantLabel: 'Okta org domain or issuer',
    tenantPlaceholder: 'customer.okta.com',
    docs: [
      'https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_scim.htm',
      'https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm',
    ],
    scimSteps: [
      'Create or edit the RedactWall app integration.',
      'Enable API integration on the Provisioning tab.',
      'Use the RedactWall SCIM base URL and the SCIM bearer token from the customer vault.',
      'Select create, update, deactivate, and group-push actions that the pilot needs.',
      'Test API Credentials before assigning production groups.',
    ],
    oidcSteps: [
      'Create an OIDC web application integration.',
      'Add the RedactWall callback URL as the sign-in redirect URI.',
      'Use the Okta org authorization server or the customer custom authorization server as the issuer.',
      'Create a client secret and store it only in the customer secret manager.',
      'Assign only RedactWall administrators, reviewers, operators, and auditors.',
    ],
  },
};

function cleanString(value, max = 512) {
  return String(value == null ? '' : value).trim().slice(0, max);
}

function normalizeProvider(value) {
  const key = cleanString(value || 'entra', 64).toLowerCase();
  if (key === 'microsoft' || key === 'azure' || key === 'azuread' || key === 'entra-id') return 'entra';
  if (key === 'okta') return 'okta';
  if (PROVIDERS[key]) return key;
  throw new Error(`unsupported identity provider: ${value}`);
}

function normalizeBaseUrl(value) {
  const raw = cleanString(value || 'https://redactwall.customer.example', 1024).replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(raw)) throw new Error('baseUrl must start with http:// or https://');
  return raw;
}

function normalizeTenant(value, fallback) {
  return cleanString(value, 256).replace(/^https?:\/\//i, '').replace(/\/+$/, '') || fallback;
}

function entraIssuer(tenant) {
  const pathTenant = tenant === PROVIDERS.entra.tenantPlaceholder ? tenant : encodeURIComponent(tenant);
  return `https://login.microsoftonline.com/${pathTenant}/v2.0`;
}

function oktaIssuer(tenant) {
  if (/^https?:\/\//i.test(tenant)) return tenant.replace(/\/+$/, '');
  const host = tenant || 'customer.okta.com';
  return `https://${host.replace(/\/+$/, '')}/oauth2/default`;
}

function providerIssuer(provider, tenant) {
  if (provider === 'entra') return entraIssuer(tenant);
  if (provider === 'okta') return oktaIssuer(tenant);
  throw new Error(`unsupported identity provider: ${provider}`);
}

function envRows(issuer, redirectUri) {
  return [
    { key: 'SCIM_BEARER_TOKEN', alias: 'REDACTWALL_SCIM_BEARER_TOKEN', value: '<32-plus-random-characters>' },
    { key: 'OIDC_ISSUER', alias: 'REDACTWALL_OIDC_ISSUER', value: issuer },
    { key: 'OIDC_CLIENT_ID', alias: 'REDACTWALL_OIDC_CLIENT_ID', value: '<registered-web-client-id>' },
    { key: 'OIDC_CLIENT_SECRET', alias: 'REDACTWALL_OIDC_CLIENT_SECRET', value: '<32-plus-random-characters>' },
    { key: 'OIDC_REDIRECT_URI', alias: 'REDACTWALL_OIDC_REDIRECT_URI', value: redirectUri },
    { key: 'OIDC_SCOPE', alias: 'REDACTWALL_OIDC_SCOPE', value: 'openid email profile' },
  ];
}

function scimGuide(meta, scimUrl) {
  return {
    tenantUrl: scimUrl,
    baseUrl: scimUrl,
    authMode: 'Bearer token',
    tokenEnv: 'SCIM_BEARER_TOKEN',
    tokenAlias: 'REDACTWALL_SCIM_BEARER_TOKEN',
    uniqueIdentifier: 'userName',
    contentType: 'application/scim+json',
    supportedActions: ['create users', 'update users', 'deactivate users', 'create groups', 'update groups', 'delete groups'],
    steps: meta.scimSteps,
  };
}

function oidcGuide(meta, issuer, redirectUri) {
  return {
    applicationType: 'web',
    issuer,
    clientIdEnv: 'OIDC_CLIENT_ID',
    clientSecretEnv: 'OIDC_CLIENT_SECRET',
    redirectUri,
    scopes: ['openid', 'email', 'profile'],
    discovery: `${issuer}/.well-known/openid-configuration`,
    explicitEndpointVars: ['OIDC_AUTHORIZATION_ENDPOINT', 'OIDC_TOKEN_ENDPOINT', 'OIDC_JWKS_URI'],
    steps: meta.oidcSteps,
  };
}

function validationSteps(scimUrl) {
  return [
    'npm run setup:check -- --skip-install',
    'curl -sS -H "Authorization: Bearer $SCIM_BEARER_TOKEN" ' + `${scimUrl}/ServiceProviderConfig`,
    'Sign in through SSO as one active SCIM-provisioned test user.',
    'node -e "const v=require(\'./server/db\').verifyAuditChain(); console.log(JSON.stringify(v)); if(!v.ok) process.exit(1)"',
  ];
}

function safetyNotes() {
  return [
    'Store SCIM bearer tokens and OIDC client secrets only in the customer secret manager.',
    'Do not put tokens, client secrets, MFA seeds, or screenshots of secrets into tickets or evidence packs.',
    'Keep local Security Admin credentials as break-glass access after SSO is tested.',
  ];
}

function buildIdentitySetupGuide(opts = {}) {
  const provider = normalizeProvider(opts.provider);
  const meta = PROVIDERS[provider];
  const baseUrl = normalizeBaseUrl(opts.baseUrl);
  const tenant = normalizeTenant(opts.tenantId || opts.tenant || opts.oktaDomain, meta.tenantPlaceholder);
  const redirectUri = `${baseUrl}/auth/oidc/callback`;
  const issuer = providerIssuer(provider, tenant);
  const scimUrl = `${baseUrl}/scim/v2`;

  return {
    provider,
    label: meta.label,
    baseUrl,
    tenant,
    tenantLabel: meta.tenantLabel,
    scim: scimGuide(meta, scimUrl),
    oidc: oidcGuide(meta, issuer, redirectUri),
    env: envRows(issuer, redirectUri),
    roleGroups: ROLE_GROUPS,
    validation: validationSteps(scimUrl),
    preflightChecks: ['scim_bearer_token_strength', 'oidc_config', 'oidc_client_secret_strength', 'oidc_scim_users', 'oidc_endpoints'],
    safety: safetyNotes(),
    docs: meta.docs,
  };
}

function renderTextGuide(guide) {
  const lines = [
    `${guide.label} setup for RedactWall`,
    '',
    'SCIM',
    `  Tenant URL: ${guide.scim.tenantUrl}`,
    `  Auth: ${guide.scim.authMode}`,
    `  Token env: ${guide.scim.tokenEnv} or ${guide.scim.tokenAlias}`,
    `  Unique identifier: ${guide.scim.uniqueIdentifier}`,
    '',
    'OIDC',
    `  Application type: ${guide.oidc.applicationType}`,
    `  Issuer: ${guide.oidc.issuer}`,
    `  Redirect URI: ${guide.oidc.redirectUri}`,
    `  Scopes: ${guide.oidc.scopes.join(' ')}`,
    '',
    'Environment',
    ...guide.env.map((row) => `  ${row.key}=${row.value}`),
    '',
    'Role groups',
    ...guide.roleGroups.map((row) => `  ${row.role}: ${row.groups.join(', ')}`),
    '',
    'Validation',
    ...guide.validation.map((step) => `  ${step}`),
  ];
  return lines.join('\n') + '\n';
}

module.exports = {
  PROVIDERS,
  ROLE_GROUPS,
  buildIdentitySetupGuide,
  normalizeProvider,
  renderTextGuide,
  _internal: { providerIssuer },
};
