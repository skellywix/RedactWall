'use strict';
/**
 * Deployment preflight checks. Local demos can run with warnings; production
 * must not start with defaults that would undermine admin or sensor security.
 */
const { withEnvAliases } = require('./env');

function bool(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').toLowerCase());
}

function check(id, ok, severity, message, remediation) {
  return { id, ok: !!ok, severity, message, remediation };
}

const MIN_SECRET_LENGTHS = {
  adminPassword: 16,
  adminTotpSecret: 16,
  approverPassword: 16,
  auditorPassword: 16,
  ingestKey: 32,
  scimBearerToken: 32,
  oidcClientSecret: 32,
  sessionSecret: 32,
  dataKey: 32,
};
const TENANT_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{1,62}$/;

function hasMinLength(value, min) {
  return String(value || '').trim().length >= min;
}

function hasValidBase32Secret(value, min) {
  const normalized = String(value || '').replace(/[\s=-]/g, '').toUpperCase();
  return normalized.length >= min && /^[A-Z2-7]+$/.test(normalized);
}

function hasValidTenantId(value) {
  return TENANT_ID_PATTERN.test(String(value || '').trim().toLowerCase());
}

function positiveInteger(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0;
}

function pathSegments(value) {
  return String(value || '')
    .replace(/\\/g, '/')
    .split('/')
    .map((segment) => segment.trim().toLowerCase())
    .filter(Boolean);
}

function cloudSyncedPathReason(value) {
  const text = String(value || '').trim();
  if (!text) return 'missing';
  const normalized = text.replace(/\\/g, '/');
  if (/^\/\//.test(normalized)) return 'network share';
  const segments = pathSegments(text);
  if (segments.some((segment) => segment === 'dropbox')) return 'Dropbox';
  if (segments.some((segment) => segment === 'google drive' || segment === 'googledrive')) return 'Google Drive';
  if (segments.some((segment) => segment === 'icloud drive' || segment === 'icloud')) return 'iCloud Drive';
  if (segments.some((segment) => segment === 'box')) return 'Box';
  const oneDrive = segments.find((segment) => segment === 'onedrive' || segment.startsWith('onedrive - '));
  if (oneDrive) return 'OneDrive';
  return null;
}

function configStatus(input = {}) {
  const env = withEnvAliases(input.env || process.env);
  const production = env.NODE_ENV === 'production';
  const severity = production ? 'error' : 'warning';
  const dbPath = input.dbPath || env.SENTINEL_DB_PATH || '';
  const dbPathReason = cloudSyncedPathReason(dbPath);
  const adminUser = String(input.adminUser ?? env.ADMIN_USER ?? 'admin').trim();
  const adminPassword = input.adminPassword ?? env.ADMIN_PASSWORD ?? '';
  const adminTotpSecret = input.adminTotpSecret ?? env.ADMIN_TOTP_SECRET ?? '';
  const approverUser = String(input.approverUser ?? env.APPROVER_USER ?? '').trim();
  const approverPassword = input.approverPassword ?? env.APPROVER_PASSWORD ?? '';
  const approverPasswordSet = !!String(approverPassword).trim();
  const approverConfigured = !!approverUser || approverPasswordSet;
  const auditorUser = String(input.auditorUser ?? env.AUDITOR_USER ?? '').trim();
  const auditorPassword = input.auditorPassword ?? env.AUDITOR_PASSWORD ?? '';
  const auditorPasswordSet = !!String(auditorPassword).trim();
  const auditorConfigured = !!auditorUser || auditorPasswordSet;
  const saasMode = bool(input.saasMode ?? env.SENTINEL_SAAS_MODE);
  const tenantId = input.tenantId ?? env.SENTINEL_TENANT_ID ?? '';
  const seatLimit = input.seatLimit ?? env.SENTINEL_SEAT_LIMIT ?? '';
  const requireTenantContext = input.requireTenantContext ?? env.SENTINEL_REQUIRE_TENANT_CONTEXT;
  const requireUserIdentity = input.requireUserIdentity ?? env.SENTINEL_REQUIRE_USER_IDENTITY;
  const saasConfigured = saasMode
    || !!String(tenantId || '').trim()
    || !!String(seatLimit || '').trim()
    || bool(requireTenantContext)
    || bool(requireUserIdentity);
  const ingestKey = input.ingestKey ?? env.INGEST_API_KEY ?? '';
  const scimBearerToken = input.scimBearerToken ?? env.SCIM_BEARER_TOKEN ?? '';
  const scimConfigured = !!String(scimBearerToken || '').trim();
  const oidcIssuer = input.oidcIssuer ?? env.OIDC_ISSUER ?? '';
  const oidcClientId = input.oidcClientId ?? env.OIDC_CLIENT_ID ?? '';
  const oidcClientSecret = input.oidcClientSecret ?? env.OIDC_CLIENT_SECRET ?? '';
  const oidcRedirectUri = input.oidcRedirectUri ?? env.OIDC_REDIRECT_URI ?? '';
  const oidcAuthorizationEndpoint = input.oidcAuthorizationEndpoint ?? env.OIDC_AUTHORIZATION_ENDPOINT ?? '';
  const oidcTokenEndpoint = input.oidcTokenEndpoint ?? env.OIDC_TOKEN_ENDPOINT ?? '';
  const oidcJwksUri = input.oidcJwksUri ?? env.OIDC_JWKS_URI ?? '';
  const oidcConfigured = [
    oidcIssuer,
    oidcClientId,
    oidcClientSecret,
    oidcRedirectUri,
    oidcAuthorizationEndpoint,
    oidcTokenEndpoint,
    oidcJwksUri,
  ].some((value) => !!String(value || '').trim());
  const oidcComplete = !oidcConfigured || (
    !!String(oidcIssuer || '').trim()
    && !!String(oidcClientId || '').trim()
    && !!String(oidcClientSecret || '').trim()
    && !!String(oidcRedirectUri || '').trim()
  );
  const oidcExplicitEndpoints = !oidcConfigured || (
    !String(oidcAuthorizationEndpoint || '').trim()
    && !String(oidcTokenEndpoint || '').trim()
    && !String(oidcJwksUri || '').trim()
  ) || (
    !!String(oidcAuthorizationEndpoint || '').trim()
    && !!String(oidcTokenEndpoint || '').trim()
    && !!String(oidcJwksUri || '').trim()
  );
  const sessionSecret = input.sessionSecret ?? env.SENTINEL_SECRET ?? '';
  const dataKeySource = input.dataKeySource ?? env.SENTINEL_DATA_KEY ?? env.SENTINEL_SECRET ?? '';
  const checks = [
    check(
      'admin_password',
      !input.adminPasswordIsDefault,
      severity,
      'Admin password is not the built-in default.',
      'Set ADMIN_PASSWORD to a unique value before any pilot or production use.',
    ),
    check(
      'admin_password_strength',
      hasMinLength(adminPassword, MIN_SECRET_LENGTHS.adminPassword),
      severity,
      `Admin password is at least ${MIN_SECRET_LENGTHS.adminPassword} characters.`,
      `Set ADMIN_PASSWORD to at least ${MIN_SECRET_LENGTHS.adminPassword} characters.`,
    ),
    check(
      'admin_mfa',
      !!String(adminTotpSecret || '').trim(),
      severity,
      'Security Admin TOTP MFA is configured.',
      'Set ADMIN_TOTP_SECRET to a base32 authenticator secret before production use.',
    ),
    check(
      'admin_mfa_secret',
      !String(adminTotpSecret || '').trim() || hasValidBase32Secret(adminTotpSecret, MIN_SECRET_LENGTHS.adminTotpSecret),
      severity,
      `Security Admin TOTP secret is valid base32 and at least ${MIN_SECRET_LENGTHS.adminTotpSecret} characters.`,
      `Set ADMIN_TOTP_SECRET to a base32 value at least ${MIN_SECRET_LENGTHS.adminTotpSecret} characters long.`,
    ),
    check(
      'approver_credentials',
      !approverConfigured || (!!approverUser && approverPasswordSet),
      severity,
      'Approver login has both APPROVER_USER and APPROVER_PASSWORD when configured.',
      'Set both APPROVER_USER and APPROVER_PASSWORD, or remove both to disable approver login.',
    ),
    check(
      'approver_user_distinct',
      !approverConfigured || !approverUser || (approverUser !== adminUser && approverUser !== auditorUser),
      severity,
      'Approver username is distinct from ADMIN_USER and AUDITOR_USER.',
      'Set APPROVER_USER to a separate review account name.',
    ),
    check(
      'approver_password_strength',
      !approverConfigured || hasMinLength(approverPassword, MIN_SECRET_LENGTHS.approverPassword),
      severity,
      `Approver password is at least ${MIN_SECRET_LENGTHS.approverPassword} characters when approver login is configured.`,
      `Set APPROVER_PASSWORD to at least ${MIN_SECRET_LENGTHS.approverPassword} characters, or remove APPROVER_USER to disable approver login.`,
    ),
    check(
      'auditor_credentials',
      !auditorConfigured || (!!auditorUser && auditorPasswordSet),
      severity,
      'Auditor login has both AUDITOR_USER and AUDITOR_PASSWORD when configured.',
      'Set both AUDITOR_USER and AUDITOR_PASSWORD, or remove both to disable auditor login.',
    ),
    check(
      'auditor_user_distinct',
      !auditorConfigured || !auditorUser || (auditorUser !== adminUser && auditorUser !== approverUser),
      severity,
      'Auditor username is distinct from ADMIN_USER and APPROVER_USER.',
      'Set AUDITOR_USER to a separate read-only account name.',
    ),
    check(
      'auditor_password_strength',
      !auditorConfigured || hasMinLength(auditorPassword, MIN_SECRET_LENGTHS.auditorPassword),
      severity,
      `Auditor password is at least ${MIN_SECRET_LENGTHS.auditorPassword} characters when auditor login is configured.`,
      `Set AUDITOR_PASSWORD to at least ${MIN_SECRET_LENGTHS.auditorPassword} characters, or remove AUDITOR_USER to disable auditor login.`,
    ),
    check(
      'ingest_key',
      !input.ingestKeyIsDefault,
      severity,
      'Sensor ingest key is not the development default.',
      'Set INGEST_API_KEY to a long random value and deploy it through managed policy or agent configuration.',
    ),
    check(
      'ingest_key_strength',
      hasMinLength(ingestKey, MIN_SECRET_LENGTHS.ingestKey),
      severity,
      `Sensor ingest key is at least ${MIN_SECRET_LENGTHS.ingestKey} characters.`,
      `Set INGEST_API_KEY to at least ${MIN_SECRET_LENGTHS.ingestKey} random characters.`,
    ),
    check(
      'scim_bearer_token_strength',
      !scimConfigured || hasMinLength(scimBearerToken, MIN_SECRET_LENGTHS.scimBearerToken),
      severity,
      `SCIM bearer token is at least ${MIN_SECRET_LENGTHS.scimBearerToken} characters when SCIM provisioning is enabled.`,
      `Set SCIM_BEARER_TOKEN to at least ${MIN_SECRET_LENGTHS.scimBearerToken} random characters, or leave it empty to disable SCIM provisioning.`,
    ),
    check(
      'oidc_config',
      oidcComplete,
      severity,
      'OIDC login has issuer, client id, client secret, and redirect URI when configured.',
      'Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_REDIRECT_URI, or remove all OIDC_* values to disable OIDC login.',
    ),
    check(
      'oidc_client_secret_strength',
      !oidcConfigured || hasMinLength(oidcClientSecret, MIN_SECRET_LENGTHS.oidcClientSecret),
      severity,
      `OIDC client secret is at least ${MIN_SECRET_LENGTHS.oidcClientSecret} characters when OIDC login is configured.`,
      `Set OIDC_CLIENT_SECRET to at least ${MIN_SECRET_LENGTHS.oidcClientSecret} random characters.`,
    ),
    check(
      'oidc_scim_users',
      !oidcConfigured || scimConfigured,
      severity,
      'OIDC login is backed by SCIM-provisioned users and groups.',
      'Set SCIM_BEARER_TOKEN and provision active users before enabling OIDC login.',
    ),
    check(
      'oidc_endpoints',
      oidcExplicitEndpoints,
      severity,
      'OIDC endpoints are either discovered from issuer metadata or configured as a complete authorization/token/JWKS set.',
      'Set all of OIDC_AUTHORIZATION_ENDPOINT, OIDC_TOKEN_ENDPOINT, and OIDC_JWKS_URI, or omit all three to use discovery.',
    ),
    check(
      'session_secret',
      input.secretSource === 'env',
      severity,
      'Session signing secret comes from SENTINEL_SECRET.',
      'Set SENTINEL_SECRET to a stable random value shared by all server instances.',
    ),
    check(
      'session_secret_strength',
      hasMinLength(sessionSecret, MIN_SECRET_LENGTHS.sessionSecret),
      severity,
      `Session signing secret is at least ${MIN_SECRET_LENGTHS.sessionSecret} characters.`,
      `Set SENTINEL_SECRET to at least ${MIN_SECRET_LENGTHS.sessionSecret} random characters.`,
    ),
    check(
      'raw_prompt_encryption',
      !!input.dataCryptoEnabled,
      severity,
      'Retained approval prompts can be encrypted at rest.',
      'Set SENTINEL_DATA_KEY or SENTINEL_SECRET before enabling raw approval retention.',
    ),
    check(
      'data_key_strength',
      hasMinLength(dataKeySource, MIN_SECRET_LENGTHS.dataKey),
      severity,
      `Raw-prompt encryption key source is at least ${MIN_SECRET_LENGTHS.dataKey} characters.`,
      `Set SENTINEL_DATA_KEY, or SENTINEL_SECRET fallback, to at least ${MIN_SECRET_LENGTHS.dataKey} random characters.`,
    ),
    check(
      'secure_cookie',
      !!input.cookieSecure || !production,
      production ? 'error' : 'info',
      'Admin session cookie is marked secure for production.',
      'Set HTTPS=true or COOKIE_SECURE=true when serving the console over TLS.',
    ),
    check(
      'sqlite_local_disk',
      !!dbPath && !dbPathReason,
      severity,
      'SQLite evidence store is configured on a local disk path.',
      dbPathReason
        ? `Set SENTINEL_DB_PATH to a local disk path; current path looks like ${dbPathReason}.`
        : 'Set SENTINEL_DB_PATH to a local disk path outside cloud-synced or network folders.',
    ),
    check(
      'saas_tenant_id',
      !saasConfigured || hasValidTenantId(tenantId),
      severity,
      'SaaS tenant id is configured.',
      'Set SENTINEL_TENANT_ID to a lowercase customer slug such as cu-acme.',
    ),
    check(
      'saas_seat_limit',
      !saasConfigured || positiveInteger(seatLimit),
      severity,
      'SaaS seat limit is configured.',
      'Set SENTINEL_SEAT_LIMIT to the purchased positive seat count.',
    ),
    check(
      'saas_tenant_context',
      !saasConfigured || saasMode || bool(requireTenantContext),
      severity,
      'SaaS sensors must send tenant context.',
      'Set SENTINEL_REQUIRE_TENANT_CONTEXT=true, or set SENTINEL_SAAS_MODE=true.',
    ),
    check(
      'saas_user_identity',
      !saasConfigured || saasMode || bool(requireUserIdentity),
      severity,
      'SaaS sensors must send managed user identity.',
      'Set SENTINEL_REQUIRE_USER_IDENTITY=true, or set SENTINEL_SAAS_MODE=true.',
    ),
  ];
  const failed = checks.filter((c) => !c.ok);
  const blockers = failed.filter((c) => c.severity === 'error');
  return {
    production,
    ready: blockers.length === 0,
    level: blockers.length ? 'blocked' : failed.length ? 'warnings' : 'ok',
    checks,
  };
}

function summarizeFailures(status) {
  return (status.checks || [])
    .filter((c) => !c.ok && c.severity === 'error')
    .map((c) => `${c.id}: ${c.remediation}`);
}

module.exports = { bool, cloudSyncedPathReason, configStatus, summarizeFailures, MIN_SECRET_LENGTHS };
