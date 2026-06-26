'use strict';
/**
 * Deployment preflight checks. Local demos can run with warnings; production
 * must not start with defaults that would undermine admin or sensor security.
 */

function bool(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').toLowerCase());
}

function check(id, ok, severity, message, remediation) {
  return { id, ok: !!ok, severity, message, remediation };
}

const MIN_SECRET_LENGTHS = {
  adminPassword: 16,
  auditorPassword: 16,
  ingestKey: 32,
  sessionSecret: 32,
  dataKey: 32,
};

function hasMinLength(value, min) {
  return String(value || '').trim().length >= min;
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
  const env = input.env || process.env;
  const production = env.NODE_ENV === 'production';
  const severity = production ? 'error' : 'warning';
  const dbPath = input.dbPath || env.SENTINEL_DB_PATH || '';
  const dbPathReason = cloudSyncedPathReason(dbPath);
  const adminUser = String(input.adminUser ?? env.ADMIN_USER ?? 'admin').trim();
  const adminPassword = input.adminPassword ?? env.ADMIN_PASSWORD ?? '';
  const auditorUser = String(input.auditorUser ?? env.AUDITOR_USER ?? '').trim();
  const auditorPassword = input.auditorPassword ?? env.AUDITOR_PASSWORD ?? '';
  const auditorPasswordSet = !!String(auditorPassword).trim();
  const auditorConfigured = !!auditorUser || auditorPasswordSet;
  const ingestKey = input.ingestKey ?? env.INGEST_API_KEY ?? '';
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
      'auditor_credentials',
      !auditorConfigured || (!!auditorUser && auditorPasswordSet),
      severity,
      'Auditor login has both AUDITOR_USER and AUDITOR_PASSWORD when configured.',
      'Set both AUDITOR_USER and AUDITOR_PASSWORD, or remove both to disable auditor login.',
    ),
    check(
      'auditor_user_distinct',
      !auditorConfigured || !auditorUser || auditorUser !== adminUser,
      severity,
      'Auditor username is distinct from ADMIN_USER.',
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
