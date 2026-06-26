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

function configStatus(input = {}) {
  const env = input.env || process.env;
  const production = env.NODE_ENV === 'production';
  const severity = production ? 'error' : 'warning';
  const checks = [
    check(
      'admin_password',
      !input.adminPasswordIsDefault,
      severity,
      'Admin password is not the built-in default.',
      'Set ADMIN_PASSWORD to a unique value before any pilot or production use.',
    ),
    check(
      'ingest_key',
      !input.ingestKeyIsDefault,
      severity,
      'Sensor ingest key is not the development default.',
      'Set INGEST_API_KEY to a long random value and deploy it through managed policy or agent configuration.',
    ),
    check(
      'session_secret',
      input.secretSource === 'env',
      severity,
      'Session signing secret comes from SENTINEL_SECRET.',
      'Set SENTINEL_SECRET to a stable random value shared by all server instances.',
    ),
    check(
      'raw_prompt_encryption',
      !!input.dataCryptoEnabled,
      severity,
      'Retained approval prompts can be encrypted at rest.',
      'Set SENTINEL_DATA_KEY or SENTINEL_SECRET before enabling raw approval retention.',
    ),
    check(
      'secure_cookie',
      !!input.cookieSecure || !production,
      production ? 'error' : 'info',
      'Admin session cookie is marked secure for production.',
      'Set HTTPS=true or COOKIE_SECURE=true when serving the console over TLS.',
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

module.exports = { bool, configStatus, summarizeFailures };
