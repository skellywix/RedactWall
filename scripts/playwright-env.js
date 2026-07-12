'use strict';

// Browser tests must never inherit production authority or outbound connector
// configuration. Keep only host tooling variables (PATH, TEMP, browser paths,
// CI flags, and similar) when constructing the isolated server environment.
const APPLICATION_ENV = /^(?:REDACTWALL_|PROMPTWALL_|SENTINEL_|APPROVAL_|SIEM_|SMTP_|OIDC_|SCIM_|ADMIN_|OPERATOR_|AUDITOR_|APPROVER_|AWS_|CLOUDFLARE_|DATABASE_URL$|INGEST_API_KEY$|COOKIE_SECURE$|HTTPS$|TRUST_PROXY$)/;

function isApplicationEnvironmentKey(key) {
  return APPLICATION_ENV.test(String(key || ''));
}

function sanitizedEnvironment(source = process.env) {
  return Object.fromEntries(Object.entries(source).filter(([key]) => !isApplicationEnvironmentKey(key)));
}

function clearApplicationEnvironment(target = process.env) {
  for (const key of Object.keys(target)) {
    if (isApplicationEnvironmentKey(key)) delete target[key];
  }
  return target;
}

module.exports = { clearApplicationEnvironment, isApplicationEnvironmentKey, sanitizedEnvironment };
