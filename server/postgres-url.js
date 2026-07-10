'use strict';

const POSTGRES_TLS_MODES = new Set(['require', 'verify-ca', 'verify-full']);

// Keep URL semantics to the intersection implemented by node-postgres and
// libpq. In particular, libpq-only hostaddr/dbname/passfile parameters must
// never make a backup address a different server or database than the app.
const SUPPORTED_POSTGRES_QUERY_PARAMS = new Set([
  'host',
  'port',
  'user',
  'password',
  'options',
  'application_name',
  'sslmode',
  'sslcert',
  'sslkey',
  'sslrootcert',
]);

// The connection URL is the sole source of connection authority. Clear
// inherited libpq variables for both the node-postgres worker and CLI tools so
// missing URL fields cannot select a different endpoint or credential source.
const POSTGRES_CONNECTION_ENV_VARS = Object.freeze([
  'PGHOST',
  'PGHOSTADDR',
  'PGPORT',
  'PGUSER',
  'PGPASSWORD',
  'PGDATABASE',
  'PGPASSFILE',
  'PGSERVICE',
  'PGSERVICEFILE',
  'PGOPTIONS',
  'PGAPPNAME',
  'PGCONNECT_TIMEOUT',
  'PGCLIENTENCODING',
  'PGREQUIRESSL',
  'PGSSLMODE',
  'PGSSLCERT',
  'PGSSLKEY',
  'PGSSLCERTMODE',
  'PGSSLROOTCERT',
  'PGSSLCRL',
  'PGSSLCRLDIR',
  'PGSSLMINPROTOCOLVERSION',
  'PGSSLMAXPROTOCOLVERSION',
  'PGSSLNEGOTIATION',
  'PGCHANNELBINDING',
  'PGTARGETSESSIONATTRS',
  'PGLOADBALANCEHOSTS',
  'PGREQUIREAUTH',
]);

function invalidPostgresUrl(message) {
  const error = new Error(message);
  error.code = 'REDACTWALL_POSTGRES_URL_INVALID';
  return error;
}

function decodeUrlPart(value, decoder) {
  try {
    return decoder(String(value || ''));
  } catch {
    throw invalidPostgresUrl('Postgres connection URL contains invalid percent encoding');
  }
}

function queryValues(url) {
  const values = Object.create(null);
  for (const [name, value] of url.searchParams.entries()) {
    if (Object.prototype.hasOwnProperty.call(values, name)) {
      throw invalidPostgresUrl('Postgres connection URL must not repeat query parameters');
    }
    if (!SUPPORTED_POSTGRES_QUERY_PARAMS.has(name)) {
      throw invalidPostgresUrl('Postgres connection URL contains an unsupported query parameter');
    }
    values[name] = value;
  }
  return values;
}

function validSingleHost(value) {
  const host = String(value || '');
  return !!host && !host.includes('\0') && !host.includes(',');
}

function validPort(value) {
  if (!value) return true;
  if (!/^\d{1,5}$/.test(value)) return false;
  const port = Number(value);
  return port >= 1 && port <= 65535;
}

function parsePostgresConnectionUrl(value) {
  const raw = String(value || '').trim();
  let url;
  try { url = new URL(raw); } catch { throw invalidPostgresUrl('Postgres connection URL is malformed'); }
  if (!['postgres:', 'postgresql:'].includes(url.protocol)) {
    throw invalidPostgresUrl('Postgres connection URL must use postgres:// or postgresql://');
  }
  // URL.hash is empty for a trailing '#', so inspect the raw marker too.
  if (raw.includes('#')) throw invalidPostgresUrl('Postgres connection URL must not include a fragment');

  const query = queryValues(url);
  const authorityHost = decodeUrlPart(url.hostname, decodeURIComponent);
  const authorityUser = decodeUrlPart(url.username, decodeURIComponent);
  const authorityPassword = decodeUrlPart(url.password, decodeURIComponent);
  const host = query.host || authorityHost;
  const port = query.port || url.port;
  const user = query.user || authorityUser;
  const password = query.password || authorityPassword;
  const database = decodeUrlPart(url.pathname.replace(/^\//, ''), decodeURI);

  if (!validSingleHost(host)) {
    throw invalidPostgresUrl('Postgres connection URL requires one explicit host');
  }
  if (!validPort(port)) throw invalidPostgresUrl('Postgres connection URL contains an invalid port');
  if (!user || user.includes('\0')) {
    throw invalidPostgresUrl('Postgres connection URL requires an explicit user');
  }
  if (!database || database.includes('\0')) {
    throw invalidPostgresUrl('Postgres connection URL requires an explicit database');
  }
  if (password.includes('\0')) throw invalidPostgresUrl('Postgres connection URL contains an invalid password');

  return { raw, url, query, host, port, user, password, database };
}

function normalizedHost(value) {
  return String(value || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
}

function isLoopbackHost(value) {
  const host = normalizedHost(value);
  if (host === 'localhost' || host === '::1') return true;
  if (/^127(?:\.\d{1,3}){3}$/.test(host)) {
    return host.split('.').every((part) => Number(part) <= 255);
  }
  return host.startsWith('/') || /^[A-Za-z]:[\\/]/.test(host);
}

function validPostgresTlsUrl(value, options = {}) {
  let parsed;
  try { parsed = parsePostgresConnectionUrl(value); } catch { return false; }
  const suppliedMode = String(parsed.query.sslmode || '');
  const sslmode = suppliedMode.trim().toLowerCase();
  if (suppliedMode !== sslmode) return false;
  if (POSTGRES_TLS_MODES.has(sslmode)) return true;
  if (sslmode && sslmode !== 'disable') return false;
  return options.allowLoopbackPlaintext === true && isLoopbackHost(parsed.host);
}

function withoutPostgresConnectionEnv(env = process.env) {
  const clean = { ...env };
  for (const variable of POSTGRES_CONNECTION_ENV_VARS) delete clean[variable];
  return clean;
}

module.exports = {
  parsePostgresConnectionUrl,
  validPostgresTlsUrl,
  withoutPostgresConnectionEnv,
  POSTGRES_TLS_MODES,
  POSTGRES_CONNECTION_ENV_VARS,
  SUPPORTED_POSTGRES_QUERY_PARAMS,
  isLoopbackHost,
};
