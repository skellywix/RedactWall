'use strict';

/**
 * OIDC endpoints are security configuration, not arbitrary fetch targets.
 * Query strings are rejected on every configured URL. Discovery and the
 * authorization builder add their own parameters, while fixed query values can
 * hide credentials or change provider behavior in ways RedactWall cannot audit.
 */
function validOidcUrl(value, options = {}) {
  let url;
  try { url = new URL(String(value || '').trim()); } catch { return false; }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) return false;
  if (options.production === true && url.protocol !== 'https:') return false;
  return !url.username && !url.password && !url.search && !url.hash;
}

function assertOidcUrls(config, fields) {
  for (const [field, label] of fields) {
    if (!validOidcUrl(config && config[field], { production: !!(config && config.production) })) {
      const transport = config && config.production ? 'HTTPS ' : '';
      throw new Error(`OIDC ${label} must be a safe ${transport}URL without credentials, query parameters, or fragments`);
    }
  }
}

module.exports = { validOidcUrl, assertOidcUrls };
