'use strict';
/**
 * Shared sensor transport guard. Sensors send the ingest key and prompt
 * metadata to the control plane; over a REMOTE connection that must be HTTPS,
 * or the ingest key travels in cleartext. HTTP is allowed only to loopback (the
 * local-plane default and dev/test), or with an explicit insecure override.
 */

function isLoopbackHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  // '<name>.localhost' (single label) is loopback per RFC 6761; reject
  // multi-label FQDNs so 'x.localhost.evil.com' is not treated as loopback.
  if (/^[a-z0-9-]+\.localhost$/.test(h)) return true;
  // IPv4 127.0.0.0/8, matched only as a strict dotted-quad. A string prefix
  // like startsWith('127.') would wrongly accept an attacker host such as
  // '127.0.0.1.evil.com' and allow cleartext HTTP to it.
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.every((n) => n <= 255) && o[0] === 127) return true;
  }
  return false;
}

// Returns a normalized origin/URL string when the target is acceptable, else
// null. https anywhere; http only to loopback or when allowInsecure.
function secureServerUrl(value, allowInsecure = false) {
  try {
    const url = new URL(String(value || ''));
    if (url.username || url.password) return null;
    if (url.protocol === 'https:') return value;
    if (url.protocol === 'http:' && (isLoopbackHost(url.hostname) || allowInsecure)) return value;
    return null;
  } catch (_) {
    return null;
  }
}

module.exports = { secureServerUrl, isLoopbackHost };
