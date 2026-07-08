'use strict';
/**
 * Shared sensor transport guard. Sensors send the ingest key and prompt
 * metadata to the control plane; over a REMOTE connection that must be HTTPS,
 * or the ingest key travels in cleartext. HTTP is allowed only to loopback (the
 * local-plane default and dev/test), or with an explicit insecure override.
 */

function isLoopbackHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h.endsWith('.localhost') || h === '127.0.0.1' || h.startsWith('127.') || h === '::1' || h === '0:0:0:0:0:0:0:1';
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
