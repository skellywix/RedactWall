(function (root) {
  'use strict';
  const VERSION = 1;
  const MAX_BYTES = 512 * 1024;
  const CLOCK_SKEW_MS = 5 * 60 * 1000;

  function bytes(text) { return new TextEncoder().encode(text); }

  function pemBytes(pem) {
    const match = /^-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+)\s*-----END PUBLIC KEY-----\s*$/.exec(String(pem || '').trim());
    if (!match) throw new Error('invalid public key');
    const raw = atob(match[1].replace(/\s+/g, ''));
    return Uint8Array.from(raw, (char) => char.charCodeAt(0));
  }

  function signatureBytes(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value)) return null;
    try {
      const raw = atob(value);
      return raw.length === 64 ? Uint8Array.from(raw, (char) => char.charCodeAt(0)) : null;
    } catch (_) { return null; }
  }

  function arrayIndexKey(value) {
    if (!/^(0|[1-9]\d*)$/.test(value)) return false;
    const parsed = Number(value);
    return Number.isInteger(parsed) && parsed >= 0 && parsed < 4294967295 && String(parsed) === value;
  }

  function orderedPolicyKeys(value, legacyLexical) {
    const keys = Object.keys(value);
    if (legacyLexical) return keys.sort();
    return [
      ...keys.filter(arrayIndexKey).sort((left, right) => Number(left) - Number(right)),
      ...keys.filter((key) => !arrayIndexKey(key)).sort(),
    ];
  }

  function canonicalPolicyJson(value, legacyLexical) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map((item) => canonicalPolicyJson(item, legacyLexical)).join(',')}]`;
    return `{${orderedPolicyKeys(value, legacyLexical).map((key) => (
      `${JSON.stringify(key)}:${canonicalPolicyJson(value[key], legacyLexical)}`
    )).join(',')}}`;
  }

  async function signingInput(bundle, canonical, legacyLexical) {
    if (!bundle.policy || typeof bundle.policy !== 'object' || Array.isArray(bundle.policy)) throw new Error('invalid policy');
    const serializedPolicy = canonical === false ? JSON.stringify(bundle.policy) : canonicalPolicyJson(bundle.policy, legacyLexical);
    const digest = await crypto.subtle.digest('SHA-256', bytes(serializedPolicy));
    const hash = [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, '0')).join('');
    return bytes(JSON.stringify({
      version: bundle.version,
      issuedAt: bundle.issuedAt,
      expiresAt: bundle.expiresAt,
      policyHash: hash,
    }));
  }

  async function verifyBundle(bundle, publicKeyPem, options) {
    const opts = options || {};
    if (!publicKeyPem) return { ok: false, reason: 'missing_pin' };
    if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return { ok: false, reason: 'no_bundle' };
    let serialized;
    try { serialized = JSON.stringify(bundle); } catch (_) { return { ok: false, reason: 'malformed_bundle' }; }
    if (!serialized || bytes(serialized).byteLength > (opts.maxBytes || MAX_BYTES)) return { ok: false, reason: 'bundle_too_large' };
    if (bundle.version !== VERSION) return { ok: false, reason: 'version_mismatch' };
    if (!bundle.policy || typeof bundle.policy !== 'object' || Array.isArray(bundle.policy)) return { ok: false, reason: 'malformed_bundle' };
    const signature = signatureBytes(bundle.signature);
    if (!signature) return { ok: false, reason: 'bad_signature' };
    const now = Number(opts.now == null ? Date.now() : opts.now);
    const issued = Date.parse(bundle.issuedAt);
    const expires = Date.parse(bundle.expiresAt);
    if (![now, issued, expires].every(Number.isFinite)
        || issued > now + CLOCK_SKEW_MS || expires <= issued
        || (!opts.allowExpired && expires <= now)) {
      return { ok: false, reason: 'expired' };
    }
    try {
      const key = await crypto.subtle.importKey('spki', pemBytes(publicKeyPem), { name: 'Ed25519' }, false, ['verify']);
      let ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, await signingInput(bundle, true));
      if (!ok) ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, await signingInput(bundle, true, true));
      if (!ok) ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, await signingInput(bundle, false));
      return ok ? { ok: true } : { ok: false, reason: 'bad_signature' };
    } catch (_) { return { ok: false, reason: 'bad_public_key' }; }
  }

  root.RedactWallPolicyTrust = { verifyBundle, VERSION, MAX_BYTES };
}(self));
