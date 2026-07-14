'use strict';

const crypto = require('node:crypto');
const { isDeploymentId } = require('./deployment-identity');
const ENTITLEMENT_KEY_ID_RE = /^rw-entitlement-[a-f0-9]{64}$/;

function connectedScopeFromEnv(env, validateBinding) {
  // Tenant slugs retain their existing normalization. The vendor-issued
  // deployment protocol identity is exact and must never be trimmed.
  const customerId = String(env.REDACTWALL_TENANT_ID || '').trim();
  const deploymentId = env.REDACTWALL_CONNECTED_DEPLOYMENT_ID ?? '';
  try {
    if (typeof validateBinding !== 'function') throw new TypeError();
    if (!isDeploymentId(deploymentId)) throw new TypeError();
    validateBinding(customerId, deploymentId);
  } catch {
    const error = new Error('connected entitlement customer and deployment identity are required');
    error.code = 'CONNECTED_ENTITLEMENT_SCOPE_REQUIRED';
    throw error;
  }
  return Object.freeze({ customerId, deploymentId });
}

function connectedVerificationKeys(env) {
  const current = connectedPublicKey(
    env, 'REDACTWALL_ENTITLEMENT_PUBLIC_KEY', 'REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64',
  );
  const currentKeyId = String(env.REDACTWALL_ENTITLEMENT_KEY_ID || '').trim();
  if (!current || !currentKeyId) {
    const error = new Error('connected entitlement public key is not configured');
    error.code = current || currentKeyId
      ? 'CONNECTED_ENTITLEMENT_CURRENT_KEY_PAIR_REQUIRED'
      : 'CONNECTED_ENTITLEMENT_KEY_REQUIRED';
    throw error;
  }
  requireEntitlementKeyId(currentKeyId, current);
  const publicKeys = { [currentKeyId]: current };
  const next = connectedPublicKey(
    env, 'REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY',
    'REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64',
  );
  const nextKeyId = String(env.REDACTWALL_ENTITLEMENT_NEXT_KEY_ID || '').trim();
  if (!!next !== !!nextKeyId) {
    const error = new Error('connected entitlement next public key and key ID must be configured together');
    error.code = 'CONNECTED_ENTITLEMENT_NEXT_KEY_PAIR_REQUIRED';
    throw error;
  }
  if (nextKeyId) requireEntitlementKeyId(nextKeyId, next);
  if (next && nextKeyId) {
    if (Object.hasOwn(publicKeys, nextKeyId)) {
      const error = new Error('connected entitlement current and next key IDs must differ');
      error.code = 'CONNECTED_ENTITLEMENT_KEY_ID_DUPLICATE';
      throw error;
    }
    publicKeys[nextKeyId] = next;
  }
  const offline = connectedOfflinePublicKey(env);
  const onlineVerdict = connectedPublicKey(
    env, 'REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY', 'REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64',
  );
  const onlineVerdictNext = connectedPublicKey(
    env, 'REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY',
    'REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64',
  );
  assertPurposeSeparatedKeys([current, next, offline, onlineVerdict, onlineVerdictNext]);
  const forbiddenPublicKeyFingerprints = [onlineVerdict, onlineVerdictNext]
    .filter(Boolean).map(publicKeyFingerprint);
  return {
    publicKeys,
    offlineKeyFingerprint: publicKeyFingerprint(offline),
    forbiddenPublicKeyFingerprints,
  };
}

function connectedOfflinePublicKey(env) {
  const key = connectedPublicKey(
    env, 'REDACTWALL_LICENSE_PUBLIC_KEY', 'REDACTWALL_LICENSE_PUBLIC_KEY_B64',
  );
  if (!key) {
    const error = new Error('offline fallback public key is not configured');
    error.code = 'OFFLINE_LICENSE_KEY_REQUIRED';
    throw error;
  }
  return key;
}

function connectedPublicKey(env, pemName, base64Name) {
  const pem = String(env[pemName] || '').trim();
  const encoded = String(env[base64Name] || '').trim();
  if (!pem && !encoded) return '';
  try {
    const pemKey = pem ? exportedConnectedPublicKey(pem) : '';
    const encodedKey = encoded ? exportedConnectedPublicKey(decodedSpki(encoded)) : '';
    if (pemKey && encodedKey
        && publicKeyFingerprint(pemKey) !== publicKeyFingerprint(encodedKey)) {
      throw configError('CONNECTED_PUBLIC_KEY_SOURCE_CONFLICT');
    }
    return pemKey || encodedKey;
  } catch (error) {
    if (error && error.code === 'CONNECTED_PUBLIC_KEY_SOURCE_CONFLICT') throw error;
    throw configError('CONNECTED_PUBLIC_KEY_INVALID');
  }
}

function decodedSpki(encoded) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new TypeError();
  const der = Buffer.from(encoded, 'base64');
  if (!der.length || der.toString('base64') !== encoded) throw new TypeError();
  return { key: der, type: 'spki', format: 'der' };
}

function publicKeyFingerprint(value) {
  try {
    const der = connectedPublicKeyObject(value).export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex');
  } catch { return ''; }
}

function exportedConnectedPublicKey(value) {
  return connectedPublicKeyObject(value)
    .export({ type: 'spki', format: 'pem' }).toString();
}

function connectedPublicKeyObject(value) {
  if (value instanceof crypto.KeyObject) {
    if (value.type !== 'public') throw new TypeError('connected trust pin must be public-only');
    if (value.asymmetricKeyType !== 'ed25519') {
      throw new TypeError('connected trust pin must be Ed25519');
    }
    return value;
  }
  try {
    crypto.createPrivateKey(value);
    throw new TypeError('connected trust pin must be public-only');
  } catch (error) {
    if (error instanceof TypeError && error.message === 'connected trust pin must be public-only') {
      throw error;
    }
  }
  const key = crypto.createPublicKey(value);
  if (key.type !== 'public') throw new TypeError('connected trust pin must be public-only');
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('connected trust pin must be Ed25519');
  }
  return key;
}

function requireEntitlementKeyId(value, publicKey) {
  const expected = `rw-entitlement-${publicKeyFingerprint(publicKey)}`;
  if (!ENTITLEMENT_KEY_ID_RE.test(value) || value !== expected) {
    const error = new Error('connected entitlement key ID is invalid');
    error.code = 'CONNECTED_ENTITLEMENT_KEY_ID_INVALID';
    throw error;
  }
}

function configError(code) {
  const error = new Error('connected public-key configuration is invalid');
  error.code = code;
  return error;
}

function assertPurposeSeparatedKeys(values) {
  const fingerprints = values.filter(Boolean).map(publicKeyFingerprint);
  if (fingerprints.some((value) => !value)
      || new Set(fingerprints).size !== fingerprints.length) {
    const error = new Error('connected entitlement signing identities must be purpose-separated');
    error.code = 'CONNECTED_ENTITLEMENT_KEY_IDENTITY_REUSED';
    throw error;
  }
}

module.exports = Object.freeze({
  connectedOfflinePublicKey,
  connectedPublicKey,
  connectedScopeFromEnv,
  connectedVerificationKeys,
  publicKeyFingerprint,
});
