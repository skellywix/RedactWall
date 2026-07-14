'use strict';

const crypto = require('node:crypto');
const protocol = require('./vendor-control-protocol');
const {
  AUTHORITY_DEFINITIONS,
  validPurposeKeyBinding,
} = require('./vendor-signed-artifact');

const KEY_BYTES = 32;
const KEY_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,95}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const PURPOSES = Object.freeze([
  'access', 'audit', 'cursor', 'customerGrant', 'diagnosticWitness', 'integrity', 'ownerAuth',
]);
const RESERVED_PURPOSES = Object.freeze([...new Set([
  ...Object.keys(AUTHORITY_DEFINITIONS),
  'command_idempotency',
  'pagination_cursor',
  'license_registry_integrity',
])]);
const CHANNEL_CREDENTIAL_PURPOSES = Object.freeze([
  'acknowledgement_credential', 'diagnostic_credential',
  'heartbeat_credential', 'shadow_candidate_credential',
]);
const OWNER_DIAGNOSTIC_INTEGRITY_PURPOSE = 'diagnostic_integrity';
const FINGERPRINT_BOUND_OWNER_PURPOSES = new Set(['entitlement', 'online_verdict']);
const DIAGNOSTIC_KEY_ENVIRONMENT = Object.freeze({
  diagnosticWitness: 'OWNER_DIAGNOSTIC_WITNESS_KEY',
  integrity: 'OWNER_DIAGNOSTIC_INTEGRITY_KEY',
});
const FACTORY_ERROR = 'vendor diagnostic key manifest rejected';

function createVendorDiagnosticKeyFactory(options = {}) {
  try { return buildFactory(options); }
  catch (error) { throw keyError(error && error.code ? error.code : 'key_manifest_invalid'); }
}

function buildFactory(options) {
  const input = factoryOptions(options);
  const now = checkedNow(input.now);
  const nowMs = now();
  const requiredVerifyHorizonMs = checkedHorizon(input.requiredVerifyHorizonMs);
  const keys = exactObject(input.keys, PURPOSES, 'key_manifest_invalid');
  const ownerManifest = ownerAuthorityManifest(input.ownerAuthorityManifest);
  const identities = [];
  const entries = {};
  for (const purpose of PURPOSES) {
    entries[purpose] = keyEntry(keys[purpose], purpose, nowMs, requiredVerifyHorizonMs);
    identities.push(entries[purpose].current, ...entries[purpose].verifyOnly);
  }
  assertDiagnosticIntegrityBinding(entries.integrity.current, ownerManifest);
  for (const purpose of RESERVED_PURPOSES) {
    if (purpose === OWNER_DIAGNOSTIC_INTEGRITY_PURPOSE) continue;
    const fingerprint = ownerManifest[purpose].identity;
    if (typeof fingerprint !== 'string' || !SHA256_RE.test(fingerprint)) {
      throw keyError('key_manifest_invalid');
    }
    identities.push({ purpose: `owner:${purpose}`, keyId: ownerManifest[purpose].keyId,
      fingerprint, key: null });
  }
  assertDistinctIdentities(identities);
  const authorities = Object.fromEntries(PURPOSES.map((purpose) => [
    purpose, authorityFor(entries[purpose], purpose, now),
  ]));
  provePurposeSeparation(authorities);
  const publicManifest = Object.freeze({
    schemaVersion: 1,
    requiredVerifyHorizonMs,
    auditRetentionMode: 'full_epoch',
    witnessRetentionMode: 'full_epoch',
    purposes: Object.freeze(Object.fromEntries(PURPOSES.map((purpose) => [
      purpose, publicEntry(entries[purpose]),
    ]))),
    ownerAuthorityManifest: Object.freeze(ownerManifest),
    channelCredentialFingerprints: Object.freeze(Object.fromEntries(
      CHANNEL_CREDENTIAL_PURPOSES.map((purpose) => [purpose, ownerManifest[purpose].identity]),
    )),
  });
  return Object.freeze({
    authority(purpose) {
      if (!PURPOSES.includes(purpose)) throw keyError('key_purpose_invalid');
      return authorities[purpose];
    },
    fingerprints() {
      return Object.freeze(Object.fromEntries(PURPOSES.map((purpose) => [
        purpose, entries[purpose].current.fingerprint,
      ])));
    },
    manifest() { return publicManifest; },
    manifestDigest: sha256(protocol.canonicalJson(publicManifest)),
  });
}

function assertDiagnosticIntegrityBinding(integrity, ownerManifest) {
  const ownerIntegrity = ownerManifest[OWNER_DIAGNOSTIC_INTEGRITY_PURPOSE];
  if (!ownerIntegrity || ownerIntegrity.keyId !== integrity.keyId
      || ownerIntegrity.identity !== integrity.fingerprint) {
    throw keyError('diagnostic_integrity_manifest_mismatch');
  }
}

function factoryOptions(value) {
  const required = [
    'keys', 'ownerAuthorityManifest', 'requiredVerifyHorizonMs',
  ];
  const allowed = new Set([...required, 'now']);
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw keyError('key_manifest_invalid');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (required.some((key) => !Object.hasOwn(descriptors, key))
      || Object.keys(descriptors).some((key) => !allowed.has(key))
      || Object.values(descriptors).some((descriptor) => !Object.hasOwn(descriptor, 'value')
        || descriptor.get || descriptor.set || descriptor.enumerable !== true)) {
    throw keyError('key_manifest_invalid');
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
}

function keyEntry(value, purpose, now, horizon) {
  const input = exactObject(value, ['current', 'verifyOnly'], 'key_manifest_invalid');
  if (!Array.isArray(input.verifyOnly) || input.verifyOnly.length > 8) {
    throw keyError('key_manifest_invalid');
  }
  const current = material(input.current, purpose, false, now, horizon);
  const verifyOnly = input.verifyOnly.map((item) => material(item, purpose, true, now, horizon));
  if (new Set([current.keyId, ...verifyOnly.map((item) => item.keyId)]).size
      !== verifyOnly.length + 1) throw keyError('key_manifest_invalid');
  return Object.freeze({ current, verifyOnly: Object.freeze(verifyOnly) });
}

function material(value, purpose, verifyOnly, now, horizon) {
  const keys = verifyOnly ? ['key', 'keyId', 'verifyUntil'] : ['key', 'keyId'];
  const input = exactObject(value, keys, 'key_manifest_invalid');
  if (typeof input.keyId !== 'string' || !KEY_ID_RE.test(input.keyId)) {
    throw keyError('key_manifest_invalid');
  }
  const key = decodeKey(input.key);
  let verifyUntil = null;
  if (verifyOnly) {
    if (purpose === 'audit' || purpose === 'diagnosticWitness') {
      if (input.verifyUntil !== null) throw keyError('audit_key_retirement_requires_epoch');
    } else {
      verifyUntil = canonicalIso(input.verifyUntil);
      if (Date.parse(verifyUntil) < now + horizon) throw keyError('key_retention_too_short');
    }
  }
  return Object.freeze({
    purpose,
    keyId: input.keyId,
    key,
    fingerprint: sha256(key),
    verifyUntil,
  });
}

function authorityFor(entry, purpose, now) {
  const byId = new Map([entry.current, ...entry.verifyOnly].map((item) => [item.keyId, item]));
  return Object.freeze({
    keyId: entry.current.keyId,
    fingerprint: entry.current.fingerprint,
    sign(domain, message) {
      checkedDomainMessage(domain, message);
      return proof(entry.current, domain, message);
    },
    verify(domain, message, candidate) {
      try {
        checkedDomainMessage(domain, message);
        if (!candidate || typeof candidate.keyId !== 'string' || typeof candidate.mac !== 'string') {
          return false;
        }
        const selected = byId.get(candidate.keyId);
        if (!selected || (selected.verifyUntil !== null && now() > Date.parse(selected.verifyUntil))) {
          return false;
        }
        const expected = Buffer.from(proof(selected, domain, message).mac, 'base64');
        const actual = Buffer.from(candidate.mac, 'base64');
        return actual.length === expected.length && actual.toString('base64') === candidate.mac
          && crypto.timingSafeEqual(actual, expected);
      } catch { return false; }
    },
    purpose,
  });
}

function proof(identity, domain, message) {
  return Object.freeze({
    keyId: identity.keyId,
    mac: crypto.createHmac('sha256', identity.key)
      .update(domain, 'utf8').update('\0')
      .update(identity.keyId, 'utf8').update('\0')
      .update(message, 'utf8').digest('base64'),
  });
}

function provePurposeSeparation(authorities) {
  const message = crypto.randomBytes(32).toString('base64');
  for (const purpose of PURPOSES) {
    const domain = `redactwall.vendor-diagnostic-key-challenge.${purpose}.v1`;
    const candidate = authorities[purpose].sign(domain, message);
    if (!authorities[purpose].verify(domain, message, candidate)
        || authorities[purpose].verify(`${domain}.altered`, message, candidate)
        || authorities[purpose].verify(domain, `${message}.altered`, candidate)
        || authorities[purpose].verify(domain, message, {
          ...candidate, keyId: candidate.keyId === 'altered' ? 'other' : 'altered',
        })) throw keyError('key_challenge_failed');
    for (const other of PURPOSES) {
      if (other !== purpose && authorities[other].verify(domain, message, candidate)) {
        throw keyError('key_cross_purpose_conflict');
      }
    }
  }
}

function assertDistinctIdentities(values) {
  const fingerprints = new Set();
  const keyIds = new Set();
  for (const value of values) {
    if (fingerprints.has(value.fingerprint)) throw keyError('key_cross_purpose_conflict');
    fingerprints.add(value.fingerprint);
    if (value.keyId !== null) {
      if (keyIds.has(value.keyId)) throw keyError('key_cross_purpose_conflict');
      keyIds.add(value.keyId);
    }
  }
}

function publicEntry(value) {
  return Object.freeze({
    current: Object.freeze({
      keyId: value.current.keyId,
      fingerprint: value.current.fingerprint,
    }),
    verifyOnly: Object.freeze(value.verifyOnly.map((item) => Object.freeze({
      keyId: item.keyId,
      fingerprint: item.fingerprint,
      verifyUntil: item.verifyUntil,
    }))),
  });
}

function ownerAuthorityManifest(value) {
  const manifest = exactObject(value, RESERVED_PURPOSES, 'key_manifest_invalid');
  return Object.freeze(Object.fromEntries(RESERVED_PURPOSES.map((purpose) => {
    const record = exactObject(manifest[purpose], ['identity', 'keyId'], 'key_manifest_invalid');
    if (typeof record.identity !== 'string' || !SHA256_RE.test(record.identity)
        || typeof record.keyId !== 'string' || !KEY_ID_RE.test(record.keyId)
        || !validPurposeKeyBinding(record.keyId, purpose, record.identity)
        || (FINGERPRINT_BOUND_OWNER_PURPOSES.has(purpose)
          && record.keyId !== `${AUTHORITY_DEFINITIONS[purpose].keyPrefix}${record.identity}`)) {
      throw keyError('key_manifest_invalid');
    }
    return [purpose, Object.freeze(record)];
  })));
}

function exactObject(value, keys, code) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) throw keyError(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const descriptor of Object.values(descriptors)) {
    if (!Object.hasOwn(descriptor, 'value') || descriptor.get || descriptor.set
        || descriptor.enumerable !== true) throw keyError(code);
  }
  return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
    key, descriptor.value,
  ]));
}

function decodeKey(value) {
  if (typeof value !== 'string' || value.length !== 44 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw keyError('key_manifest_invalid');
  }
  const key = Buffer.from(value, 'base64');
  if (key.length !== KEY_BYTES || key.toString('base64') !== value) throw keyError('key_manifest_invalid');
  return key;
}

function checkedNow(value) {
  const now = value === undefined ? Date.now : value;
  if (typeof now !== 'function') throw keyError('key_manifest_invalid');
  const probe = now();
  if (!Number.isSafeInteger(probe) || probe < 0) throw keyError('key_manifest_invalid');
  return now;
}

function checkedHorizon(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 366 * 24 * 60 * 60 * 1000) {
    throw keyError('key_manifest_invalid');
  }
  return value;
}

function checkedDomainMessage(domain, message) {
  if (typeof domain !== 'string' || domain.length < 8 || domain.length > 256
      || typeof message !== 'string' || Buffer.byteLength(message, 'utf8') > 1024 * 1024) {
    throw keyError('key_input_invalid');
  }
}

function canonicalIso(value) {
  if (typeof value !== 'string') throw keyError('key_manifest_invalid');
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw keyError('key_manifest_invalid');
  }
  return value;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function keyError(code) {
  const error = new Error(FACTORY_ERROR);
  error.code = code;
  return error;
}

module.exports = {
  CHANNEL_CREDENTIAL_PURPOSES,
  DIAGNOSTIC_KEY_ENVIRONMENT,
  PURPOSES,
  RESERVED_PURPOSES,
  createVendorDiagnosticKeyFactory,
};
