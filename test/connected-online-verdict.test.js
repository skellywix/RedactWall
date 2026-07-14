'use strict';

const crypto = require('node:crypto');
const test = require('node:test');
const assert = require('node:assert/strict');
const verdict = require('../server/connected-online-verdict');

const CUSTOMER_ID = 'customer_alpha';
const DEPLOYMENT_ID = 'dep_0123456789abcdef0123456789abcdef';
const current = crypto.generateKeyPairSync('ed25519');
const next = crypto.generateKeyPairSync('ed25519');
const other = crypto.generateKeyPairSync('ed25519');
const CURRENT_ID = verdict.keyIdForPublicKey(current.publicKey);
const NEXT_ID = verdict.keyIdForPublicKey(next.publicKey);

function payload(overrides = {}) {
  return {
    kind: verdict.VERDICT_DOMAIN,
    keyId: CURRENT_ID,
    status: 'active',
    customerId: CUSTOMER_ID,
    deploymentId: DEPLOYMENT_ID,
    issuedAt: '2026-07-13T12:00:00.000Z',
    registryGeneration: 9,
    registryStateDigest: '9'.repeat(64),
    ...overrides,
  };
}

function sign(value = payload(), privateKey = current.privateKey, domain = verdict.VERDICT_DOMAIN) {
  const payloadB64 = Buffer.from(JSON.stringify(value), 'utf8').toString('base64');
  const signature = crypto.sign(
    null, Buffer.from(`${domain}\0${payloadB64}`, 'utf8'), privateKey,
  ).toString('base64');
  return `${payloadB64}.${signature}`;
}

function expectCode(callback, expected) {
  assert.throws(callback, (error) => error && error.code === expected);
}

test('v2 verifier binds canonical payload, SPKI key ID, signature, and deployment scope', () => {
  const verified = verdict.verifySignedOnlineVerdict(
    sign(), new Map([[CURRENT_ID, current.publicKey], [NEXT_ID, next.publicKey]]),
  );
  assert.deepEqual(verified.payload, payload());
  assert.equal(verified.signingKeyId, CURRENT_ID);
  assert.equal(verified.signingKeyFingerprint, verdict.keyFingerprint(current.publicKey));
  assert.equal(verified.signatureDomain, verdict.VERDICT_DOMAIN);
  assert.match(verified.signedEnvelopeDigest, /^[a-f0-9]{64}$/);
});

test('current and next are the only accepted fresh identities', () => {
  const nextPayload = payload({ keyId: NEXT_ID, registryGeneration: 10,
    registryStateDigest: 'a'.repeat(64) });
  assert.equal(verdict.verifySignedOnlineVerdict(
    sign(nextPayload, next.privateKey), { [CURRENT_ID]: current.publicKey, [NEXT_ID]: next.publicKey },
  ).payload.keyId, NEXT_ID);

  const otherId = verdict.keyIdForPublicKey(other.publicKey);
  const otherPayload = payload({ keyId: otherId });
  expectCode(
    () => verdict.verifySignedOnlineVerdict(
      sign(otherPayload, other.privateKey), new Map([[CURRENT_ID, current.publicKey]]),
    ),
    'registry_signing_key_unknown',
  );
});

test('wrong signature, wrong domain, payload mutation, and noncanonical JSON fail closed', () => {
  expectCode(
    () => verdict.verifySignedOnlineVerdict(
      sign(payload(), other.privateKey), { [CURRENT_ID]: current.publicKey },
    ),
    'registry_signature_invalid',
  );
  expectCode(
    () => verdict.verifySignedOnlineVerdict(
      sign(payload(), current.privateKey, 'redactwall.connected-license-verdict.v1'),
      { [CURRENT_ID]: current.publicKey },
    ),
    'registry_signature_invalid',
  );
  const [payloadB64, signature] = sign().split('.');
  const changed = { ...JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8')), status: 'revoked' };
  expectCode(
    () => verdict.verifySignedOnlineVerdict(
      `${Buffer.from(JSON.stringify(changed)).toString('base64')}.${signature}`,
      { [CURRENT_ID]: current.publicKey },
    ),
    'registry_signature_invalid',
  );
  const reordered = {
    status: 'active', kind: verdict.VERDICT_DOMAIN, keyId: CURRENT_ID,
    customerId: CUSTOMER_ID, deploymentId: DEPLOYMENT_ID,
    issuedAt: '2026-07-13T12:00:00.000Z', registryGeneration: 9,
    registryStateDigest: '9'.repeat(64),
  };
  expectCode(
    () => verdict.verifySignedOnlineVerdict(
      sign(reordered), { [CURRENT_ID]: current.publicKey },
    ),
    'registry_payload_noncanonical',
  );
});

test('keyring rejects aliases, purpose mismatch, duplicate identity, forbidden reuse, and excess keys', () => {
  expectCode(
    () => verdict.normalizeKeyring({ 'rw-online-verdict-alias': current.publicKey }),
    'registry_key_id_invalid',
  );
  expectCode(
    () => verdict.normalizeKeyring({ [NEXT_ID]: current.publicKey }),
    'registry_key_id_invalid',
  );
  expectCode(
    () => verdict.normalizeKeyring(new Map([
      [CURRENT_ID, current.publicKey],
      [NEXT_ID, current.publicKey],
    ])),
    'registry_key_id_invalid',
  );
  expectCode(
    () => verdict.normalizeKeyring({ [CURRENT_ID]: current.publicKey }, {
      forbiddenPublicKeyFingerprints: [verdict.keyFingerprint(current.publicKey)],
    }),
    'registry_key_identity_reused',
  );
  const third = crypto.generateKeyPairSync('ed25519');
  expectCode(
    () => verdict.normalizeKeyring({
      [CURRENT_ID]: current.publicKey,
      [NEXT_ID]: next.publicKey,
      [verdict.keyIdForPublicKey(third.publicKey)]: third.publicKey,
    }),
    'registry_keyring_invalid',
  );
});

test('payload key ID is signed and cannot disagree with the resolved key identity', () => {
  const nextPayload = payload({ keyId: NEXT_ID });
  expectCode(
    () => verdict.verifySignedOnlineVerdict(
      sign(nextPayload, current.privateKey),
      { [CURRENT_ID]: current.publicKey, [NEXT_ID]: next.publicKey },
    ),
    'registry_signature_invalid',
  );
  expectCode(
    () => verdict.verifySignedOnlineVerdict(
      sign(payload({ keyId: 'rw-online-verdict-2026' })),
      { [CURRENT_ID]: current.publicKey },
    ),
    'registry_payload_invalid',
  );
});

test('signed input size, base64 canonical form, and public-only Ed25519 keys are bounded', () => {
  expectCode(
    () => verdict.verifySignedOnlineVerdict('A'.repeat(verdict.MAX_SIGNED_BYTES + 1), {
      [CURRENT_ID]: current.publicKey,
    }),
    'registry_signed_verdict_invalid',
  );
  expectCode(
    () => verdict.verifySignedOnlineVerdict(`${Buffer.from('{}').toString('base64url')}.AA`, {
      [CURRENT_ID]: current.publicKey,
    }),
    'registry_signed_verdict_invalid',
  );
  expectCode(
    () => verdict.normalizeKeyring({ [CURRENT_ID]: current.privateKey }),
    'registry_public_key_invalid',
  );
  const privatePem = current.privateKey.export({ type: 'pkcs8', format: 'pem' });
  expectCode(
    () => verdict.normalizeKeyring({ [CURRENT_ID]: privatePem }),
    'registry_public_key_invalid',
  );
  const p256 = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  expectCode(
    () => verdict.normalizeKeyring({ [CURRENT_ID]: p256.publicKey }),
    'registry_public_key_invalid',
  );
});
