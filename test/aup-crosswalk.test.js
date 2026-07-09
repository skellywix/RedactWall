'use strict';

const test = require('node:test');
const assert = require('node:assert');
const aup = require('../server/aup-crosswalk');
const controlMap = require('../server/control-map');

const GOVERNED_POLICY = { governedDestinations: ['claude.ai'], blockUnapprovedAiDestinations: true };
const ATTESTATION = { adoptedAt: '2026-07-01T00:00:00.000Z', reference: 'Board minutes 2026-Q2' };

test('AUP crosswalk maps each clause to enforcing controls', () => {
  assert.ok(Array.isArray(aup.AUP_CROSSWALK) && aup.AUP_CROSSWALK.length >= 5);
  for (const c of aup.AUP_CROSSWALK) {
    assert.strictEqual(typeof c.id, 'string');
    assert.strictEqual(typeof c.clause, 'string');
    assert.ok(Array.isArray(c.enforcedBy) && c.enforcedBy.length >= 1, `${c.id} names an enforcing control`);
  }
  // Every enforcing control referenced must exist in the control map (no dangling ids).
  const controlIds = new Set(controlMap.CONTROL_MAPPINGS.map((m) => m.id));
  for (const c of aup.AUP_CROSSWALK) {
    for (const id of c.enforcedBy) assert.ok(controlIds.has(id), `${c.id} -> unknown control ${id}`);
  }
});

test('AUP attestation normalizer keeps only a bounded date + reference', () => {
  const ok = aup.normalizeAupAttestation(ATTESTATION);
  assert.strictEqual(ok.adoptedAt, ATTESTATION.adoptedAt);
  assert.strictEqual(ok.reference, ATTESTATION.reference);
  assert.strictEqual(aup.normalizeAupAttestation({ adoptedAt: 'not-a-date' }), null);
  assert.strictEqual(aup.normalizeAupAttestation(null), null);
  // Reference is bounded to 120 chars.
  const long = aup.normalizeAupAttestation({ adoptedAt: ATTESTATION.adoptedAt, reference: 'x'.repeat(500) });
  assert.strictEqual(long.reference.length, 120);
});

test('ai_acceptable_use control reflects enforcement AND attestation honestly', () => {
  const stateFor = (input) => controlMap.buildControlMappings(input).find((c) => c.id === 'ai_acceptable_use').state;

  // No policy attached -> not_provided.
  assert.strictEqual(stateFor({ generatedAt: 'now' }), 'not_provided');

  // Enforced by policy but board adoption not attested -> attention (honest: enforced, not attested).
  assert.strictEqual(stateFor({ generatedAt: 'now', policy: GOVERNED_POLICY }), 'attention');

  // Attested but enforcing control not configured -> attention.
  assert.strictEqual(stateFor({ generatedAt: 'now', policy: {}, aupAttestation: ATTESTATION }), 'attention');

  // Enforced AND attested -> covered.
  assert.strictEqual(stateFor({ generatedAt: 'now', policy: GOVERNED_POLICY, aupAttestation: ATTESTATION }), 'covered');
});
