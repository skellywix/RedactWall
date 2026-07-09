'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const sp = require('../server/security-package');

const PKG = { packageInfo: { name: 'redactwall', version: '0.4.0' } };

test('every control carries an assurance level; nothing is third-party-verified', () => {
  const pkg = sp.trustPackage(PKG);
  assert.ok(Array.isArray(pkg.controls) && pkg.controls.length);
  for (const c of pkg.controls) {
    assert.ok(['self-attested', 'ci-verified', 'third-party-verified'].includes(c.assurance), `${c.id} assurance value`);
    assert.notStrictEqual(c.assurance, 'third-party-verified', `${c.id} must not claim third-party-verified`);
  }
  assert.strictEqual(pkg.controls.find((c) => c.id === 'audit_chain').assurance, 'ci-verified');
});

test('trust package includes an NCUA-mapped due-diligence questionnaire', () => {
  const pkg = sp.trustPackage(PKG);
  assert.ok(Array.isArray(pkg.dueDiligence) && pkg.dueDiligence.length >= 6);
  for (const d of pkg.dueDiligence) {
    assert.strictEqual(typeof d.dimension, 'string');
    assert.match(d.ncuaReference, /NCUA|GLBA|FFIEC/);
    assert.ok(Array.isArray(d.evidence) && d.evidence.length >= 1, `${d.dimension} cites evidence`);
  }
  const independent = pkg.dueDiligence.find((d) => /Independent assurance/i.test(d.dimension));
  assert.match(independent.response, /self-attested|no third-party/i);
});

test('legal templates are labeled non-binding and the sample files exist', () => {
  const pkg = sp.trustPackage(PKG);
  assert.match(pkg.legalTemplates.note, /non-binding/i);
  assert.strictEqual(pkg.legalTemplates.templates.length, 3);
  for (const t of pkg.legalTemplates.templates) {
    const abs = path.join(__dirname, '..', t.path);
    assert.ok(fs.existsSync(abs), `${t.path} exists on disk`);
    assert.match(fs.readFileSync(abs, 'utf8'), /SAMPLE\s*[—-]{1,2}\s*NON-BINDING/i, `${t.path} labeled non-binding`);
  }
});
