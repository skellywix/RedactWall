'use strict';

const test = require('node:test');
const assert = require('node:assert');
const controlMap = require('../server/control-map');

test('control map marks partial backup evidence as attention', () => {
  const mappings = controlMap.buildControlMappings({
    generatedAt: '2026-06-28T12:00:00.000Z',
    backup: { ok: true },
    restoreDrill: { ok: false },
  });
  const backup = mappings.find((item) => item.id === 'backup_recoverability');

  assert.strictEqual(backup.state, 'attention');
  assert.strictEqual(backup.summary, 'Backup or restore-drill evidence is missing or failing.');
  assert.strictEqual(backup.lastVerifiedAt, '2026-06-28T12:00:00.000Z');
});

test('control map defaults unknown controls to not provided', () => {
  assert.strictEqual(controlMap._internal.stateFor({ id: 'future_control' }, {}), 'not_provided');
});

test('control map appends FFIEC handbook labels to mapped controls only', () => {
  const mappings = controlMap.buildControlMappings({ generatedAt: '2026-07-09T00:00:00.000Z' });
  const audit = mappings.find((m) => m.id === 'tamper_evident_audit');
  assert.ok(audit.controlFamilies.some((f) => /FFIEC Audit booklet/.test(f)));
  const dlp = mappings.find((m) => m.id === 'ai_prompt_dlp');
  assert.ok(dlp.controlFamilies.some((f) => /FFIEC Information Security/.test(f)));
  // A control with no FFIEC mapping is left unchanged (no dangling FFIEC label).
  const threat = mappings.find((m) => m.id === 'prompt_threat_defense');
  assert.ok(!threat.controlFamilies.some((f) => /FFIEC/.test(f)));
});
