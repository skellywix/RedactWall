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
