'use strict';
/** LEEF envelope must not let sensor-controlled fields inject attributes/events. */
const test = require('node:test');
const assert = require('node:assert');

const formats = require('../server/siem-formats');

test('qradar LEEF strips tab/pipe/newline from sensor-controlled fields', () => {
  const alert = {
    queryId: 'q1',
    action: 'BLOCKED',
    user: 'alice\tusrName=admin',
    destination: 'chat.example\nLEEF:2.0|RedactWall|ControlPlane|1.0|ALLOWED|',
    source: 'ext|forged',
    maxSeverity: 3,
    riskScore: 90,
    createdAt: '2026-07-06T00:00:00.000Z',
  };
  const req = formats.buildRequest(alert, { type: 'qradar', url: 'https://collector.example' });

  // Exactly one LEEF header (no injected second record) and no newline record separator.
  assert.strictEqual(req.body.match(/LEEF:2\.0\|/g).length, 1);
  assert.ok(!/[\r\n]/.test(req.body), 'no injected newline record separator');
  // Tab is the LEEF attribute delimiter: the header + its 8 attributes must be
  // exactly 9 tab-delimited segments. A leaked tab in `user` would add a 10th.
  assert.strictEqual(req.body.split('\t').length, 9, 'no extra tab-delimited attribute injected');
  // Pipe (the LEEF header delimiter) inside a value is neutralized to a space.
  assert.ok(req.body.includes('src=ext forged'), 'pipe in value neutralized');
});
