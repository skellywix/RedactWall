'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { systemBootClock } = require('../server/system-boot-clock');

test('operating-system boot identity is process-stable while monotonic time advances', () => {
  const first = systemBootClock();
  const second = systemBootClock();
  assert.match(first.bootId, /^[a-f0-9]{32}$/);
  assert.equal(second.bootId, first.bootId);
  assert.equal(Number.isSafeInteger(first.nowMs), true);
  assert.equal(second.nowMs >= first.nowMs, true);
});
