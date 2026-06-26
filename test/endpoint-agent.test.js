'use strict';
/** Endpoint file sensor must route real file content through /scan-file. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanFile } = require('../endpoint-agent/agent');

test('sends supported file bytes to scan-file API instead of redacted gate preview', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ps-agent-'));
  const filename = 'loan.txt';
  const raw = 'Loan file. SSN 524-71-9043. Card 4111 1111 1111 1111.';
  fs.writeFileSync(path.join(dir, filename), raw);

  let request;
  let gateCalled = false;
  const res = await scanFile(filename, {
    watchDir: dir,
    user: 'unit-user',
    scanFileApi: async (req) => {
      request = req;
      return { decision: 'block', mode: 'block', id: 'q_test', findings: [{ type: 'US_SSN' }], categories: [], riskScore: 74 };
    },
    report: async () => { gateCalled = true; },
  });

  assert.strictEqual(res.decision, 'block');
  assert.strictEqual(gateCalled, false);
  assert.strictEqual(request.filename, filename);
  assert.strictEqual(Buffer.from(request.contentBase64, 'base64').toString('utf8'), raw);
  assert.ok(!request.contentBase64.includes('[US_SSN]'));

  fs.rmSync(dir, { recursive: true, force: true });
});
