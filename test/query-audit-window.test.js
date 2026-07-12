'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const source = (relative) => fs.readFileSync(path.join(ROOT, relative), 'utf8');

test('query audit response reports the bounded global search window', () => {
  const app = source('server/app.js');
  const route = app.slice(app.indexOf("const AUDIT_QUERY_SCAN_LIMIT = 2000"), app.indexOf("// Safe-to-send receipt verification"));

  assert.match(route, /db\.listAudit\(queryId \? AUDIT_QUERY_SCAN_LIMIT : resultLimit\)/);
  assert.match(route, /scanned\.filter\(\(entry\) => entry\.queryId === queryId\)/);
  assert.match(route, /const integrity = db\.verifyAuditChain\(\)/);
  assert.match(route, /totalEntries = integrity\.count/);
  assert.match(route, /complete: integrity\.ok === true && scannedEntries === totalEntries/);
  assert.match(route, /scanned\.length/);
  assert.match(route, /matched\.length/);
  assert.match(route, /entries\.length/);
});

test('query audit decoder rejects contradictory completeness and count metadata', () => {
  const audit = source('console/src/api/audit.ts');

  assert.match(audit, /total !== integrity\.count/);
  assert.match(audit, /integrity\.ok && scanned > total/);
  assert.match(audit, /matched > scanned/);
  assert.match(audit, /returned > matched/);
  assert.match(audit, /returned !== returnedEntries/);
  assert.match(audit, /const complete = integrity\.ok && scanned === total/);
  assert.match(audit, /row\.complete !== complete/);
  assert.match(audit, /decodeAuditLog\([\s\S]*?'query'/);
});

test('queue copy never turns an incomplete empty window into an all-time empty claim', () => {
  const detail = source('console/src/components/queue/QueueDetail.tsx');

  assert.match(detail, /history\.window\.complete/);
  assert.match(detail, /complete retained audit set has no entries for this incident/);
  assert.match(detail, /No entries were found in the verified recent window; older entries may exist/);
  assert.match(detail, /matching entries from the verified recent window; older entries may exist/);
  assert.doesNotMatch(detail, /No entries were recorded for this incident/);
});
