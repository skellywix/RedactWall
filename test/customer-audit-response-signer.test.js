'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const serverRoot = path.join(__dirname, '..', 'server');

function localDependencyClosure(entry) {
  const pending = [entry];
  const seen = new Set();
  while (pending.length > 0) {
    const file = pending.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(/require\(['"](\.\.?\/[^'"]+)['"]\)/g)) {
      const resolved = path.resolve(path.dirname(file), `${match[1]}.js`);
      if (resolved.startsWith(`${serverRoot}${path.sep}`) && fs.existsSync(resolved)) {
        pending.push(resolved);
      }
    }
  }
  return [...seen].sort();
}

test('customer response signer dependency closure excludes the vendor key registry', () => {
  const entry = path.join(serverRoot, 'customer-audit-response-signer.js');
  const closure = localDependencyClosure(entry);
  const names = closure.map((file) => path.basename(file));
  assert.ok(!names.includes('customer-audit-response.js'));

  const source = closure.map((file) => fs.readFileSync(file, 'utf8')).join('\n');
  assert.doesNotMatch(source, /createCustomerAuditResponseKeyRegistry/);
  assert.doesNotMatch(source, /customer_audit_response_registry/);
  assert.doesNotMatch(source, /better-sqlite3|monotonic-anchor-authority/);

  assert.deepEqual(
    Object.keys(require('../server/customer-audit-response-signer')).sort(),
    [
      'CUSTOMER_AUDIT_RESPONSE_SIGNATURE_DOMAIN',
      'assertCustomerAuditResponsePayload',
      'createCustomerAuditResponseSigner',
      'customerAuditResponseSigningInput',
      'isCustomerAuditResponseSigner',
    ],
  );
});
