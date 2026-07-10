'use strict';
const crypto = require('crypto');
const policyBundle = require('../../server/policy-bundle');

try {
  const pem = policyBundle.publicKeyPem({ reload: true });
  process.stdout.write(`${crypto.createHash('sha256').update(pem).digest('hex')}\n`);
} catch (error) {
  process.stderr.write(`${error && error.stack || error}\n`);
  process.exitCode = 1;
}
