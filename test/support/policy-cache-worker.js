'use strict';
const fs = require('node:fs');
const signedPolicy = require('../../sensors/shared/signed-policy');

const [, , bundleFile, publicKeyPath, cachePath] = process.argv;
try {
  const bundle = JSON.parse(fs.readFileSync(bundleFile, 'utf8'));
  const result = signedPolicy.acceptSignedPolicyBundle(bundle, {
    policyPublicKeyPath: publicKeyPath,
    policyCachePath: cachePath,
    sensorId: 'process-race',
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error && error.message || 'policy cache worker failed'}\n`);
  process.exitCode = 1;
}
