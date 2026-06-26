'use strict';
/** CI guard: fail if any extension engine copy has drifted from its source. */
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const FILES = [['shared/detect.js', 'extension/lib/detect.js'], ['shared/adapters.js', 'extension/lib/adapters.js']];
let drift = false;
for (const [src, dst] of FILES) {
  if (!fs.readFileSync(path.join(root, src)).equals(fs.readFileSync(path.join(root, dst)))) {
    console.error('ENGINE DRIFT: ' + dst + ' differs from ' + src + '. Run: npm run sync-engine');
    drift = true;
  }
}
if (drift) process.exit(1);
console.log('engine copies identical');
