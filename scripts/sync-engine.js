'use strict';
/** Copy the canonical shared modules into the extension. Single source of truth. */
const fs = require('fs');
const path = require('path');
const root = path.join(__dirname, '..');
const FILES = [['detection-engine/detect.js', 'sensors/browser-extension/lib/detect.js'], ['detection-engine/adapters.js', 'sensors/browser-extension/lib/adapters.js']];
for (const [src, dst] of FILES) {
  fs.copyFileSync(path.join(root, src), path.join(root, dst));
  console.log('synced ' + dst + ' from ' + src);
}
