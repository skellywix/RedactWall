'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const dockerignore = fs.readFileSync(path.join(__dirname, '..', '.dockerignore'), 'utf8');

test('Docker build context excludes local secrets, backups, and database state', () => {
  for (const pattern of [
    /^backups\/$/m,
    /^\.codex\/$/m,
    /^\.playwright-cli\/$/m,
    /^sensors\/browser-extension\/_metadata\/$/m,
    /^\.env\.\*$/m,
    /^\*\*\/\*\.db$/m,
    /^\*\*\/\*\.db-\*$/m,
    /^\*\*\/\*\.sqlite$/m,
    /^\*\*\/\*\.sqlite3$/m,
    /^\*\*\/\*\.pem$/m,
    /^\*\*\/\*\.key$/m,
    /^\*\*\/\*\.p12$/m,
    /^\*\*\/\*\.pfx$/m,
  ]) {
    assert.match(dockerignore, pattern);
  }
  assert.match(dockerignore, /^!\.env\.example$/m, '.env.example remains available as a safe template');
  assert.ok(
    dockerignore.indexOf('!.env.example') > dockerignore.indexOf('.env.*'),
    'the allow rule must follow the broad local-env exclusion',
  );
});
