'use strict';
/**
 * CI smoke for native modules. better-sqlite3 can install successfully while
 * leaving an unusable .node binding, so verify an actual Database instance.
 */
const { spawnSync } = require('node:child_process');

function checkNativeBinding(DatabaseImpl) {
  const Database = DatabaseImpl || require('better-sqlite3');
  const db = new Database(':memory:');
  try {
    const row = db.prepare('select 1 as ok').get();
    if (!row || row.ok !== 1) {
      throw new Error('better-sqlite3 smoke query returned an unexpected result');
    }
  } finally {
    db.close();
  }
}

function errorText(err) {
  return `${err && err.message ? err.message : err}\n${err && err.stack ? err.stack : ''}`;
}

function isNativeBindingFailure(err) {
  return /better[-_]sqlite3|bindings file|\.node\b|ERR_DLOPEN|NODE_MODULE_VERSION|module did not self-register|invalid ELF|was compiled against/i
    .test(errorText(err));
}

function npmCommand() {
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function rebuildNativeBinding(deps = {}) {
  const spawn = deps.spawnSync || spawnSync;
  const npm = deps.npmCommand || npmCommand;
  return spawn(npm(), ['rebuild', 'better-sqlite3'], {
    stdio: 'inherit',
    windowsHide: true,
  });
}

function main(argv = process.argv.slice(2), deps = {}) {
  const check = deps.checkNativeBinding || checkNativeBinding;
  const rebuild = deps.rebuildNativeBinding || rebuildNativeBinding;
  const io = deps.console || console;
  const repair = argv.includes('--repair');
  try {
    check();
    io.log('[native] better-sqlite3 binding ok');
    return 0;
  } catch (err) {
    io.error(`[native] better-sqlite3 binding check failed: ${err && err.message ? err.message : err}`);
    if (!repair || !isNativeBindingFailure(err)) {
      io.error('[native] Run npm rebuild better-sqlite3, then rerun npm run native:check.');
      return 1;
    }
  }

  io.warn('[native] retrying better-sqlite3 native install via npm rebuild');
  const rebuilt = rebuild();
  if (rebuilt.status !== 0) return rebuilt.status || 1;

  try {
    check();
    io.log('[native] better-sqlite3 binding ok after rebuild');
    return 0;
  } catch (err) {
    io.error(`[native] better-sqlite3 binding still fails after rebuild: ${err && err.message ? err.message : err}`);
    return 1;
  }
}

if (require.main === module) process.exitCode = main();

module.exports = {
  checkNativeBinding,
  isNativeBindingFailure,
  main,
  npmCommand,
  rebuildNativeBinding,
};
