'use strict';
/** Native addon checks should fail early with an actionable CI error. */
const test = require('node:test');
const assert = require('node:assert');
const {
  checkNativeBinding,
  isNativeBindingFailure,
  main,
  npmCommand,
  rebuildNativeBinding,
} = require('../scripts/ensure-native-bindings');

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(['log', message]); },
    warn(message) { lines.push(['warn', message]); },
    error(message) { lines.push(['error', message]); },
  };
}

test('better-sqlite3 native binding can construct a database', () => {
  assert.doesNotThrow(() => checkNativeBinding());
});

test('native binding failure classifier recognizes missing binding errors', () => {
  assert.strictEqual(isNativeBindingFailure(new Error('Could not locate the bindings file for better_sqlite3.node')), true);
  assert.strictEqual(isNativeBindingFailure(new Error('ordinary validation error')), false);
});

test('native binding smoke fails when the query returns an unexpected row', () => {
  let closed = false;
  class FakeDatabase {
    prepare() {
      return { get: () => ({ ok: 0 }) };
    }

    close() {
      closed = true;
    }
  }

  assert.throws(
    () => checkNativeBinding(FakeDatabase),
    /unexpected result/
  );
  assert.strictEqual(closed, true);
});

test('native binding rebuild invokes npm rebuild without opening a window', () => {
  let call;
  const result = rebuildNativeBinding({
    npmCommand: () => 'npm-test',
    spawnSync: (file, args, opts) => {
      call = { file, args, opts };
      return { status: 0 };
    },
  });

  assert.deepStrictEqual(result, { status: 0 });
  assert.deepStrictEqual(call, {
    file: 'npm-test',
    args: ['rebuild', 'better-sqlite3'],
    opts: { stdio: 'inherit', windowsHide: true },
  });
});

test('native binding CLI exits cleanly when the smoke query succeeds', () => {
  const io = captureConsole();
  const code = main([], {
    checkNativeBinding() {},
    console: io,
  });

  assert.strictEqual(code, 0);
  assert.ok(io.lines.some(([, message]) => message.includes('binding ok')));
});

test('native binding CLI gives repair guidance for non-repairable failures', () => {
  const io = captureConsole();
  const code = main([], {
    checkNativeBinding() { throw new Error('ordinary validation error'); },
    console: io,
  });

  assert.strictEqual(code, 1);
  assert.ok(io.lines.some(([, message]) => message.includes('npm rebuild better-sqlite3')));
});

test('native binding repair retries rebuild and rechecks the binding', () => {
  const io = captureConsole();
  let checks = 0;
  const code = main(['--repair'], {
    checkNativeBinding() {
      checks += 1;
      if (checks === 1) throw new Error('Could not locate the bindings file for better_sqlite3.node');
    },
    rebuildNativeBinding() { return { status: 0 }; },
    console: io,
  });

  assert.strictEqual(code, 0);
  assert.strictEqual(checks, 2);
  assert.ok(io.lines.some(([level, message]) => level === 'warn' && message.includes('retrying')));
});

test('native binding repair reports rebuild and post-rebuild failures', () => {
  const io = captureConsole();
  const brokenBinding = () => { throw new Error('invalid ELF header for better_sqlite3.node'); };

  assert.strictEqual(main(['--repair'], {
    checkNativeBinding: brokenBinding,
    rebuildNativeBinding() { return { status: 7 }; },
    console: io,
  }), 7);

  assert.strictEqual(main(['--repair'], {
    checkNativeBinding: brokenBinding,
    rebuildNativeBinding() { return { status: 0 }; },
    console: io,
  }), 1);
  assert.ok(io.lines.some(([, message]) => message.includes('still fails after rebuild')));
});

test('native binding CLI chooses the platform npm executable', () => {
  assert.ok(['npm', 'npm.cmd'].includes(npmCommand()));
});
