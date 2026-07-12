'use strict';

function createDeferred() {
  let resolvePromise;
  let released = false;
  const promise = new Promise((resolve) => {
    resolvePromise = resolve;
  });

  return {
    promise,
    release() {
      if (released) return;
      released = true;
      resolvePromise();
    },
  };
}

module.exports = { createDeferred };
