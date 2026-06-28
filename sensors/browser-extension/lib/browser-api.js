/* PromptWall WebExtension API bridge.
 * Normalizes Chrome's callback namespace and Firefox's promise namespace for
 * the small API surface the extension uses.
 */
(function () {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : self;
  const promiseNamespace = !root.chrome && !!root.browser;
  const api = root.chrome || root.browser;
  if (!api) return;
  if (!root.chrome) root.chrome = api;

  function lastError() {
    return api.runtime && api.runtime.lastError ? api.runtime.lastError : null;
  }

  function promiseOrCallback(invoke) {
    return new Promise((resolve) => {
      let settled = false;
      function done(value) {
        if (settled) return;
        settled = true;
        resolve(value || null);
      }
      try {
        const result = invoke(done);
        if (result && typeof result.then === 'function') {
          result.then(done).catch(() => done(null));
        } else if (result !== undefined) {
          done(result);
        }
      } catch (_) {
        done(null);
      }
    });
  }

  function storageArea(name) {
    return api.storage && api.storage[name];
  }

  root.PWBrowserApi = {
    api,
    lastError,
    sendMessage(message) {
      if (promiseNamespace) {
        return api.runtime.sendMessage(message).catch(() => null);
      }
      return promiseOrCallback((done) => (
        api.runtime && api.runtime.sendMessage
          ? api.runtime.sendMessage(message, (res) => done(lastError() ? null : res))
          : null
      ));
    },
    storageGet(area, keys) {
      const store = storageArea(area);
      if (promiseNamespace) return store && store.get ? store.get(keys).catch(() => null) : Promise.resolve(null);
      return promiseOrCallback((done) => (store && store.get ? store.get(keys, done) : null));
    },
    storageSet(area, value) {
      const store = storageArea(area);
      if (promiseNamespace) return store && store.set ? store.set(value).catch(() => null) : Promise.resolve(null);
      return promiseOrCallback((done) => (store && store.set ? store.set(value, done) : null));
    },
    addRuntimeMessageListener(listener) {
      if (api.runtime && api.runtime.onMessage) api.runtime.onMessage.addListener(listener);
    },
    addStorageChangeListener(listener) {
      if (api.storage && api.storage.onChanged) api.storage.onChanged.addListener(listener);
    },
  };
})();
