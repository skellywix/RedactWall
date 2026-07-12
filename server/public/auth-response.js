(function installBoundedAuthResponseReader(global) {
  'use strict';

  const DEFAULT_MAX_BYTES = 16 * 1024;
  const DEFAULT_TIMEOUT_MS = 2_000;

  function cancelBody(response) {
    try { void response.body?.cancel().catch(() => undefined); } catch {}
  }

  function declaredLength(response) {
    const raw = response.headers.get('content-length');
    if (raw === null) return null;
    if (!/^\d+$/.test(raw)) return 'invalid';
    const value = Number(raw);
    return Number.isSafeInteger(value) ? value : 'invalid';
  }

  async function collect(reader, maxBytes, timeoutMs) {
    const chunks = [];
    let total = 0;
    let timer = 0;
    const timeout = new Promise((resolve) => { timer = global.setTimeout(() => resolve(null), timeoutMs); });
    try {
      for (;;) {
        const part = await Promise.race([reader.read(), timeout]);
        if (part === null) return null;
        if (part.done) break;
        total += part.value?.byteLength || 0;
        if (total > maxBytes) return null;
        if (part.value) chunks.push(part.value);
      }
    } catch {
      return null;
    } finally {
      global.clearTimeout(timer);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  }

  async function readJson(response, maxBytes = DEFAULT_MAX_BYTES, timeoutMs = DEFAULT_TIMEOUT_MS) {
    if (!response || response.bodyUsed || !Number.isSafeInteger(maxBytes) || maxBytes <= 0) return null;
    const media = String(response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
    const length = declaredLength(response);
    if ((media !== 'application/json' && !media.endsWith('+json')) || length === 'invalid' || (length !== null && length > maxBytes)) {
      cancelBody(response);
      return null;
    }
    const reader = response.body?.getReader();
    if (!reader) return null;
    const bytes = await collect(reader, maxBytes, timeoutMs);
    if (!bytes?.byteLength) {
      void reader.cancel().catch(() => undefined);
      return null;
    }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { return null; }
  }

  global.RedactWallAuthResponse = Object.freeze({ readJson });
})(window);
