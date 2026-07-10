'use strict';

const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_TIMEOUT_MS = 10000;

function boundedPositive(value, fallback, min = 1, max = 32 * 1024 * 1024) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function headerValue(headers, name) {
  if (!headers) return '';
  if (typeof headers.get === 'function') return String(headers.get(name) || '');
  const wanted = String(name || '').toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (String(key).toLowerCase() === wanted) return String(value || '');
  }
  return '';
}

function declaredLength(response) {
  const raw = headerValue(response && response.headers, 'content-length').trim();
  if (!/^\d+$/.test(raw)) return null;
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

function bodyError(label, suffix) {
  const err = new Error(`${label} ${suffix}`);
  err.code = suffix === 'timed out' ? 'REDACTWALL_RESPONSE_TIMEOUT' : 'REDACTWALL_RESPONSE_TOO_LARGE';
  return err;
}

async function cancelReader(reader) {
  if (!reader || typeof reader.cancel !== 'function') return;
  try { await reader.cancel(); } catch { /* best effort */ }
}

async function cancelBody(response) {
  const body = response && response.body;
  try {
    if (body && typeof body.cancel === 'function') await body.cancel();
    else if (body && typeof body.destroy === 'function') body.destroy();
    else if (body && typeof body.return === 'function') await body.return();
  } catch { /* best effort */ }
}

async function cancelResponseBody(response) {
  await cancelBody(response);
}

async function readWebStream(stream, limit, label, state) {
  const reader = stream.getReader();
  state.cancel = () => cancelReader(reader);
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value || []);
      total += chunk.length;
      if (total > limit) {
        await cancelReader(reader);
        throw bodyError(label, `exceeds ${limit} byte limit`);
      }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks, total);
  } finally {
    try { if (typeof reader.releaseLock === 'function') reader.releaseLock(); } catch { /* best effort */ }
  }
}

async function readAsyncIterable(stream, limit, label, state) {
  state.cancel = async () => {
    if (typeof stream.destroy === 'function') stream.destroy();
    else if (typeof stream.return === 'function') await stream.return();
  };
  const chunks = [];
  let total = 0;
  for await (const value of stream) {
    const chunk = Buffer.from(value || []);
    total += chunk.length;
    if (total > limit) {
      if (typeof stream.destroy === 'function') stream.destroy();
      throw bodyError(label, `exceeds ${limit} byte limit`);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

function streamRead(response, limit, label, state) {
  const stream = response && response.body;
  if (stream && typeof stream.getReader === 'function') return readWebStream(stream, limit, label, state);
  if (stream && typeof stream[Symbol.asyncIterator] === 'function') return readAsyncIterable(stream, limit, label, state);
  const err = new Error(`${label} does not expose a bounded response stream`);
  err.code = 'REDACTWALL_RESPONSE_UNSTREAMABLE';
  throw err;
}

async function withReadTimeout(read, state, timeoutMs, label) {
  let timer;
  const timeout = new Promise((resolve, reject) => {
    timer = setTimeout(() => {
      void state.cancel();
      reject(bodyError(label, 'timed out'));
    }, timeoutMs);
  });
  try {
    return await Promise.race([read, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function readBoundedBuffer(response, opts = {}) {
  const limit = boundedPositive(opts.maxBytes, DEFAULT_MAX_BYTES);
  const timeoutMs = boundedPositive(opts.timeoutMs, DEFAULT_TIMEOUT_MS, 1, 10 * 60 * 1000);
  const label = String(opts.label || 'response').replace(/[\r\n]+/g, ' ').slice(0, 80);
  const announced = declaredLength(response);
  if (announced != null && announced > limit) {
    await cancelBody(response);
    throw bodyError(label, `exceeds ${limit} byte limit`);
  }

  const state = { cancel: async () => {} };
  return withReadTimeout(streamRead(response, limit, label, state), state, timeoutMs, label);
}

async function readBoundedText(response, opts = {}) {
  const body = await readBoundedBuffer(response, opts);
  return { text: body.toString(opts.encoding || 'utf8'), sizeBytes: body.length };
}

async function readBoundedJson(response, opts = {}) {
  const body = await readBoundedText(response, opts);
  try {
    return { json: body.text ? JSON.parse(body.text) : null, ...body };
  } catch {
    const err = new Error(`${String(opts.label || 'response')} contains invalid JSON`);
    err.code = 'REDACTWALL_RESPONSE_INVALID_JSON';
    throw err;
  }
}

module.exports = {
  cancelResponseBody,
  declaredLength,
  headerValue,
  readBoundedBuffer,
  readBoundedJson,
  readBoundedText,
};
