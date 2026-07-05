'use strict';
/**
 * Disposable extraction child. Runs attacker-controlled file parsing away from
 * the web process so the parent can SIGKILL a wedged or oversized parse
 * without taking down auth, approvals, or live streams. Spawned only by
 * server/parse-pool.js over an IPC channel with advanced serialization.
 */
const processors = require('./processors');

const FAILED = { text: '', processor: null, supported: true, extractionOk: false, error: 'extract_failed' };

function toBuffer(content) {
  if (Buffer.isBuffer(content)) return content;
  if (content instanceof Uint8Array) return Buffer.from(content.buffer, content.byteOffset, content.byteLength);
  return Buffer.from(String(content || ''), 'utf8');
}

process.on('message', async (msg) => {
  if (!msg || msg.type !== 'extract') return;
  let result;
  try {
    result = await processors.extractText(msg.name, toBuffer(msg.buf), msg.opts || {});
  } catch {
    result = { ...FAILED };
  }
  try { process.send({ type: 'result', id: msg.id, result }); } catch {}
});

process.on('disconnect', () => process.exit(0));
