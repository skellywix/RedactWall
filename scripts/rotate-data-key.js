'use strict';
/**
 * Re-encrypt sealed at-rest blobs (retained raw prompts and token vaults in
 * query records) under a new data key.
 *
 * Operator flow:
 *   1. Set REDACTWALL_DATA_KEY=<new key> and REDACTWALL_DATA_KEY_PREVIOUS=<old key>.
 *   2. Run `node scripts/rotate-data-key.js` (add --dry-run to preview).
 *   3. When the run reports `unreadable: 0`, unset REDACTWALL_DATA_KEY_PREVIOUS.
 *
 * Output is counts only — this tool NEVER prints prompt plaintext, sealed
 * tokens, or key material. Exits 1 if any sealed value is unreadable with both
 * keys (evidence at risk; do not retire the old key until investigated).
 */
require('../server/env').loadEnv();
const dataCrypto = require('../server/crypto');

const SEALED_FIELDS = ['_rawPrompt', '_tokenVault'];

function parseArgs(argv) {
  const out = { _: [] };
  for (const arg of argv) {
    if (arg === '--dry-run') out.dryRun = true;
    else out._.push(arg);
  }
  return out;
}

/**
 * Reseal one stored value under the current key. Returns the replacement
 * token, or undefined when nothing needs writing (plaintext row, already on
 * the current key, or unreadable — the latter is counted, not rewritten).
 */
function resealToken(token, counts) {
  if (!dataCrypto.isSealed(token)) return undefined;
  const plaintext = dataCrypto.open(token);
  if (plaintext === null) {
    counts.unreadable++;
    return undefined;
  }
  if (!dataCrypto.needsReseal(token)) return undefined;
  counts.resealed++;
  return dataCrypto.seal(plaintext);
}

function resealPatch(record, counts) {
  const patch = {};
  for (const field of SEALED_FIELDS) {
    const resealed = resealToken(record[field], counts);
    if (resealed !== undefined) patch[field] = resealed;
  }
  return patch;
}

function rotateRecord(store, record, counts, dryRun) {
  if (dryRun) return resealPatch(record, counts);
  if (typeof store.mutateQueryWithAudit !== 'function') {
    throw new Error('query mutation with audit is unavailable');
  }
  let resealedFields = 0;
  const result = store.mutateQueryWithAudit(record.id, (current) => {
    const patch = resealPatch(current, counts);
    resealedFields = Object.keys(patch).length;
    return resealedFields ? patch : null;
  }, () => ({
    action: 'DATA_KEY_RESEALED',
    actor: 'operator',
    detail: JSON.stringify({ resealedFields }),
  }));
  if (result.outcome === 'not_found') throw new Error('query disappeared during data-key rotation');
  return result;
}

/**
 * Walk every query record and reseal previous-key tokens under the current
 * key. Counts: scanned = records inspected, resealed/unreadable = tokens.
 */
function rotateDataKey({ db, dryRun = false } = {}) {
  const store = db || require('../server/db');
  const counts = { scanned: 0, resealed: 0, unreadable: 0 };
  for (const record of store.listQueries({ all: true })) {
    counts.scanned++;
    rotateRecord(store, record, counts, dryRun);
  }
  return counts;
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const rotate = deps.rotateDataKey || rotateDataKey;
  const cryptoModule = deps.dataCrypto || dataCrypto;
  const args = parseArgs(argv);
  const status = cryptoModule.rotationStatus();
  if (!status.enabled) throw new Error('data encryption is not enabled; set REDACTWALL_DATA_KEY to the new key first');
  if (!status.previousKeyConfigured) throw new Error('set REDACTWALL_DATA_KEY_PREVIOUS to the old key before rotating');
  const db = deps.db || require('../server/db');
  const dryRun = !!args.dryRun;
  const counts = rotate({ db, dryRun });
  if (!dryRun && counts.resealed > 0) {
    db.appendAudit({ action: 'DATA_KEY_ROTATED', actor: 'operator', detail: JSON.stringify(counts) });
  }
  const result = { ok: counts.unreadable === 0, dryRun, ...counts };
  io.log(JSON.stringify(result, null, 2));
  return result;
}

if (require.main === module) {
  main()
    .then((result) => { if (!result.ok) process.exit(1); })
    .catch((e) => { console.error(e.message); process.exit(1); });
}

module.exports = { parseArgs, rotateDataKey, main };
