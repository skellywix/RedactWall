'use strict';
/** Persistent AI app catalog: prompt-free discovery, transparent risk scoring,
 *  and a review workflow that writes policy + catalog status together. */
const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');

// Isolate the SQLite store BEFORE requiring db.
const dbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pw-catalog-'));
process.env.SENTINEL_DB_PATH = path.join(dbDir, 'test.db');
// Close the SQLite handle before deleting: Windows cannot unlink open files.
test.after(() => {
  try { db._db.close(); } catch {}
  fs.rmSync(dbDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

const catalog = require('../server/app-catalog');
const db = require('../server/db');

test('discovery records a prompt-free sighting and creates a catalog entry', () => {
  catalog.recordSighting({ destination: 'chat.deepseek.com', source: 'browser' });
  catalog.recordSighting({ destination: 'chat.deepseek.com', source: 'browser' });
  const app = catalog.publicCatalog().find((a) => a.destination === 'chat.deepseek.com');
  assert.ok(app, 'entry created');
  assert.strictEqual(app.eventCount, 2);
  assert.strictEqual(app.sources.browser, 2);
  // No prompt/response content anywhere in the stored record.
  assert.ok(!JSON.stringify(db.getAiApp('chat.deepseek.com')).match(/prompt|content|response/i));
});

test('risk score is transparent and ranks a CN trains-on-data provider critical', () => {
  const deepseek = catalog.publicCatalog().find((a) => a.destination === 'chat.deepseek.com');
  assert.strictEqual(deepseek.riskTier, 'critical');
  assert.ok(deepseek.riskScore >= 80);
  catalog.recordSighting({ destination: 'claude.ai', source: 'gateway' });
  const claude = catalog.publicCatalog().find((a) => a.destination === 'claude.ai');
  assert.ok(claude.riskScore < deepseek.riskScore, 'an opt-in US provider scores lower than a CN trains-on-data one');
});

test('CSV import ingests plausible hosts and skips junk', () => {
  const r = catalog.importCsv('perplexity.ai\npoe.com,7\nnot a host!!!\n\n');
  assert.strictEqual(r.imported, 2);
  assert.ok(r.skipped >= 1);
  assert.ok(catalog.publicCatalog().some((a) => a.destination === 'perplexity.ai'));
  assert.ok(!catalog.publicCatalog().some((a) => a.destination.includes('!')));
});

test('manual entry can pre-sanction an internal app', () => {
  const rec = catalog.addManual({ destination: 'internal-llm.corp', appName: 'Internal LLM', sanctionedStatus: 'sanctioned' });
  assert.ok(rec);
  const app = catalog.publicCatalog().find((a) => a.destination === 'internal-llm.corp');
  assert.strictEqual(app.sanctionedStatus, 'sanctioned');
  assert.strictEqual(app.appName, 'Internal LLM');
});

test('annotating a never-sighted host creates the catalog entry (review is not dropped)', () => {
  assert.strictEqual(catalog.publicCatalog().some((a) => a.destination === 'never-seen.ai'), false);
  const rec = catalog.annotate('never-seen.ai', { sanctionedStatus: 'blocked', owner: 'sec@cu.org' });
  assert.ok(rec, 'a record is created for the reviewed host');
  const app = catalog.publicCatalog().find((a) => a.destination === 'never-seen.ai');
  assert.strictEqual(app.sanctionedStatus, 'blocked');
  assert.strictEqual(app.owner, 'sec@cu.org');
});

test('annotate sets owner/notes/status without duplicating the entry', () => {
  const before = catalog.publicCatalog().length;
  catalog.annotate('poe.com', { owner: 'security@cu.org', notes: 'personal-tier risk', sanctionedStatus: 'unsanctioned' });
  const app = catalog.publicCatalog().find((a) => a.destination === 'poe.com');
  assert.strictEqual(app.owner, 'security@cu.org');
  assert.strictEqual(app.sanctionedStatus, 'unsanctioned');
  assert.strictEqual(catalog.publicCatalog().length, before, 'no duplicate row');
});
