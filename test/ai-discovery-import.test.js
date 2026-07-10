'use strict';
/** Discovery importer should sanitize vendor exports before control-plane ingest. */
const test = require('node:test');
const assert = require('node:assert');
const importer = require('../scripts/import-ai-discovery');

function jsonResponse(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('discovery importer parses CSV, strips URL paths, and aggregates observations', () => {
  const csv = [
    'User,Request URL,Requests,Last Seen,Category,Confidence',
    'ops@example.test,"https://chatgpt.com/c/member-case?token=abc",3,2026-07-03T10:00:00Z,Chat,90',
    'ops@example.test,https://chatgpt.com/g/team-workspace,4,2026-07-03T11:00:00Z,chatbot,0.95',
    'analyst@example.test,Claude,2,2026-07-03T12:00:00Z,LLM,0.8',
  ].join('\n');

  const records = importer.parseCsv(csv);
  const { batches, stats } = importer.buildBatches(records, {
    source: 'proxy',
    vendor: 'zscaler',
    user: 'importer@example.test',
  });

  assert.strictEqual(stats.inputRows, 3);
  assert.strictEqual(stats.acceptedRows, 3);
  assert.strictEqual(stats.acceptedSightings, 2);
  assert.strictEqual(batches.length, 1);
  assert.strictEqual(batches[0].vendor, 'zscaler');
  assert.strictEqual(batches[0].source, 'proxy');

  const chatgpt = batches[0].sightings.find((item) => item.destination === 'chatgpt.com');
  assert.ok(chatgpt);
  assert.strictEqual(chatgpt.events, 7);
  assert.strictEqual(chatgpt.user, 'ops@example.test');
  assert.strictEqual(chatgpt.category, 'chatbot');
  assert.strictEqual(chatgpt.confidence, 0.95);

  const claude = batches[0].sightings.find((item) => item.destination === 'claude.ai');
  assert.ok(claude);
  assert.strictEqual(claude.events, 2);

  const wire = JSON.stringify(batches);
  assert.ok(!wire.includes('/c/member-case'));
  assert.ok(!wire.includes('token=abc'));
});

test('discovery importer rejects sensitive identifiers, raw app labels without hosts, and prompt-like rows', () => {
  const records = [
    { user: 'ops@example.test', url: 'https://perplexity.ai/search/public', count: 4 },
    { user: 'ops@example.test', url: 'https://chatgpt-524-71-9043.example/path', count: 1 },
    { user: 'ops@example.test', app: 'Internal AI Pilot', count: 5 },
    { user: 'ops@example.test', destination: 'Customer SSN 524-71-9043', count: 1 },
  ];
  const { batches, stats } = importer.buildBatches(records, {
    source: 'firewall',
    vendor: 'generic',
    user: 'importer@example.test',
  });

  assert.strictEqual(stats.inputRows, 4);
  assert.strictEqual(stats.acceptedRows, 1);
  assert.strictEqual(stats.skippedRows, 3);
  assert.strictEqual(batches[0].sightings.length, 1);
  assert.strictEqual(batches[0].sightings[0].destination, 'perplexity.ai');
  assert.strictEqual(JSON.stringify(batches).includes('524-71-9043'), false);
  assert.strictEqual(JSON.stringify(batches).includes('Internal AI Pilot'), false);
});

test('discovery importer batches sanitized sightings and posts with ingest auth only', async () => {
  const records = [];
  for (let i = 0; i < importer.API_BATCH_SIZE + 2; i += 1) {
    records.push({ destination: `ai-${i}.example.com`, user: 'ops@example.test', events: 1 });
  }
  const { batches, stats } = importer.buildBatches(records, {
    source: 'proxy',
    vendor: 'netskope',
    user: 'importer@example.test',
  });
  assert.strictEqual(stats.acceptedSightings, importer.API_BATCH_SIZE + 2);
  assert.strictEqual(batches.length, 2);
  assert.strictEqual(batches[0].sightings.length, importer.API_BATCH_SIZE);
  assert.strictEqual(batches[1].sightings.length, 2);

  const calls = [];
  const body = await importer.postBatch(batches[0], {
    redactwallUrl: 'http://127.0.0.1:4000/',
    apiKey: 'unit-ingest-key',
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return jsonResponse(202, { status: 'imported', imported: 100, observations: 100 });
    },
  });

  assert.strictEqual(body.status, 'imported');
  assert.strictEqual(calls[0].url, 'http://127.0.0.1:4000/api/v1/discovery');
  assert.strictEqual(calls[0].options.redirect, 'error');
  assert.strictEqual(calls[0].options.headers['x-api-key'], 'unit-ingest-key');
  assert.strictEqual(JSON.parse(calls[0].options.body).vendor, 'netskope');
  assert.strictEqual(JSON.stringify(calls[0]).includes('unit-ingest-key'), true);
  assert.ok(!calls[0].options.body.includes('unit-ingest-key'));
});

test('discovery importer main supports dry-run and json summaries without requiring secrets', async () => {
  const logs = [];
  const result = await importer.main([
    '--input', 'sample.json',
    '--format', 'json',
    '--vendor', 'purview',
    '--dry-run',
    '--json',
  ], {
    readFile: () => JSON.stringify({ records: [
      { application: 'Gemini', userPrincipalName: 'lending@example.test', hits: 8 },
      { url: 'https://notebooklm.google.com/notebook/member-notes', username: 'ops@example.test', hits: 2 },
    ] }),
    console: {
      log: (msg) => logs.push(String(msg)),
      error: (msg) => logs.push(String(msg)),
    },
    setExitCode: () => assert.fail('dry-run should not set an exit code'),
  });

  assert.strictEqual(result.status, 'ready');
  assert.strictEqual(result.sightings, 2);
  assert.strictEqual(result.observations, 10);
  assert.ok(result.destinations.includes('gemini.google.com'));
  assert.ok(result.destinations.includes('notebooklm.google.com'));
  assert.ok(logs[0].includes('"privacy"'));
  assert.strictEqual(logs[0].includes('/notebook/member-notes'), false);
});

test('discovery importer supports JSONL exports and server-safe identity fields', () => {
  const records = importer.parseJsonRecords([
    JSON.stringify({ url: 'https://poe.com/chat/abc', user: 'DOMAIN\\bad-user', hits: 2 }),
    JSON.stringify({ url: 'https://cursor.com/project/private-path', user: 'dev@example.test', hits: 3 }),
  ].join('\n'));
  const { batches } = importer.buildBatches(records, {
    source: 'bad source',
    vendor: 'netskope',
    user: 'importer@example.test',
  });

  assert.strictEqual(batches[0].source, 'proxy');
  assert.strictEqual(batches[0].sightings.length, 2);
  assert.strictEqual(batches[0].sightings.find((item) => item.destination === 'poe.com').user, 'importer@example.test');
  assert.strictEqual(batches[0].sightings.find((item) => item.destination === 'cursor.com').user, 'dev@example.test');
  assert.strictEqual(JSON.stringify(batches).includes('/project/private-path'), false);

  const args = importer.parseArgs(['--source', 'bad source', '--vendor', 'bad vendor!', '--user', 'DOMAIN\\user']);
  assert.strictEqual(args.source, 'proxy');
  assert.strictEqual(args.vendor, 'generic');
  assert.strictEqual(args.user, 'discovery-import');
});

test('discovery importer surfaces missing input and posting failures without leaking payloads', async () => {
  let exitCode = 0;
  const errors = [];
  const missing = await importer.main([], {
    console: { log: () => {}, error: (msg) => errors.push(String(msg)) },
    setExitCode: (code) => { exitCode = code; },
  });
  assert.strictEqual(missing.status, 'error');
  assert.strictEqual(exitCode, 2);

  const err = new Error('should not be called');
  await assert.rejects(() => importer.postBatch({ sightings: [] }, {
    redactwallUrl: 'http://127.0.0.1:4000',
    apiKey: '',
    fetchImpl: async () => { throw err; },
  }), /INGEST_API_KEY/);

  let called = false;
  await assert.rejects(() => importer.postBatch({ sightings: [] }, {
    redactwallUrl: 'http://redactwall.example',
    apiKey: 'unit-ingest-key',
    fetchImpl: async () => { called = true; },
  }), /must use HTTPS or loopback HTTP/);
  assert.strictEqual(called, false);
});
