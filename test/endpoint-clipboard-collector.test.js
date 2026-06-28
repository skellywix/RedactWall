'use strict';
/** Endpoint clipboard guard must inspect locally and report only sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');

const {
  clipboardRecord,
  collectClipboard,
  exitCodeForResult,
  parseArgs,
  publicError,
} = require('../sensors/endpoint-agent/collectors/clipboard-guard');

const RAW_SSN = '524-71-9043';
const RAW_CARD = '4111 1111 1111 1111';

test('report-only clipboard guard posts masked findings without raw clipboard text', async () => {
  let reportRequest;
  const result = await collectClipboard({
    readClipboard: async () => `Loan note. SSN ${RAW_SSN}. Card ${RAW_CARD}.`,
    policy: { enforcementMode: 'warn', alwaysBlock: ['US_SSN', 'CREDIT_CARD'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { id: 'q_clip_flagged', status: 'paste_flagged' };
    },
    user: 'clipboard-user@example.test',
    destination: 'Copilot Desktop',
  });

  assert.strictEqual(result.status, 'flagged');
  assert.strictEqual(result.sensitive, true);
  assert.strictEqual(result.recorded, true);
  assert.strictEqual(result.cleared, false);
  assert.strictEqual(result.id, 'q_clip_flagged');
  assert.deepStrictEqual(result.labels.sort(), ['CREDIT_CARD', 'US_SSN']);
  assert.strictEqual(reportRequest.source, 'endpoint_agent');
  assert.strictEqual(reportRequest.channel, 'clipboard');
  assert.strictEqual(reportRequest.destination, 'Copilot Desktop');
  assert.strictEqual(reportRequest.clientOutcome, 'paste_flagged');
  assert.strictEqual(reportRequest.clientPreRedacted, true);
  assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'US_SSN'));
  assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'CREDIT_CARD'));
  assert.match(reportRequest.prompt, /^\[clipboard flagged locally\]/);
  assert.ok(!JSON.stringify(reportRequest).includes(RAW_SSN));
  assert.ok(!JSON.stringify(reportRequest).includes(RAW_CARD));
  assert.ok(!JSON.stringify(result).includes(RAW_SSN));
  assert.ok(!JSON.stringify(result).includes(RAW_CARD));
});

test('clear-on-block clears locally and records a blocked clipboard action', async () => {
  let cleared = 0;
  let reportRequest;
  const result = await collectClipboard({
    readClipboard: async () => `Member SSN ${RAW_SSN}`,
    clearClipboard: async () => { cleared += 1; },
    clearOnBlock: true,
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { id: 'q_clip_blocked', status: 'action_blocked' };
    },
  });

  assert.strictEqual(cleared, 1);
  assert.strictEqual(result.status, 'blocked');
  assert.strictEqual(result.cleared, true);
  assert.strictEqual(result.recorded, true);
  assert.strictEqual(reportRequest.clientOutcome, 'action_blocked');
  assert.strictEqual(reportRequest.clientPreRedacted, true);
  assert.match(reportRequest.note, /clipboard cleared locally/);
  assert.ok(!JSON.stringify(reportRequest).includes(RAW_SSN));
  assert.ok(!JSON.stringify(result).includes(RAW_SSN));
});

test('clean and empty clipboard values do not report to the control plane', async () => {
  let calls = 0;
  const clean = await collectClipboard({
    readClipboard: async () => 'Summarize the public product roadmap.',
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async () => { calls += 1; },
  });
  const empty = await collectClipboard({
    readClipboard: async () => '   ',
    report: async () => { calls += 1; },
  });

  assert.strictEqual(clean.status, 'clean');
  assert.strictEqual(empty.status, 'empty');
  assert.strictEqual(calls, 0);
});

test('clipboard guard keeps blocked result local even when recording fails', async () => {
  let cleared = 0;
  const result = await collectClipboard({
    readClipboard: async () => `Member SSN ${RAW_SSN}`,
    clearClipboard: async () => { cleared += 1; },
    clearOnBlock: true,
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async () => null,
  });

  assert.strictEqual(cleared, 1);
  assert.strictEqual(result.status, 'blocked');
  assert.strictEqual(result.cleared, true);
  assert.strictEqual(result.recorded, false);
  assert.match(result.error, /control plane recording unavailable/);
  assert.ok(!JSON.stringify(result).includes(RAW_SSN));
});

test('clear failures fall back to sanitized report-only evidence', async () => {
  let reportRequest;
  const result = await collectClipboard({
    readClipboard: async () => `Member SSN ${RAW_SSN}`,
    clearClipboard: async () => { throw new Error(`cannot clear ${RAW_SSN}`); },
    clearOnBlock: true,
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { id: 'q_clip_clear_failed', status: 'paste_flagged' };
    },
  });

  assert.strictEqual(result.status, 'clear_failed');
  assert.strictEqual(result.cleared, false);
  assert.strictEqual(result.recorded, true);
  assert.match(result.error, /clipboard cannot be cleared/);
  assert.strictEqual(reportRequest.clientOutcome, 'paste_flagged');
  assert.ok(!JSON.stringify(reportRequest).includes(RAW_SSN));
  assert.ok(!JSON.stringify(result).includes(RAW_SSN));
  assert.strictEqual(exitCodeForResult(result), 1);
});

test('helpers keep CLI parsing and public errors bounded', () => {
  assert.deepStrictEqual(parseArgs(['--clear-on-block', '--destination', 'Desktop AI', '--max-chars', '4096']), {
    clearOnBlock: true,
    destination: 'Desktop AI',
    maxChars: 4096,
  });
  assert.strictEqual(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['--destination']), /requires a value/);
  assert.strictEqual(publicError(new Error('clipboard guard is not supported on this platform')), 'clipboard guard is only supported on Windows');
  assert.strictEqual(exitCodeForResult({ status: 'blocked' }), 1);
  assert.strictEqual(exitCodeForResult({ status: 'flagged' }), 0);
});

test('clipboardRecord never includes raw content fields', () => {
  const analysis = {
    findings: [{ type: 'US_SSN', severity: 3, score: 1, value: RAW_SSN }],
    categories: [],
    entityCounts: { US_SSN: 1 },
    riskScore: 60,
    maxSeverity: 3,
    maxSeverityLabel: 'high',
  };
  const record = clipboardRecord(analysis, 'paste_flagged', { destination: 'Claude Desktop' });

  assert.strictEqual(record.channel, 'clipboard');
  assert.strictEqual(record.contentBase64, undefined);
  assert.notStrictEqual(record.clientFindings[0].masked, RAW_SSN);
  assert.match(record.clientFindings[0].masked, /9043$/);
  assert.ok(!JSON.stringify(record).includes(RAW_SSN));
});
