'use strict';
/** Endpoint clipboard guard must inspect locally and report only sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');

const {
  analyzeClipboard,
  clipboardRecord,
  collectClipboard,
  exitCodeForResult,
  main,
  parseArgs,
  printHuman,
  publicError,
  usage,
  _internal,
} = require('../sensors/endpoint-agent/collectors/clipboard-guard');

const RAW_SSN = '524-71-9043';
const RAW_CARD = '4111 1111 1111 1111';

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(['log', message]); },
    error(message) { lines.push(['error', message]); },
  };
}

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

test('default clipboard PowerShell commands are hidden and bounded', async () => {
  const calls = [];
  const text = await _internal.readClipboard({
    platform: 'win32',
    execFileAsync: async (file, args, opts) => {
      calls.push({ file, args, opts });
      return { stdout: 'clipboard text' };
    },
  });
  await _internal.clearClipboard({
    platform: 'win32',
    execFileAsync: async (file, args, opts) => {
      calls.push({ file, args, opts });
      return { stdout: '' };
    },
  });

  assert.strictEqual(text, 'clipboard text');
  assert.strictEqual(calls[0].file, 'powershell.exe');
  assert.ok(calls[0].args.includes('Get-Clipboard -Raw'));
  assert.strictEqual(calls[0].opts.windowsHide, true);
  assert.strictEqual(calls[0].opts.maxBuffer, 2 * 1024 * 1024);
  assert.ok(calls[1].args.includes("Set-Clipboard -Value ''"));
  assert.strictEqual(calls[1].opts.windowsHide, true);
  await assert.rejects(
    () => _internal.readClipboard({ platform: 'linux', execFileAsync: async () => ({ stdout: '' }) }),
    /not supported/
  );
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

test('default policy/report path fails closed without an ingest key', async () => {
  const result = await collectClipboard({
    readClipboard: async () => `Member SSN ${RAW_SSN}`,
    key: '',
  });

  assert.strictEqual(result.status, 'flagged');
  assert.strictEqual(result.sensitive, true);
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
  assert.deepStrictEqual(parseArgs([
    '--user', 'analyst@example.test',
    '--env', 'endpoint.env',
    '--json',
    '--quiet',
    '--max-chars', 'not-a-number',
  ]), {
    user: 'analyst@example.test',
    envPath: 'endpoint.env',
    json: true,
    quiet: true,
    maxChars: 200000,
  });
  assert.match(usage(), /--clear-on-block/);
  assert.strictEqual(parseArgs(['--help']).help, true);
  assert.throws(() => parseArgs(['--destination']), /requires a value/);
  assert.throws(() => parseArgs(['--bad']), /Unknown option/);
  assert.throws(() => parseArgs(['unexpected']), /Unexpected argument/);
  assert.strictEqual(publicError(new Error('clipboard guard is not supported on this platform')), 'clipboard guard is only supported on Windows');
  assert.strictEqual(publicError(new Error('EACCES denied')), 'clipboard cannot be accessed');
  assert.strictEqual(publicError(new Error('raw private failure detail')), 'clipboard guard failed');
  assert.strictEqual(exitCodeForResult(null), 1);
  assert.strictEqual(exitCodeForResult({ status: 'blocked' }), 1);
  assert.strictEqual(exitCodeForResult({ status: 'flagged' }), 0);
});

test('analyzeClipboard honors max character bounds before detection', () => {
  const analysis = analyzeClipboard(`Member SSN ${RAW_SSN}`, {
    ignore: [],
    disabledDetectors: [],
    customDetectors: [],
  }, { maxChars: 1024 });

  assert.ok(analysis.findings.some((finding) => finding.type === 'US_SSN'));
});

test('printHuman summarizes clean, empty, and recorded states without raw content', () => {
  const io = captureConsole();

  printHuman({ status: 'clean' }, io);
  printHuman({ status: 'empty' }, io);
  printHuman({
    status: 'blocked',
    labels: ['US_SSN'],
    cleared: true,
    recorded: false,
  }, io);

  assert.deepStrictEqual(io.lines.map(([, message]) => message), [
    'PromptWall clipboard guard clean',
    'PromptWall clipboard guard empty',
    'PromptWall clipboard guard blocked: US_SSN: clipboard cleared: not recorded',
  ]);
  assert.ok(!JSON.stringify(io.lines).includes(RAW_SSN));
});

test('clipboard guard main prints help, JSON, human output, quiet output, and sanitized errors', async () => {
  const helpIo = captureConsole();
  assert.strictEqual(await main(['--help'], { console: helpIo }), 0);
  assert.ok(helpIo.lines.some(([, message]) => message.includes('Usage: node')));

  const jsonIo = captureConsole();
  assert.strictEqual(await main(['--json'], {
    console: jsonIo,
    collectClipboard: async () => ({ status: 'flagged', labels: ['US_SSN'], recorded: true, riskScore: 55 }),
  }), 0);
  assert.deepStrictEqual(JSON.parse(jsonIo.lines[0][1]), {
    status: 'flagged',
    labels: ['US_SSN'],
    recorded: true,
    riskScore: 55,
  });

  const humanIo = captureConsole();
  assert.strictEqual(await main([], {
    console: humanIo,
    collectClipboard: async () => ({ status: 'blocked', labels: ['US_SSN'], cleared: true, recorded: false }),
  }), 1);
  assert.strictEqual(humanIo.lines[0][1], 'PromptWall clipboard guard blocked: US_SSN: clipboard cleared: not recorded');

  const quietIo = captureConsole();
  assert.strictEqual(await main(['--quiet'], {
    console: quietIo,
    collectClipboard: async () => ({ status: 'clean', recorded: false }),
  }), 0);
  assert.deepStrictEqual(quietIo.lines, []);

  const errIo = captureConsole();
  assert.strictEqual(await main(['--json', '--destination'], { console: errIo }), 1);
  assert.ok(errIo.lines.some(([level, message]) => level === 'error' && /requires a value/.test(message)));
  assert.deepStrictEqual(JSON.parse(errIo.lines.find(([level]) => level === 'log')[1]), {
    status: 'failed',
    error: '--destination requires a value',
  });

  const quietErrIo = captureConsole();
  assert.strictEqual(await main(['--quiet', '--destination'], { console: quietErrIo }), 1);
  assert.deepStrictEqual(quietErrIo.lines, []);
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
