'use strict';
/** Endpoint git push guard must inspect diffs locally and report only sanitized evidence. */
const test = require('node:test');
const assert = require('node:assert');

const guard = require('../sensors/endpoint-agent/collectors/git-push-guard');

const RAW_SSN = '524-71-9043';
const RAW_SECRET = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890';
const LOCAL_SHA = '1111111111111111111111111111111111111111';
const REMOTE_SHA = '2222222222222222222222222222222222222222';

function captureConsole() {
  const lines = [];
  return {
    lines,
    log(message) { lines.push(['log', message]); },
    error(message) { lines.push(['error', message]); },
  };
}

test('parseArgs supports pre-push, manual, and allowlist options without secrets', () => {
  const parsed = guard.parseArgs([
    '--pre-push',
    '--repo', 'C:/repo',
    '--remote-name', 'origin',
    '--remote-url', 'git@github.com:customer/repo.git',
    '--base', REMOTE_SHA,
    '--head', LOCAL_SHA,
    '--allowed-host', 'github.com',
    '--env', 'endpoint.env',
    '--user', 'engineer@example.test',
    '--max-chars', '4096',
    '--max-diff-bytes', '65536',
    '--json',
    '--quiet',
  ]);

  assert.strictEqual(parsed.prePush, true);
  assert.strictEqual(parsed.repo, 'C:/repo');
  assert.strictEqual(parsed.remoteName, 'origin');
  assert.strictEqual(parsed.remoteUrl, 'git@github.com:customer/repo.git');
  assert.deepStrictEqual(parsed.allowedHosts, ['github.com']);
  assert.strictEqual(parsed.maxChars, 4096);
  assert.strictEqual(parsed.maxDiffBytes, 65536);
  assert.strictEqual(parsed.json, true);
  assert.strictEqual(parsed.quiet, true);
  assert.match(guard.usage(), /--pre-push/);
  assert.strictEqual(guard.parseArgs(['--help']).help, true);
  assert.throws(() => guard.parseArgs(['--remote-url']), /requires a value/);
  assert.throws(() => guard.parseArgs(['--secret', 'x']), /Unknown option/);
  assert.throws(() => guard.parseArgs(['unexpected']), /Unexpected argument/);
});

test('remote destination keeps only host-level attribution', () => {
  assert.strictEqual(guard.remoteHost('git@github.com:customer/member-524-71-9043.git'), 'github.com');
  assert.strictEqual(guard.destinationFromRemote('https://dev.azure.com/org/project/_git/repo', 'origin'), 'git:dev.azure.com');
  assert.strictEqual(guard.destinationFromRemote('', 'origin'), 'git:origin');
  assert.strictEqual(guard.destinationFromRemote('C:/repos/private.git', ''), 'git-remote');
  assert.strictEqual(guard.destinationAllowed('ssh://git@sub.github.com/org/repo', { allowedHosts: ['github.com'] }), true);
  assert.strictEqual(guard.destinationAllowed('ssh://git@gitlab.example/org/repo', { allowedHosts: ['github.com'] }), false);
});

test('pre-push stdin maps existing branches and first pushes to complete ranges', () => {
  const ranges = guard.parsePrePushStdin([
    `refs/heads/main ${LOCAL_SHA} refs/heads/main ${REMOTE_SHA}`,
    `refs/heads/new ${REMOTE_SHA} refs/heads/new 0000000000000000000000000000000000000000`,
    `refs/heads/delete 0000000000000000000000000000000000000000 refs/heads/delete ${REMOTE_SHA}`,
  ].join('\n'));

  assert.deepStrictEqual(ranges, [
    { localRef: 'main', remoteRef: 'main', base: REMOTE_SHA, head: LOCAL_SHA, newBranch: false },
    { localRef: 'new', remoteRef: 'new', base: guard.EMPTY_TREE, head: REMOTE_SHA, newBranch: true },
  ]);
  assert.throws(() => guard.parsePrePushStdin('bad line'), /invalid push range/);
});

test('sensitive outbound diff is blocked locally and reports masked evidence only', async () => {
  let reportRequest;
  const diff = [
    'diff --git a/member.txt b/member.txt',
    '+const token = "' + RAW_SECRET + '";',
    '+member SSN ' + RAW_SSN,
  ].join('\n');

  const result = await guard.collectGitPush({
    diffText: diff,
    remoteUrl: 'git@unknown.example:customer/member-524-71-9043.git',
    user: 'engineer@example.test',
    policy: { enforcementMode: 'block', alwaysBlock: ['US_SSN', 'SECRET_KEY'], ignore: [], disabledDetectors: [] },
    report: async (req) => {
      reportRequest = req;
      return { id: 'q_git_blocked', status: 'action_blocked' };
    },
  });

  assert.strictEqual(result.status, 'blocked');
  assert.strictEqual(result.blocked, true);
  assert.strictEqual(result.recorded, true);
  assert.strictEqual(result.id, 'q_git_blocked');
  assert.ok(result.labels.includes('US_SSN'));
  assert.ok(result.labels.includes('SECRET_KEY'));
  assert.strictEqual(result.destination, 'git:unknown.example');
  assert.strictEqual(reportRequest.source, 'endpoint_agent');
  assert.strictEqual(reportRequest.channel, 'git_push');
  assert.strictEqual(reportRequest.clientOutcome, 'action_blocked');
  assert.strictEqual(reportRequest.clientPreRedacted, true);
  assert.match(reportRequest.prompt, /^\[git push blocked locally\]/);
  assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'US_SSN'));
  assert.ok(reportRequest.clientFindings.some((finding) => finding.type === 'SECRET_KEY'));
  assert.ok(!JSON.stringify(reportRequest).includes(RAW_SSN));
  assert.ok(!JSON.stringify(reportRequest).includes(RAW_SECRET));
  assert.ok(!JSON.stringify(reportRequest).includes('member-524-71-9043'));
  assert.ok(!JSON.stringify(result).includes(RAW_SSN));
  assert.ok(!JSON.stringify(result).includes(RAW_SECRET));
});

test('allowed corporate git host permits source-code-only pushes but still blocks secrets', async () => {
  let reports = 0;
  const codeOnly = await guard.collectGitPush({
    diffText: 'diff --git a/app.js b/app.js\n+function renderAccountCard(account) { return account.id; }',
    remoteUrl: 'https://github.com/customer/repo.git',
    allowedHosts: ['github.com'],
    policy: { enforcementMode: 'block', alwaysBlock: ['SECRET_KEY'], ignore: [], disabledDetectors: [] },
    report: async () => { reports += 1; },
  });
  const secret = await guard.collectGitPush({
    diffText: 'diff --git a/app.js b/app.js\n+const key = "' + RAW_SECRET + '";',
    remoteUrl: 'https://github.com/customer/repo.git',
    allowedHosts: ['github.com'],
    policy: { enforcementMode: 'block', alwaysBlock: ['SECRET_KEY'], ignore: [], disabledDetectors: [] },
    report: async () => {
      reports += 1;
      return { id: 'q_secret', status: 'action_blocked' };
    },
  });

  assert.strictEqual(codeOnly.status, 'clean');
  assert.strictEqual(secret.status, 'blocked');
  assert.strictEqual(reports, 1);
  assert.ok(!JSON.stringify(secret).includes(RAW_SECRET));
});

test('empty and clean diffs do not report to the control plane', async () => {
  let reports = 0;
  const empty = await guard.collectGitPush({
    diffText: '',
    remoteUrl: 'https://github.com/customer/repo.git',
    report: async () => { reports += 1; },
  });
  const clean = await guard.collectGitPush({
    diffText: 'diff --git a/readme.md b/readme.md\n+Public release note.',
    remoteUrl: 'https://github.com/customer/repo.git',
    report: async () => { reports += 1; },
  });

  assert.strictEqual(empty.status, 'clean');
  assert.strictEqual(clean.status, 'clean');
  assert.strictEqual(reports, 0);
});

test('unbounded diffs fail closed with sanitized blocked evidence', async () => {
  let reportRequest;
  const result = await guard.collectGitPush({
    diffText: 'x'.repeat(5000),
    maxDiffBytes: 4096,
    remoteUrl: 'https://gitlab.example/customer/repo.git',
    report: async (req) => {
      reportRequest = req;
      return { id: 'q_git_large', status: 'action_blocked' };
    },
  });

  assert.strictEqual(result.status, 'blocked');
  assert.strictEqual(result.reason, 'diff_too_large');
  assert.strictEqual(result.recorded, true);
  assert.strictEqual(reportRequest.clientOutcome, 'action_blocked');
  assert.match(reportRequest.note, /exceeded inspection bounds/);
  assert.ok(!JSON.stringify(result).includes('x'.repeat(100)));
});

test('collectDiff uses bounded git commands for pre-push ranges', async () => {
  const calls = [];
  const result = await guard.collectDiff({
    prePush: true,
    stdin: `refs/heads/main ${LOCAL_SHA} refs/heads/main ${REMOTE_SHA}`,
    repo: 'C:/repo',
    remoteUrl: 'git@github.com:org/repo.git',
    execFileAsync: async (file, args, opts) => {
      calls.push({ file, args, opts });
      return { stdout: '+public change' };
    },
  });

  assert.strictEqual(result.status, 'ok');
  assert.strictEqual(result.text, '+public change');
  assert.strictEqual(calls[0].file, 'git');
  assert.deepStrictEqual(calls[0].args.slice(0, 3), ['-C', 'C:/repo', 'diff']);
  assert.ok(calls[0].args.includes('--no-ext-diff'));
  assert.ok(calls[0].args.includes('--no-color'));
  assert.ok(calls[0].args.includes(REMOTE_SHA));
  assert.ok(calls[0].args.includes(LOCAL_SHA));
  assert.strictEqual(calls[0].opts.windowsHide, true);
  assert.ok(calls[0].opts.maxBuffer <= guard.DEFAULT_MAX_DIFF_BYTES + 4096);
});

test('public errors and human output are bounded', () => {
  assert.strictEqual(guard.publicError(new Error('stdout maxBuffer length exceeded')), 'git diff is too large to inspect locally');
  assert.strictEqual(guard.publicError(new Error('ENOENT')), 'git repository is not available');
  assert.strictEqual(guard.publicError(new Error('invalid sha in push range')), 'invalid sha in push range');
  assert.strictEqual(guard.publicError(new Error('raw private failure')), 'git push guard failed');

  const io = captureConsole();
  guard.printHuman({ status: 'clean', destination: 'git:github.com' }, io);
  guard.printHuman({ status: 'blocked', destination: 'git:unknown.example', labels: ['US_SSN'], recorded: false }, io);
  guard.printHuman({ status: 'failed', error: 'git repository is not available' }, io);
  assert.deepStrictEqual(io.lines.map(([, message]) => message), [
    'PromptWall git push guard clean: git:github.com',
    'PromptWall git push guard blocked: git:unknown.example: US_SSN: not recorded',
    'PromptWall git push guard failed: git repository is not available',
  ]);
  assert.ok(!JSON.stringify(io.lines).includes(RAW_SSN));
});

test('main prints help, JSON, human output, quiet output, and sanitized errors', async () => {
  const helpIo = captureConsole();
  assert.strictEqual(await guard.main(['--help'], { console: helpIo }), 0);
  assert.ok(helpIo.lines.some(([, message]) => message.includes('Usage: node')));

  const jsonIo = captureConsole();
  assert.strictEqual(await guard.main(['--json'], {
    console: jsonIo,
    collectGitPush: async () => ({ status: 'blocked', destination: 'git:example', labels: ['SECRET_KEY'], blocked: true }),
  }), 1);
  assert.deepStrictEqual(JSON.parse(jsonIo.lines[0][1]), {
    status: 'blocked',
    destination: 'git:example',
    labels: ['SECRET_KEY'],
    blocked: true,
  });

  const humanIo = captureConsole();
  assert.strictEqual(await guard.main([], {
    console: humanIo,
    collectGitPush: async () => ({ status: 'clean', destination: 'git:github.com' }),
  }), 0);
  assert.strictEqual(humanIo.lines[0][1], 'PromptWall git push guard clean: git:github.com');

  const quietIo = captureConsole();
  assert.strictEqual(await guard.main(['--quiet'], {
    console: quietIo,
    collectGitPush: async () => ({ status: 'clean', destination: 'git:github.com' }),
  }), 0);
  assert.deepStrictEqual(quietIo.lines, []);

  const errIo = captureConsole();
  assert.strictEqual(await guard.main(['--json', '--remote-url'], { console: errIo }), 1);
  assert.ok(errIo.lines.some(([level, message]) => level === 'error' && /requires a value/.test(message)));
  assert.deepStrictEqual(JSON.parse(errIo.lines.find(([level]) => level === 'log')[1]), {
    status: 'failed',
    error: '--remote-url requires a value',
  });
});

test('gitPushRecord never includes raw diff or repository identifiers', () => {
  const analysis = {
    findings: [{ type: 'US_SSN', severity: 4, score: 1, value: RAW_SSN }],
    categories: [],
    entityCounts: { US_SSN: 1 },
    riskScore: 80,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
  };
  const record = guard.gitPushRecord(analysis, 'action_blocked', {
    remoteUrl: 'git@github.com:customer/member-524-71-9043.git',
  });

  assert.strictEqual(record.channel, 'git_push');
  assert.strictEqual(record.destination, 'git:github.com');
  assert.strictEqual(record.contentBase64, undefined);
  assert.notStrictEqual(record.clientFindings[0].masked, RAW_SSN);
  assert.ok(!JSON.stringify(record).includes(RAW_SSN));
  assert.ok(!JSON.stringify(record).includes('member-524-71-9043'));
});
