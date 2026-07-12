'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const test = require('node:test');
const ts = require('../console/node_modules/typescript');

const ROOT = path.join(__dirname, '..');
const QUERIES_PATH = path.join(ROOT, 'console', 'src', 'api', 'queries.ts');
const ACTIVITY_PATH = path.join(ROOT, 'console', 'src', 'views', 'Activity.tsx');
const QUEUE_ACTIONS_PATH = path.join(ROOT, 'console', 'src', 'components', 'queue', 'useQueueActions.ts');

function loadQueryModule(apiOverrides = {}) {
  const source = fs.readFileSync(QUERIES_PATH, 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const module = { exports: {} };
  const apiStub = {
    api: async () => null,
    apiErrorSummary: async (_response, fallback) => fallback,
    responseJsonBounded: async () => null,
    ...apiOverrides,
  };
  const scopedRequire = (request) => {
    if (request === '../lib/api') return apiStub;
    throw new Error(`unexpected decoder dependency: ${request}`);
  };
  new Function('require', 'module', 'exports', output)(scopedRequire, module, module.exports);
  return module.exports;
}

const {
  decodeAssignmentQuery,
  decodeBulkDecisionResult,
  decodeDecisionQuery,
  decodePublicQuery,
  decodePublicQuerySnapshot,
  decodeRevealResult,
} = loadQueryModule();

function publicQuery(overrides = {}) {
  return {
    id: 'q_0123456789abcdef',
    createdAt: '2026-07-11T12:00:00.000Z',
    status: 'pending',
    user: 'analyst@example.test',
    actor: 'analyst@example.test',
    action: 'gate',
    destination: 'chat.openai.com',
    source: 'browser_extension',
    channel: 'chat',
    redactedPrompt: 'Member [MEMBER_ID] requested a balance summary.',
    findings: [{
      type: 'MEMBER_ID', severity: 3, score: 0.97, confidence: null,
      masked: '**** 1234', vendor: 'core', vendorLabel: 'Core member id',
    }],
    categories: ['FINANCIAL_INFORMATION'],
    entityCounts: { MEMBER_ID: 1, FINANCIAL_INFORMATION: 1 },
    reasons: ['Sensitive member identifier'],
    riskScore: 81,
    maxSeverity: 3,
    maxSeverityLabel: 'high',
    rawRetained: true,
    assignedRole: 'approver',
    assignedUser: null,
    assignedGroup: 'compliance',
    decidedBy: null,
    decidedAt: null,
    decisionNote: null,
    workflowReason: 'detector:MEMBER_ID',
    escalationReason: null,
    notificationStatus: 'sent',
    notificationChannels: ['email'],
    scoreBreakdown: [{
      kind: 'finding', type: 'MEMBER_ID', severity: 3, severityLabel: 'high',
      confidence: 'very_likely', points: 23, regulations: ['GLBA', 'NCUA'],
    }],
    serverOnlyField: { never: 'render this' },
    ...overrides,
  };
}

test('publicQuery decoder accepts the representative server/db shape and strips unrendered fields', () => {
  const decoded = decodePublicQuery(publicQuery());
  assert.ok(decoded);
  assert.strictEqual(decoded.id, 'q_0123456789abcdef');
  assert.strictEqual(decoded.findings[0].confidence, undefined, 'legacy null optional is normalized away');
  assert.strictEqual(decoded.assignedUser, undefined);
  assert.strictEqual(decoded.serverOnlyField, undefined);
  assert.deepStrictEqual(decoded.entityCounts, { MEMBER_ID: 1, FINANCIAL_INFORMATION: 1 });
  assert.deepStrictEqual(decoded.scoreBreakdown[0].regulations, ['GLBA', 'NCUA']);
});

test('publicQuery snapshot rejects a partial row instead of inventing display defaults', () => {
  const partial = publicQuery();
  delete partial.createdAt;
  assert.strictEqual(decodePublicQuerySnapshot([publicQuery(), partial]), null);
  assert.strictEqual(decodePublicQuery(publicQuery({ createdAt: 'not-a-timestamp' })), null);
});

test('publicQuery decoder rejects object-valued display fields and malformed children', () => {
  assert.strictEqual(decodePublicQuery(publicQuery({ user: { label: 'object user' } })), null);
  assert.strictEqual(decodePublicQuery(publicQuery({ findings: [{ type: 'MEMBER_ID', masked: { raw: true } }] })), null);
  assert.strictEqual(decodePublicQuery(publicQuery({ entityCounts: [] })), null);
});

test('publicQuery snapshot rejects duplicate ids as an ambiguous snapshot', () => {
  const first = publicQuery();
  const duplicate = publicQuery({ status: 'pending_justification' });
  assert.strictEqual(decodePublicQuerySnapshot([first, duplicate]), null);
});

test('publicQuery decoder rejects oversized arrays and strings', () => {
  const oversized = [
    { user: 'u'.repeat(513) },
    { redactedPrompt: 'x'.repeat(200_001) },
    { categories: Array.from({ length: 251 }, () => 'PII') },
    { reasons: ['r'.repeat(241)] },
    { notificationChannels: Array.from({ length: 9 }, () => 'email') },
    { findings: Array.from({ length: 251 }, () => ({ type: 'MEMBER_ID' })) },
    { scoreBreakdown: Array.from({ length: 501 }, () => ({ type: 'MEMBER_ID' })) },
  ];
  for (const fields of oversized) assert.strictEqual(decodePublicQuery(publicQuery(fields)), null);
});

test('publicQuery decoder rejects impossible numeric ranges', () => {
  assert.strictEqual(decodePublicQuery(publicQuery({ riskScore: 101 })), null);
  assert.strictEqual(decodePublicQuery(publicQuery({ maxSeverity: 5 })), null);
  assert.strictEqual(decodePublicQuery(publicQuery({ findings: [{ type: 'MEMBER_ID', score: 1.1 }] })), null);
  assert.strictEqual(decodePublicQuery(publicQuery({ entityCounts: { MEMBER_ID: 100_001 } })), null);
});

test('Activity uses the shared decoder for both snapshots and SSE query events', () => {
  const source = fs.readFileSync(ACTIVITY_PATH, 'utf8');
  assert.match(source, /decodePublicQuery\(\(data as \{ query\?: unknown \}\)\.query\)/);
  assert.match(source, /decodePublicQuerySnapshot\(payload\)/);
  assert.doesNotMatch(source, /function asActivityQuery|function decodeActivityRows/);
});

test('queue fetch decodes the bounded response before exposing rows', () => {
  const source = fs.readFileSync(QUERIES_PATH, 'utf8');
  assert.match(source, /decodePublicQuerySnapshot\(await responseJsonBounded<unknown>\(res, QUEUE_RESPONSE_MAX_BYTES\)\)/);
  assert.doesNotMatch(source, /rows as QueueQuery\[\]/);
});

test('single-decision decoder requires the requested id and finalized status metadata', () => {
  const decided = publicQuery({
    status: 'approved',
    decidedBy: 'security-admin@example.test',
    decidedAt: '2026-07-11T12:01:00.000Z',
  });
  assert.ok(decodeDecisionQuery(decided, decided.id, 'approved'));
  assert.strictEqual(decodeDecisionQuery(decided, 'q_different', 'approved'), null);
  assert.strictEqual(decodeDecisionQuery(decided, decided.id, 'denied'), null);
  assert.strictEqual(decodeDecisionQuery({ ...decided, decidedAt: null }, decided.id, 'approved'), null);
  assert.strictEqual(decodeDecisionQuery({ ...decided, rawRetained: 'yes' }, decided.id, 'approved'), null);
});

test('assignment decoder requires the same held query and echoes every requested owner field', () => {
  const assigned = publicQuery({ assignedUser: 'new-approver', assignedGroup: null, assignedRole: 'approver' });
  assert.ok(decodeAssignmentQuery(assigned, assigned.id, {
    assignedUser: ' new-approver ', assignedGroup: '', assignedRole: 'approver',
  }));
  assert.strictEqual(decodeAssignmentQuery(assigned, 'q_different', { assignedUser: 'new-approver' }), null);
  assert.strictEqual(decodeAssignmentQuery({ ...assigned, status: 'approved' }, assigned.id, { assignedUser: 'new-approver' }), null);
  assert.strictEqual(decodeAssignmentQuery(assigned, assigned.id, { assignedUser: 'another-user' }), null);
});

test('reveal decoder exposes only a bounded, internally consistent payload for the requested query', () => {
  const valid = {
    id: 'q_0123456789abcdef',
    rawPrompt: 'Synthetic member [MEMBER_ID] review text.',
    rawRetained: true,
    rawDiffersFromRedacted: true,
    extra: 'not copied',
  };
  assert.deepStrictEqual(decodeRevealResult(valid, valid.id), {
    id: valid.id,
    rawPrompt: valid.rawPrompt,
    rawRetained: true,
    rawDiffersFromRedacted: true,
  });
  assert.strictEqual(decodeRevealResult({ ...valid, id: 'q_different' }, valid.id), null);
  assert.strictEqual(decodeRevealResult({ ...valid, rawRetained: false }, valid.id), null);
  assert.strictEqual(decodeRevealResult({ ...valid, rawPrompt: { text: valid.rawPrompt } }, valid.id), null);
  assert.strictEqual(decodeRevealResult({ ...valid, rawPrompt: 'x'.repeat(200_001) }, valid.id), null);
});

test('bulk decision decoder binds result order, ids, outcomes, safe reasons, and exact counts', () => {
  const ids = ['q_first', 'q_second'];
  const valid = {
    results: [
      { id: ids[0], outcome: 'approved' },
      { id: ids[1], outcome: 'skipped', reason: 'already denied' },
    ],
    decided: 1,
    skipped: 1,
  };
  assert.deepStrictEqual(decodeBulkDecisionResult(valid, ids, 'approved'), valid);
  assert.strictEqual(decodeBulkDecisionResult({ ...valid, decided: 2 }, ids, 'approved'), null);
  assert.strictEqual(decodeBulkDecisionResult({ ...valid, results: [...valid.results].reverse() }, ids, 'approved'), null);
  assert.strictEqual(decodeBulkDecisionResult({
    ...valid,
    results: [valid.results[0], { id: ids[1], outcome: 'skipped', reason: 'user john@example.test included sensitive text' }],
  }, ids, 'approved'), null);
  assert.strictEqual(decodeBulkDecisionResult(valid, [ids[0], ids[0]], 'approved'), null);
});

test('every queue mutation fails closed on malformed 2xx payloads without returning raw response text', async () => {
  const sensitiveSentinel = 'Synthetic raw account 999999999999';
  const response = { ok: true, status: 200 };
  const module = loadQueryModule({
    api: async () => response,
    responseJsonBounded: async () => ({
      id: 'q_wrong',
      rawPrompt: sensitiveSentinel,
      rawRetained: 'true',
      rawDiffersFromRedacted: true,
    }),
  });
  const cases = [
    [module.approveQuery('q_expected', '', 'synthetic-password'), 'Approve failed'],
    [module.denyQuery('q_expected', ''), 'Deny failed'],
    [module.bulkDecision(['q_expected'], 'deny', ''), 'Bulk decision failed'],
    [module.revealQuery('q_expected', 'synthetic-password'), 'Reveal failed'],
    [module.assignQuery('q_expected', { assignedRole: 'approver' }), 'Reassign failed'],
  ];
  for (const [pending, error] of cases) {
    const result = await pending;
    assert.deepStrictEqual(result, { data: null, error });
    assert.strictEqual(JSON.stringify(result).includes(sensitiveSentinel), false);
  }
});

test('queue action success claims require a decoded data payload', () => {
  const source = fs.readFileSync(QUEUE_ACTIONS_PATH, 'utf8');
  assert.match(source, /const result = await denyQuery[\s\S]*?if \(!result\.data\)[\s\S]*?Prompt denied\./);
  assert.match(source, /const result = await assignQuery[\s\S]*?if \(!result\.data\)[\s\S]*?Assignment updated\./);
  assert.match(source, /const result = await approveQuery[\s\S]*?if \(!result\.data\)[\s\S]*?Prompt approved and released\./);
  assert.match(source, /const data = result\.data;[\s\S]*?if \(!data\)[\s\S]*?setReveals/);
});
