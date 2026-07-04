'use strict';
/**
 * Broad webapp QA matrix based on common public web testing checklists:
 * functional routes, validation, security/privacy controls, accessibility,
 * responsive UI markers, browser-extension coverage, and error handling.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

process.env.ADMIN_PASSWORD = 'unit-pass';
process.env.SENTINEL_SECRET = 'unit-secret-stable';
process.env.SENTINEL_DATA_KEY = 'unit-data-key-stable';
process.env.INGEST_API_KEY = 'unit-ingest-key';
process.env.SENTINEL_DB_PATH = path.join(os.tmpdir(), 'ps-webapp-qa-1000-' + crypto.randomBytes(6).toString('hex') + '.db');
const policyPath = path.join(os.tmpdir(), 'ps-webapp-qa-1000-policy-' + crypto.randomBytes(6).toString('hex') + '.json');
process.env.SENTINEL_POLICY_PATH = policyPath;
fs.copyFileSync(path.join(__dirname, '..', 'config', 'policy.json'), policyPath);

const app = require('../server/app');
const detect = require('../detection-engine/detect');
const adapters = require('../detection-engine/adapters');
const policy = require('../server/policy');
const validation = require('../server/validation');
const { listen, loopbackHttpFetch } = require('./support/listen');

const root = path.join(__dirname, '..');
const dashboardHtml = fs.readFileSync(path.join(root, 'server', 'public', 'index.html'), 'utf8');
const dashboardJs = fs.readFileSync(path.join(root, 'server', 'public', 'dashboard.js'), 'utf8');
const siemPackageJs = fs.readFileSync(path.join(root, 'server', 'public', 'siem-package.js'), 'utf8');
const threatGuardrailsJs = fs.readFileSync(path.join(root, 'server', 'public', 'ai-threat-guardrails.js'), 'utf8');
const operatorFlowJs = fs.readFileSync(path.join(root, 'server', 'public', 'operator-flow.js'), 'utf8');
const policyGuidesJs = fs.readFileSync(path.join(root, 'server', 'public', 'policy-guides.js'), 'utf8');
const behaviorBaselinesJs = fs.readFileSync(path.join(root, 'server', 'public', 'behavior-baselines.js'), 'utf8');
const competitiveReadinessJs = fs.readFileSync(path.join(root, 'server', 'public', 'competitive-readiness.js'), 'utf8');
const coverageFileFlowJs = fs.readFileSync(path.join(root, 'server', 'public', 'coverage-file-flow.js'), 'utf8');
const decisionQualityJs = fs.readFileSync(path.join(root, 'server', 'public', 'decision-quality.js'), 'utf8');
const detectorFeedbackJs = fs.readFileSync(path.join(root, 'server', 'public', 'detector-feedback.js'), 'utf8');
const loginHtml = fs.readFileSync(path.join(root, 'server', 'public', 'login.html'), 'utf8');
const loginJs = fs.readFileSync(path.join(root, 'server', 'public', 'login.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'manifest.json'), 'utf8'));
const contentJs = fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'content.js'), 'utf8');
const backgroundJs = fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'background.js'), 'utf8');
const browserAdaptersJs = fs.readFileSync(path.join(root, 'sensors', 'browser-extension', 'lib', 'adapters.js'), 'utf8');

const cases = [];
function add(area, name, run) {
  cases.push({ area, name, run });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function expectSchemaPass(schema, payload) {
  const result = schema.safeParse(payload);
  assert.strictEqual(result.success, true, result.success ? '' : JSON.stringify(validation.validationFields(result.error)));
  return result.data;
}

function expectSchemaField(schema, payload, field, secret) {
  const result = schema.safeParse(payload);
  assert.strictEqual(result.success, false, 'expected schema failure');
  const fields = validation.validationFields(result.error);
  assert.ok(fields.includes(field), `expected ${field}, got ${fields.join(',')}`);
  if (secret) assert.ok(!JSON.stringify(fields).includes(secret), 'validation field list leaked submitted value');
}

function expectDetector(type, text) {
  const analysis = detect.analyze(text);
  const hits = analysis.findings.map((item) => item.type)
    .concat(analysis.categories.map((item) => item.category));
  assert.ok(hits.includes(type), `expected ${type} in ${JSON.stringify(hits)} for ${text}`);
}

function expectNoDetector(type, text) {
  const analysis = detect.analyze(text);
  const hits = analysis.findings.map((item) => item.type)
    .concat(analysis.categories.map((item) => item.category));
  assert.ok(!hits.includes(type), `did not expect ${type} in ${JSON.stringify(hits)} for ${text}`);
}

function expectContains(source, marker) {
  assert.ok(source.includes(marker), `missing marker ${marker}`);
}

function expectMatch(source, pattern) {
  assert.match(source, pattern);
}

function areaCounts() {
  return cases.reduce((acc, item) => {
    acc[item.area] = (acc[item.area] || 0) + 1;
    return acc;
  }, {});
}

const detectorBases = [
  ['US_SSN', 'member SSN 123-45-6789'],
  ['CREDIT_CARD', 'card 4111 1111 1111 1111 exp 09/27'],
  ['ROUTING_NUMBER', 'routing number 021000021'],
  ['BANK_ACCOUNT', 'bank account number 123456789012'],
  ['US_PASSPORT', 'passport 123456789'],
  ['US_ITIN', 'ITIN 900-70-0000'],
  ['US_NPI', 'NPI 1234567893'],
  ['MEMBER_ID', 'member id CU1234567'],
  ['LOAN_NUMBER', 'loan number LN1234567'],
  ['MEDICAL_RECORD_NUMBER', 'MRN MR1234567'],
  ['HEALTH_INSURANCE_ID', 'health insurance member id HX1234567'],
  ['SECRET_KEY', 'AWS key AKIA1234567890ABCDEF'],
  ['PASSWORD', 'password=Summer2026!'],
  ['PHONE_NUMBER', 'phone 415-555-0182'],
  ['EMAIL_ADDRESS', 'email jane@example.com'],
  ['US_ADDRESS', '482 Oakwood Drive'],
  ['SOURCE_CODE', 'function parseCsv(input) { return input.split(","); }'],
  ['LEGAL_CONTRACT', 'This agreement shall be governed by confidentiality and limitation of liability.'],
  ['CREDENTIALS', 'API_KEY=abcd1234SECRETvalue'],
  ['CONFIDENTIAL_BUSINESS', 'Strictly confidential: we are considering leaving our vendor before the announcement.'],
];
const detectorContexts = [
  'Please review: ',
  'Security check input: ',
  'Synthetic QA sample contains ',
  'Block before AI egress: ',
  'Compliance test data: ',
];
for (const [type, text] of detectorBases) {
  for (const prefix of detectorContexts) {
    add('detector-positive', `${type} positive ${prefix.trim()}`, () => expectDetector(type, prefix + text));
  }
}

for (let i = 0; i < 80; i += 1) {
  const selector = i % 8;
  add('detector-positive', `generated structured positive ${i + 1}`, () => {
    if (selector === 0) expectDetector('US_SSN', `member social security number ${120 + (i % 40)}-${10 + (i % 70)}-${2000 + i}`);
    else if (selector === 1) expectDetector('CREDIT_CARD', `visa card 4012 8888 8888 1881 for synthetic dispute ${i}`);
    else if (selector === 2) expectDetector('ROUTING_NUMBER', `ACH routing number 021000021 for test ${i}`);
    else if (selector === 3) expectDetector('BANK_ACCOUNT', `checking account number ${123456700000 + i}`);
    else if (selector === 4) expectDetector('MEMBER_ID', `member number CU-${10000 + i}`);
    else if (selector === 5) expectDetector('LOAN_NUMBER', `loan number LN-${20000 + i}`);
    else if (selector === 6) expectDetector('EMAIL_ADDRESS', `email member${i}@example.test`);
    else expectDetector('PHONE_NUMBER', `phone 415-555-${String(1000 + i).padStart(4, '0')}`);
  });
}

const negativeTexts = [
  ['US_SSN', 'tracking id 900123456 is not a social security value'],
  ['US_SSN', 'ordinary reference 123456789 without sensitive wording'],
  ['CREDIT_CARD', 'ticket 1234567890123456 is not a card'],
  ['CREDIT_CARD', 'order 0000 0000 0000 0000 should not be a card'],
  ['ROUTING_NUMBER', 'case id 021000021 appears without banking context'],
  ['BANK_ACCOUNT', 'accounting topic with no actual account number'],
  ['SECRET_KEY', 'rotate API keys every quarter without pasting them'],
  ['PASSWORD', 'password policy should require length and rotation'],
  ['DOB', '03/14/2024 is a normal project milestone'],
  ['HEALTH_RECORD', 'HIPAA awareness training with no patient details'],
  ['SOURCE_CODE', 'ask for a high level product strategy summary'],
  ['LEGAL_CONTRACT', 'summarize public contract law concepts'],
  ['CONFIDENTIAL_BUSINESS', 'write a public announcement after release'],
  ['MEMBER_ID', 'membership growth was 12 percent'],
  ['LOAN_NUMBER', 'loan demand trends are rising'],
  ['MEDICAL_RECORD_NUMBER', 'medical policy overview without chart identifiers'],
  ['HEALTH_INSURANCE_ID', 'insurance education plan without subscriber values'],
  ['US_PASSPORT', 'passport renewal instructions without a number'],
  ['US_NPI', 'provider taxonomy overview without identifier'],
  ['PRIVATE_KEY', 'private key rotation checklist without key material'],
];
for (const [type, text] of negativeTexts) {
  for (let i = 0; i < 6; i += 1) {
    add('detector-negative', `${type} bait ${i + 1}`, () => expectNoDetector(type, `${text} ref ${i}`));
  }
}

const destinationBases = [
  ['https://ChatGPT.com/c/123', 'chatgpt.com'],
  ['https://www.Poe.com/chat', 'poe.com'],
  ['CLAUDE.AI', 'claude.ai'],
  ['https://gemini.google.com/app?x=1', 'gemini.google.com'],
  ['https://www.perplexity.ai/search', 'perplexity.ai'],
  ['copilot.microsoft.com/path', 'copilot.microsoft.com'],
  ['https://chat.deepseek.com/a', 'chat.deepseek.com'],
  ['www.notebooklm.google.com', 'notebooklm.google.com'],
  ['https://x.ai/grok', 'x.ai'],
  ['http://localhost:4000/index.html', 'localhost'],
];
for (const [raw, expected] of destinationBases) {
  for (let i = 0; i < 4; i += 1) {
    add('policy-destination', `normalizes destination ${raw} variant ${i + 1}`, () => {
      const input = i === 0 ? raw : i === 1 ? raw.toUpperCase() : i === 2 ? `${raw}/extra/path` : `  ${raw}  `;
      assert.strictEqual(policy.normalizeDestination(input), expected);
    });
  }
}

for (let i = 0; i < 30; i += 1) {
  const host = destinationBases[i % destinationBases.length][1];
  add('policy-destination', `destination match ${i + 1}`, () => {
    if (i % 3 === 0) assert.strictEqual(policy.destinationMatches(host, [host]), true);
    else if (i % 3 === 1) assert.strictEqual(policy.destinationMatches(`sub.${host}`, [`*.${host}`]), true);
    else assert.strictEqual(policy.destinationMatches(host, ['example.invalid']), false);
  });
}

for (let i = 0; i < 20; i += 1) {
  add('policy-destination', `destination decision ${i + 1}`, () => {
    const p = {
      ...policy.DEFAULT_POLICY,
      governedDestinations: ['chatgpt.com'],
      allowedDestinations: ['approved.ai'],
      blockedDestinations: ['blocked.ai'],
      blockUnapprovedAiDestinations: true,
    };
    if (i % 4 === 0) assert.strictEqual(policy.destinationBlocked('blocked.ai', p), true);
    else if (i % 4 === 1) assert.strictEqual(policy.destinationBlocked('approved.ai', p), false);
    else if (i % 4 === 2) assert.strictEqual(policy.destinationReviewed('chatgpt.com', p), true);
    else assert.strictEqual(policy.destinationAllowed('approved.ai', p), true);
  });
}

for (let i = 0; i < 20; i += 1) {
  add('policy-destination', `browser action policy ${i + 1}`, () => {
    const action = ['paste', 'drop', 'copy', 'download'][i % 4];
    const p = { ...policy.DEFAULT_POLICY, blockedBrowserActions: [{ id: `rule_${i}`, action, destinations: ['chatgpt.com'], reason: `${action}_blocked` }] };
    assert.strictEqual(policy.browserActionBlocked(action, 'chatgpt.com', p), true);
    assert.strictEqual(policy.browserActionBlocked(action, 'approved.ai', p), false);
  });
}

for (const destination of ['poe.com', 'chatgpt.com', 'claude.ai', 'gemini.google.com', 'grok.com']) {
  for (const decision of ['govern', 'allow', 'block']) {
    add('policy-destination', `review ${destination} as ${decision}`, () => {
      const result = policy.reviewDestination(policy.DEFAULT_POLICY, destination, decision);
      assert.strictEqual(result.destination, destination);
      assert.strictEqual(result.decision, decision);
    });
  }
}

for (let i = 0; i < 15; i += 1) {
  add('policy-destination', `effective policy scope ${i + 1}`, () => {
    const p = {
      ...policy.DEFAULT_POLICY,
      policyScopes: [{
        id: 'scope_code',
        enabled: true,
        categories: ['SOURCE_CODE'],
        destinations: ['chatgpt.com'],
        enforcementMode: 'block',
        blockRiskScore: 5,
      }],
      policyExceptions: [{
        id: 'allow_legal',
        enabled: true,
        action: 'allow',
        expiresAt: '2030-01-01T00:00:00.000Z',
        categories: ['LEGAL_CONTRACT'],
        destinations: ['claude.ai'],
      }],
    };
    const sourceCode = { findings: [], categories: [{ category: 'SOURCE_CODE', score: 0.9 }], maxSeverity: 3, maxSeverityLabel: 'high', riskScore: 20 };
    const legal = { findings: [], categories: [{ category: 'LEGAL_CONTRACT', score: 0.9 }], maxSeverity: 3, maxSeverityLabel: 'high', riskScore: 20 };
    if (i % 2 === 0) {
      const evaluated = policy.evaluate(sourceCode, p, { destination: 'chatgpt.com' });
      assert.strictEqual(evaluated.decision, 'block');
      assert.ok(evaluated.policyScopeIds.includes('scope_code'));
    } else {
      const evaluated = policy.evaluate(legal, p, { destination: 'claude.ai' });
      assert.strictEqual(evaluated.decision, 'allow');
      assert.strictEqual(evaluated.policyExceptionId, 'allow_legal');
    }
  });
}

const baseGate = {
  prompt: 'Draft a generic branch lobby update.',
  user: 'analyst@example.test',
  destination: 'chatgpt.com',
  source: 'browser_extension',
  channel: 'submit',
};
const gateMutations = [
  ['prompt', (b, s) => { delete b.prompt; b.secret = s; }],
  ['prompt', (b) => { b.prompt = ''; }],
  ['prompt', (b) => { b.prompt = 'x'.repeat(validation.LIMITS.promptChars + 1); }],
  ['clientOutcome', (b) => { b.clientOutcome = 'teleport'; }],
  ['rawPrompt', (b, s) => { b.rawPrompt = s; }],
  ['clientFindings.0.type', (b) => { b.clientFindings = [{ type: 'NOT_REAL_DETECTOR', score: 0.5 }]; }],
  ['clientFindings.0.score', (b) => { b.clientFindings = [{ type: 'US_SSN', score: 2 }]; }],
  ['sensor.token', (b, s) => { b.sensor = { name: 'browser_extension', token: s }; }],
  ['sensor.version', (b) => { b.sensor = { name: 'browser_extension', version: 'x'.repeat(600) }; }],
  ['note', (b) => { b.note = 'x'.repeat(validation.LIMITS.noteChars + 1); }],
  ['clientRiskScore', (b) => { b.clientRiskScore = 101; }],
  ['clientMaxSeverityLabel', (b) => { b.clientMaxSeverityLabel = 'urgent'; }],
];
for (let i = 0; i < 60; i += 1) {
  add('validation-schema', `gate invalid payload ${i + 1}`, () => {
    const payload = clone(baseGate);
    const [field, mutate] = gateMutations[i % gateMutations.length];
    const secret = `524-71-${String(9000 + i).padStart(4, '0')}`;
    mutate(payload, secret);
    expectSchemaField(validation.gateSchema, payload, field, secret);
  });
}

const validOutcomes = [
  'allowed', 'redacted_sent', 'redacted_available', 'injection_blocked', 'shadow_ai',
  'file_too_large', 'file_unsupported', 'ocr_required', 'scan_unavailable', 'destination_blocked',
  'file_upload_blocked', 'action_blocked', 'paste_flagged', 'sent_after_warning', 'justified',
  'blocked_by_user', 'awaiting_approval', null,
];
for (let i = 0; i < 40; i += 1) {
  add('validation-schema', `gate valid payload ${i + 1}`, () => {
    const payload = {
      ...baseGate,
      clientOutcome: validOutcomes[i % validOutcomes.length],
      sensor: { name: 'browser_extension', version: '0.3.0', platform: 'chrome_mv3' },
      clientFindings: i % 2 === 0 ? [{ type: 'US_SSN', severity: 4, score: 0.95, masked: '***-**-6789' }] : [],
      clientCategories: i % 3 === 0 ? [{ category: 'CONFIDENTIAL_BUSINESS', score: 0.8 }] : [],
      clientEntityCounts: i % 2 === 0 ? { US_SSN: 1 } : {},
      clientRiskScore: i % 100,
      clientMaxSeverity: i % 5,
      clientMaxSeverityLabel: ['none', 'low', 'medium', 'high', 'critical'][i % 5],
    };
    expectSchemaPass(validation.gateSchema, payload);
  });
}

for (let i = 0; i < 40; i += 1) {
  add('validation-schema', `scan-file validation ${i + 1}`, () => {
    const valid = {
      filename: `qa-${i}.txt`,
      contentBase64: Buffer.from(`synthetic body ${i}`).toString('base64'),
      user: 'qa@example.test',
      destination: 'chatgpt.com',
    };
    if (i % 4 === 0) expectSchemaField(validation.scanFileSchema, { ...valid, contentBase64: 'not-base64!' }, 'contentBase64');
    else if (i % 4 === 1) expectSchemaField(validation.scanFileSchema, { ...valid, filename: '' }, 'filename');
    else if (i % 4 === 2) expectSchemaField(validation.scanFileSchema, { ...valid, rawFileText: '524-71-9043' }, 'rawFileText', '524-71-9043');
    else expectSchemaPass(validation.scanFileSchema, valid);
  });
}

const policyMutations = [
  ['enforcementMode', (b) => { b.enforcementMode = 'monitor'; }],
  ['alwaysBlock.0', (b) => { b.alwaysBlock = ['NOT_REAL_DETECTOR']; }],
  ['rawRetentionDays', (b) => { b.rawRetentionDays = -1; }],
  ['blockedBrowserActions.0.action', (b) => { b.blockedBrowserActions = [{ id: 'bad_rule', action: 'print', destinations: ['chatgpt.com'] }]; }],
  ['requiredSensors.0', (b) => { b.requiredSensors = ['Browser Extension']; }],
  ['desiredSensorVersions.browser_extension', (b) => { b.desiredSensorVersions = { browser_extension: '0.3.0<script>' }; }],
  ['scanner.maxFileBytes', (b) => { b.scanner = { maxFileBytes: 1 }; }],
  ['governedDestinations.0', (b) => { b.governedDestinations = ['member-524-71-9043.example']; }],
  ['approvalRoutingRules.0.destinations.0', (b) => { b.approvalRoutingRules = [{ id: 'bad_route', destinations: ['member-524-71-9043.example'], assignedGroup: 'security', assignedRole: 'approver', slaMinutes: 60 }]; }],
  ['approvalRoutingRules.0.detectors.0', (b) => { b.approvalRoutingRules = [{ id: 'bad_route', detectors: ['NOT_REAL_DETECTOR'], assignedGroup: 'security', assignedRole: 'approver', slaMinutes: 60 }]; }],
  ['policyScopes.0.id', (b) => { b.policyScopes = [{ id: 'bad_scope' }]; }],
  ['policyExceptions.0.expiresAt', (b) => { b.policyExceptions = [{ id: 'bad_exception', expiresAt: 'not-a-date', users: ['qa@example.test'] }]; }],
];
for (let i = 0; i < 50; i += 1) {
  add('validation-schema', `policy invalid payload ${i + 1}`, () => {
    const payload = {};
    const [field, mutate] = policyMutations[i % policyMutations.length];
    mutate(payload);
    expectSchemaField(validation.policyUpdateSchema, payload, field);
  });
}

const miscSchemaCases = [
  [validation.loginSchema, { user: '', password: 'unit-pass' }, 'user'],
  [validation.loginSchema, { user: 'admin', password: '' }, 'password'],
  [validation.loginSchema, { user: 'admin', password: 'unit-pass', otp: '1'.repeat(40) }, 'otp'],
  [validation.updateConfigSchema, { remoteName: '-origin' }, 'remoteName'],
  [validation.updateConfigSchema, { branch: 'main..bad' }, 'branch'],
  [validation.updateConfigSchema, { restartCommand: 'npm run start && whoami' }, 'restartCommand'],
  [validation.destinationReviewSchema, { destination: 'member-524-71-9043.example', decision: 'allow', reason: 'pilot' }, 'destination'],
  [validation.destinationReviewSchema, { destination: 'poe.com', decision: 'maybe', reason: 'pilot' }, 'decision'],
  [validation.destinationReviewSchema, { destination: 'poe.com', decision: 'allow', reason: '' }, 'reason'],
  [validation.applyTemplateSchema, { id: '../bad' }, 'id'],
];
for (let i = 0; i < 30; i += 1) {
  add('validation-schema', `misc schema invalid ${i + 1}`, () => {
    const [schema, payload, field] = miscSchemaCases[i % miscSchemaCases.length];
    expectSchemaField(schema, payload, field, '524-71-9043');
  });
}

const selectorMarkers = [
  'id="f"', 'id="user"', 'id="password"', 'id="otp"', 'id="oidc"', 'id="err"', 'aria-live="polite"', 'autocomplete="username"',
  'autocomplete="current-password"', 'autocomplete="one-time-code"', 'id="globalSearch"', 'id="refreshQueue"', 'id="queueList"', 'data-queue-filter="all"',
  'id="queueCategoryFilter"', 'id="queueDestinationFilter"', 'id="incidentDetail"', 'id="topEntities"', 'id="monitorSearch"', 'id="monitorStatusFilters"',
  'id="monitorMetrics"', 'id="monitorPanelGrid"', 'id="monitorActivityFeed"', 'id="monitorInspector"', 'id="activityRows"', 'id="activityPager"',
  'id="refreshCoverage"', 'id="coverageScore"', 'id="coveragePosture"', 'id="fleetRows"', 'id="endpointAiToolRows"', 'id="governedRows"',
  'id="shadowRows"', 'id="identityProvider"', 'id="identityTenant"', 'id="refreshIdentity"', 'id="identitySummary"', 'id="identityScimRows"',
  'id="identityOidcRows"', 'id="identityEnvRows"', 'id="identityRoleRows"', 'id="identityValidation"', 'id="refreshLineage"', 'id="lineageSummary"',
  'id="lineageUsers"', 'id="lineageDestinations"', 'id="lineageSensors"', 'id="lineageCategories"', 'id="lineageChannels"', 'id="lineageDecisions"',
  'id="exportEvidence"', 'id="exportStatus"', 'id="integrity"', 'id="auditRows"', 'id="auditPager"', 'id="policyBox"', 'id="configurationStatus"',
  'id="updateBox"', 'id="updateConsoleStatus"', 'id="logout"', 'data-tab="queue"', 'data-tab="monitor"', 'data-tab="activity"', 'data-tab="coverage"',
  'data-tab="identity"', 'data-tab="lineage"', 'data-tab="audit"', 'data-tab="policy"', 'data-tab="updates"', 'aria-label="Pending approval prompts"',
  'aria-label="AI Command Center"', 'aria-label="All Activity"', 'aria-label="Coverage"', 'aria-label="Identity"', 'aria-label="Lineage"', 'aria-label="Audit Log"',
];
for (const marker of selectorMarkers) {
  add('static-ui', `ui marker ${marker}`, () => expectContains(dashboardHtml + loginHtml, marker));
}

const accessibilityMarkers = [
  /role="alert"/, /aria-describedby="err"/, /aria-current="page"/, /aria-pressed="/, /aria-selected="/,
  /role="list"/, /role="listbox"/, /role="option"/, /aria-busy="/, /aria-expanded="/,
  /aria-hidden="true"/, /aria-label="Approval queue metadata filters"/, /aria-invalid/, /aria-live="polite"/,
  /label for="user"/, /label for="password"/, /label for="otp"/, /data-queue-filter="all"/,
  /label for="queueCategoryFilter"/, /label for="queueDestinationFilter"/, /label for="monitorSearch"/,
  /inputmode="numeric"/, /type="search"/, /type="password"/, /type="button"/,
  /type="submit"/, /maxlength="6"/, /placeholder="Filter signals"/, /placeholder="Password"/,
  /role="region"/, /aria-label="Selected incident details"/, /aria-label="Status filters"/,
  /aria-label="Monitored systems"/, /aria-label="Signal event timeline"/, /aria-label="Identity provider"/,
  /aria-label="Tenant or domain"/, /aria-live="polite"/, /role="img"/, /aria-label="Live monitoring online"/,
];
for (const pattern of accessibilityMarkers) {
  add('static-ui', `accessibility marker ${pattern}`, () => expectMatch(dashboardHtml + dashboardJs + loginHtml + loginJs, pattern));
}

const securityStaticCases = [
  () => assert.strictEqual(/\son[a-z]+\s*=/.test(dashboardHtml), false),
  () => assert.strictEqual(/\son[a-z]+\s*=/.test(loginHtml), false),
  () => assert.strictEqual(/<script>\s*\S/.test(dashboardHtml), false),
  () => assert.strictEqual(/<script>\s*\S/.test(loginHtml), false),
  () => {
    expectContains(dashboardHtml, '<script src="/siem-package.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/ai-threat-guardrails.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/operator-flow.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/policy-guides.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/behavior-baselines.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/competitive-readiness.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/coverage-file-flow.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/decision-quality.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/detector-feedback.js" defer></script>');
    expectContains(dashboardHtml, '<script src="/dashboard.js" defer></script>');
    expectContains(dashboardHtml, 'id="endpointFileFlowRows"');
    expectContains(dashboardHtml, 'Endpoint File Flow');
    expectContains(dashboardHtml, 'id="decisionQualityRows"');
    expectContains(dashboardHtml, 'Decision Quality');
    expectContains(dashboardHtml, 'id="behaviorBaselineRows"');
    expectContains(dashboardHtml, 'Behavior Baselines');
    expectContains(dashboardHtml, 'id="detectorFeedbackRows"');
    expectContains(dashboardHtml, 'Detection Feedback');
    expectContains(threatGuardrailsJs, 'PromptWallThreatGuardrails');
    expectContains(operatorFlowJs, 'PromptWallOperatorFlow');
    expectContains(operatorFlowJs, 'data-flow-target');
    expectContains(operatorFlowJs, 'Behavior baselines');
    expectContains(policyGuidesJs, 'addApprovalRoute');
    expectContains(policyGuidesJs, 'addMcpToolRule');
    expectContains(behaviorBaselinesJs, 'PromptWallBehaviorBaselines');
    expectContains(behaviorBaselinesJs, 'behavior-baseline-row');
    expectContains(competitiveReadinessJs, 'competitiveReadiness');
    expectContains(competitiveReadinessJs, '/api/posture?limit=5000');
    expectContains(coverageFileFlowJs, 'endpointFileFlowProfiles');
    expectContains(coverageFileFlowJs, 'Local path: not reported');
    expectContains(decisionQualityJs, 'decisionQuality');
    expectContains(decisionQualityJs, 'PromptWallDecisionQuality');
    expectContains(detectorFeedbackJs, '/api/detector-feedback/report');
    expectContains(detectorFeedbackJs, 'PromptWallDetectorFeedback');
  },
  () => expectContains(loginHtml, '<script src="/login.js" defer></script>'),
  () => expectContains(dashboardJs, 'escapeHtml'),
  () => expectContains(dashboardJs, 'csrfToken'),
  () => expectContains(dashboardJs, "headers.set('x-csrf-token', csrfToken)"),
  () => expectContains(loginJs, "fetch('/api/login-options')"),
  () => assert.ok(!/client_secret|OIDC_CLIENT_SECRET/.test(loginJs)),
  () => expectContains(dashboardJs, 'apiErrorSummary'),
  () => expectContains(dashboardJs, 'responseJsonObjectBody'),
  () => expectContains(dashboardJs, 'rawDiffersFromRedacted'),
  () => expectContains(dashboardJs, 'prompt-reveal-status'),
  () => expectContains(dashboardJs, 'Run retention purge'),
  () => expectContains(dashboardJs, 'Update from GitHub'),
  () => expectContains(dashboardJs, 'confirmBackup'),
  () => expectContains(dashboardJs, 'Save configuration'),
  () => expectContains(dashboardJs, 'Read-only auditor view'),
  () => expectContains(dashboardHtml, 'Security Console'),
  () => expectContains(dashboardHtml, 'Tamper-evident Audit Log'),
  () => expectContains(dashboardHtml, 'Live posture objectives, sanitized AI activity, and control outcomes without prompt bodies.'),
  () => expectContains(loginHtml, 'Hash-chained audit history'),
  () => expectContains(loginHtml, 'Local-first detection posture'),
  () => expectContains(dashboardJs, 'prompt-reveal-status'),
  () => expectContains(dashboardJs, 'rawPrompt'),
  () => expectContains(dashboardJs, 'policyExceptions'),
  () => expectContains(dashboardJs, 'blockedBrowserActions'),
  () => expectContains(dashboardJs, 'blockUnapprovedAiDestinations'),
  () => expectContains(dashboardJs, 'loadQueue'),
  () => expectContains(dashboardJs, 'loadCoverage'),
  () => expectContains(dashboardJs, 'loadIdentitySetup'),
  () => expectContains(dashboardJs, 'loadLineage'),
  () => {
    expectContains(dashboardJs, 'loadUpdates');
    expectContains(siemPackageJs, '/api/integrations/siem/package?profile=');
    expectContains(siemPackageJs, 'siem-profile-row');
  },
];
for (let i = 0; i < securityStaticCases.length; i += 1) {
  add('static-ui', `static security marker ${i + 1}`, securityStaticCases[i]);
}

const responsiveMarkers = [
  /@media\(max-width:1180px\)/, /content-tabs\{display:flex;top:0/, /@media\(max-width:760px\)/,
  /@media\(max-width:820px\)/, /grid-template-columns:minmax\(0,1fr\)/, /overflow-x:auto/,
  /minmax\(0,1fr\)/, /word-break:break-word/, /overflow-wrap:anywhere/, /scrollbar-width:none/,
  /position:sticky/, /max-width:460px/, /width:min\(100%,920px\)/, /height:100vh/,
  /min-height:44px/, /min-height:40px/, /border-radius:8px/, /letter-spacing:0/,
  /prefers-reduced-motion/, /queue-density-compact/, /body\[data-theme="dark"\]/, /data-theme-choice="light"/,
  /data-theme-choice="dark"/, /aria-hidden="true"/, /viewport/, /device-width/,
  /grid-template-columns:repeat/, /flex-wrap:wrap/, /white-space:nowrap/, /text-overflow:ellipsis/,
];
for (const pattern of responsiveMarkers) {
  add('static-ui', `responsive marker ${pattern}`, () => expectMatch(dashboardHtml + loginHtml, pattern));
}

async function jsonFetch(port, apiPath, { method = 'GET', body, headers = {} } = {}) {
  return loopbackHttpFetch(`http://127.0.0.1:${port}${apiPath}`, {
    method,
    headers: body === undefined ? headers : { 'Content-Type': 'application/json', ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function login(port) {
  const res = await jsonFetch(port, '/api/login', {
    method: 'POST',
    body: { user: 'admin', password: 'unit-pass' },
  });
  assert.strictEqual(res.status, 200);
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  assert.ok(cookie.includes('promptwall_session='));
  const csrfRes = await jsonFetch(port, '/api/csrf', { headers: { cookie } });
  assert.strictEqual(csrfRes.status, 200);
  const csrf = await csrfRes.json();
  return { cookie, csrfToken: csrf.csrfToken };
}

function addHttpCases(ctx) {
  const publicRoutes = [
    ['/healthz', 200], ['/readyz', 200], ['/login.html', 200], ['/', 302], ['/index.html', 302],
    ['/api/me', 401], ['/api/queries', 401], ['/api/stats', 401], ['/api/policy', 401], ['/api/audit', 401],
    ['/api/coverage', 401], ['/api/lineage', 401], ['/api/risk', 401], ['/api/preflight', 401], ['/api/export/evidence', 401],
    ['/api/billing/seats', 401], ['/api/metrics', 401], ['/api/update/status', 401], ['/api/identity/setup-guide', 401],
    ['/api/policy/templates', 401], ['/api/policy/impact', 401], ['/api/destinations/review', 401], ['/api/v1/policy', 401], ['/api/v1/detectors', 401],
    ['/api/login-options', 200], ['/missing-page', 404], ['/dashboard.js', 200], ['/login.js', 200], ['/api/stream', 401],
    ['/api/queries/not-real-id', 401], ['/api/v1/status/not-real-id', 401], ['/api/update/check', 401], ['/api/update/apply', 401],
    ['/api/update/restart', 401], ['/api/logout', 401], ['/api/retention/purge', 401],
  ];
  const postRoutes = new Set(['/api/update/check', '/api/update/apply', '/api/update/restart', '/api/logout', '/api/retention/purge', '/api/policy/impact']);
  for (const [route, status] of publicRoutes) {
    add('http-webapp', `unauth route ${route}`, async () => {
      const res = await jsonFetch(ctx.port, route, { method: postRoutes.has(route) ? 'POST' : 'GET' });
      assert.strictEqual(res.status, status);
    });
  }

  const authGetRoutes = [
    '/api/me', '/api/queries', '/api/stats', '/api/preflight', '/api/policy', '/api/audit',
    '/api/coverage', '/api/lineage', '/api/risk', '/api/policy/templates', '/api/destinations/review',
    '/api/identity/setup-guide', '/api/update/status', '/api/billing/seats', '/api/metrics',
  ];
  for (let i = 0; i < 30; i += 1) {
    const route = authGetRoutes[i % authGetRoutes.length];
    add('http-webapp', `auth route ${i + 1} ${route}`, async () => {
      const res = await jsonFetch(ctx.port, route, { headers: { cookie: ctx.cookie } });
      assert.ok([200, 204].includes(res.status), `expected 2xx for ${route}, got ${res.status}`);
    });
  }

  for (let i = 0; i < 24; i += 1) {
    add('http-webapp', `ingest boundary ${i + 1}`, async () => {
      if (i % 5 === 0) {
        const res = await jsonFetch(ctx.port, '/api/v1/gate', { method: 'POST', body: { prompt: 'safe prompt' } });
        assert.strictEqual(res.status, 401);
      } else if (i % 5 === 1) {
        const res = await jsonFetch(ctx.port, '/api/v1/gate', { method: 'POST', headers: { 'x-api-key': 'unit-ingest-key' }, body: { prompt: '' } });
        assert.strictEqual(res.status, 400);
        assert.ok((await res.json()).fields.includes('prompt'));
      } else if (i % 5 === 2) {
        const res = await jsonFetch(ctx.port, '/api/v1/gate', { method: 'POST', headers: { 'x-api-key': 'unit-ingest-key' }, body: { prompt: 'Draft a lobby update.', destination: 'chatgpt.com' } });
        assert.strictEqual(res.status, 200);
        assert.strictEqual((await res.json()).decision, 'allow');
      } else if (i % 5 === 3) {
        const res = await jsonFetch(ctx.port, '/api/v1/scan-response', { method: 'POST', headers: { 'x-api-key': 'unit-ingest-key' }, body: { text: 'response with card 4111 1111 1111 1111', destination: 'chatgpt.com' } });
        assert.strictEqual(res.status, 200);
        assert.ok(['flag', 'redact', 'block', 'allow'].includes((await res.json()).decision));
      } else {
        const res = await jsonFetch(ctx.port, '/api/v1/heartbeat', { method: 'POST', headers: { 'x-api-key': 'unit-ingest-key' }, body: { source: 'browser_extension', checks: [{ id: 'extension_manifest', ok: true, detail: 'ok' }] } });
        assert.strictEqual(res.status, 200);
      }
    });
  }

  const headerRoutes = ['/healthz', '/readyz', '/login.html', '/dashboard.js', '/siem-package.js', '/policy-guides.js', '/behavior-baselines.js', '/login.js'];
  for (let i = 0; i < 20; i += 1) {
    const route = headerRoutes[i % headerRoutes.length];
    add('http-webapp', `security header ${i + 1} ${route}`, async () => {
      const res = await jsonFetch(ctx.port, route);
      assert.strictEqual(res.headers.get('x-powered-by'), null);
      assert.strictEqual(res.headers.get('x-content-type-options'), 'nosniff');
      assert.match(res.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
    });
  }
}

const extensionMarkers = [
  'manifest_version', 'host_permissions', 'content_scripts', 'background', 'service_worker',
  'storage', 'managed_schema', 'default_popup', 'downloads', 'alarms',
  'chatgpt.com', 'claude.ai', 'gemini.google.com', 'copilot.microsoft.com', 'perplexity.ai',
  'poe.com', 'deepseek.com', 'qwen.ai', 'grok.com', 'localhost',
];
for (const marker of extensionMarkers) {
  add('browser-extension-static', `manifest marker ${marker}`, () => {
    assert.ok(JSON.stringify(manifest).includes(marker), `missing ${marker}`);
  });
}

const extensionContentMarkers = [
  'document.addEventListener(\'keydown\'', 'document.addEventListener(\'click\'', 'document.addEventListener(\'paste\'',
  'document.addEventListener(\'copy\'', 'document.addEventListener(\'drop\'', 'type: \'report\'',
  'clientPreRedacted', 'safeClientPrompt', 'reportBlockedBrowserAction', 'reportLocalFileEvent',
  'TEXT_UPLOAD_EXTENSIONS', 'OCR_UPLOAD_EXTENSIONS', 'cleanUploadBypass', 'showBanner',
  'role\', \'alertdialog\'', 'aria-labelledby', 'aria-describedby', 'D.tokenize', 'D.detokenize', 'window.PSAdapters',
];
for (const marker of extensionContentMarkers) {
  add('browser-extension-static', `content marker ${marker}`, () => expectContains(contentJs, marker));
}

const extensionBackgroundMarkers = [
  'failClosed', 'missingServerConfigReason', 'validServerOrigin', 'sensorMetadata', 'buildInstallChecks',
  'reportInstallHealth', 'refreshPolicy', 'fetchJsonWithTimeout', 'browserActionBlockRule', 'handleDownloadCreated',
];
for (const marker of extensionBackgroundMarkers) {
  add('browser-extension-static', `background marker ${marker}`, () => expectContains(backgroundJs, marker));
}

test('1000-case webapp QA matrix passes', async () => {
  const server = await listen(app);
  const ctx = { port: server.address().port };
  try {
    Object.assign(ctx, await login(ctx.port));
    addHttpCases(ctx);

    assert.deepStrictEqual(areaCounts(), {
      'detector-positive': 180,
      'detector-negative': 120,
      'policy-destination': 140,
      'validation-schema': 220,
      'static-ui': 180,
      'browser-extension-static': 50,
      'http-webapp': 110,
    });
    assert.strictEqual(cases.length, 1000);

    const failures = [];
    for (let i = 0; i < cases.length; i += 1) {
      const item = cases[i];
      try {
        await item.run();
      } catch (err) {
        failures.push(`${i + 1}. [${item.area}] ${item.name}: ${err && err.message ? err.message : err}`);
      }
    }
    if (failures.length) {
      assert.fail(`${failures.length} QA matrix case(s) failed:\n${failures.slice(0, 20).join('\n')}`);
    }

    assert.strictEqual(adapters.isAiHost('chatgpt.com'), true);
    assert.strictEqual(adapters.isGoverned('chatgpt.com', manifest.content_scripts[0].matches), true);
    assert.strictEqual(browserAdaptersJs.includes('scanInjection'), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(process.env.SENTINEL_DB_PATH + suffix); } catch {}
  }
  try { fs.unlinkSync(policyPath); } catch {}
});
