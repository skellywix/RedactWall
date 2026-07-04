'use strict';
/**
 * Native Linear approval-ticket smoke.
 *
 * This exercises server/notifiers.js against Linear with a synthetic routed
 * approval. The request body is built from the same sanitized notifier payload
 * used in production and is checked for raw prompt markers before any network
 * call is made.
 */
require('../server/env').loadEnv();
const notifiers = require('../server/notifiers');

const SENSITIVE_MARKERS = [
  '000-00-0000',
  'Synthetic Member',
  'sealed-linear-smoke-raw',
  'sealed-linear-smoke-vault',
  'linear-smoke-release-token',
  'ps_ingest_linear_smoke_secret',
];

function envValue(env, ...names) {
  for (const name of names) {
    const value = env && env[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function csv(value) {
  return String(value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseArgs(argv = []) {
  const args = { send: false };
  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (raw === '--send') {
      args.send = true;
      continue;
    }
    const match = /^--([^=]+)=(.*)$/.exec(raw);
    const key = match ? match[1] : raw.startsWith('--') ? raw.slice(2) : '';
    if (!key) continue;
    const value = match ? match[2] : argv[i + 1];
    if (!match) i += 1;
    if (key === 'team-id') args.teamId = value;
    else if (key === 'state-id') args.stateId = value;
    else if (key === 'project-id') args.projectId = value;
    else if (key === 'label-ids') args.labelIds = value;
    else if (key === 'api-url') args.apiUrl = value;
    else if (key === 'query-id') args.queryId = value;
  }
  return args;
}

function linearEnv(env, args) {
  const out = { ...env };
  if (args.apiUrl) out.PROMPTWALL_APPROVAL_LINEAR_API_URL = args.apiUrl;
  if (args.teamId) out.PROMPTWALL_APPROVAL_LINEAR_TEAM_ID = args.teamId;
  if (args.stateId) out.PROMPTWALL_APPROVAL_LINEAR_STATE_ID = args.stateId;
  if (args.projectId) out.PROMPTWALL_APPROVAL_LINEAR_PROJECT_ID = args.projectId;
  if (args.labelIds) out.PROMPTWALL_APPROVAL_LINEAR_LABEL_IDS = args.labelIds;
  return out;
}

function linearChannelForPayload(env) {
  const teamId = envValue(env, 'PROMPTWALL_APPROVAL_LINEAR_TEAM_ID', 'APPROVAL_LINEAR_TEAM_ID');
  if (!teamId) throw new Error('missing Linear team id: set PROMPTWALL_APPROVAL_LINEAR_TEAM_ID or pass --team-id');
  const url = notifiers.linearApiUrl(envValue(env, 'PROMPTWALL_APPROVAL_LINEAR_API_URL', 'APPROVAL_LINEAR_API_URL'));
  if (!url) throw new Error('invalid Linear API URL: use an https:// endpoint');
  return {
    type: 'linear',
    name: 'linear',
    url,
    teamId,
    stateId: envValue(env, 'PROMPTWALL_APPROVAL_LINEAR_STATE_ID', 'APPROVAL_LINEAR_STATE_ID'),
    projectId: envValue(env, 'PROMPTWALL_APPROVAL_LINEAR_PROJECT_ID', 'APPROVAL_LINEAR_PROJECT_ID'),
    labelIds: csv(envValue(env, 'PROMPTWALL_APPROVAL_LINEAR_LABEL_IDS', 'APPROVAL_LINEAR_LABEL_IDS')),
  };
}

function syntheticApprovalQuery({ now = new Date(), queryId } = {}) {
  const createdAt = new Date(now.getTime() - 60 * 1000).toISOString();
  const slaDueAt = new Date(now.getTime() + 30 * 60 * 1000).toISOString();
  return {
    id: queryId || `linear_smoke_${now.toISOString().replace(/[^0-9]/g, '').slice(0, 14)}`,
    createdAt,
    status: 'pending',
    user: 'linear-smoke@example.test',
    orgId: 'promptwall-smoke',
    source: 'linear_smoke',
    channel: 'approval_ticket',
    sensor: {
      name: 'linear_smoke',
      version: 'local',
      platform: 'codex',
      ingestKey: 'ps_ingest_linear_smoke_secret',
    },
    destination: 'chatgpt.com',
    redactedPrompt: 'Synthetic Member has SSN [US_SSN]',
    _rawPrompt: 'sealed-linear-smoke-raw Synthetic Member 000-00-0000',
    _tokenVault: 'sealed-linear-smoke-vault',
    _releaseTokenHash: 'linear-smoke-release-token',
    decisionNote: 'Synthetic Member 000-00-0000 should never be sent to Linear',
    findings: [{ type: 'US_SSN', severity: 4, score: 0.92, masked: '***-**-0000', value: '000-00-0000' }],
    categories: [],
    reasons: ['Hard-stop entity present: US_SSN'],
    riskScore: 88,
    maxSeverity: 4,
    maxSeverityLabel: 'critical',
    assignedRole: 'security_admin',
    assignedGroup: 'security',
    workflowReason: 'linear_smoke',
    slaDueAt,
    escalatedAt: null,
    notificationStatus: 'not_configured',
  };
}

function assertSanitizedWire(wire) {
  for (const marker of SENSITIVE_MARKERS) {
    if (wire.includes(marker)) throw new Error(`Linear smoke payload leaked marker: ${marker}`);
  }
}

function buildSmokeRequest({ env = process.env, argv = [], now = new Date() } = {}) {
  const args = Array.isArray(argv) ? parseArgs(argv) : argv;
  const mergedEnv = linearEnv(env, args);
  const channel = linearChannelForPayload(mergedEnv);
  const query = syntheticApprovalQuery({ now, queryId: args.queryId });
  const payload = notifiers.sanitizedApprovalNotification(query);
  const body = notifiers.linearIssuePayload(channel, payload);
  const wire = JSON.stringify(body);
  assertSanitizedWire(wire);
  return { args, body, channel, env: mergedEnv, payload, query, wire };
}

async function runSmoke({ env = process.env, argv = process.argv.slice(2), fetchImpl = fetch, now = new Date() } = {}) {
  const request = buildSmokeRequest({ env, argv, now });
  if (!request.args.send) {
    return {
      dryRun: true,
      sent: false,
      queryId: request.query.id,
      title: request.body.variables.input.title,
      teamId: request.body.variables.input.teamId,
      url: request.channel.url,
    };
  }

  if (!envValue(request.env, 'PROMPTWALL_APPROVAL_LINEAR_API_KEY', 'APPROVAL_LINEAR_API_KEY')) {
    throw new Error('missing Linear API key: set PROMPTWALL_APPROVAL_LINEAR_API_KEY or APPROVAL_LINEAR_API_KEY before --send');
  }

  const result = await notifiers.emitApprovalNotification(request.query, {
    env: request.env,
    fetch: fetchImpl,
  });
  const linear = (result.results || []).find((item) => item.channel === 'linear') || null;
  if (!result.sent || !linear || !linear.sent) {
    const reason = linear && linear.reason ? linear.reason : result.reason || result.status || 'unknown';
    throw new Error(`Linear approval smoke failed: ${reason}`);
  }
  return {
    dryRun: false,
    sent: true,
    queryId: request.query.id,
    externalId: linear.externalId || null,
    url: linear.url || null,
    status: result.status,
  };
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const run = deps.runSmoke || ((options) => runSmoke(options));
  const result = await run({ argv, env: deps.env || process.env, fetchImpl: deps.fetchImpl || fetch, now: deps.now || new Date() });
  if (result.dryRun) {
    io.log(`LINEAR_APPROVAL_SMOKE_DRY_RUN query=${result.queryId} team=${result.teamId} endpoint=${result.url}`);
    io.log(`title=${result.title}`);
    io.log('wire=sanitized send=false');
    io.log('Add --send after setting PROMPTWALL_APPROVAL_LINEAR_API_KEY to create a real Linear issue.');
    return;
  }
  io.log(`LINEAR_APPROVAL_SMOKE_OK query=${result.queryId} issue=${result.externalId || 'created'} status=${result.status}`);
  if (result.url) io.log(`url=${result.url}`);
}

if (require.main === module) main().catch((err) => { console.error(err && err.message ? err.message : err); process.exitCode = 1; });

module.exports = {
  assertSanitizedWire,
  buildSmokeRequest,
  linearChannelForPayload,
  linearEnv,
  main,
  parseArgs,
  runSmoke,
  syntheticApprovalQuery,
};
