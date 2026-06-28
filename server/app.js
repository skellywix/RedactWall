'use strict';
/**
 * PromptWall — inline DLP gateway for AI chat prompts.
 *
 * Flow:
 *   1. The network proxy (Squid+ICAP) or an SDK calls POST /api/v1/gate with the
 *      user's prompt + context before it is allowed to reach the AI service.
 *   2. PromptWall analyzes for PII, applies policy, and either ALLOWS or
 *      BLOCKS (holds) the prompt. Blocked prompts enter the approval queue.
 *   3. A Security Admin reviews the queue in the dashboard and approves/denies.
 *   4. The waiting client polls GET /api/v1/status/:id (or long-poll /await/:id)
 *      and proceeds only if released.
 */
require('./env').loadEnv();
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

const detector = require('./detector');
const processors = require('./processors');
const policy = require('./policy');
const db = require('./db');
const auth = require('./auth');
const dataCrypto = require('./crypto');
const templates = require('./templates');
const alerts = require('./alerts');
const evidence = require('./evidence');
const preflight = require('./preflight');
const validation = require('./validation');
const coverage = require('./coverage');
const releaseTokens = require('./release-token');
const tenant = require('./tenant');
const routing = require('./routing');
const workflow = require('./workflow');
const roles = require('./roles');
const scim = require('./scim');
const oidc = require('./oidc');
const identitySetup = require('./identity-setup');

const app = express();
const PORT = process.env.PORT || 4000;
const SECURE_COOKIE = preflight.bool(process.env.COOKIE_SECURE || process.env.HTTPS);
const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'strict',
  secure: SECURE_COOKIE,
  path: '/',
  maxAge: 8 * 3600 * 1000,
};
const SESSION_COOKIE_CLEAR_OPTIONS = {
  path: SESSION_COOKIE_OPTIONS.path,
  sameSite: SESSION_COOKIE_OPTIONS.sameSite,
  secure: SESSION_COOKIE_OPTIONS.secure,
};
const OIDC_STATE_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: SECURE_COOKIE,
  path: '/',
  maxAge: oidc.STATE_TTL_MS,
};
const OIDC_STATE_COOKIE_CLEAR_OPTIONS = {
  path: OIDC_STATE_COOKIE_OPTIONS.path,
  sameSite: OIDC_STATE_COOKIE_OPTIONS.sameSite,
  secure: OIDC_STATE_COOKIE_OPTIONS.secure,
};

app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use((req, res, next) => {
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

app.use(express.json({ limit: '12mb', type: ['application/json', 'application/*+json'] }));
app.use('/scim/v2', scim.router());
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'request body too large' });
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) return res.status(400).json({ error: 'invalid json' });
  return next(err);
});
app.use(cookieParser());

// ---- Health / readiness (public, no sensitive data) -------------------------
app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'promptwall', version: require('../package.json').version }));
app.get('/readyz', (req, res) => {
  try {
    db.stats();
    const cfg = currentPreflight();
    res.status(cfg.ready ? 200 : 503).json({ ready: cfg.ready, database: true, configuration: cfg.level });
  } catch (e) {
    res.status(503).json({ ready: false, database: false, error: String((e && e.message) || e) });
  }
});

// ---- Live updates (Server-Sent Events) --------------------------------------
const sseClients = new Set();
function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) { try { res.write(payload); } catch {} }
}

function emitSecurityAlert(row, action, opts = {}) {
  fireSecurityAlert(row, { action, ...opts });
  if (!opts.adminEvent) {
    workflow.fireAndPersistApprovalNotification(row, {
      db,
      action: action === 'APPROVAL_ESCALATED' ? action : 'APPROVAL_ROUTED',
      onUpdate: (updated) => broadcast('query', { type: updated.status, query: publicQuery(updated) }),
    });
    try {
      emitSensorVersionGapAlert(row);
    } catch {}
  }
}

function fireSecurityAlert(row, opts) {
  try {
    Promise.resolve(alerts.emitSecurityAlert(row, opts)).catch(() => {});
  } catch {}
}

const SENSOR_VERSION_ALERT_SOURCES = new Set(['browser_extension', 'endpoint_agent', 'mcp_guard']);

function sensorVersionGapFor(row) {
  if (!row || !SENSOR_VERSION_ALERT_SOURCES.has(row.source)) return null;
  const report = coverage.summarize(db.listQueries({ limit: 5000 }), policy.loadPolicy());
  const sensor = (report.sensors || []).find((item) => item.source === row.source);
  if (!sensor || !sensor.events || sensor.versionHealth === 'current') return null;
  return {
    source: sensor.source,
    label: sensor.label,
    versionHealth: sensor.versionHealth,
    latestVersion: sensor.latestVersion || null,
    desiredVersion: sensor.desiredVersion || null,
    versions: (sensor.versions || []).map((item) => ({
      version: item.version,
      events: item.events,
      lastSeen: item.lastSeen,
    })),
    platforms: sensor.platforms || [],
  };
}

function emitSensorVersionGapAlert(row) {
  const gap = sensorVersionGapFor(row);
  if (!gap) return;
  fireSecurityAlert(row, {
    action: 'SENSOR_VERSION_GAP',
    force: true,
    sensorVersionGap: gap,
  });
}

function emitAdminSecurityAlert(req, action, actor, scope) {
  const q = req && req.params && req.params.id ? db.getQuery(req.params.id) : null;
  if (!q) return;
  emitSecurityAlert(q, action, {
    force: true,
    adminEvent: true,
    adminActor: actor || 'unknown',
    stepUpScope: scope || null,
  });
}

// =============================================================================
// INGEST / GATE  (called by the proxy/SDK — protected by an API key)
// =============================================================================
const INGEST_KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const INGEST_AUTH_MAX_FAILURES = boundedEnvInt('INGEST_AUTH_MAX_FAILURES', 20, 3, 1000);
const INGEST_AUTH_WINDOW_MS = boundedEnvInt('INGEST_AUTH_WINDOW_MS', 60000, 1000, 3600000);
const INGEST_AUTH_LOCK_MS = boundedEnvInt('INGEST_AUTH_LOCK_MS', 60000, 1000, 3600000);
const ingestFailures = new Map();

function currentPreflight() {
  return preflight.configStatus({
    env: process.env,
    adminPasswordIsDefault: auth.ADMIN_PASSWORD_IS_DEFAULT,
    ingestKeyIsDefault: INGEST_KEY === 'dev-ingest-key',
    secretSource: auth.SECRET_SOURCE,
    dataCryptoEnabled: dataCrypto.ENABLED,
    cookieSecure: SESSION_COOKIE_OPTIONS.secure,
    dbPath: process.env.SENTINEL_DB_PATH || '',
  });
}

function publicBaseUrl(req) {
  const forwardedProto = String(req.get('x-forwarded-proto') || '').split(',')[0].trim();
  const forwardedHost = String(req.get('x-forwarded-host') || '').split(',')[0].trim();
  const proto = forwardedProto || req.protocol || 'http';
  const host = forwardedHost || req.get('host') || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

function checkIngestKey(req, res, next) {
  const key = req.get('x-api-key') || '';
  const subject = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
  if (constantTimeStringEqual(key, INGEST_KEY)) {
    ingestFailures.delete(subject);
    return next();
  }
  const status = registerIngestFailure(subject);
  if (status.locked) return res.status(429).json({ error: 'too many ingest key attempts', retryMs: status.retryMs });
  return res.status(401).json({ error: 'invalid ingest key' });
}

function constantTimeStringEqual(actual, expected) {
  const actualText = String(actual || '');
  const expectedText = String(expected || '');
  if (actualText.length > 4096 || expectedText.length > 4096) return false;
  const length = Math.max(actualText.length, expectedText.length, 1);
  const actualBuffer = Buffer.alloc(length);
  const expectedBuffer = Buffer.alloc(length);
  Buffer.from(actualText).copy(actualBuffer);
  Buffer.from(expectedText).copy(expectedBuffer);
  return actualText.length === expectedText.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function boundedEnvInt(name, fallback, min, max) {
  const n = Number(process.env[name]);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function registerIngestFailure(subject) {
  const now = Date.now();
  const current = ingestFailures.get(subject) || { count: 0, firstAt: now, lockedUntil: 0 };
  if (current.lockedUntil > now) return { locked: true, retryMs: current.lockedUntil - now };
  if (now - current.firstAt > INGEST_AUTH_WINDOW_MS) {
    current.count = 0;
    current.firstAt = now;
    current.lockedUntil = 0;
  }
  current.count += 1;
  if (current.count >= INGEST_AUTH_MAX_FAILURES) current.lockedUntil = now + INGEST_AUTH_LOCK_MS;
  ingestFailures.set(subject, current);
  return { locked: current.lockedUntil > now, retryMs: Math.max(0, current.lockedUntil - now) };
}

function pruneIngestFailures() {
  const now = Date.now();
  for (const [subject, status] of ingestFailures) {
    if (status.lockedUntil > now) continue;
    if (now - status.firstAt <= INGEST_AUTH_WINDOW_MS) continue;
    ingestFailures.delete(subject);
  }
}

setInterval(pruneIngestFailures, Math.min(INGEST_AUTH_WINDOW_MS, 60000)).unref();

// Privacy: only the raw prompt of an item HELD for admin approval is retained,
// and only sealed (AES-256-GCM). Returns undefined when nothing should be
// persisted — so allowed/warned/justified items keep ONLY redacted + masked
// data, and no cleartext member data ever lands on disk.
function rawToStore(text, status, pol) {
  const held = status === 'pending' || status === 'pending_justification';
  if (!held) return undefined;
  if (pol && pol.storeRawForApproval === false) return undefined;
  const sealed = dataCrypto.seal(text);
  return sealed == null ? undefined : sealed;
}

function scimGroupsForUser(userName) {
  const user = db.getScimUserByUserName(String(userName || '').trim());
  if (!user || user.active === false) return [];
  return db.listScimGroups()
    .filter((group) => (group.members || []).some((member) => member.value === user.id))
    .map((group) => group.displayName)
    .filter(Boolean);
}

function policyContext(input = {}) {
  return {
    user: input.user || 'unknown',
    orgId: input.orgId || null,
    destination: input.destination || 'unknown',
    source: input.source || 'api',
    channel: input.channel || 'submit',
    groups: scimGroupsForUser(input.user),
  };
}

function policyDecisionMetadata(verdict = {}) {
  return {
    ...((verdict.policyScopeIds || []).length ? { policyScopeIds: verdict.policyScopeIds } : {}),
    ...(verdict.policyExceptionId ? { policyExceptionId: verdict.policyExceptionId } : {}),
  };
}

function routeOptionsFor(query = {}, opts = {}) {
  if (!routing.routeableStatus(query.status) || query.assignedRole || query.assignedGroup || query.slaDueAt) {
    return opts;
  }
  const base = policyContext(query);
  const extra = opts.context || opts.identityContext || {};
  const groups = [...new Set([
    ...(Array.isArray(base.groups) ? base.groups : []),
    ...(Array.isArray(extra.groups) ? extra.groups : []),
  ].filter(Boolean))];
  return {
    ...opts,
    context: {
      ...base,
      ...extra,
      groups,
    },
  };
}

function createQuery(query, opts = {}) {
  return db.createQuery(routing.withWorkflow(query, routeOptionsFor(query, opts)));
}

function createQueryWithReleaseToken(query) {
  const routed = routing.withWorkflow(query, routeOptionsFor(query));
  if (routed && routed.status === 'pending') {
    const release = releaseTokens.issueReleaseToken();
    return {
      row: db.createQuery({ ...routed, _releaseTokenHash: release.hash }),
      releaseToken: release.token,
    };
  }
  return { row: db.createQuery(routed), releaseToken: null };
}

function releaseTokenPayload(releaseToken) {
  return releaseToken ? { releaseToken } : {};
}

function enforceTenantForSensor(req, res) {
  const check = tenant.validateSensorAccess({ body: req.body || {}, db });
  if (check.ok) {
    req.body.orgId = check.orgId || null;
    return true;
  }

  if (check.audit) {
    const body = req.body || {};
    const row = createQuery({
      status: check.status,
      mode: 'billing',
      user: check.user || body.user || 'unknown',
      orgId: check.orgId || tenant.config().tenantId || null,
      destination: body.destination || 'unknown',
      source: body.source || 'api',
      channel: body.channel || 'submit',
      sensor: body.sensor || null,
      redactedPrompt: '[' + check.message + ']',
      findings: [],
      categories: [],
      entityCounts: {},
      riskScore: 0,
      maxSeverity: 0,
      maxSeverityLabel: 'none',
      reasons: [check.message],
      seatLimit: check.seatLimit || null,
      seatsUsed: check.seatsUsed || null,
    });
    db.appendAudit({
      action: check.action,
      queryId: row.id,
      actor: check.user || body.user || 'unknown',
      detail: 'tenant=' + (row.orgId || 'unknown') + '; seats=' + (check.seatsUsed || 0) + '/' + (check.seatLimit || 0),
    });
    emitSecurityAlert(row, check.action);
    broadcast('query', { type: check.status, query: publicQuery(row) });
    broadcast('stats', db.stats());
  }

  res.status(check.statusCode || 403).json({
    error: check.message,
    decision: 'block',
    status: check.status,
    seatLimit: check.seatLimit || undefined,
    seatsUsed: check.seatsUsed || undefined,
  });
  return false;
}

function runRetentionPurge({ actor = 'system', now = new Date() } = {}) {
  const pol = policy.loadPolicy();
  const rawRetentionDays = policy.rawRetentionDays(pol);
  const cutoff = new Date(now.getTime() - rawRetentionDays * 24 * 60 * 60 * 1000).toISOString();
  const purged = db.purgeRetainedSensitiveData({
    before: cutoff,
    actor,
    reason: 'rawRetentionDays=' + rawRetentionDays,
  });
  if (purged.length) {
    broadcast('stats', db.stats());
  }
  return { rawRetentionDays, cutoff, purged };
}

function runWorkflowEscalation({ actor = 'system', now = new Date(), notify = true } = {}) {
  const result = workflow.escalateDueApprovals({
    db,
    actor,
    now,
    notify,
    onUpdate: (updated) => broadcast('query', { type: updated.status, query: publicQuery(updated) }),
  });
  if (result.escalated.length) broadcast('stats', db.stats());
  return result;
}

function safeNumber(value, fallback, min = 0, max = 100) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function safeInstallChecks(checks = []) {
  return (Array.isArray(checks) ? checks : []).map((check) => ({
    id: String(check.id || '').slice(0, 80),
    ok: check.ok === true,
    ...(check.detail ? { detail: String(check.detail).slice(0, 160) } : {}),
  }));
}

function failedInstallCheckIds(checks = []) {
  return checks.filter((check) => !check.ok).map((check) => check.id).filter(Boolean);
}

function hasSensitivity(analysis) {
  return !!(analysis && ((analysis.findings || []).length || (analysis.categories || []).length));
}

function canTokenizeAllSensitivity(analysis) {
  return !!(analysis && (analysis.findings || []).length && !(analysis.categories || []).length);
}

function categoryNames(analysis) {
  return [...new Set(((analysis && analysis.categories) || []).map((c) => c.category).filter(Boolean))];
}

function safePreview(text, analysis, prefix = '', limit = 600) {
  const categories = categoryNames(analysis);
  if (categories.length) return prefix + '[REDACTED: ' + categories.join(', ') + ']';
  return prefix + detector.redact(text, analysis.findings || []).slice(0, limit);
}

function responseScanOutcome(mode) {
  const normalized = policy.normalizeResponseScanMode(mode);
  if (normalized === 'block') return { status: 'response_blocked', decision: 'block', action: 'RESPONSE_BLOCKED' };
  if (normalized === 'redact') return { status: 'response_redacted', decision: 'redact', action: 'RESPONSE_REDACTED' };
  return { status: 'response_flagged', decision: 'flag', action: 'RESPONSE_FLAGGED' };
}

function clientFindingsFrom(body) {
  return (body.clientFindings || [])
    .filter((f) => f && typeof f.type === 'string')
    .map((f) => ({
      type: f.type,
      severity: safeNumber(f.severity, detector.SEVERITY[f.type] || 1, 0, 4),
      score: safeNumber(f.score, 0.5, 0, 1),
      masked: typeof f.masked === 'string' ? f.masked : undefined,
    }));
}

function clientCategoriesFrom(body) {
  return (body.clientCategories || [])
    .map((c) => (typeof c === 'string' ? { category: c, score: 0.72 } : c))
    .filter((c) => c && typeof c.category === 'string')
    .map((c) => ({ category: c.category, score: safeNumber(c.score, 0.72, 0, 1) }));
}

function clientAnalysisFrom(body) {
  if (!body || (!Array.isArray(body.clientFindings) && !Array.isArray(body.clientCategories))) return null;
  const findings = clientFindingsFrom(body);
  const categories = clientCategoriesFrom(body);
  if (!findings.length && !categories.length) return null;
  const entityCounts = body.clientEntityCounts && typeof body.clientEntityCounts === 'object'
    ? { ...body.clientEntityCounts }
    : {};
  for (const f of findings) entityCounts[f.type] = (entityCounts[f.type] || 0) + 1;
  for (const c of categories) entityCounts[c.category] = entityCounts[c.category] || 1;
  let maxSeverity = safeNumber(body.clientMaxSeverity, 0, 0, 4);
  for (const f of findings) if (f.severity > maxSeverity) maxSeverity = f.severity;
  for (const c of categories) {
    const s = detector.SEVERITY[c.category] || 2;
    if (s > maxSeverity) maxSeverity = s;
  }
  maxSeverity = safeNumber(maxSeverity, 0, 0, 4);
  const computedRisk = Math.min(100, Math.round(findings.reduce((s, f) => s + f.severity * f.score * 8, 0)
    + categories.reduce((s, c) => s + (detector.SEVERITY[c.category] || 2) * c.score * 7, 0)));
  const riskScore = Math.max(safeNumber(body.clientRiskScore, computedRisk), computedRisk);
  return {
    findings,
    categories,
    entityCounts,
    riskScore,
    maxSeverity,
    maxSeverityLabel: detector.SEVERITY_LABEL[maxSeverity] || 'none',
  };
}

function blockDestinationByPolicy(res, context = {}, responseExtra = {}) {
  const {
    user = 'unknown',
    orgId = null,
    destination = 'unknown',
    sourceIp = null,
    source = 'api',
    channel = 'submit',
    sensor = null,
    redactedPrompt = null,
    reason = 'Destination blocked by policy',
  } = context;
  const normalized = policy.normalizeDestination(destination);
  const row = createQuery({
    status: 'destination_blocked',
    mode: 'destination_block',
    user,
    orgId,
    destination: normalized,
    sourceIp,
    source,
    channel,
    sensor,
    redactedPrompt: redactedPrompt || ('[destination blocked] ' + normalized),
    findings: [],
    categories: [],
    entityCounts: {},
    riskScore: 0,
    maxSeverity: 0,
    maxSeverityLabel: 'none',
    reasons: [reason],
  });
  db.appendAudit({ action: 'DESTINATION_BLOCKED', queryId: row.id, actor: user, detail: `${source}/${channel}: ${normalized}` });
  emitSecurityAlert(row, 'DESTINATION_BLOCKED');
  broadcast('query', { type: 'destination_blocked', query: publicQuery(row) });
  broadcast('stats', db.stats());
  return res.json({
    id: row.id,
    decision: 'block',
    mode: 'destination_block',
    status: 'destination_blocked',
    riskScore: 0,
    findings: [],
    categories: [],
    reasons: [reason],
    ...responseExtra,
  });
}

function blockFileUploadByPolicy(res, context = {}, responseExtra = {}) {
  const {
    user = 'unknown',
    orgId = null,
    destination = 'unknown',
    sourceIp = null,
    source = 'api',
    channel = 'file_upload',
    sensor = null,
  } = context;
  const normalized = policy.normalizeDestination(destination);
  const reason = 'File upload blocked by policy';
  const row = createQuery({
    status: 'file_upload_blocked',
    mode: 'file_upload_block',
    user,
    orgId,
    destination: normalized,
    sourceIp,
    source,
    channel,
    sensor,
    redactedPrompt: '[file upload blocked] ' + normalized,
    findings: [],
    categories: [],
    entityCounts: {},
    riskScore: 0,
    maxSeverity: 0,
    maxSeverityLabel: 'none',
    reasons: [reason],
  });
  db.appendAudit({ action: 'FILE_UPLOAD_BLOCKED', queryId: row.id, actor: user, detail: `${source}/${channel}: ${normalized}` });
  emitSecurityAlert(row, 'FILE_UPLOAD_BLOCKED');
  broadcast('query', { type: 'file_upload_blocked', query: publicQuery(row) });
  broadcast('stats', db.stats());
  return res.json({
    id: row.id,
    decision: 'block',
    mode: 'file_upload_block',
    status: 'file_upload_blocked',
    riskScore: 0,
    findings: [],
    categories: [],
    reasons: [reason],
    ...responseExtra,
  });
}

const SAFE_CLIENT_ACTION_RE = /^[a-z][a-z0-9_:-]{0,79}$/;

function blockedActionLabel(action, source) {
  const requested = String(action || '').trim().toLowerCase();
  const browserAction = policy.normalizeBrowserAction(requested);
  if (browserAction) return browserAction;
  if (source !== 'browser_extension' && SAFE_CLIENT_ACTION_RE.test(requested)) return requested;
  return 'browser_action';
}

function blockedActionEvidence(analysis) {
  if (!analysis) {
    return {
      findings: [],
      categories: [],
      entityCounts: {},
      riskScore: 0,
      maxSeverity: 0,
      maxSeverityLabel: 'none',
    };
  }
  return {
    findings: (analysis.findings || []).map((f) => ({
      type: f.type,
      severity: f.severity,
      score: f.score,
      masked: f.masked || detector.maskValue(f.type, f.value || ''),
    })),
    categories: (analysis.categories || []).map((c) => c.category),
    entityCounts: analysis.entityCounts || {},
    riskScore: analysis.riskScore || 0,
    maxSeverity: analysis.maxSeverity || 0,
    maxSeverityLabel: analysis.maxSeverityLabel || 'none',
  };
}

function blockBrowserActionByPolicy(res, context = {}, responseExtra = {}) {
  const {
    user = 'unknown',
    orgId = null,
    destination = 'unknown',
    sourceIp = null,
    source = 'browser_extension',
    channel = 'paste',
    sensor = null,
    action = channel || 'paste',
    reason = 'Browser action blocked by policy',
    analysis = null,
  } = context;
  const normalized = policy.normalizeDestination(destination);
  const normalizedAction = blockedActionLabel(action, source);
  const evidence = blockedActionEvidence(analysis);
  const auditAction = source === 'browser_extension' ? 'BROWSER_ACTION_BLOCKED' : 'CLIENT_ACTION_BLOCKED';
  const promptLabel = source === 'browser_extension' ? 'browser action' : 'client action';
  const row = createQuery({
    status: 'action_blocked',
    mode: 'browser_action_block',
    user,
    orgId,
    destination: normalized,
    sourceIp,
    source,
    channel: normalizedAction,
    sensor,
    redactedPrompt: '[' + promptLabel + ' blocked] ' + normalizedAction + ' ' + normalized,
    findings: evidence.findings,
    categories: evidence.categories,
    entityCounts: evidence.entityCounts,
    riskScore: evidence.riskScore,
    maxSeverity: evidence.maxSeverity,
    maxSeverityLabel: evidence.maxSeverityLabel,
    reasons: [reason],
  });
  db.appendAudit({ action: auditAction, queryId: row.id, actor: user, detail: `${source}/${normalizedAction}: ${normalized}` });
  emitSecurityAlert(row, auditAction);
  broadcast('query', { type: 'action_blocked', query: publicQuery(row) });
  broadcast('stats', db.stats());
  return res.json({
    id: row.id,
    decision: 'block',
    mode: 'browser_action_block',
    status: 'action_blocked',
    riskScore: evidence.riskScore,
    findings: evidence.findings,
    categories: evidence.categories,
    reasons: [reason],
    ...responseExtra,
  });
}

app.post('/api/v1/gate', checkIngestKey, validation.validateBody(validation.gateSchema), (req, res) => {
  if (!enforceTenantForSensor(req, res)) return;
  const {
    prompt, user = 'unknown', destination = 'unknown', sourceIp = null,
    source = 'api', channel = 'submit', clientOutcome = null, note = '', orgId = null,
    sensor = null,
  } = req.body || {};
  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'prompt (string) required' });
  }

  const pol = policy.loadPolicy();
  if (policy.destinationBlocked(destination, pol) || clientOutcome === 'destination_blocked') {
    return blockDestinationByPolicy(res, {
      user,
      orgId,
      destination,
      sourceIp,
      source,
      channel,
      sensor,
      reason: policy.destinationBlockReason(destination, pol),
    });
  }
  if (clientOutcome === 'file_upload_blocked') {
    return blockFileUploadByPolicy(res, { user, orgId, destination, sourceIp, source, channel, sensor });
  }
  const declaredClientPreRedacted = req.body && req.body.clientPreRedacted === true;
  const clientAnalysis = declaredClientPreRedacted ? clientAnalysisFrom(req.body) : null;
  if (declaredClientPreRedacted && !clientAnalysis) {
    return res.status(400).json({ error: 'client redaction analysis required' });
  }
  const browserActionRule = policy.browserActionBlockRule(channel, destination, pol);
  if (browserActionRule || clientOutcome === 'action_blocked') {
    return blockBrowserActionByPolicy(res, {
      user,
      orgId,
      destination,
      sourceIp,
      source,
      channel,
      sensor,
      action: channel,
      reason: browserActionRule
        ? policy.browserActionBlockReason(channel, destination, pol)
        : source === 'browser_extension' ? 'Browser action blocked by policy' : 'Client action blocked locally',
      analysis: clientAnalysis,
    });
  }
  const analyzeOpts = policy.analyzeOpts(pol);
  const serverAnalysis = detector.analyze(prompt, analyzeOpts);
  const clientPreRedacted = declaredClientPreRedacted && clientAnalysis && !hasSensitivity(serverAnalysis);
  const clientRedactionResolved = (clientOutcome === 'redacted_sent' || clientOutcome === 'redacted_available') && clientPreRedacted;
  const analysis = clientPreRedacted ? clientAnalysis : serverAnalysis;
  const ctx = policyContext({ user, orgId, destination, source, channel });
  const verdict = policy.evaluate(analysis, pol, ctx);
  const decisionPolicy = verdict.policy || pol;

  // Privacy-preserving record: redacted prompt + masked findings + categories.
  const redactedPrompt = clientRedactionResolved && !categoryNames(analysis).length ? prompt : safePreview(prompt, analysis);
  const findings = analysis.findings.map((f) => ({
    type: f.type, severity: f.severity, score: f.score, masked: f.masked || detector.maskValue(f.type, f.value || ''),
  }));
  const categories = (analysis.categories || []).map((c) => c.category);

  const base = {
    user, orgId, destination, sourceIp, source, channel, sensor,
    redactedPrompt, findings, categories, entityCounts: analysis.entityCounts,
    riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity,
    maxSeverityLabel: analysis.maxSeverityLabel, reasons: verdict.reasons,
    ...policyDecisionMetadata(verdict),
  };

  // Man-in-the-Prompt: the sensor stopped a prompt carrying hidden instructions.
  if (clientOutcome === 'injection_blocked') {
    const row = createQuery({ status: 'injection_blocked', ...base });
    db.appendAudit({ action: 'INJECTION_BLOCKED', queryId: row.id, actor: user, detail: note || 'hidden instructions detected' });
    emitSecurityAlert(row, 'INJECTION_BLOCKED');
    broadcast('query', { type: 'injection_blocked', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'block', status: 'injection_blocked' });
  }

  // Shadow-AI discovery: a visit to an AI tool policy does not govern. Recorded
  // as an informational event so the examiner sees unmonitored paths, not a leak.
  if (clientOutcome === 'shadow_ai') {
    if (policy.unapprovedAiDestination(destination, pol)) {
      return blockDestinationByPolicy(res, {
        user,
        orgId,
        destination,
        sourceIp,
        source,
        channel,
        sensor,
        redactedPrompt: '[unapproved AI blocked] ' + policy.normalizeDestination(destination),
        reason: policy.destinationBlockReason(destination, pol),
      });
    }
    const row = createQuery({ status: 'shadow_ai', ...base });
    db.appendAudit({ action: 'SHADOW_AI', queryId: row.id, actor: user, detail: `ungoverned AI tool: ${destination}` });
    emitSecurityAlert(row, 'SHADOW_AI');
    broadcast('query', { type: 'shadow_ai', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'log', status: 'shadow_ai' });
  }

  if (clientOutcome === 'file_too_large' || clientOutcome === 'file_unsupported' || clientOutcome === 'ocr_required' || clientOutcome === 'scan_unavailable') {
    const status = clientOutcome === 'ocr_required' ? 'ocr_required' : 'file_blocked_unscanned';
    const action = status === 'ocr_required' ? 'FILE_OCR_REQUIRED' : 'FILE_BLOCKED_UNSCANNED';
    const row = createQuery({ status, ...base });
    db.appendAudit({ action, queryId: row.id, actor: user, detail: note || 'file blocked unscanned' });
    emitSecurityAlert(row, action);
    broadcast('query', { type: status, query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'block', status });
  }

  if (verdict.decision === 'allow') {
    const row = createQuery({ status: 'allowed', ...base });
    db.appendAudit({ action: 'ALLOWED', queryId: row.id, actor: user, detail: `${source} risk ${analysis.riskScore}` });
    emitSecurityAlert(row, 'ALLOWED');
    broadcast('query', { type: 'allowed', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', riskScore: analysis.riskScore, findings, categories });
  }

  if (clientOutcome === 'paste_flagged') {
    const row = createQuery({ status: 'paste_flagged', mode: decisionPolicy.enforcementMode || 'block', ...base });
    db.appendAudit({ action: 'PASTE_FLAGGED', queryId: row.id, actor: user, detail: note || `${source}/paste: ${verdict.reasons.join('; ')}` });
    emitSecurityAlert(row, 'PASTE_FLAGGED');
    broadcast('query', { type: 'paste_flagged', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'log', status: 'paste_flagged', riskScore: analysis.riskScore, findings, categories });
  }

  // Sensitive content detected. Behaviour depends on the org enforcement mode.
  // 'redact' neutralizes even hard-stop entities by tokenizing them (that is the
  // point — the prompt can proceed because it no longer contains real PII).
  // Otherwise hard-stop entities force 'block' regardless of mode.
  const hardStop = analysis.findings.some((f) => decisionPolicy.alwaysBlock.includes(f.type));
  const mode = clientRedactionResolved ? 'redact'
    : decisionPolicy.enforcementMode === 'redact' ? 'redact'
    : (hardStop ? 'block' : (decisionPolicy.enforcementMode || 'block'));

  // Status reflects how the sensor resolved it (from clientOutcome) or, for the
  // API/proxy path, defaults to the mode's behaviour.
  let status;
  const wholeChunkClientRedacted = declaredClientPreRedacted && /^\s*\[REDACTED:[^\]]+\]\s*$/i.test(prompt);
  if (clientOutcome === 'sent_after_warning') status = 'warned_sent';
  else if (clientOutcome === 'redacted_sent') status = canTokenizeAllSensitivity(analysis) || wholeChunkClientRedacted ? 'redacted' : 'pending';
  else if (clientOutcome === 'redacted_available') status = canTokenizeAllSensitivity(analysis) || wholeChunkClientRedacted ? 'redacted' : 'pending';
  else if (clientOutcome === 'justified') status = 'justified';
  else if (clientOutcome === 'blocked_by_user') status = 'blocked_by_user';
  else if (clientOutcome === 'awaiting_approval') status = 'pending';
  else if (mode === 'redact') status = canTokenizeAllSensitivity(analysis) ? 'redacted' : 'pending';
  else if (mode === 'block') status = 'pending';
  else if (mode === 'warn') status = 'warned';
  else if (mode === 'justify') status = 'pending_justification';
  else status = 'pending';

  // Reversible tokenization: replace each detected value with a stable typed
  // placeholder and seal the token->value map (the "vault") at rest. The caller
  // sends `tokenizedPrompt` to the AI; POST /api/v1/rehydrate restores the real
  // values in the model's response. The model never sees real PII; the vault is
  // AES-256-GCM encrypted and revealed only on an audit-logged rehydrate.
  let tokenizedPrompt, tokenVault;
  if (status === 'redacted' && !clientRedactionResolved) {
    const t = detector.tokenize(prompt, analysis.findings);
    tokenizedPrompt = t.text;                       // PII-free, safe to retain/display
    tokenVault = dataCrypto.seal(JSON.stringify(t.map));
  } else if (status === 'redacted') {
    tokenizedPrompt = prompt;
  }

  const { row, releaseToken } = createQueryWithReleaseToken({
    status, mode, ...base, decisionNote: note,
    _rawPrompt: rawToStore(prompt, status, decisionPolicy),
    _tokenVault: tokenVault,
    tokenizedPrompt,
  });
  const action = status === 'pending' ? 'BLOCKED'
    : status === 'redacted' ? 'REDACTED'
    : status === 'justified' ? 'JUSTIFIED'
    : status === 'warned_sent' ? 'WARNED_SENT'
    : status === 'blocked_by_user' ? 'SELF_BLOCKED' : 'FLAGGED';
  db.appendAudit({ action, queryId: row.id, actor: user, detail: `${source}/${channel}: ${verdict.reasons.join('; ')}` });
  emitSecurityAlert(row, action);
  broadcast('query', { type: status, query: publicQuery(row) });
  broadcast('stats', db.stats());
  return res.json({
    id: row.id, decision: status === 'redacted' ? 'redact' : 'block', mode, status,
    ...releaseTokenPayload(releaseToken),
    riskScore: analysis.riskScore, findings, categories, reasons: verdict.reasons,
    tokenizedPrompt,
    message: status === 'redacted' ? 'Sensitive values tokenized — safe to send; re-hydrate the AI response via /api/v1/rehydrate.'
      : mode === 'redact' ? 'Sensitive category cannot be tokenized safely; withheld pending Security Admin approval.'
      : mode === 'block' ? 'Withheld pending Security Admin approval.'
      : mode === 'justify' ? 'Justification required before sending.'
      : 'Sensitive content — user warned.',
  });
});

app.post('/api/v1/heartbeat', checkIngestKey, validation.validateBody(validation.heartbeatSchema), (req, res) => {
  if (!enforceTenantForSensor(req, res)) return;
  const {
    user = 'unknown',
    orgId = null,
    destination = 'sensor-health',
    source = 'api',
    sensor = null,
  } = req.body || {};
  const checks = safeInstallChecks(req.body && req.body.checks);
  const failedChecks = failedInstallCheckIds(checks);
  const row = createQuery({
    status: 'sensor_heartbeat',
    mode: 'sensor_health',
    user,
    orgId,
    destination: policy.normalizeDestination(destination),
    source,
    channel: 'sensor_health',
    sensor,
    redactedPrompt: '[sensor heartbeat] ' + String(source || 'api').slice(0, 80),
    findings: [],
    categories: [],
    entityCounts: {},
    riskScore: 0,
    maxSeverity: 0,
    maxSeverityLabel: 'none',
    reasons: failedChecks.length ? ['Sensor health attention: ' + failedChecks.join(', ')] : ['Sensor heartbeat OK'],
    installChecks: checks,
  });
  db.appendAudit({
    action: failedChecks.length ? 'SENSOR_HEALTH_ATTENTION' : 'SENSOR_HEARTBEAT',
    queryId: row.id,
    actor: user,
    detail: JSON.stringify({ source, failedChecks, checkCount: checks.length }),
  });
  if (failedChecks.length) emitSecurityAlert(row, 'SENSOR_HEALTH_ATTENTION');
  else {
    try { emitSensorVersionGapAlert(row); } catch {}
  }
  broadcast('query', { type: 'sensor_heartbeat', query: publicQuery(row) });
  broadcast('stats', db.stats());
  return res.json({
    id: row.id,
    decision: 'recorded',
    status: 'sensor_heartbeat',
    failedChecks,
  });
});

// Re-hydrate an AI response: swap tokens back to their real values using the
// sealed vault for this query. Lets a proxy/SDK restore the model's answer
// after a 'redact'-mode send. Audit-logged; never returns the vault itself.
app.post('/api/v1/rehydrate', checkIngestKey, validation.validateBody(validation.rehydrateSchema), (req, res) => {
  const { id, text } = req.body || {};
  const q = id && db.getQuery(id);
  if (!q) return res.status(404).json({ error: 'not found' });
  if (!q._tokenVault) return res.json({ id, text: text || '', rehydrated: false, reason: 'no vault for this item' });
  const mapJson = dataCrypto.open(q._tokenVault);
  if (mapJson == null) return res.status(409).json({ error: 'vault unavailable (no/incorrect data key)' });
  let map; try { map = JSON.parse(mapJson); } catch { return res.status(500).json({ error: 'vault corrupt' }); }
  const out = detector.detokenize(typeof text === 'string' ? text : '', map);
  db.appendAudit({ action: 'REHYDRATE', queryId: q.id, actor: q.user || 'sensor', detail: `re-hydrated ${Object.keys(map).length} token(s)` });
  res.json({ id: q.id, text: out, rehydrated: true });
});

// Public policy for sensors (ingest-key protected).
app.get('/api/v1/policy', checkIngestKey, (req, res) => {
  const p = policy.loadPolicy();
  res.json({
    enforcementMode: p.enforcementMode, blockMinSeverity: p.blockMinSeverity,
    blockRiskScore: p.blockRiskScore, alwaysBlock: p.alwaysBlock,
    ignore: p.ignore || [],
    disabledDetectors: p.disabledDetectors || [],
    customDetectors: policy.customDetectorsForSensors(),
    governedDestinations: p.governedDestinations,
    allowedDestinations: p.allowedDestinations || [],
    blockedDestinations: p.blockedDestinations || [],
    blockedFileUploadDestinations: p.blockedFileUploadDestinations || [],
    blockedBrowserActions: p.blockedBrowserActions || [],
    blockUnapprovedAiDestinations: p.blockUnapprovedAiDestinations !== false,
    responseScanMode: p.responseScanMode || policy.DEFAULT_POLICY.responseScanMode,
    desktopCollectorDestination: p.desktopCollectorDestination || policy.DEFAULT_POLICY.desktopCollectorDestination,
    requiredSensors: p.requiredSensors || policy.DEFAULT_POLICY.requiredSensors,
    desiredSensorVersions: p.desiredSensorVersions || policy.DEFAULT_POLICY.desiredSensorVersions,
    scanner: p.scanner || {},
  });
});

// List available detectors (for the console enable/disable UI).
app.get('/api/v1/detectors', checkIngestKey, (req, res) => res.json(detector.listDetectors({
  customDetectors: policy.customDetectorsForSensors(),
})));

// Scan an uploaded FILE: extract text (pdf/docx/xlsx/text), then gate it.
app.post('/api/v1/scan-file', checkIngestKey, validation.validateBody(validation.scanFileSchema), async (req, res) => {
  if (!enforceTenantForSensor(req, res)) return;
  const { filename, contentBase64, user = 'unknown', destination = 'unknown', source = 'api', channel = 'file_upload', orgId = null, sensor = null } = req.body || {};
  if (!filename || !contentBase64) return res.status(400).json({ error: 'filename and contentBase64 required' });
  const pol = policy.loadPolicy();
  if (policy.destinationBlocked(destination, pol)) {
    return blockDestinationByPolicy(res, {
      user, orgId, destination, source, channel, sensor,
      redactedPrompt: '[file upload blocked by destination policy] ' + policy.normalizeDestination(destination),
      reason: policy.destinationBlockReason(destination, pol),
    }, { supported: true, inspected: false });
  }
  if (policy.fileUploadBlocked(destination, pol)) {
    return blockFileUploadByPolicy(res, { user, orgId, destination, source, channel, sensor }, { supported: true, inspected: false });
  }
  let buf;
  try { buf = Buffer.from(contentBase64, 'base64'); } catch { return res.status(400).json({ error: 'bad base64' }); }
  if (buf.length > (pol.scanner && pol.scanner.maxFileBytes || 6.6e6)) return res.status(413).json({ error: 'file too large' });

  let extracted;
  try { extracted = await processors.extractText(filename, buf); }
  catch (e) { extracted = { text: '', processor: null, supported: true, extractionOk: false, error: 'extract_failed' }; }
  if (!extracted.supported) {
    const row = createQuery({ status: 'flagged', user, orgId, destination, source, channel, sensor,
      redactedPrompt: '[unsupported file] ' + filename, findings: [], categories: [], entityCounts: {},
      riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none', reasons: ['Unsupported file type recorded'] });
    db.appendAudit({ action: 'FILE_RECORDED', queryId: row.id, actor: user, detail: filename });
    emitSecurityAlert(row, 'FILE_RECORDED');
    broadcast('query', { type: 'flagged', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', supported: false, filename });
  }
  if (!extracted.extractionOk) {
    const ocrRequired = extracted.error === 'ocr_required' || extracted.ocrRequired === true;
    const status = ocrRequired ? 'ocr_required' : 'file_blocked_unscanned';
    const reason = ocrRequired ? 'OCR is required before this file can be inspected'
      : extracted.error === 'timeout' ? 'File extraction timed out before inspection completed'
      : 'File could not be inspected';
    const row = createQuery({ status, user, orgId, destination, source, channel, sensor,
      filename, processor: extracted.processor, redactedPrompt: (ocrRequired ? '[ocr required file] ' : '[unreadable file] ') + filename,
      findings: [], categories: [], entityCounts: {}, riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none',
      reasons: [reason] });
    const action = ocrRequired ? 'FILE_OCR_REQUIRED' : 'FILE_BLOCKED_UNREADABLE';
    db.appendAudit({ action, queryId: row.id, actor: user, detail: `${filename}: ${extracted.error || 'extract_failed'}` });
    emitSecurityAlert(row, action);
    broadcast('query', { type: status, query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({
      id: row.id,
      decision: 'block',
      mode: 'block',
      status,
      supported: true,
      inspected: false,
      filename,
      processor: extracted.processor,
      ...(ocrRequired ? { ocrRequired: true } : {}),
      reasons: [reason],
    });
  }

  const analysis = detector.analyze(extracted.text, policy.analyzeOpts(pol));
  const ctx = policyContext({ user, orgId, destination, source, channel });
  const verdict = policy.evaluate(analysis, pol, ctx);
  const decisionPolicy = verdict.policy || pol;
  const findings = analysis.findings.map((x) => ({ type: x.type, severity: x.severity, score: x.score, masked: detector.maskValue(x.type, x.value) }));
  const categories = (analysis.categories || []).map((c) => c.category);
  const preview = safePreview(extracted.text, analysis, '[file:' + filename + '] ');
  const base = { user, orgId, destination, source, channel, sensor, filename, processor: extracted.processor,
    redactedPrompt: preview, findings, categories, entityCounts: analysis.entityCounts,
    riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity, maxSeverityLabel: analysis.maxSeverityLabel, reasons: verdict.reasons,
    ...policyDecisionMetadata(verdict) };

  if (verdict.decision === 'allow') {
    const row = createQuery({ status: 'allowed', ...base });
    db.appendAudit({ action: 'FILE_ALLOWED', queryId: row.id, actor: user, detail: filename + ' risk ' + analysis.riskScore });
    emitSecurityAlert(row, 'FILE_ALLOWED');
    broadcast('query', { type: 'allowed', query: publicQuery(row) }); broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', supported: true, filename, riskScore: analysis.riskScore, findings, categories });
  }
  const hardStop = analysis.findings.some((x) => decisionPolicy.alwaysBlock.includes(x.type));
  const mode = decisionPolicy.enforcementMode === 'redact' ? 'redact' : (hardStop ? 'block' : (decisionPolicy.enforcementMode || 'block'));
  const status = mode === 'redact' ? (canTokenizeAllSensitivity(analysis) ? 'redacted' : 'pending')
    : mode === 'warn' ? 'warned'
    : mode === 'justify' ? 'pending_justification'
    : 'pending';
  const rawFile = '[file:' + filename + ']\n' + extracted.text.slice(0, 5000);
  let tokenizedPrompt, tokenVault;
  if (status === 'redacted') {
    const t = detector.tokenize(extracted.text, analysis.findings);
    tokenizedPrompt = '[file:' + filename + ']\n' + t.text;
    tokenVault = dataCrypto.seal(JSON.stringify(t.map));
  }
  const { row, releaseToken } = createQueryWithReleaseToken({
    status, mode, ...base, _rawPrompt: rawToStore(rawFile, status, decisionPolicy), _tokenVault: tokenVault, tokenizedPrompt,
  });
  const action = status === 'pending' ? 'FILE_BLOCKED'
    : status === 'redacted' ? 'FILE_REDACTED'
    : 'FILE_FLAGGED';
  db.appendAudit({ action, queryId: row.id, actor: user, detail: filename + ': ' + verdict.reasons.join('; ') });
  emitSecurityAlert(row, action);
  broadcast('query', { type: status, query: publicQuery(row) }); broadcast('stats', db.stats());
  res.json({
    id: row.id,
    decision: status === 'redacted' ? 'redact' : 'block',
    mode,
    status,
    ...releaseTokenPayload(releaseToken),
    supported: true,
    filename,
    riskScore: analysis.riskScore,
    findings,
    categories,
    reasons: verdict.reasons,
    tokenizedPrompt,
    message: status === 'redacted' ? 'Sensitive file values tokenized - safe to send.'
      : mode === 'redact' ? 'Sensitive file category cannot be tokenized safely; withheld pending Security Admin approval.'
      : 'Sensitive file withheld pending Security Admin approval.',
  });
});

// Scan an AI RESPONSE for sensitive data leaking back to the user (e.g. an MCP
// tool pulled PII, or the model echoed it). Parity with output-scanning DLP.
app.post('/api/v1/scan-response', checkIngestKey, validation.validateBody(validation.scanResponseSchema), (req, res) => {
  if (!enforceTenantForSensor(req, res)) return;
  const { text, user = 'unknown', destination = 'unknown', source = 'api', orgId = null, sensor = null } = req.body || {};
  if (typeof text !== 'string' || !text.trim()) return res.status(400).json({ error: 'text (string) required' });
  const pol = policy.loadPolicy();
  if (policy.destinationBlocked(destination, pol)) {
    return blockDestinationByPolicy(res, {
      user, orgId, destination, source, channel: 'ai_response', sensor,
      redactedPrompt: '[AI response blocked by destination policy] ' + policy.normalizeDestination(destination),
      reason: policy.destinationBlockReason(destination, pol),
    }, { leaked: false, findings: [], categories: [], redacted: '' });
  }
  const analysis = detector.analyze(text, policy.analyzeOpts(pol));
  const findings = analysis.findings.map((f) => ({ type: f.type, severity: f.severity, score: f.score, masked: detector.maskValue(f.type, f.value) }));
  const categories = (analysis.categories || []).map((c) => c.category);
  const redacted = safePreview(text, analysis);
  const leaked = findings.length > 0 || categories.length > 0;
  const outcome = responseScanOutcome(pol.responseScanMode);
  if (leaked) {
    const row = createQuery({ status: outcome.status, mode: 'response_' + outcome.decision, user, orgId, destination, source, channel: 'ai_response', sensor,
      redactedPrompt: '[AI response] ' + redacted, findings, categories, entityCounts: analysis.entityCounts,
      riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity, maxSeverityLabel: analysis.maxSeverityLabel,
      reasons: ['Sensitive data present in AI response', 'Response scan mode: ' + outcome.decision] });
    db.appendAudit({ action: outcome.action, queryId: row.id, actor: user, detail: `${source}: ${findings.map((f) => f.type).join(', ') || categories.join(', ')}` });
    emitSecurityAlert(row, outcome.action);
    broadcast('query', { type: outcome.status, query: publicQuery(row) });
    broadcast('stats', db.stats());
  }
  res.json({
    leaked,
    decision: leaked ? outcome.decision : 'allow',
    status: leaked ? outcome.status : 'allowed',
    blocked: leaked && outcome.decision === 'block',
    findings,
    categories,
    redacted,
    reasons: leaked ? ['Sensitive data present in AI response', 'Response scan mode: ' + outcome.decision] : ['Nothing sensitive detected'],
  });
});

// Client polls for release decision.
app.get('/api/v1/status/:id', checkIngestKey, (req, res) => {
  const q = db.getQuery(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  const releaseToken = req.get('x-release-token') || '';
  if (!releaseTokens.verifyReleaseToken(q, releaseToken)) return res.status(401).json({ error: 'invalid release token' });
  const released = q.status === 'approved' || q.status === 'allowed';
  res.json({ id: q.id, status: q.status, released });
});

// =============================================================================
// AUTH
// =============================================================================
app.post('/api/login', validation.validateBody(validation.loginSchema), (req, res) => {
  const { user, password, otp } = req.body || {};
  const key = (user || '?') + '|' + (req.ip || (req.connection && req.connection.remoteAddress) || '');
  const st = auth.loginStatus(key);
  if (st.locked) {
    db.appendAudit({ action: 'LOGIN_LOCKED', actor: user || '?', detail: 'too many attempts' });
    return res.status(429).json({ error: 'too many attempts — temporarily locked', retryMs: st.retryMs });
  }
  const account = auth.authenticate(user, password);
  if (!account) {
    const r = auth.registerFail(key);
    db.appendAudit({ action: 'LOGIN_FAILED', actor: user || '?', detail: r.locked ? 'locked out' : (r.remaining + ' attempts left') });
    return res.status(401).json({ error: 'invalid credentials', remaining: r.remaining });
  }
  if (account.role === 'security_admin' && auth.ADMIN_MFA_REQUIRED && !auth.verifyTotpCode(otp)) {
    const r = auth.registerFail(key);
    db.appendAudit({ action: 'ADMIN_MFA_FAILED', actor: account.user, detail: r.locked ? 'locked out' : (r.remaining + ' attempts left') });
    return res.status(401).json({ error: 'invalid mfa code', mfaRequired: true, remaining: r.remaining });
  }
  auth.registerSuccess(key);
  const token = auth.createSession(account.user, account.role);
  res.cookie(auth.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTIONS);
  res.clearCookie(auth.LEGACY_SESSION_COOKIE_NAME, SESSION_COOKIE_CLEAR_OPTIONS);
  db.appendAudit({
    action: roles.loginAuditAction(account.role),
    actor: account.user,
    detail: account.role,
  });
  res.json({ ok: true, user: account.user, role: account.role });
});

app.get('/api/login-options', (req, res) => {
  res.json({ oidc: oidc.publicOptions() });
});

app.get('/auth/oidc/start', async (req, res) => {
  try {
    const redirect = await oidc.buildAuthorizationRedirect({
      req,
      returnTo: req.query.returnTo,
    });
    res.cookie(oidc.STATE_COOKIE_NAME, redirect.cookieValue, OIDC_STATE_COOKIE_OPTIONS);
    res.redirect(redirect.url);
  } catch (err) {
    db.appendAudit({ action: 'OIDC_LOGIN_FAILED', actor: 'oidc', detail: oidc.publicError(err) });
    res.status(404).json({ error: oidc.publicError(err) });
  }
});

app.get('/auth/oidc/callback', async (req, res) => {
  try {
    const result = await oidc.handleCallback({
      req,
      query: req.query || {},
      stateCookie: req.cookies && req.cookies[oidc.STATE_COOKIE_NAME],
    });
    const token = auth.createSession(result.account.user, result.account.role, result.sessionExtras);
    res.cookie(auth.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTIONS);
    res.clearCookie(auth.LEGACY_SESSION_COOKIE_NAME, SESSION_COOKIE_CLEAR_OPTIONS);
    res.clearCookie(oidc.STATE_COOKIE_NAME, OIDC_STATE_COOKIE_CLEAR_OPTIONS);
    db.appendAudit({
      action: roles.loginAuditAction(result.account.role),
      actor: result.account.user,
      detail: result.account.role + '; oidc',
    });
    res.redirect(result.returnTo || '/index.html');
  } catch (err) {
    db.appendAudit({ action: 'OIDC_LOGIN_FAILED', actor: 'oidc', detail: oidc.publicError(err) });
    res.clearCookie(oidc.STATE_COOKIE_NAME, OIDC_STATE_COOKIE_CLEAR_OPTIONS);
    res.redirect('/login.html?oidc=failed');
  }
});

const sessionWrite = [auth.requireAuth, auth.requireCsrf];
const adminWrite = [auth.requireAuth, auth.requireCsrf, auth.requireRole(roles.SECURITY_ADMIN)];
const decisionWrite = [auth.requireAuth, auth.requireCsrf, auth.requireRole(roles.SECURITY_ADMIN, roles.APPROVER)];

app.get('/api/csrf', auth.requireAuth, (req, res) => {
  res.json({ csrfToken: auth.createCsrfToken(auth.sessionTokenFromRequest(req)) });
});

app.post('/api/logout', ...sessionWrite, (req, res) => {
  res.clearCookie(auth.SESSION_COOKIE_NAME, SESSION_COOKIE_CLEAR_OPTIONS);
  res.clearCookie(auth.LEGACY_SESSION_COOKIE_NAME, SESSION_COOKIE_CLEAR_OPTIONS);
  res.json({ ok: true });
});

function stepUpKey(scope, user, req) {
  return String(scope || 'admin').toLowerCase() + '|' + (user || '?') + '|' + (req.ip || (req.connection && req.connection.remoteAddress) || '');
}

function requireStepUpPassword(scope) {
  const auditScope = String(scope || 'ADMIN').toUpperCase();
  return (req, res, next) => {
    const user = req.user && req.user.user;
    const key = stepUpKey(auditScope, user, req);
    const st = auth.loginStatus(key);
    if (st.locked) {
      db.appendAudit({ action: auditScope + '_LOCKED', queryId: req.params.id, actor: user || '?', detail: 'too many attempts' });
      emitAdminSecurityAlert(req, auditScope + '_LOCKED', user, auditScope);
      return res.status(429).json({ error: 'too many attempts - temporarily locked', retryMs: st.retryMs });
    }
    if (auth.oidcStepUpSatisfied(req.user)) {
      auth.registerSuccess(key);
      return next();
    }
    if (!auth.verifyPassword(user, req.body && req.body.password)) {
      const r = auth.registerFail(key);
      db.appendAudit({ action: auditScope + '_FAILED', queryId: req.params.id, actor: user || '?', detail: r.locked ? 'locked out' : (r.remaining + ' attempts left') });
      emitAdminSecurityAlert(req, auditScope + '_FAILED', user, auditScope);
      return res.status(401).json({ error: 'invalid credentials', remaining: r.remaining });
    }
    auth.registerSuccess(key);
    next();
  };
}

const requireRevealPassword = requireStepUpPassword('REVEAL');
const requireApprovePassword = requireStepUpPassword('APPROVE');

function requireDecisionAccess(req, res, next) {
  const q = db.getQuery(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  if (!roles.canDecideQuery(req.user, q)) return res.status(403).json({ error: 'forbidden' });
  req.queryRecord = q;
  next();
}

app.get('/api/me', auth.requireAuth, (req, res) => {
  res.json({
    user: req.user.user,
    role: req.user.role,
    authProvider: req.user.provider || 'local',
    defaultPassword: auth.ADMIN_PASSWORD_IS_DEFAULT,
  });
});

// =============================================================================
// ADMIN API (session-protected)
// =============================================================================
function publicQuery(q, { includeRaw = false } = {}) {
  const { _rawPrompt, _tokenVault, _releaseTokenHash, ...rest } = q;
  return includeRaw ? { ...rest, rawPrompt: _rawPrompt } : rest;
}

app.get('/api/queries', auth.requireAuth, (req, res) => {
  const status = req.query.status;
  const rows = db.listQueries({ status, limit: Number(req.query.limit) || 200 });
  res.json(rows.map((q) => publicQuery(q)));
});

app.get('/api/queries/:id', auth.requireAuth, (req, res) => {
  const q = db.getQuery(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  res.json(publicQuery(q));
});

// Reveal raw prompt (sensitive): decrypts the sealed value, requires password
// step-up, and logs the action. Falls back to the redacted prompt when raw was
// not retained (privacy mode, item not held, or no data key configured).
app.post(
  '/api/queries/:id/reveal',
  ...adminWrite,
  validation.validateBody(validation.revealSchema),
  requireRevealPassword,
  (req, res) => {
    const q = db.getQuery(req.params.id);
    if (!q) return res.status(404).json({ error: 'not found' });
    db.appendAudit({ action: 'REVEAL_RAW', queryId: q.id, actor: req.user.user });
    let rawPrompt, rawRetained = false;
    if (q._rawPrompt) {
      const opened = dataCrypto.open(q._rawPrompt);
      if (opened == null) rawPrompt = '[sealed - data key unavailable or value tampered]';
      else { rawPrompt = opened; rawRetained = true; }
    } else {
      rawPrompt = q.redactedPrompt;
    }
    res.json({ id: q.id, rawPrompt, rawRetained });
  },
);

app.post(
  '/api/queries/:id/approve',
  ...decisionWrite,
  validation.validateBody(validation.approveSchema),
  requireDecisionAccess,
  requireApprovePassword,
  (req, res) => {
    const q = req.queryRecord;
    if (q.status !== 'pending') return res.status(409).json({ error: `already ${q.status}` });
    const note = (req.body && req.body.note) || '';
    const updated = db.updateQuery(q.id, {
      status: 'approved', decidedBy: req.user.user, decidedAt: new Date().toISOString(), decisionNote: note,
    });
    db.appendAudit({ action: 'APPROVED', queryId: q.id, actor: req.user.user, detail: note });
    broadcast('decision', { id: q.id, status: 'approved' });
    broadcast('stats', db.stats());
    res.json(publicQuery(updated));
  },
);

app.post('/api/queries/:id/deny', ...decisionWrite, validation.validateBody(validation.noteSchema), requireDecisionAccess, (req, res) => {
  const q = req.queryRecord;
  if (q.status !== 'pending') return res.status(409).json({ error: `already ${q.status}` });
  const note = (req.body && req.body.note) || '';
  const updated = db.updateQuery(q.id, {
    status: 'denied', decidedBy: req.user.user, decidedAt: new Date().toISOString(), decisionNote: note,
  });
  db.appendAudit({ action: 'DENIED', queryId: q.id, actor: req.user.user, detail: note });
  broadcast('decision', { id: q.id, status: 'denied' });
  broadcast('stats', db.stats());
  res.json(publicQuery(updated));
});

app.get('/api/stats', auth.requireAuth, (req, res) => res.json(db.stats()));

app.get('/api/billing/seats', auth.requireAuth, (req, res) => {
  res.json(tenant.seatReport(db));
});

// Ops metrics (admin) — counts + live audit-integrity, for dashboards/monitoring.
app.get('/api/metrics', auth.requireAuth, (req, res) => {
  const integ = db.verifyAuditChain();
  res.json({ uptimeSec: Math.round(process.uptime()), ...db.stats(), auditOk: integ.ok, auditCount: integ.count, ts: new Date().toISOString() });
});

app.get('/api/preflight', auth.requireAuth, (req, res) => res.json(currentPreflight()));

app.get('/api/identity/setup-guide', auth.requireAuth, (req, res) => {
  try {
    res.json(identitySetup.buildIdentitySetupGuide({
      provider: req.query.provider,
      baseUrl: req.query.baseUrl || publicBaseUrl(req),
      tenantId: req.query.tenantId || req.query.tenant || req.query.oktaDomain,
    }));
  } catch (e) {
    res.status(400).json({ error: String((e && e.message) || e) });
  }
});

app.post('/api/retention/purge', ...adminWrite, (req, res) => {
  const result = runRetentionPurge({ actor: req.user.user });
  res.json({
    rawRetentionDays: result.rawRetentionDays,
    cutoff: result.cutoff,
    purged: result.purged.length,
    records: result.purged,
  });
});

// Per-user risk — answers the examiner's "did employee X expose member data?".
app.get('/api/risk', auth.requireAuth, (req, res) => {
  const rows = db.listQueries({ limit: 5000 });
  const by = {};
  for (const q of rows) {
    const u = q.user || 'unknown';
    const r = (by[u] = by[u] || { user: u, orgId: q.orgId || null, events: 0, blocked: 0, redacted: 0, riskSum: 0, maxSeverity: 0, entities: {} });
    r.events++;
    if (q.status === 'pending' || q.status === 'denied') r.blocked++;
    if (q.status === 'redacted') r.redacted++;
    r.riskSum += q.riskScore || 0;
    if ((q.maxSeverity || 0) > r.maxSeverity) r.maxSeverity = q.maxSeverity;
    for (const [k, v] of Object.entries(q.entityCounts || {})) r.entities[k] = (r.entities[k] || 0) + v;
  }
  const users = Object.values(by).map((r) => ({
    user: r.user, orgId: r.orgId, events: r.events, blocked: r.blocked, redacted: r.redacted,
    avgRisk: r.events ? Math.round(r.riskSum / r.events) : 0, maxSeverity: r.maxSeverity,
    topEntities: Object.entries(r.entities).sort((a, b) => b[1] - a[1]).slice(0, 5),
  })).sort((a, b) => (b.avgRisk * b.events) - (a.avgRisk * a.events));
  res.json({ users });
});

app.get('/api/coverage', auth.requireAuth, (req, res) => {
  res.json(coverage.summarize(db.listQueries({ limit: 5000 }), policy.loadPolicy()));
});

app.get('/api/lineage', auth.requireAuth, (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit) || 1000, 5000));
  const queries = db.listQueries({ limit });
  res.json({
    limit,
    lineage: evidence.buildLineage(queries),
  });
});

app.get('/api/destinations/review', auth.requireAuth, (req, res) => {
  const report = coverage.summarize(db.listQueries({ limit: 5000 }), policy.loadPolicy());
  res.json({ destinations: report.shadowDestinations || [], coverage: report });
});

app.post('/api/destinations/review', ...adminWrite, validation.validateBody(validation.destinationReviewSchema), (req, res) => {
  const before = policy.loadPolicy();
  let reviewed;
  try {
    reviewed = policy.reviewDestination(before, req.body.destination, req.body.decision);
  } catch (e) {
    return res.status(400).json({ error: 'invalid destination review' });
  }
  policy.savePolicy(reviewed.policy);
  db.appendAudit({
    action: 'DESTINATION_REVIEWED',
    actor: req.user.user,
    detail: policy.policyChangeDetail(before, reviewed.policy, { reason: req.body.reason }),
  });
  const report = coverage.summarize(db.listQueries({ limit: 5000 }), reviewed.policy);
  broadcast('stats', db.stats());
  res.json({ destination: reviewed.destination, decision: reviewed.decision, policy: reviewed.policy, coverage: report });
});

// Regulation policy templates (list + one-click apply).
app.get('/api/policy/templates', auth.requireAuth, (req, res) => res.json(templates.list()));
app.put('/api/policy/apply-template', ...adminWrite, validation.validateBody(validation.applyTemplateSchema), (req, res) => {
  const t = templates.get((req.body || {}).id);
  if (!t) return res.status(404).json({ error: 'unknown template' });
  const before = policy.loadPolicy();
  const merged = { ...before, ...t.policy };
  policy.savePolicy(merged);
  db.appendAudit({ action: 'POLICY_TEMPLATE_APPLIED', actor: req.user.user, detail: policy.policyChangeDetail(before, merged, { templateId: req.body.id }) });
  res.json(merged);
});

app.get('/api/audit', auth.requireAuth, (req, res) => {
  res.json({ entries: db.listAudit(Number(req.query.limit) || 200), integrity: db.verifyAuditChain() });
});

app.get('/api/export/evidence', auth.requireAuth, (req, res) => {
  const queryLimit = Math.min(Number(req.query.queryLimit) || 500, 5000);
  const auditLimit = Math.min(Number(req.query.auditLimit) || 500, 5000);
  const activePolicy = policy.loadPolicy();
  const queries = db.listQueries({ limit: queryLimit });
  const summaryQueries = db.listQueries({ all: true });
  res.json(evidence.buildEvidencePack({
    version: require('../package.json').version,
    queryLimit,
    auditLimit,
    summaryRowsIncluded: summaryQueries.length,
    summariesUseFullHistory: true,
    policy: activePolicy,
    stats: db.stats(),
    auditIntegrity: db.verifyAuditChain(),
    coverage: coverage.summarize(summaryQueries, activePolicy),
    policyExceptionReview: policy.policyExceptionReview(activePolicy),
    detectors: detector.listDetectors({ customDetectors: policy.customDetectorsForSensors() }),
    queries,
    lineageQueries: summaryQueries,
    audit: db.listAudit(auditLimit),
  }));
});

app.get('/api/policy', auth.requireAuth, (req, res) => res.json(policy.loadPolicy()));
app.put('/api/policy', ...adminWrite, validation.validateBody(validation.policyUpdateSchema), (req, res) => {
  const before = policy.loadPolicy();
  const merged = {
    ...before,
    ...(req.body || {}),
    ...(req.body && req.body.scanner ? { scanner: { ...(before.scanner || {}), ...req.body.scanner } } : {}),
  };
  policy.savePolicy(merged);
  const saved = policy.loadPolicy();
  db.appendAudit({ action: 'POLICY_UPDATED', actor: req.user.user, detail: policy.policyChangeDetail(before, saved) });
  res.json(saved);
});

// SSE stream for the dashboard.
app.get('/api/stream', auth.requireAuth, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
  res.flushHeaders();
  res.write(`event: hello\ndata: ${JSON.stringify({ ok: true })}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

// ---- Static dashboard --------------------------------------------------------
app.get('/', (req, res) => res.redirect('/index.html'));
app.get('/index.html', auth.requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use(express.static(path.join(__dirname, 'public')));

function logStartup(port) {
  console.log(`PromptWall running on http://localhost:${port}`);
  if (auth.ADMIN_PASSWORD_IS_DEFAULT) {
    console.log('  [!] Using DEFAULT admin password. Set ADMIN_PASSWORD before production.');
  }
  if (!auth.SECRET_IS_STABLE) {
    console.log('  [!] Session secret is ' + auth.SECRET_SOURCE + ' — set SENTINEL_SECRET (stable) for multi-instance deployments.');
  }
  if (!dataCrypto.ENABLED) {
    console.log('  [!] No SENTINEL_DATA_KEY/SENTINEL_SECRET set — raw prompts are NOT stored (reveal shows redacted). Set a key to enable encrypted raw retention for approvals.');
  } else {
    const days = policy.rawRetentionDays(policy.loadPolicy());
    console.log(`  Raw-prompt retention: encrypted at rest (AES-256-GCM), held items only; finalized records purge after ${days} day(s).`);
  }
  console.log(`  Ingest key: ${INGEST_KEY === 'dev-ingest-key' ? 'dev-ingest-key (override with INGEST_API_KEY)' : 'configured'}`);
}

function startServer(port = PORT) {
  const cfg = currentPreflight();
  const blockers = preflight.summarizeFailures(cfg);
  if (blockers.length) {
    for (const blocker of blockers) console.error('[preflight] ' + blocker);
    throw new Error('Production preflight failed');
  }
  runRetentionPurge();
  runWorkflowEscalation();
  const server = app.listen(port, () => {
    const address = server.address();
    logStartup(address && address.port ? address.port : port);
  });
  const retentionTimer = setInterval(() => runRetentionPurge(), 60 * 60 * 1000);
  const workflowTimer = setInterval(() => runWorkflowEscalation(), 5 * 60 * 1000);
  retentionTimer.unref();
  workflowTimer.unref();
  server.on('close', () => {
    clearInterval(retentionTimer);
    clearInterval(workflowTimer);
  });
  return server;
}

if (require.main === module) {
  startServer();
}

app.startServer = startServer;
app.runRetentionPurge = runRetentionPurge;
app.runWorkflowEscalation = runWorkflowEscalation;

module.exports = app;
