'use strict';
/**
 * RedactWall — inline DLP gateway for AI chat prompts.
 *
 * Flow:
 *   1. The network proxy (Squid+ICAP) or an SDK calls POST /api/v1/gate with the
 *      user's prompt + context before it is allowed to reach the AI service.
 *   2. RedactWall analyzes for PII, applies policy, and either ALLOWS or
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
const fs = require('fs');
const path = require('path');
const os = require('os');

const detector = require('./detector');
const email = require('./email');
const fleet = require('./fleet');
const adapters = require('../detection-engine/adapters');
const parsePool = require('./parse-pool');
const policy = require('./policy');
const policyImpact = require('./policy-impact');
const db = require('./db');
fleet.init(db);
const auth = require('./auth');
// SCIM deactivation invalidates already-issued sessions, not just new logins.
auth.setSessionRevokedCheck((session) => db.identityRevokedSince(session.user, session.iat));
const dataCrypto = require('./crypto');
const templates = require('./templates');
const alerts = require('./alerts');
const subscriptions = require('./subscriptions');
const policyBundle = require('./policy-bundle');
const siemPackage = require('./siem-package');
const evidence = require('./evidence');
const securityPackage = require('./security-package');
const preflight = require('./preflight');
const validation = require('./validation');
const coverage = require('./coverage');
const insights = require('./insights');
const appCatalog = require('./app-catalog');
const posture = require('./posture');
const detectorFeedback = require('./detector-feedback');
const detectionQuality = require('./detection-quality');
const ticketSync = require('./ticket-sync');
const semanticRemote = require('./semantic-remote');
const {
  endpointAiToolAttentionIds,
  endpointMcpServerAttentionIds,
  failedInstallCheckIds,
} = require('./install-checks');
const releaseTokens = require('./release-token');
const receipts = require('./receipts');
const tenant = require('./tenant');
const license = require('./license');
const openapi = require('./openapi');
const routing = require('./routing');
const workflow = require('./workflow');
const roles = require('./roles');
const scim = require('./scim');
const oidc = require('./oidc');
const identitySetup = require('./identity-setup');
const updater = require('./updater');

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

// Behind a load balancer/proxy, req.ip is otherwise the proxy's address, which
// collapses per-client ingest throttling into one shared bucket (one bad client
// could lock out the whole sensor fleet) and lets x-forwarded-* be trusted
// blindly. Default OFF (direct-connect/demo); set TRUST_PROXY when deployed
// behind a known proxy: a hop count ("1"), "true", or an IP/subnet list.
(function configureTrustProxy() {
  const raw = String(process.env.TRUST_PROXY || process.env.REDACTWALL_TRUST_PROXY || '').trim();
  if (!raw) return;
  if (/^\d+$/.test(raw)) app.set('trust proxy', Number(raw));
  else if (/^(true|false)$/i.test(raw)) app.set('trust proxy', raw.toLowerCase() === 'true');
  else app.set('trust proxy', raw.split(',').map((s) => s.trim()).filter(Boolean));
})();

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
function jsonErrorHandler(err, req, res, next) {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'request body too large' });
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) return res.status(400).json({ error: 'invalid json' });
  return next(err);
}
app.use(jsonErrorHandler);
app.use(cookieParser());

// ---- Health / readiness (public, no sensitive data) -------------------------
app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'redactwall', version: require('../package.json').version }));
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

const postureFeedState = { lastAttemptAt: 0, lastSentAt: 0, fingerprint: '' };

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
    try {
      emitAutomaticPostureFeed(action);
    } catch {}
  }
}

function fireSecurityAlert(row, opts) {
  try {
    Promise.resolve(alerts.emitSecurityAlert(row, opts)).catch(() => {});
    // Fan out to configured named SIEM/SOAR subscriptions (retry + delivery
    // history). Same threshold gate as the single webhook; payloads are the
    // prompt-free sanitized event.
    if (alerts.shouldAlert(row, opts)) {
      Promise.resolve(subscriptions.dispatch(alerts.sanitizedAlert(row, opts))).catch(() => {});
    }
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
    dbPath: process.env.REDACTWALL_DB_PATH || '',
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
    accountType: input.accountType || 'unknown',
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
  const row = db.createQuery(routing.withWorkflow(query, routeOptionsFor(query, opts)));
  fleet.recordPresence(row);
  return row;
}

function createQueryWithReleaseToken(query) {
  const routed = routing.withWorkflow(query, routeOptionsFor(query));
  let result;
  if (routed && (routed.status === 'pending' || routed._tokenVault)) {
    const release = releaseTokens.issueReleaseToken();
    result = { row: db.createQuery({ ...routed, _releaseTokenHash: release.hash }), releaseToken: release.token };
  } else {
    result = { row: db.createQuery(routed), releaseToken: null };
  }
  fleet.recordPresence(result.row);
  return result;
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

function safeFileLabel(filename) {
  const raw = String(filename || 'file').split(/[\\/]/).pop() || 'file';
  const base = path.basename(raw)
    .replace(/[\r\n\t]/g, ' ')
    .slice(0, 128)
    .trim() || 'file';
  const analysis = detector.analyze(base);
  return hasSensitivity(analysis) ? '[sensitive filename]' : base;
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

// Rebuild the "why this score" rationale for sensor-computed verdicts, using
// the same weights the engine applies, so client-scored rows explain
// themselves in the console exactly like server-scored ones.
function clientScoreBreakdown(findings, categories) {
  const entry = (kind, type, severity, score) => ({
    kind, type, severity,
    severityLabel: detector.SEVERITY_LABEL[severity] || 'none',
    confidence: score >= 0.9 ? 'very_likely' : score >= 0.7 ? 'likely' : 'possible',
    points: Math.round(severity * score * (kind === 'finding' ? 8 : 7)),
    regulations: detector.regulationsFor(type),
  });
  return findings.map((f) => entry('finding', f.type, f.severity, f.score))
    .concat(categories.map((c) => entry('category', c.category, detector.SEVERITY[c.category] || 2, c.score)));
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
  const scoreBreakdown = clientScoreBreakdown(findings, categories);
  return {
    findings,
    categories,
    entityCounts,
    riskScore,
    maxSeverity,
    maxSeverityLabel: detector.SEVERITY_LABEL[maxSeverity] || 'none',
    scoreBreakdown,
    regulations: [...new Set(scoreBreakdown.flatMap((e) => e.regulations))],
  };
}

function identityGroupsForRows(rows = []) {
  const wantedUsers = new Set((Array.isArray(rows) ? rows : [])
    .map((row) => String(row && row.user || '').trim().toLowerCase())
    .filter(Boolean));
  if (!wantedUsers.size) return {};
  const usersById = new Map();
  for (const user of db.listScimUsers()) {
    const userName = String(user && user.userName || '').trim();
    if (!userName || user.active === false || !wantedUsers.has(userName.toLowerCase())) continue;
    usersById.set(user.id, userName.toLowerCase());
  }
  const groupsByUser = {};
  if (!usersById.size) return groupsByUser;
  for (const group of db.listScimGroups()) {
    const displayName = String(group && group.displayName || '').trim();
    if (!displayName) continue;
    for (const member of group.members || []) {
      const userName = usersById.get(member && member.value);
      if (!userName) continue;
      if (!groupsByUser[userName]) groupsByUser[userName] = [];
      if (!groupsByUser[userName].includes(displayName)) groupsByUser[userName].push(displayName);
    }
  }
  return groupsByUser;
}

function currentPostureReport(limit = 5000, opts = {}) {
  const pol = policy.loadPolicy();
  const rows = db.listQueries({ limit });
  const feedbackReport = detectorFeedback.report({
    rows,
    feedback: db.listDetectorFeedback({ limit: 1000 }),
  });
  const detectionQualityReport = detectionQuality.report();
  return posture.summarize({
    rows,
    policy: pol,
    auditIntegrity: db.verifyAuditChain(),
    actionStates: db.postureActionStates(),
    segmentId: posture.normalizedSegmentId(opts.segmentId),
    identityGroups: identityGroupsForRows(rows),
    detectorFeedbackReport: feedbackReport,
    detectionQualityReport,
  });
}

function currentSecurityTrustPackage() {
  const activePolicy = policy.loadPolicy();
  const rows = db.listQueries({ all: true });
  const auditIntegrity = db.verifyAuditChain();
  const coverageReport = coverage.summarize(rows, activePolicy);
  return securityPackage.trustPackage({
    packageInfo: require('../package.json'),
    policy: activePolicy,
    auditIntegrity,
    preflight: currentPreflight(),
    coverage: coverageReport,
    posture: posture.summarize({
      rows,
      policy: activePolicy,
      coverageReport,
      auditIntegrity,
      actionStates: db.postureActionStates(1000),
      detectorFeedbackReport: detectorFeedback.report({
        rows,
        feedback: db.listDetectorFeedback({ limit: 1000 }),
      }),
      detectionQualityReport: detectionQuality.report(),
    }),
    env: process.env,
  });
}

function emitAutomaticPostureFeed(trigger = 'evidence') {
  if (!alerts.postureFeedEnabled(process.env)) return;
  const report = currentPostureReport(5000);
  Promise.resolve(alerts.emitPostureFeed(report, {
    state: postureFeedState,
    action: 'POSTURE_FEED',
    trigger,
  })).then((result) => {
    if (!result || !result.attempted) return;
    db.appendAudit({
      action: result.sent ? 'POSTURE_FEED_SENT' : 'POSTURE_FEED_FAILED',
      actor: 'system',
      detail: result.sent ? `sent:${result.status || 'ok'}` : `not_sent:${result.reason || 'unknown'}`,
    });
  }).catch(() => {});
}

function isoOrNow(value) {
  const parsed = value ? new Date(value) : null;
  return parsed && Number.isFinite(parsed.getTime()) ? parsed.toISOString() : new Date().toISOString();
}

function isoOrNull(value) {
  const parsed = value ? new Date(value) : null;
  return parsed && Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function discoveryEvidenceReasons({ source, vendor, events }) {
  const sourceLabel = vendor || source || 'proxy';
  return [
    'AI asset discovered from sanitized inventory',
    `Source: ${sourceLabel}`,
    `${events} observation${events === 1 ? '' : 's'}`,
  ];
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
      ...(f.vendor ? { vendor: f.vendor, vendorLabel: f.vendorLabel } : {}),
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

// Prompt-free AI-app discovery hook. Records a sighting only for real AI hosts
// (governed or shadow), never for internal labels like 'gateway:...' or
// 'sensor-health'. Best-effort — never blocks the gate path.
function recordAiSighting(destination, source, outcome) {
  try {
    const host = adapters.normalizeHost(destination);
    if (!host || host.includes(':') || !adapters.isAiHost(host)) return;
    appCatalog.recordSighting({ destination: host, source: source === 'browser_extension' ? 'browser' : source, outcome });
  } catch (e) { /* discovery is best-effort */ }
}
app.post('/api/v1/discovery', checkIngestKey, validation.validateBody(validation.aiDiscoverySchema), (req, res) => {
  if (!enforceTenantForSensor(req, res)) return;
  const {
    source = 'proxy',
    user = 'discovery-import',
    orgId = null,
    vendor = '',
    sensor = null,
    sightings = [],
  } = req.body || {};
  const rows = [];
  let observations = 0;

  for (const sighting of sightings) {
    const destination = policy.normalizeDestination(sighting.destination);
    const events = Math.max(1, Math.min(100000, Number(sighting.events) || 1));
    const createdAt = isoOrNow(sighting.lastSeen);
    observations += events;
    const row = createQuery({
      createdAt,
      status: 'shadow_ai',
      mode: 'discovery',
      user: sighting.user || user,
      orgId: sighting.orgId || orgId || null,
      destination,
      source,
      channel: 'shadow_ai',
      sensor,
      redactedPrompt: `[AI discovery import] ${destination}`,
      findings: [],
      categories: [],
      entityCounts: {},
      riskScore: 0,
      maxSeverity: 0,
      maxSeverityLabel: 'none',
      reasons: discoveryEvidenceReasons({ source, vendor, events }),
      discoveryEvents: events,
      discoverySource: vendor || source,
      discoveryCategory: sighting.category || 'unknown',
      discoveryConfidence: Number.isFinite(Number(sighting.confidence)) ? Number(sighting.confidence) : null,
      firstSeen: isoOrNull(sighting.firstSeen),
      lastSeen: createdAt,
    });
    rows.push(row);
  }

  const first = rows[0] || null;
  db.appendAudit({
    action: 'AI_DISCOVERY_IMPORTED',
    queryId: first ? first.id : null,
    actor: user,
    detail: `${source}: ${rows.length} destinations / ${observations} observations`,
  });
  for (const row of rows) {
    broadcast('query', { type: 'shadow_ai', query: publicQuery(row) });
  }
  broadcast('stats', db.stats());
  return res.status(202).json({
    status: 'imported',
    imported: rows.length,
    observations,
    privacy: 'prompt bodies and raw URLs are not accepted',
    destinations: rows.map((row) => ({
      id: row.id,
      destination: row.destination,
      observations: row.discoveryEvents || 1,
      status: row.status,
    })),
  });
});

app.post('/api/v1/gate', checkIngestKey, validation.validateBody(validation.gateSchema), async (req, res) => {
  if (!enforceTenantForSensor(req, res)) return;
  const {
    prompt, user = 'unknown', destination = 'unknown', sourceIp = null,
    source = 'api', channel = 'submit', clientOutcome = null, note = '', orgId = null,
    sensor = null,
  } = req.body || {};
  if (typeof prompt !== 'string' || !prompt.trim()) return res.status(400).json({ error: 'prompt (string) required' });

  const clientAccount = (req.body && req.body.clientAccount) || {};
  const accountType = ['personal', 'corporate', 'unknown'].includes(clientAccount.type) ? clientAccount.type : 'unknown';
  const accountSignal = clientAccount.signal || 'none';
  const originApp = (req.body && typeof req.body.originApp === 'string' && /^[a-z][a-z0-9_]{0,39}$/.test(req.body.originApp)) ? req.body.originApp : null;
  const pol = policy.loadPolicy();
  const declaredClientPreRedacted = req.body && req.body.clientPreRedacted === true;
  const clientAnalysis = declaredClientPreRedacted ? clientAnalysisFrom(req.body) : null;
  if (clientOutcome === 'proxy_observed') {
    if (source !== 'proxy' || channel !== 'proxy_monitor') {
      return res.status(400).json({ error: 'proxy monitor source required' });
    }
    if (!declaredClientPreRedacted) {
      return res.status(400).json({ error: 'proxy monitor requires pre-redacted evidence' });
    }
    const normalized = policy.normalizeDestination(destination);
    const safePrompt = String(prompt || '').trim();
    const isProxyObservationLabel = safePrompt === `[proxy observed] ${normalized}`;
    const isRedactedEvidenceLabel = /^\[REDACTED: [A-Z0-9_, ]+\]$/.test(safePrompt);
    if (!isProxyObservationLabel && !isRedactedEvidenceLabel) {
      return res.status(400).json({ error: 'proxy monitor prompt must be pre-redacted' });
    }
    const safePromptAnalysis = detector.analyze(prompt, policy.analyzeOpts(pol));
    if (hasSensitivity(safePromptAnalysis)) {
      return res.status(400).json({ error: 'proxy monitor prompt must be pre-redacted' });
    }
    const analysis = clientAnalysis || {
      findings: [],
      categories: [],
      entityCounts: {},
      riskScore: 0,
      maxSeverity: 0,
      maxSeverityLabel: 'none',
    };
    const findings = analysis.findings.map((f) => ({
      type: f.type, severity: f.severity, score: f.score, masked: f.masked,
    }));
    const categories = (analysis.categories || []).map((c) => c.category);
    const reasons = hasSensitivity(analysis)
      ? ['AI-domain request observed by monitor proxy', 'Sensitive content observed locally by proxy monitor']
      : ['AI-domain request observed by monitor proxy'];
    const row = createQuery({
      status: 'proxy_observed',
      mode: 'monitor',
      user,
      orgId,
      destination: normalized,
      sourceIp,
      source,
      channel,
      sensor,
      redactedPrompt: String(prompt || '').slice(0, 600),
      findings,
      categories,
      entityCounts: analysis.entityCounts || {},
      riskScore: analysis.riskScore || 0,
      maxSeverity: analysis.maxSeverity || 0,
      maxSeverityLabel: analysis.maxSeverityLabel || 'none',
      reasons,
    });
    db.appendAudit({ action: 'PROXY_OBSERVED', queryId: row.id, actor: user, detail: `${source}/${channel}: ${normalized}` });
    emitSecurityAlert(row, 'PROXY_OBSERVED');
    broadcast('query', { type: 'proxy_observed', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({
      id: row.id,
      decision: 'log',
      mode: 'monitor',
      status: 'proxy_observed',
      riskScore: analysis.riskScore || 0,
      findings,
      categories,
      reasons,
    });
  }
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
  // Server-side mirror of the extension's personal-account block (N4). Never
  // blocks on 'unknown'; the label enum arrives sanitized (no email).
  if (policy.personalAccountBlocked(accountType, pol)) {
    return blockDestinationByPolicy(res, {
      user,
      orgId,
      destination,
      sourceIp,
      source,
      channel,
      sensor,
      redactedPrompt: '[personal AI account blocked] ' + policy.normalizeDestination(destination),
      reason: 'Personal AI account blocked by policy; sign in with the corporate workspace account',
    });
  }
  if (clientOutcome === 'file_upload_blocked') {
    return blockFileUploadByPolicy(res, { user, orgId, destination, sourceIp, source, channel, sensor });
  }
  if (policy.unmanagedInstallBlocked(user, pol)) {
    return blockDestinationByPolicy(res, {
      user,
      orgId,
      destination,
      sourceIp,
      source,
      channel,
      sensor,
      redactedPrompt: '[unmanaged install blocked] ' + policy.normalizeDestination(destination),
      reason: 'Unmanaged browser install blocked by policy; enroll the device for managed identity',
    });
  }
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
  const serverAnalysis = await semanticRemote.augmentAnalysis(prompt, detector.analyze(prompt, analyzeOpts));
  const clientPreRedacted = declaredClientPreRedacted && clientAnalysis && !hasSensitivity(serverAnalysis);
  const clientRedactionResolved = (clientOutcome === 'redacted_sent' || clientOutcome === 'redacted_available') && clientPreRedacted;
  const analysis = clientPreRedacted ? clientAnalysis : serverAnalysis;
  const ctx = policyContext({ user, orgId, destination, source, channel, accountType });
  const verdict = policy.evaluate(analysis, pol, ctx);
  const decisionPolicy = verdict.policy || pol;

  // Privacy-preserving record: redacted prompt + masked findings + categories.
  const redactedPrompt = clientRedactionResolved && !categoryNames(analysis).length ? prompt : safePreview(prompt, analysis);
  const findings = analysis.findings.map((f) => ({
    type: f.type, severity: f.severity, score: f.score, confidence: f.confidenceLabel || null,
    masked: f.masked || detector.maskValue(f.type, f.value || ''),
    ...(f.vendor ? { vendor: f.vendor, vendorLabel: f.vendorLabel } : {}),
  }));
  const categories = (analysis.categories || []).map((c) => c.category);

  const base = {
    user, orgId, destination, sourceIp, source, channel, sensor,
    redactedPrompt, findings, categories, entityCounts: analysis.entityCounts,
    riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity,
    maxSeverityLabel: analysis.maxSeverityLabel, reasons: verdict.reasons,
    scoreBreakdown: analysis.scoreBreakdown, regulations: analysis.regulations,
    accountType, accountSignal,
    ...(originApp ? { originApp } : {}),
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

  // One discovery sighting per gate request. Shadow-AI visits are recorded in
  // their own branch below with the 'shadow' outcome, so skip the 'gated' record
  // for them to avoid double-counting a single user action.
  if (clientOutcome !== 'shadow_ai') recordAiSighting(destination, source, 'gated');

  // Shadow-AI discovery: a visit to an AI tool policy does not govern. Recorded
  // as an informational event so the examiner sees unmonitored paths, not a leak.
  if (clientOutcome === 'shadow_ai') {
    recordAiSighting(destination, source, 'shadow');
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
    return res.json({
      id: row.id, decision: 'allow', riskScore: analysis.riskScore, findings, categories,
      receipt: receipts.issueReceipt({ id: row.id, status: 'allowed', outboundText: prompt, policy: decisionPolicy, destination, user }),
    });
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

  // alwaysBlock invariant: when the prompt still contains a raw hard-stop value
  // (serverAnalysis found it — so this is NOT a genuine client pre-redaction),
  // a sensor-declared outcome can never clear it as sent/justified/warned. Hold
  // it for Security Admin approval so no raw regulated value is recorded as
  // cleared or issued a safe-to-send receipt. 'redacted' is exempt because the
  // server re-tokenizes it below (real values never leave); 'blocked_by_user'
  // already withholds.
  if (hardStop && status !== 'redacted' && status !== 'blocked_by_user') status = 'pending';

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
  // Safe-to-send receipt: signed proof the outbound text (tokenized for
  // redact, original for warn/justify paths) was scanned under this policy.
  const receipt = receipts.issueReceipt({
    id: row.id, status,
    outboundText: status === 'redacted' ? tokenizedPrompt : prompt,
    policy: decisionPolicy, destination, user,
  });
  return res.json({
    id: row.id, decision: status === 'redacted' ? 'redact' : 'block', mode, status,
    ...releaseTokenPayload(releaseToken),
    riskScore: analysis.riskScore, findings, categories, reasons: verdict.reasons,
    tokenizedPrompt,
    ...(receipt ? { receipt } : {}),
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
  const aiToolAttention = endpointAiToolAttentionIds(checks);
  const mcpServerAttention = endpointMcpServerAttentionIds(checks);
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
    reasons: failedChecks.length
      ? ['Sensor health attention: ' + failedChecks.join(', ')]
      : aiToolAttention.length
        ? ['Endpoint AI tool inventory attention: ' + aiToolAttention.join(', ')]
        : mcpServerAttention.length
          ? ['Endpoint MCP server inventory attention: ' + mcpServerAttention.join(', ')]
          : ['Sensor heartbeat OK'],
    installChecks: checks,
  });
  db.appendAudit({
    action: failedChecks.length ? 'SENSOR_HEALTH_ATTENTION' : 'SENSOR_HEARTBEAT',
    queryId: row.id,
    actor: user,
    detail: JSON.stringify({ source, failedChecks, aiToolAttention, mcpServerAttention, checkCount: checks.length }),
  });
  if (aiToolAttention.length) {
    db.appendAudit({
      action: 'ENDPOINT_AI_TOOL_ATTENTION',
      queryId: row.id,
      actor: user,
      detail: JSON.stringify({ source, unapprovedTools: aiToolAttention }),
    });
  }
  if (mcpServerAttention.length) {
    db.appendAudit({
      action: 'ENDPOINT_MCP_SERVER_ATTENTION',
      queryId: row.id,
      actor: user,
      detail: JSON.stringify({ source, unapprovedServers: mcpServerAttention }),
    });
  }
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
    // Tell this sensor about its peers on the same identity, so sensors can
    // surface each other's absence (extension installed but agent missing, ...).
    companions: fleet.companionsFor(user, { exclude: source }),
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
  const releaseToken = req.get('x-release-token') || '';
  if (!q._releaseTokenHash || !releaseTokens.verifyReleaseToken(q, releaseToken)) return res.status(401).json({ error: 'invalid release token' });
  const mapJson = dataCrypto.open(q._tokenVault);
  if (mapJson == null) return res.status(409).json({ error: 'vault unavailable (no/incorrect data key)' });
  let map; try { map = JSON.parse(mapJson); } catch { return res.status(500).json({ error: 'vault corrupt' }); }
  const out = detector.detokenize(typeof text === 'string' ? text : '', map);
  db.appendAudit({ action: 'REHYDRATE', queryId: q.id, actor: q.user || 'sensor', detail: `re-hydrated ${Object.keys(map).length} token(s)` });
  res.json({ id: q.id, text: out, rehydrated: true });
});

// Public policy for sensors (ingest-key protected).
function sensorSafePolicy() {
  const p = policy.loadPolicy();
  return {
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
    corporateAiAccounts: p.corporateAiAccounts || policy.DEFAULT_POLICY.corporateAiAccounts,
    responseScanMode: p.responseScanMode || policy.DEFAULT_POLICY.responseScanMode,
    unmanagedInstalls: p.unmanagedInstalls || policy.DEFAULT_POLICY.unmanagedInstalls,
    desktopCollectorDestination: p.desktopCollectorDestination || policy.DEFAULT_POLICY.desktopCollectorDestination,
    requiredSensors: p.requiredSensors || policy.DEFAULT_POLICY.requiredSensors,
    desiredSensorVersions: p.desiredSensorVersions || policy.DEFAULT_POLICY.desiredSensorVersions,
    mcpAllowedTools: p.mcpAllowedTools || policy.DEFAULT_POLICY.mcpAllowedTools,
    mcpBlockedTools: p.mcpBlockedTools || policy.DEFAULT_POLICY.mcpBlockedTools,
    mcpApprovalRequiredTools: p.mcpApprovalRequiredTools || policy.DEFAULT_POLICY.mcpApprovalRequiredTools,
    scanner: p.scanner || {},
  };
}

app.get('/api/v1/policy', checkIngestKey, (req, res) => {
  res.json(sensorSafePolicy());
});

// Signed, versioned, expiring policy bundle. Sensors verify with the public key
// (GET /api/v1/policy/pubkey) and FAIL CLOSED when the bundle is unverifiable or
// stale — moving policy trust to the sensor edge.
app.get('/api/v1/policy/bundle', checkIngestKey, (req, res) => {
  res.json(policyBundle.buildBundle(sensorSafePolicy()));
});

app.get('/api/v1/policy/pubkey', checkIngestKey, (req, res) => {
  res.json({ publicKey: policyBundle.publicKeyPem(), algorithm: 'ed25519', bundleVersion: policyBundle.BUNDLE_VERSION });
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
  const fileLabel = safeFileLabel(filename);
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
  try { extracted = await parsePool.extractText(filename, buf); }
  catch (e) { extracted = { text: '', processor: null, supported: true, extractionOk: false, error: 'extract_failed' }; }
  if (!extracted.supported) {
    const row = createQuery({ status: 'flagged', user, orgId, destination, source, channel, sensor,
      redactedPrompt: '[unsupported file] ' + fileLabel, findings: [], categories: [], entityCounts: {},
      riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none', reasons: ['Unsupported file type recorded'] });
    db.appendAudit({ action: 'FILE_RECORDED', queryId: row.id, actor: user, detail: fileLabel });
    emitSecurityAlert(row, 'FILE_RECORDED');
    broadcast('query', { type: 'flagged', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', supported: false, filename: fileLabel });
  }
  if (!extracted.extractionOk) {
    const ocrRequired = extracted.error === 'ocr_required' || extracted.ocrRequired === true;
    const status = ocrRequired ? 'ocr_required' : 'file_blocked_unscanned';
    const reason = ocrRequired ? 'OCR is required before this file can be inspected'
      : extracted.error === 'timeout' ? 'File extraction timed out before inspection completed'
      : 'File could not be inspected';
    const row = createQuery({ status, user, orgId, destination, source, channel, sensor,
      filename: fileLabel, processor: extracted.processor, redactedPrompt: (ocrRequired ? '[ocr required file] ' : '[unreadable file] ') + fileLabel,
      findings: [], categories: [], entityCounts: {}, riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none',
      reasons: [reason] });
    const action = ocrRequired ? 'FILE_OCR_REQUIRED' : 'FILE_BLOCKED_UNREADABLE';
    db.appendAudit({ action, queryId: row.id, actor: user, detail: `${fileLabel}: ${extracted.error || 'extract_failed'}` });
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
      filename: fileLabel,
      processor: extracted.processor,
      ...(ocrRequired ? { ocrRequired: true } : {}),
      reasons: [reason],
    });
  }

  const analysis = detector.analyze(extracted.text, policy.analyzeOpts(pol));
  const ctx = policyContext({ user, orgId, destination, source, channel });
  const verdict = policy.evaluate(analysis, pol, ctx);
  const decisionPolicy = verdict.policy || pol;
  const findings = analysis.findings.map((x) => ({ type: x.type, severity: x.severity, score: x.score, masked: detector.maskValue(x.type, x.value), ...(x.vendor ? { vendor: x.vendor, vendorLabel: x.vendorLabel } : {}) }));
  const categories = (analysis.categories || []).map((c) => c.category);
  const preview = safePreview(extracted.text, analysis, '[file:' + fileLabel + '] ');
  const base = { user, orgId, destination, source, channel, sensor, filename: fileLabel, processor: extracted.processor,
    redactedPrompt: preview, findings, categories, entityCounts: analysis.entityCounts,
    riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity, maxSeverityLabel: analysis.maxSeverityLabel, reasons: verdict.reasons,
    scoreBreakdown: analysis.scoreBreakdown, regulations: analysis.regulations,
    ...policyDecisionMetadata(verdict) };

  if (verdict.decision === 'allow') {
    const row = createQuery({ status: 'allowed', ...base });
    db.appendAudit({ action: 'FILE_ALLOWED', queryId: row.id, actor: user, detail: fileLabel + ' risk ' + analysis.riskScore });
    emitSecurityAlert(row, 'FILE_ALLOWED');
    broadcast('query', { type: 'allowed', query: publicQuery(row) }); broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', supported: true, filename: fileLabel, riskScore: analysis.riskScore, findings, categories });
  }
  const hardStop = analysis.findings.some((x) => decisionPolicy.alwaysBlock.includes(x.type));
  const mode = decisionPolicy.enforcementMode === 'redact' ? 'redact' : (hardStop ? 'block' : (decisionPolicy.enforcementMode || 'block'));
  const status = mode === 'redact' ? (canTokenizeAllSensitivity(analysis) ? 'redacted' : 'pending')
    : mode === 'warn' ? 'warned'
    : mode === 'justify' ? 'pending_justification'
    : 'pending';
  const rawFile = '[file:' + fileLabel + ']\n' + extracted.text.slice(0, 5000);
  let tokenizedPrompt, tokenVault;
  if (status === 'redacted') {
    const t = detector.tokenize(extracted.text, analysis.findings);
    tokenizedPrompt = '[file:' + fileLabel + ']\n' + t.text;
    tokenVault = dataCrypto.seal(JSON.stringify(t.map));
  }
  const { row, releaseToken } = createQueryWithReleaseToken({
    status, mode, ...base, _rawPrompt: rawToStore(rawFile, status, decisionPolicy), _tokenVault: tokenVault, tokenizedPrompt,
  });
  const action = status === 'pending' ? 'FILE_BLOCKED'
    : status === 'redacted' ? 'FILE_REDACTED'
    : 'FILE_FLAGGED';
  db.appendAudit({ action, queryId: row.id, actor: user, detail: fileLabel + ': ' + verdict.reasons.join('; ') });
  emitSecurityAlert(row, action);
  broadcast('query', { type: status, query: publicQuery(row) }); broadcast('stats', db.stats());
  res.json({
    id: row.id,
    decision: status === 'redacted' ? 'redact' : 'block',
    mode,
    status,
    ...releaseTokenPayload(releaseToken),
    supported: true,
    filename: fileLabel,
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
app.post('/api/v1/scan-response', checkIngestKey, validation.validateBody(validation.scanResponseSchema), async (req, res) => {
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
  const analysis = await semanticRemote.augmentAnalysis(text, detector.analyze(text, policy.analyzeOpts(pol)));
  const findings = analysis.findings.map((f) => ({ type: f.type, severity: f.severity, score: f.score, masked: detector.maskValue(f.type, f.value), ...(f.vendor ? { vendor: f.vendor, vendorLabel: f.vendorLabel } : {}) }));
  const categories = (analysis.categories || []).map((c) => c.category);
  const redacted = safePreview(text, analysis);
  const leaked = findings.length > 0 || categories.length > 0;
  const outcome = responseScanOutcome(pol.responseScanMode);
  if (leaked) {
    const row = createQuery({ status: outcome.status, mode: 'response_' + outcome.decision, user, orgId, destination, source, channel: 'ai_response', sensor,
      redactedPrompt: '[AI response] ' + redacted, findings, categories, entityCounts: analysis.entityCounts,
      riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity, maxSeverityLabel: analysis.maxSeverityLabel,
      scoreBreakdown: analysis.scoreBreakdown, regulations: analysis.regulations,
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

// Machine-readable API spec. Public like /healthz — the route inventory is
// already public in docs, and the spec carries no data. Built once and cached.
app.get('/api/v1/openapi.json', (req, res) => res.json(openapi.document()));

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
    const recoveryIndex = auth.recoveryCodeIndex(otp);
    if (recoveryIndex < 0 || !db.consumeMfaRecoveryCode(recoveryIndex)) {
      const r = auth.registerFail(key);
      db.appendAudit({ action: 'ADMIN_MFA_FAILED', actor: account.user, detail: r.locked ? 'locked out' : (r.remaining + ' attempts left') });
      return res.status(401).json({ error: 'invalid mfa code', mfaRequired: true, remaining: r.remaining });
    }
    db.appendAudit({ action: 'ADMIN_MFA_RECOVERY_USED', actor: account.user, detail: `recovery code ${recoveryIndex + 1} of ${auth.MFA_RECOVERY_CODE_COUNT} consumed` });
  }
  auth.registerSuccess(key);
  const token = auth.createSession(account.user, account.role);
  res.cookie(auth.SESSION_COOKIE_NAME, token, SESSION_COOKIE_OPTIONS);
  for (const legacyCookie of auth.LEGACY_SESSION_COOKIE_NAMES) res.clearCookie(legacyCookie, SESSION_COOKIE_CLEAR_OPTIONS);
  db.appendAudit({
    action: roles.loginAuditAction(account.role),
    actor: account.user,
    detail: account.role,
  });
  res.json({ ok: true, user: account.user, role: account.role });
});

app.get('/api/login-options', (req, res) => {
  res.json({ oidc: oidc.publicOptions(), defaultAdminCredential: auth.ADMIN_PASSWORD_IS_DEFAULT });
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
    for (const legacyCookie of auth.LEGACY_SESSION_COOKIE_NAMES) res.clearCookie(legacyCookie, SESSION_COOKIE_CLEAR_OPTIONS);
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
const adminRead = [auth.requireAuth, auth.requireRole(roles.SECURITY_ADMIN)];
// license.requireWritable is appended LAST: past the license grace window it
// returns 403 license_readonly for config writes, but exempts /api/queries/
// (reveal/assign keep the approval workflow alive) and the license-install
// route. It never gates ingest, SCIM, or decision routes — the security
// function must never be disabled for billing.
const adminWrite = [auth.requireAuth, auth.requireCsrf, auth.requireRole(roles.SECURITY_ADMIN), license.requireWritable];
const decisionWrite = [auth.requireAuth, auth.requireCsrf, auth.requireRole(roles.SECURITY_ADMIN, roles.APPROVER)];
// Compliance evidence exports: the auditor's whole job, without admin power.
const auditRead = [auth.requireAuth, auth.requireRole(roles.SECURITY_ADMIN, roles.AUDITOR)];
// Fleet/runtime operations: updates, posture triage, delivery checks - no policy power.
const operatorRead = [auth.requireAuth, auth.requireRole(roles.SECURITY_ADMIN, roles.OPERATOR)];
const operatorWrite = [auth.requireAuth, auth.requireCsrf, auth.requireRole(roles.SECURITY_ADMIN, roles.OPERATOR), license.requireWritable];
const API_MAX_LIST_LIMIT = 5000;

function boundedApiLimit(value, fallback = 200, max = API_MAX_LIST_LIMIT) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(1, Math.min(Math.trunc(parsed), max));
}

app.get('/api/csrf', auth.requireAuth, (req, res) => {
  res.json({ csrfToken: auth.createCsrfToken(auth.sessionTokenFromRequest(req)) });
});

app.post('/api/logout', ...sessionWrite, (req, res) => {
  res.clearCookie(auth.SESSION_COOKIE_NAME, SESSION_COOKIE_CLEAR_OPTIONS);
  for (const legacyCookie of auth.LEGACY_SESSION_COOKIE_NAMES) res.clearCookie(legacyCookie, SESSION_COOKIE_CLEAR_OPTIONS);
  res.json({ ok: true });
});

// Dedicated step-up flow: verify the password once, then re-issue the session
// with a short-lived elevation window that reveal/approve actions accept.
app.post('/api/auth/step-up', ...sessionWrite, (req, res) => {
  const user = req.user && req.user.user;
  const key = stepUpKey('STEP_UP', user, req);
  const st = auth.loginStatus(key);
  if (st.locked) {
    db.appendAudit({ action: 'STEP_UP_LOCKED', actor: user || '?', detail: 'too many attempts' });
    return res.status(429).json({ error: 'too many attempts - temporarily locked', retryMs: st.retryMs });
  }
  if (req.user.provider === 'oidc') {
    if (auth.stepUpSatisfied(req.user)) return res.json({ ok: true, stepUpUntil: req.user.stepUpUntil });
    return res.status(409).json({ error: 'reauthenticate with your identity provider to elevate', oidc: true });
  }
  if (!auth.verifyPassword(user, req.body && req.body.password)) {
    const r = auth.registerFail(key);
    db.appendAudit({ action: 'STEP_UP_FAILED', actor: user || '?', detail: r.locked ? 'locked out' : (r.remaining + ' attempts left') });
    return res.status(401).json({ error: 'invalid credentials', remaining: r.remaining });
  }
  auth.registerSuccess(key);
  const elevated = auth.elevateSession(req.user);
  res.cookie(auth.SESSION_COOKIE_NAME, elevated, SESSION_COOKIE_OPTIONS);
  db.appendAudit({ action: 'STEP_UP_GRANTED', actor: user, detail: `elevated for ${Math.round(auth.STEP_UP_TTL_MS / 60000)} min` });
  res.json({ ok: true, stepUpUntil: Date.now() + auth.STEP_UP_TTL_MS });
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
    if (auth.stepUpSatisfied(req.user)) {
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

function requireFeedbackAccess(req, res, next) {
  const q = db.getQuery(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  if (req.user && req.user.role === roles.SECURITY_ADMIN) {
    req.queryRecord = q;
    return next();
  }
  if (!roles.canDecideQuery(req.user, q)) return res.status(403).json({ error: 'forbidden' });
  req.queryRecord = q;
  return next();
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
  const sanitized = { ...rest, rawRetained: Boolean(_rawPrompt) };
  return includeRaw ? { ...sanitized, rawPrompt: _rawPrompt } : sanitized;
}

app.get('/api/queries', auth.requireAuth, (req, res) => {
  const status = req.query.status;
  const rows = db.listQueries({ status, limit: boundedApiLimit(req.query.limit, 200) });
  res.json(rows.map((q) => publicQuery(q)));
});

// Two-way ticket state: pull Jira/Linear issue status back onto queries.
app.post('/api/tickets/sync', ...adminWrite, async (req, res) => {
  const result = await ticketSync.syncTicketStatuses({
    db,
    onUpdate: (updated) => broadcast('query', { type: 'ticket_synced', query: publicQuery(updated) }),
  });
  res.json(result);
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
    res.json({
      id: q.id,
      rawPrompt,
      rawRetained,
      rawDiffersFromRedacted: rawRetained && String(rawPrompt || '') !== String(q.redactedPrompt || ''),
    });
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

// Bulk decision: approve or deny up to 50 held prompts in one audited pass.
// Same gates as single decisions - role, per-item decision access, and
// password step-up for approvals - with per-item outcomes so a partial bulk
// is honest about what it skipped and why.
function applyBulkDecision(req) {
  const status = req.body.action === 'approve' ? 'approved' : 'denied';
  const note = (req.body && req.body.note) || '';
  const results = [];
  for (const id of req.body.ids) {
    const q = db.getQuery(id);
    if (!q) { results.push({ id, outcome: 'skipped', reason: 'not found' }); continue; }
    if (q.status !== 'pending') { results.push({ id, outcome: 'skipped', reason: `already ${q.status}` }); continue; }
    if (!roles.canDecideQuery(req.user, q)) { results.push({ id, outcome: 'skipped', reason: 'not yours to decide' }); continue; }
    db.updateQuery(id, { status, decidedBy: req.user.user, decidedAt: new Date().toISOString(), decisionNote: note });
    db.appendAudit({ action: status.toUpperCase(), queryId: id, actor: req.user.user, detail: note ? `${note} (bulk)` : 'bulk decision' });
    broadcast('decision', { id, status });
    results.push({ id, outcome: status });
  }
  broadcast('stats', db.stats());
  return results;
}

app.post(
  '/api/queries/bulk-decision',
  ...decisionWrite,
  validation.validateBody(validation.bulkDecisionSchema),
  (req, res, next) => (req.body.action === 'approve' ? requireApprovePassword(req, res, next) : next()),
  (req, res) => {
    const results = applyBulkDecision(req);
    res.json({
      results,
      decided: results.filter((r) => r.outcome !== 'skipped').length,
      skipped: results.filter((r) => r.outcome === 'skipped').length,
    });
  },
);

// Inline reassignment: Security Admins can change who owns a held decision
// straight from the queue row. Metadata only - the audit line records the new
// owner, never prompt content. Empty string clears a field; omitted fields
// keep their routed value.
function assignmentPatch(body = {}) {
  const patch = {};
  for (const key of ['assignedUser', 'assignedGroup', 'assignedRole']) {
    if (body[key] === undefined) continue;
    patch[key] = String(body[key]).trim() || null;
  }
  return patch;
}

app.post('/api/queries/:id/assign', ...adminWrite, validation.validateBody(validation.assignSchema), (req, res) => {
  const q = db.getQuery(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  if (!routing.routeableStatus(q.status)) return res.status(409).json({ error: `not reassignable: ${q.status}` });
  const updated = db.updateQuery(q.id, assignmentPatch(req.body));
  db.appendAudit({
    action: 'APPROVAL_REASSIGNED',
    queryId: q.id,
    actor: req.user.user,
    detail: [
      `assignedUser=${updated.assignedUser || 'none'}`,
      `assignedGroup=${updated.assignedGroup || 'none'}`,
      `assignedRole=${updated.assignedRole || 'none'}`,
    ].join('; '),
  });
  broadcast('query', { type: updated.status, query: publicQuery(updated) });
  res.json(publicQuery(updated));
});

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

// AI-usage analytics for the Insights dashboard (metadata only; no prompt text).
app.get('/api/insights', auth.requireAuth, (req, res) => {
  const windowDays = boundedApiLimit(req.query.windowDays, 30, 90);
  res.json(insights.summarize(db.listQueries({ limit: 5000 }), { windowDays }));
});

app.get('/api/billing/seats', ...adminRead, (req, res) => {
  res.json({ ...tenant.seatReport(db), license: license.publicStatus() });
});

app.get('/api/billing/license', ...adminRead, (req, res) => {
  res.json(license.publicStatus());
});

// Installing a renewal must always work, even in readonly state — so this is
// NOT gated by license.requireWritable (adminRead has no requireWritable; the
// POST uses an explicit chain without it).
app.post('/api/billing/license',
  auth.requireAuth, auth.requireCsrf, auth.requireRole(roles.SECURITY_ADMIN),
  validation.validateBody(validation.licenseInstallSchema),
  (req, res) => {
    const text = String(req.body.license || '');
    const v = license.verifyLicenseText(text);
    if (!v.ok) {
      db.appendAudit({ action: 'LICENSE_INSTALL_REJECTED', actor: req.user.user, detail: `reason=${v.reason}` });
      return res.status(400).json({ error: 'invalid_license', reason: v.reason });
    }
    try {
      fs.writeFileSync(license.licensePath(), text.trim() + '\n', { mode: 0o600 });
    } catch (e) {
      return res.status(500).json({ error: 'license_write_failed' });
    }
    license.refresh({ appendAudit: (rec) => db.appendAudit(rec) });
    db.appendAudit({
      action: 'LICENSE_INSTALLED',
      actor: req.user.user,
      detail: `customerId=${v.payload.customerId}; plan=${v.payload.plan}; seats=${v.payload.seats}; expires=${v.payload.expires}`,
    });
    res.json(license.publicStatus());
  });

// Ops metrics (admin) - counts + live audit-integrity, for dashboards/monitoring.
app.get('/api/metrics', ...adminRead, (req, res) => {
  const integ = db.verifyAuditChain();
  res.json({ uptimeSec: Math.round(process.uptime()), ...db.stats(), auditOk: integ.ok, auditCount: integ.count, ts: new Date().toISOString() });
});

app.get('/api/preflight', auth.requireAuth, (req, res) => res.json(currentPreflight()));

function updateAuditDetail(result = {}) {
  const source = result.check || result;
  const config = result.config || source.config || {};
  const parts = [];
  if (config.remoteName || source.remoteRef) parts.push(`remote=${config.remoteName || source.remoteRef}`);
  if (config.branch) parts.push(`branch=${config.branch}`);
  if (config.installMode) parts.push(`install=${config.installMode}`);
  if (source.currentShortCommit) parts.push(`current=${source.currentShortCommit}`);
  if (source.latestShortCommit) parts.push(`latest=${source.latestShortCommit}`);
  if (Number.isFinite(source.behind)) parts.push(`behind=${source.behind}`);
  if (result.updated === true) parts.push('updated=true');
  if (result.updated === false) parts.push('updated=false');
  if (result.restartScheduled === true) parts.push('restart=scheduled');
  return parts.join('; ');
}

function updateConfigAuditDetail(config = {}) {
  return [
    `remote=${config.remoteName || 'origin'}`,
    `branch=${config.branch || 'main'}`,
    `install=${config.installMode || 'npm-ci-omit-dev'}`,
    `restart=${config.restartCommand ? 'configured' : 'manual'}`,
    `autoRestart=${config.restartAfterUpdate === true}`,
  ].join('; ');
}

function sendUpdateError(res, err) {
  res.status(err && err.statusCode ? err.statusCode : 500).json({ error: updater.publicError(err) });
}

app.get('/api/update/status', ...operatorRead, async (req, res) => {
  try {
    res.json(await updater.status());
  } catch (err) {
    sendUpdateError(res, err);
  }
});

app.put('/api/update/config', ...adminWrite, validation.validateBody(validation.updateConfigSchema), async (req, res) => {
  try {
    const config = updater.saveConfig(req.body);
    db.appendAudit({ action: 'APP_UPDATE_CONFIGURED', actor: req.user.user, detail: updateConfigAuditDetail(config) });
    res.json(await updater.status());
  } catch (err) {
    db.appendAudit({ action: 'APP_UPDATE_CONFIG_FAILED', actor: req.user.user, detail: updater.publicError(err) });
    sendUpdateError(res, err);
  }
});

app.post('/api/update/check', ...operatorWrite, async (req, res) => {
  try {
    const result = await updater.checkForUpdates();
    db.appendAudit({ action: 'APP_UPDATE_CHECKED', actor: req.user.user, detail: updateAuditDetail(result) });
    res.json(result);
  } catch (err) {
    db.appendAudit({ action: 'APP_UPDATE_CHECK_FAILED', actor: req.user.user, detail: updater.publicError(err) });
    sendUpdateError(res, err);
  }
});

app.post('/api/update/apply', ...operatorWrite, validation.validateBody(validation.updateApplySchema), async (req, res) => {
  db.appendAudit({ action: 'APP_UPDATE_STARTED', actor: req.user.user, detail: 'backup=true; fastForwardOnly=true' });
  try {
    const result = await updater.applyUpdate({ confirmBackup: req.body.confirmBackup === true });
    db.appendAudit({ action: 'APP_UPDATE_APPLIED', actor: req.user.user, detail: updateAuditDetail(result) });
    res.json(result);
  } catch (err) {
    db.appendAudit({ action: 'APP_UPDATE_FAILED', actor: req.user.user, detail: updater.publicError(err) });
    sendUpdateError(res, err);
  }
});

app.post('/api/update/restart', ...operatorWrite, async (req, res) => {
  try {
    const result = updater.scheduleRestart();
    db.appendAudit({ action: 'APP_UPDATE_RESTART_SCHEDULED', actor: req.user.user, detail: 'restart command scheduled' });
    res.json(result);
  } catch (err) {
    db.appendAudit({ action: 'APP_UPDATE_RESTART_FAILED', actor: req.user.user, detail: updater.publicError(err) });
    sendUpdateError(res, err);
  }
});

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

app.get('/api/posture', auth.requireAuth, (req, res) => {
  res.json(currentPostureReport(boundedApiLimit(req.query.limit, 5000), {
    segmentId: req.query.segment,
  }));
});

app.get('/api/detector-feedback/report', auth.requireAuth, (req, res) => {
  res.json({
    ...detectorFeedback.report({
      rows: db.listQueries({ limit: boundedApiLimit(req.query.queryLimit, 1000) }),
      feedback: db.listDetectorFeedback({ limit: boundedApiLimit(req.query.feedbackLimit, 1000) }),
    }),
    quality: detectionQuality.report(),
  });
});

app.post('/api/queries/:id/detector-feedback', ...decisionWrite, validation.validateBody(validation.detectorFeedbackSchema), requireFeedbackAccess, (req, res) => {
  const q = req.queryRecord;
  const observed = detectorFeedback.detectorIdsForQuery(q);
  if (req.body.verdict !== 'missed' && !observed.includes(req.body.detectorId)) {
    return res.status(400).json({ error: 'detector_not_on_query' });
  }
  const record = db.createDetectorFeedback({
    queryId: q.id,
    detectorId: req.body.detectorId,
    verdict: req.body.verdict,
    reason: req.body.reason || '',
    actor: req.user.user,
    role: req.user.role,
    queryUser: q.user || '',
    orgId: q.orgId || '',
    source: q.source || '',
    channel: q.channel || '',
    destination: coverage.normalizeDestination(q.destination || 'unknown'),
    queryStatus: q.status || '',
    riskScore: q.riskScore || 0,
    maxSeverity: q.maxSeverity || 0,
  });
  const audit = db.appendAudit({
    action: 'DETECTOR_FEEDBACK_RECORDED',
    queryId: q.id,
    actor: req.user.user,
    detail: `${record.detectorId}:${record.verdict}`,
  });
  res.json({
    feedback: detectorFeedback.publicFeedback(record),
    audit: { id: audit.id, ts: audit.ts, hash: audit.hash },
  });
});

app.post('/api/posture/actions', ...operatorWrite, validation.validateBody(validation.postureActionSchema), (req, res) => {
  const payload = {
    id: req.body.id,
    status: req.body.status,
    owner: req.body.owner || (req.body.status === 'assigned' ? req.user.user : ''),
    note: req.body.note || '',
    snoozeUntil: req.body.status === 'snoozed' ? req.body.snoozeUntil : null,
  };
  const audit = db.appendAudit({
    action: db._internal.POSTURE_ACTION_AUDIT,
    actor: req.user.user,
    detail: JSON.stringify(payload),
  });
  broadcast('stats', db.stats());
  res.json({
    action: payload,
    audit: {
      id: audit.id,
      ts: audit.ts,
      hash: audit.hash,
    },
  });
});

app.post('/api/posture/notify', ...adminWrite, async (req, res) => {
  const report = currentPostureReport(5000);
  const result = await alerts.emitPostureAlert(report, { action: 'POSTURE_SNAPSHOT' });
  db.appendAudit({
    action: 'POSTURE_SNAPSHOT_SENT',
    actor: req.user.user,
    detail: result.sent ? `sent:${result.status || 'ok'}` : `not_sent:${result.reason || 'unknown'}`,
  });
  res.status(result.sent ? 200 : 202).json({
    ...result,
    posture: {
      generatedAt: report.generatedAt,
      score: report.hardening && report.hardening.score,
      state: report.hardening && report.hardening.state,
    },
  });
});

app.get('/api/integrations/siem/package', ...auditRead, (req, res) => {
  try {
    const profile = req.query.profile || 'all';
    const pkg = siemPackage.integrationPackage({ profile });
    const suffix = pkg.requestedProfile === 'all' ? 'all' : pkg.profiles[0].id;
    const format = String(req.query.format || req.query.download || '').toLowerCase();
    if (format === 'zip') {
      const archive = siemPackage.packageArchive(pkg);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="redactwall-siem-${suffix}-package.zip"`);
      return res.send(archive);
    }
    if (format === '1' || format === 'true' || format === 'json') {
      res.setHeader('Content-Disposition', `attachment; filename="redactwall-siem-${suffix}-package.json"`);
    }
    res.json(pkg);
  } catch (err) {
    if (err && err.code === 'UNSUPPORTED_PROFILE') {
      return res.status(400).json({
        error: 'unsupported_profile',
        supportedProfiles: siemPackage.SUPPORTED_PROFILES,
      });
    }
    throw err;
  }
});

app.get('/api/security/package', ...auditRead, (req, res) => {
  const pkg = currentSecurityTrustPackage();
  const format = String(req.query.format || req.query.download || '').toLowerCase();
  if (format === 'zip') {
    const archive = securityPackage.packageArchive(pkg);
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="redactwall-security-trust-package.zip"');
    return res.send(archive);
  }
  if (format === '1' || format === 'true' || format === 'json') {
    res.setHeader('Content-Disposition', 'attachment; filename="redactwall-security-trust-package.json"');
  }
  res.json(pkg);
});

app.get('/api/lineage', auth.requireAuth, (req, res) => {
  const limit = boundedApiLimit(req.query.limit, 1000);
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

// ---- AI app catalog ---------------------------------------------------------
app.get('/api/catalog', auth.requireAuth, (req, res) => {
  res.json({ apps: appCatalog.publicCatalog() });
});

app.post('/api/catalog', ...adminWrite, validation.validateBody(validation.catalogAddSchema), (req, res) => {
  const record = appCatalog.addManual(req.body);
  if (!record) return res.status(400).json({ error: 'invalid destination' });
  db.appendAudit({ action: 'CATALOG_ADDED', actor: req.user.user, detail: `manual catalog entry: ${record.canonicalHost}` });
  res.json({ app: appCatalog.publicCatalog().find((a) => a.destination === record.canonicalHost) || null });
});

app.post('/api/catalog/import', ...adminWrite, validation.validateBody(validation.catalogImportSchema), (req, res) => {
  const result = appCatalog.importCsv(req.body.csv, { source: req.body.source || 'csv_import' });
  db.appendAudit({ action: 'CATALOG_IMPORTED', actor: req.user.user, detail: `discovery import: ${result.imported} host(s), ${result.skipped} skipped` });
  res.json({ ...result, apps: appCatalog.publicCatalog() });
});

// Review a catalogued app: apply a govern/allow/block decision to policy (reusing
// the existing destination-review path) AND update catalog status/ownership.
app.post('/api/catalog/:host/review', ...adminWrite, validation.validateBody(validation.catalogReviewSchema), (req, res) => {
  const host = adapters.normalizeHost(req.params.host);
  if (!host) return res.status(400).json({ error: 'invalid host' });
  const before = policy.loadPolicy();
  let reviewed;
  try {
    reviewed = policy.reviewDestination(before, host, req.body.decision);
  } catch (e) {
    return res.status(400).json({ error: 'invalid catalog review' });
  }
  policy.savePolicy(reviewed.policy);
  const statusMap = { govern: 'tolerated', allow: 'sanctioned', block: 'blocked' };
  appCatalog.annotate(host, {
    owner: req.body.owner,
    notes: req.body.notes,
    sanctionedStatus: req.body.sanctionedStatus || statusMap[req.body.decision],
  });
  db.appendAudit({
    action: 'CATALOG_REVIEWED',
    actor: req.user.user,
    detail: policy.policyChangeDetail(before, reviewed.policy, { reason: req.body.reason }),
  });
  broadcast('stats', db.stats());
  res.json({
    destination: host,
    decision: reviewed.decision,
    app: appCatalog.publicCatalog().find((a) => a.destination === host) || null,
  });
});

// ---- Posture subscriptions (SIEM/SOAR delivery) -----------------------------
app.get('/api/subscriptions', ...operatorRead, (req, res) => {
  res.json({ destinations: subscriptions.publicDestinations(), supportedTypes: require('./siem-formats').supportedTypes() });
});

app.get('/api/subscriptions/deliveries', ...operatorRead, (req, res) => {
  res.json({ deliveries: db.listDeliveries(boundedApiLimit(req.query.limit, 200)) });
});

// Send a synthetic test event to one destination (proves connectivity + auth).
app.post('/api/subscriptions/:id/test', ...operatorWrite, async (req, res) => {
  const dest = subscriptions.findDestination(req.params.id);
  if (!dest) return res.status(404).json({ error: 'unknown subscription' });
  const testAlert = alerts.sanitizedAlert({
    id: 'test_' + Date.now(), createdAt: new Date().toISOString(), status: 'subscription_test',
    user: req.user.user, orgId: null, source: 'console', channel: 'test', destination: 'redactwall:test',
    riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none', findings: [], categories: [], reasons: ['subscription connectivity test'],
  }, { action: 'SUBSCRIPTION_TEST', force: true });
  const result = await subscriptions.deliverTo(dest, testAlert, { force: true });
  db.appendAudit({ action: 'SUBSCRIPTION_TESTED', actor: req.user.user, detail: `subscription ${dest.id} (${dest.type}): ${result.status}` });
  res.json({ result: { destId: result.destId, status: result.status, attempts: result.attempts, httpStatus: result.httpStatus || null } });
});

// ---- Sensor rollout downloads (Deploy tab) -----------------------------------
const DEPLOY_ARTIFACTS = Object.freeze({
  'extension-chrome': {
    label: 'Browser extension (Chrome/Brave MV3)', kind: 'extension', target: 'chrome',
    requires: 'Chrome or Brave 88+ (Manifest V3)',
    install: 'Force-install via browser policy: docs/examples/chrome-extension-settings.example.json',
  },
  'extension-edge': {
    label: 'Browser extension (Microsoft Edge)', kind: 'extension', target: 'edge',
    requires: 'Microsoft Edge 88+ (Manifest V3)',
    install: 'Force-install via browser policy: docs/examples/edge-extension-settings.example.json',
  },
  'extension-firefox': {
    label: 'Browser extension (Firefox)', kind: 'extension', target: 'firefox',
    requires: 'Firefox 109+',
    install: 'Signed XPI + policy: docs/examples/firefox-extension-settings.example.json',
  },
  'endpoint-agent': {
    label: 'Endpoint agent (desktop file/clipboard sensor)', kind: 'endpoint',
    requires: 'Windows, macOS, or Linux with Node.js 22+',
    install: 'Unzip on the endpoint, then follow the technician runbook service-install steps',
  },
  'mcp-guard': {
    label: 'MCP guard (agent/connector sensor)', kind: 'mcp',
    requires: 'Any MCP-capable client, Node.js 22+',
    install: 'Wrap each MCP server command per the connector SDK guide',
  },
});

function buildDeployArtifact(id) {
  const spec = DEPLOY_ARTIFACTS[id];
  if (!spec) return null;
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'redactwall-deploy-'));
  if (spec.kind === 'extension') {
    return require('../scripts/package-extension').packageExtension({ outDir, target: spec.target });
  }
  if (spec.kind === 'endpoint') {
    return require('../scripts/package-endpoint-agent').packageEndpointAgent({ outDir });
  }
  return require('../scripts/package-mcp-guard').packageMcpGuard({ outDir });
}

let deployMetadataCache = null;

function deployArtifactMetadata() {
  if (deployMetadataCache) return deployMetadataCache;
  deployMetadataCache = Object.entries(DEPLOY_ARTIFACTS).map(([id, spec]) => {
    try {
      const built = buildDeployArtifact(id);
      const manifest = built.packageManifest || {};
      const meta = {
        id,
        label: spec.label,
        kind: spec.kind,
        fileName: path.basename(built.zipPath),
        fileType: 'application/zip',
        sizeBytes: manifest.sizeBytes || fs.statSync(built.zipPath).size,
        sha256: manifest.sha256 || null,
        fileCount: Array.isArray(manifest.files) ? manifest.files.length : null,
        version: manifest.version || require('../package.json').version,
        requires: spec.requires,
        install: spec.install,
        guide: spec.kind === 'extension' ? 'docs/MANAGED_EXTENSION_DEPLOYMENT.md'
          : spec.kind === 'endpoint' ? 'docs/TECHNICIAN_DEPLOYMENT_GUIDE.md'
            : 'docs/MCP_CONNECTOR_SDK.md',
      };
      fs.rmSync(path.dirname(built.zipPath), { recursive: true, force: true });
      return meta;
    } catch {
      return { id, label: spec.label, kind: spec.kind, error: 'packaging failed' };
    }
  });
  return deployMetadataCache;
}

function deployDownloadHistory(limit = 20) {
  return db.listAudit(500)
    .filter((entry) => entry.action === 'DEPLOY_ARTIFACT_DOWNLOADED')
    .slice(0, limit)
    .map((entry) => ({ ts: entry.ts, actor: entry.actor, detail: entry.detail }));
}

app.get('/api/deploy/artifacts', ...operatorRead, (req, res) => {
  res.json({
    artifacts: deployArtifactMetadata(),
    history: deployDownloadHistory(),
    version: require('../package.json').version,
  });
});

app.get('/api/deploy/download/:artifact', ...operatorRead, (req, res) => {
  const id = String(req.params.artifact || '');
  if (!DEPLOY_ARTIFACTS[id]) return res.status(404).json({ error: 'unknown artifact' });
  let built;
  try {
    built = buildDeployArtifact(id);
  } catch (err) {
    return res.status(500).json({ error: 'packaging failed' });
  }
  db.appendAudit({ action: 'DEPLOY_ARTIFACT_DOWNLOADED', actor: req.user.user, detail: `${id} v${built.packageManifest.version || 'unknown'} sha256:${(built.packageManifest.sha256 || '').slice(0, 16)}` });
  res.download(built.zipPath, path.basename(built.zipPath), () => {
    fs.rm(path.dirname(built.zipPath), { recursive: true, force: true }, () => {});
  });
});

// Regulation policy templates (list + one-click apply).
// Per-user sensor fleet: which sensors cover each identity, with the coverage
// gaps the sensors reported about each other.
app.get('/api/fleet', auth.requireAuth, (req, res) => {
  res.json(fleet.summary());
});

// Analyst risk-score override with a required justification, visible to every
// admin next to the computed score. Null score clears the override.
app.post('/api/catalog/:host/override', ...adminWrite, (req, res) => {
  const { score, note } = req.body || {};
  if (score != null && (!Number.isFinite(Number(score)) || Number(score) < 0 || Number(score) > 100)) {
    return res.status(400).json({ error: 'score must be 0-100 or null to clear' });
  }
  if (score != null && !String(note || '').trim()) {
    return res.status(400).json({ error: 'a justification note is required for an override' });
  }
  const updated = appCatalog.overrideScore(req.params.host, { score, note, actor: req.user.user });
  if (!updated) return res.status(404).json({ error: 'unknown app' });
  db.appendAudit({
    action: score == null ? 'CATALOG_OVERRIDE_CLEARED' : 'CATALOG_SCORE_OVERRIDDEN',
    actor: req.user.user,
    detail: score == null ? req.params.host : `${req.params.host} -> ${Math.round(Number(score))}: ${String(note).slice(0, 200)}`,
  });
  res.json({ ok: true });
});

// Identity configuration self-test: reports which sign-in paths are actually
// wired (config completeness only - no outbound calls), and audits the check.
app.post('/api/identity/test', ...adminRead, auth.requireCsrf, (req, res) => {
  const oidcConfig = oidc.config();
  const scimToken = String(process.env.SCIM_BEARER_TOKEN || '').trim();
  const checks = [
    { id: 'oidc', label: 'OIDC single sign-on', ok: !!oidcConfig.enabled,
      detail: oidcConfig.enabled ? `issuer ${oidcConfig.issuer}` : 'set OIDC_ISSUER, OIDC_CLIENT_ID, and OIDC_CLIENT_SECRET' },
    { id: 'oidc_redirect', label: 'OIDC redirect URI', ok: !oidcConfig.enabled || !!oidcConfig.redirectUri,
      detail: oidcConfig.redirectUri || 'set OIDC_REDIRECT_URI to this console\'s /auth/oidc/callback' },
    { id: 'scim', label: 'SCIM provisioning', ok: scimToken.length >= 32,
      detail: scimToken ? (scimToken.length >= 32 ? 'bearer token configured' : 'token shorter than 32 chars') : 'set SCIM_BEARER_TOKEN (32+ chars)' },
    { id: 'break_glass', label: 'Local break-glass account', ok: true, detail: 'ADMIN_USER/ADMIN_PASSWORD active' },
  ];
  db.appendAudit({ action: 'IDENTITY_CONFIG_TESTED', actor: req.user.user, detail: checks.filter((c) => !c.ok).map((c) => c.id).join(', ') || 'all ok' });
  res.json({ checkedAt: new Date().toISOString(), ok: checks.every((c) => c.ok), checks });
});

// Daily digest: yesterday's decision counts to every destination subscribed to
// the 'digest' event type. On a 24h timer and on demand for testing.
let lastDigest = null;

async function sendDailyDigest(actor = 'scheduler') {
  const s = db.stats();
  const alert = {
    action: 'digest', status: 'digest', riskScore: 0, maxSeverity: 0,
    title: 'RedactWall daily digest',
    summary: { pending: s.pending, todayBlocked: s.todayBlocked, approved: s.approved, denied: s.denied, totalQueries: s.total },
    generatedAt: new Date().toISOString(),
  };
  const results = await subscriptions.dispatch(alert);
  lastDigest = { at: alert.generatedAt, delivered: results.filter((r) => r.status === 'delivered').length, total: results.length, actor };
  if (results.length) db.appendAudit({ action: 'DIGEST_SENT', actor, detail: `${lastDigest.delivered}/${results.length} delivered` });
  return results;
}
setInterval(() => { sendDailyDigest().catch(() => {}); }, 24 * 3600 * 1000).unref();

app.post('/api/reports/digest/send', ...adminWrite, async (req, res) => {
  res.json({ results: await sendDailyDigest(req.user.user) });
});

// Notification plumbing status for the console: SMTP relay wiring (secrets
// redacted), email destinations, and the last digest run.
app.get('/api/notifications/status', ...adminRead, (req, res) => {
  const smtp = email.config();
  const emailDests = subscriptions.publicDestinations().filter((d) => d.type === 'email');
  res.json({
    smtp: {
      configured: smtp.enabled,
      host: smtp.enabled ? smtp.host : null,
      port: smtp.enabled ? smtp.port : null,
      secure: smtp.secure,
      from: smtp.enabled ? smtp.from : null,
      authConfigured: !!smtp.user,
    },
    emailDestinations: emailDests.map((d) => ({ id: d.id, name: d.name, recipients: d.recipients, eventTypes: d.eventTypes })),
    digest: { intervalHours: 24, last: lastDigest },
  });
});

// Prove the relay end to end with a synthetic message. The recipient address
// is audited masked; message content is fixed and prompt-free.
app.post('/api/notifications/test-email', ...adminWrite, async (req, res) => {
  const to = String((req.body || {}).to || '').trim();
  if (!/^[^\s@]+@[^\s@]+$/.test(to)) return res.status(400).json({ error: 'provide a recipient address' });
  const result = await email.send({
    to,
    subject: 'RedactWall test notification',
    text: 'This is a test notification from your RedactWall console. Delivery works.',
  });
  const masked = to.replace(/^(.).*(@.*)$/, '$1***$2');
  db.appendAudit({ action: 'EMAIL_TEST_SENT', actor: req.user.user, detail: `${masked}: ${result.ok ? 'delivered' : result.error}` });
  res.json(result);
});

// Sensor staleness: when a tracked sensor goes silent past the fleet's 48h
// threshold, tell destinations subscribed to the SENSOR_STALE event type.
// Payload is metadata only - user, sensor name, last-seen timestamp - and each
// silence period alerts once (a sensor re-qualifies only after reporting again).
async function runSensorStaleSweep(actor = 'scheduler', opts = {}) {
  const stale = fleet.staleTransitions({ now: opts.now || Date.now() });
  if (!stale.length) return { stale: 0, results: [] };
  const alert = {
    action: 'SENSOR_STALE',
    status: 'sensor_stale',
    riskScore: 0,
    maxSeverity: 0,
    staleAfterHours: fleet.STALE_MS / 3600000,
    staleCount: stale.length,
    sensors: stale.slice(0, 50),
    generatedAt: new Date().toISOString(),
  };
  const results = await subscriptions.dispatch(alert, opts.dispatch || {});
  db.appendAudit({
    action: 'SENSOR_STALE_ALERTED',
    actor,
    detail: `${stale.length} sensor(s) stale; ${results.filter((r) => r.status === 'delivered').length}/${results.length} delivered`,
  });
  return { stale: stale.length, results };
}

// Static detector metadata (severity scale + regulation map) so the console
// can explain historical rows that predate persisted score breakdowns.
app.get('/api/detectors/meta', auth.requireAuth, (req, res) => {
  res.json({ severityLabels: detector.SEVERITY_LABEL, regulations: detector.REGULATIONS });
});

// Detection tester: run a sample through the live engine + policy and return
// the full rationale. The sample is analyzed in memory only - never stored,
// never logged, never written to the audit chain.
app.post('/api/detectors/test', auth.requireAuth, (req, res) => {
  const text = String((req.body || {}).text || '');
  if (!text || text.length > 20000) return res.status(400).json({ error: 'provide sample text up to 20k chars' });
  const pol = policy.loadPolicy();
  const analysis = detector.analyze(text, policy.analyzeOpts(pol));
  const verdict = policy.evaluate(analysis, pol, policyContext({ user: req.user.user, source: 'detector_test', channel: 'test' }));
  res.json({
    decision: verdict.decision,
    reasons: verdict.reasons,
    riskScore: analysis.riskScore,
    maxSeverityLabel: analysis.maxSeverityLabel,
    regulations: analysis.regulations,
    scoreBreakdown: analysis.scoreBreakdown,
    findings: analysis.findings.map((f) => ({
      type: f.type, severity: f.severity, severityLabel: detector.SEVERITY_LABEL[f.severity],
      confidence: f.confidenceLabel, masked: detector.maskValue(f.type, f.value), regulations: f.regulations,
      ...(f.vendor ? { vendor: f.vendor, vendorLabel: f.vendorLabel } : {}),
    })),
    categories: (analysis.categories || []).map((c) => ({ category: c.category, confidence: c.confidenceLabel })),
  });
});

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
  const queryId = String(req.query.queryId || '').trim();
  const entries = queryId
    ? db.listAudit(2000).filter((e) => e.queryId === queryId).slice(0, boundedApiLimit(req.query.limit, 50))
    : db.listAudit(boundedApiLimit(req.query.limit, 200));
  res.json({
    entries,
    integrity: db.verifyAuditChain(),
    retention: 'Append-only and hash-chained: entries are never edited or purged for the life of this database. Export an evidence pack for long-term archives.',
  });
});

// Safe-to-send receipt verification: any console session (including read-only
// auditors) can confirm a receipt was issued by this control plane and has not
// been edited. Verification is prompt-free — the receipt carries hashes only.
app.post('/api/receipts/verify', ...sessionWrite, validation.validateBody(validation.receiptVerifySchema), (req, res) => {
  res.json(receipts.verifyReceipt(req.body));
});

app.get('/api/export/evidence', ...auditRead, (req, res) => {
  const queryLimit = boundedApiLimit(req.query.queryLimit, 500);
  const auditLimit = boundedApiLimit(req.query.auditLimit, 500);
  const activePolicy = policy.loadPolicy();
  const queries = db.listQueries({ limit: queryLimit });
  const summaryQueries = db.listQueries({ all: true });
  const coverageReport = coverage.summarize(summaryQueries, activePolicy);
  const auditIntegrity = db.verifyAuditChain();
  const detectorFeedbackReport = detectorFeedback.report({
    rows: summaryQueries,
    feedback: db.listDetectorFeedback({ limit: auditLimit }),
  });
  const detectionQualityReport = detectionQuality.report();
  res.json(evidence.buildEvidencePack({
    version: require('../package.json').version,
    queryLimit,
    auditLimit,
    summaryRowsIncluded: summaryQueries.length,
    summariesUseFullHistory: true,
    policy: activePolicy,
    stats: db.stats(),
    auditIntegrity,
    coverage: coverageReport,
    posture: posture.summarize({
      rows: summaryQueries,
      policy: activePolicy,
      coverageReport,
      auditIntegrity,
      actionStates: db.postureActionStates(auditLimit),
      detectorFeedbackReport,
      detectionQualityReport,
    }),
    policyExceptionReview: policy.policyExceptionReview(activePolicy),
    detectorFeedback: detectorFeedbackReport,
    detectors: detector.listDetectors({ customDetectors: policy.customDetectorsForSensors() }),
    queries,
    lineageQueries: summaryQueries,
    audit: db.listAudit(auditLimit),
  }));
});

// Compliance framework coverage (lightweight; the full pack is /api/export/evidence).
app.get('/api/compliance', auth.requireAuth, (req, res) => {
  const controlMap = require('./control-map');
  const activePolicy = policy.loadPolicy();
  const summaryQueries = db.listQueries({ all: true });
  const mappings = controlMap.buildControlMappings({
    generatedAt: new Date().toISOString(),
    scope: { rawPromptBodiesIncluded: false },
    policy: activePolicy,
    detectors: detector.listDetectors({ customDetectors: policy.customDetectorsForSensors() }),
    auditIntegrity: db.verifyAuditChain(),
    coverage: coverage.summarize(summaryQueries, activePolicy),
  });
  res.json({ controlMappings: mappings });
});

app.get('/api/policy', auth.requireAuth, (req, res) => res.json(policy.loadPolicy()));
app.post('/api/policy/impact', ...adminWrite, validation.validateBody(validation.policyUpdateSchema), (req, res) => {
  const before = policy.loadPolicy();
  const proposed = policy.normalizePolicy({
    ...before,
    ...(req.body || {}),
    ...(req.body && req.body.scanner ? { scanner: { ...(before.scanner || {}), ...req.body.scanner } } : {}),
  });
  const limit = boundedApiLimit(req.query.limit, 1000);
  res.json(policyImpact.buildPolicyImpact({
    rows: db.listQueries({ limit }),
    currentPolicy: before,
    proposedPolicy: proposed,
    limit,
  }));
});
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
// REDACTWALL_CONSOLE_DEFAULT=app makes the new console the landing surface once
// enough views are ported for a deployment's operators; legacy stays default.
app.get('/', (req, res) =>
  res.redirect(String(process.env.REDACTWALL_CONSOLE_DEFAULT || 'legacy') === 'app' ? '/app/' : '/index.html'));
app.get('/index.html', auth.requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'index.html')));
// New console (Vite build output; hashed assets under /app/assets stay public
// like every other data-free static file — all data flows through /api/*).
app.get(['/app', '/app/', '/app/index.html'], auth.requireAuth, (req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'app', 'index.html')));
app.use(express.static(path.join(__dirname, 'public')));

function logStartup(port, deps = {}) {
  const io = deps.console || console;
  const authModule = deps.auth || auth;
  const cryptoModule = deps.dataCrypto || dataCrypto;
  const policyModule = deps.policy || policy;
  const ingestKey = Object.prototype.hasOwnProperty.call(deps, 'ingestKey') ? deps.ingestKey : INGEST_KEY;
  io.log(`RedactWall running on http://localhost:${port}`);
  if (authModule.ADMIN_PASSWORD_IS_DEFAULT) {
    io.log('  [!] Using DEFAULT admin password. Set ADMIN_PASSWORD before production.');
  }
  if (!authModule.SECRET_IS_STABLE) {
    io.log('  [!] Session secret is ' + authModule.SECRET_SOURCE + ' — set REDACTWALL_SECRET (stable) for multi-instance deployments.');
  }
  if (!cryptoModule.ENABLED) {
    io.log('  [!] No REDACTWALL_DATA_KEY/REDACTWALL_SECRET set — raw prompts are NOT stored (reveal shows redacted). Set a key to enable encrypted raw retention for approvals.');
  } else {
    const days = policyModule.rawRetentionDays(policyModule.loadPolicy());
    io.log(`  Raw-prompt retention: encrypted at rest (AES-256-GCM), held items only; finalized records purge after ${days} day(s).`);
  }
  io.log(`  Ingest key: ${ingestKey === 'dev-ingest-key' ? 'dev-ingest-key (override with INGEST_API_KEY)' : 'configured'}`);
  const lic = (deps.license || license).publicStatus();
  if (lic.state === 'unlicensed') io.log('  License: unlicensed (demo mode) — detection and enforcement run; install a license to unlock the admin console fully.');
  else if (lic.state === 'grace') io.log(`  [!] License expired ${lic.expires} — in grace until ${lic.graceEndsAt}; admin console goes read-only after that.`);
  else if (lic.state === 'readonly') io.log('  [!] License past grace — admin console is READ-ONLY. Detection, enforcement, approvals, and evidence export still run. Install a renewal to restore config writes.');
  else io.log(`  License: ${lic.plan} plan, ${lic.seats} seats, expires ${lic.expires}.`);
}

function startServer(port = PORT, opts = {}) {
  const preflightCheck = opts.currentPreflight || currentPreflight;
  const preflightModule = opts.preflight || preflight;
  const retentionPurge = opts.runRetentionPurge || runRetentionPurge;
  const workflowEscalation = opts.runWorkflowEscalation || runWorkflowEscalation;
  const staleSweep = opts.runSensorStaleSweep || ((...args) => runSensorStaleSweep(...args).catch(() => {}));
  const setIntervalFn = opts.setInterval || setInterval;
  const clearIntervalFn = opts.clearInterval || clearInterval;
  const appToListen = opts.app || app;
  const log = opts.logStartup || logStartup;
  const cfg = preflightCheck();
  const blockers = preflightModule.summarizeFailures(cfg);
  if (blockers.length) {
    for (const blocker of blockers) console.error('[preflight] ' + blocker);
    throw new Error('Production preflight failed');
  }
  retentionPurge();
  workflowEscalation();
  (opts.runLicenseRefresh || (() => license.refresh({ appendAudit: (rec) => db.appendAudit(rec) })))();
  const server = appToListen.listen(port, () => {
    const address = server.address();
    log(address && address.port ? address.port : port);
  });
  const retentionTimer = setIntervalFn(() => retentionPurge(), 60 * 60 * 1000);
  const workflowTimer = setIntervalFn(() => workflowEscalation(), 5 * 60 * 1000);
  const staleTimer = setIntervalFn(() => staleSweep(), 60 * 60 * 1000);
  const licenseTimer = setIntervalFn(() => license.refresh({ appendAudit: (rec) => db.appendAudit(rec) }), 24 * 60 * 60 * 1000);
  retentionTimer.unref();
  workflowTimer.unref();
  staleTimer.unref();
  licenseTimer.unref();
  server.on('close', () => {
    clearIntervalFn(retentionTimer);
    clearIntervalFn(workflowTimer);
    clearIntervalFn(staleTimer);
    clearIntervalFn(licenseTimer);
  });
  return server;
}

function installShutdownHandlers(server, deps = {}) {
  const proc = deps.process || process;
  const io = deps.console || console;
  const setTimeoutFn = deps.setTimeout || setTimeout;
  const clearTimeoutFn = deps.clearTimeout || clearTimeout;
  const exit = deps.exit || ((code) => process.exit(code));
  const shutdown = (signal) => {
    io.log(`RedactWall received ${signal}; shutting down`);
    const timeout = setTimeoutFn(() => exit(1), 10000);
    if (timeout.unref) timeout.unref();
    server.close(() => {
      clearTimeoutFn(timeout);
      exit(0);
    });
  };
  proc.once('SIGTERM', () => shutdown('SIGTERM'));
  proc.once('SIGINT', () => shutdown('SIGINT'));
  return shutdown;
}

if (require.main === module) installShutdownHandlers(startServer());

app.startServer = startServer;
app.runRetentionPurge = runRetentionPurge;
app.runWorkflowEscalation = runWorkflowEscalation;
app.runSensorStaleSweep = runSensorStaleSweep;
app.currentPreflight = currentPreflight;
app.currentSecurityTrustPackage = currentSecurityTrustPackage;
app._internal = {
  jsonErrorHandler,
  registerIngestFailure,
  pruneIngestFailures,
  ingestFailures,
  logStartup,
  startServer,
  currentPreflight,
  currentSecurityTrustPackage,
  installShutdownHandlers,
};

module.exports = app;
