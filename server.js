'use strict';
/**
 * PromptSentinel — inline DLP gateway for AI chat prompts.
 *
 * Flow:
 *   1. The network proxy (Squid+ICAP) or an SDK calls POST /api/v1/gate with the
 *      user's prompt + context before it is allowed to reach the AI service.
 *   2. PromptSentinel analyzes for PII, applies policy, and either ALLOWS or
 *      BLOCKS (holds) the prompt. Blocked prompts enter the approval queue.
 *   3. A Security Admin reviews the queue in the dashboard and approves/denies.
 *   4. The waiting client polls GET /api/v1/status/:id (or long-poll /await/:id)
 *      and proceeds only if released.
 */
require('./src/env').loadEnv();
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const crypto = require('crypto');
const path = require('path');

const detector = require('./src/detector');
const processors = require('./src/processors');
const policy = require('./src/policy');
const db = require('./src/db');
const auth = require('./src/auth');
const dataCrypto = require('./src/crypto');
const templates = require('./src/templates');
const alerts = require('./src/alerts');
const evidence = require('./src/evidence');
const preflight = require('./src/preflight');
const validation = require('./src/validation');
const coverage = require('./src/coverage');

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

app.use(express.json({ limit: '12mb' }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'request body too large' });
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) return res.status(400).json({ error: 'invalid json' });
  return next(err);
});
app.use(cookieParser());

// ---- Health / readiness (public, no sensitive data) -------------------------
app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'promptsentinel', version: require('./package.json').version }));
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
  alerts.emitSecurityAlert(row, { action, ...opts }).catch(() => {});
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
  });
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

function safeNumber(value, fallback, min = 0, max = 100) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
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

app.post('/api/v1/gate', checkIngestKey, validation.validateBody(validation.gateSchema), (req, res) => {
  const {
    prompt, user = 'unknown', destination = 'unknown', sourceIp = null,
    source = 'api', channel = 'submit', clientOutcome = null, note = '', orgId = null,
    sensor = null,
  } = req.body || {};
  if (typeof prompt !== 'string' || !prompt.trim()) {
    return res.status(400).json({ error: 'prompt (string) required' });
  }

  const pol = policy.loadPolicy();
  const analyzeOpts = policy.analyzeOpts(pol);
  const declaredClientRedacted = clientOutcome === 'redacted_sent' && req.body && req.body.clientPreRedacted === true;
  const clientAnalysis = declaredClientRedacted ? clientAnalysisFrom(req.body) : null;
  if (declaredClientRedacted && !clientAnalysis) {
    return res.status(400).json({ error: 'client redaction analysis required' });
  }
  const serverAnalysis = detector.analyze(prompt, analyzeOpts);
  const clientRedacted = declaredClientRedacted && clientAnalysis && !hasSensitivity(serverAnalysis);
  const analysis = clientRedacted ? clientAnalysis : serverAnalysis;
  const verdict = policy.evaluate(analysis, pol);

  // Privacy-preserving record: redacted prompt + masked findings + categories.
  const redactedPrompt = clientRedacted && !categoryNames(analysis).length ? prompt : safePreview(prompt, analysis);
  const findings = analysis.findings.map((f) => ({
    type: f.type, severity: f.severity, score: f.score, masked: f.masked || detector.maskValue(f.type, f.value || ''),
  }));
  const categories = (analysis.categories || []).map((c) => c.category);

  const base = {
    user, orgId, destination, sourceIp, source, channel, sensor,
    redactedPrompt, findings, categories, entityCounts: analysis.entityCounts,
    riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity,
    maxSeverityLabel: analysis.maxSeverityLabel, reasons: verdict.reasons,
  };

  // Man-in-the-Prompt: the sensor stopped a prompt carrying hidden instructions.
  if (clientOutcome === 'injection_blocked') {
    const row = db.createQuery({ status: 'injection_blocked', ...base });
    db.appendAudit({ action: 'INJECTION_BLOCKED', queryId: row.id, actor: user, detail: note || 'hidden instructions detected' });
    emitSecurityAlert(row, 'INJECTION_BLOCKED');
    broadcast('query', { type: 'injection_blocked', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'block', status: 'injection_blocked' });
  }

  // Shadow-AI discovery: a visit to an AI tool policy does not govern. Recorded
  // as an informational event so the examiner sees unmonitored paths, not a leak.
  if (clientOutcome === 'shadow_ai') {
    const row = db.createQuery({ status: 'shadow_ai', ...base });
    db.appendAudit({ action: 'SHADOW_AI', queryId: row.id, actor: user, detail: `ungoverned AI tool: ${destination}` });
    emitSecurityAlert(row, 'SHADOW_AI');
    broadcast('query', { type: 'shadow_ai', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'log', status: 'shadow_ai' });
  }

  if (clientOutcome === 'file_too_large' || clientOutcome === 'file_unsupported' || clientOutcome === 'scan_unavailable') {
    const row = db.createQuery({ status: 'file_blocked_unscanned', ...base });
    db.appendAudit({ action: 'FILE_BLOCKED_UNSCANNED', queryId: row.id, actor: user, detail: note || 'file blocked unscanned' });
    emitSecurityAlert(row, 'FILE_BLOCKED_UNSCANNED');
    broadcast('query', { type: 'file_blocked_unscanned', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'block', status: 'file_blocked_unscanned' });
  }

  if (verdict.decision === 'allow') {
    const row = db.createQuery({ status: 'allowed', ...base });
    db.appendAudit({ action: 'ALLOWED', queryId: row.id, actor: user, detail: `${source} risk ${analysis.riskScore}` });
    emitSecurityAlert(row, 'ALLOWED');
    broadcast('query', { type: 'allowed', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', riskScore: analysis.riskScore, findings, categories });
  }

  if (clientOutcome === 'paste_flagged') {
    const row = db.createQuery({ status: 'paste_flagged', mode: pol.enforcementMode || 'block', ...base });
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
  const hardStop = analysis.findings.some((f) => pol.alwaysBlock.includes(f.type));
  const mode = clientRedacted ? 'redact'
    : pol.enforcementMode === 'redact' ? 'redact'
    : (hardStop ? 'block' : (pol.enforcementMode || 'block'));

  // Status reflects how the sensor resolved it (from clientOutcome) or, for the
  // API/proxy path, defaults to the mode's behaviour.
  let status;
  const wholeChunkClientRedacted = declaredClientRedacted && /^\s*\[REDACTED:[^\]]+\]\s*$/i.test(prompt);
  if (clientOutcome === 'sent_after_warning') status = 'warned_sent';
  else if (clientOutcome === 'redacted_sent') status = canTokenizeAllSensitivity(analysis) || wholeChunkClientRedacted ? 'redacted' : 'pending';
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
  if (status === 'redacted' && !clientRedacted) {
    const t = detector.tokenize(prompt, analysis.findings);
    tokenizedPrompt = t.text;                       // PII-free, safe to retain/display
    tokenVault = dataCrypto.seal(JSON.stringify(t.map));
  } else if (status === 'redacted') {
    tokenizedPrompt = prompt;
  }

  const row = db.createQuery({
    status, mode, ...base, decisionNote: note,
    _rawPrompt: rawToStore(prompt, status, pol),
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
    riskScore: analysis.riskScore, findings, categories, reasons: verdict.reasons,
    tokenizedPrompt,
    message: status === 'redacted' ? 'Sensitive values tokenized — safe to send; re-hydrate the AI response via /api/v1/rehydrate.'
      : mode === 'redact' ? 'Sensitive category cannot be tokenized safely; withheld pending Security Admin approval.'
      : mode === 'block' ? 'Withheld pending Security Admin approval.'
      : mode === 'justify' ? 'Justification required before sending.'
      : 'Sensitive content — user warned.',
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
    governedDestinations: p.governedDestinations,
    scanner: p.scanner || {},
  });
});

// List available detectors (for the console enable/disable UI).
app.get('/api/v1/detectors', checkIngestKey, (req, res) => res.json(detector.listDetectors()));

// Scan an uploaded FILE: extract text (pdf/docx/xlsx/text), then gate it.
app.post('/api/v1/scan-file', checkIngestKey, validation.validateBody(validation.scanFileSchema), async (req, res) => {
  const { filename, contentBase64, user = 'unknown', destination = 'unknown', source = 'api', channel = 'file_upload', orgId = null, sensor = null } = req.body || {};
  if (!filename || !contentBase64) return res.status(400).json({ error: 'filename and contentBase64 required' });
  let buf;
  try { buf = Buffer.from(contentBase64, 'base64'); } catch { return res.status(400).json({ error: 'bad base64' }); }
  const pol = policy.loadPolicy();
  if (buf.length > (pol.scanner && pol.scanner.maxFileBytes || 6.6e6)) return res.status(413).json({ error: 'file too large' });

  let extracted;
  try { extracted = await processors.extractText(filename, buf); }
  catch (e) { extracted = { text: '', processor: null, supported: true, extractionOk: false, error: 'extract_failed' }; }
  if (!extracted.supported) {
    const row = db.createQuery({ status: 'flagged', user, orgId, destination, source, channel, sensor,
      redactedPrompt: '[unsupported file] ' + filename, findings: [], categories: [], entityCounts: {},
      riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none', reasons: ['Unsupported file type recorded'] });
    db.appendAudit({ action: 'FILE_RECORDED', queryId: row.id, actor: user, detail: filename });
    emitSecurityAlert(row, 'FILE_RECORDED');
    broadcast('query', { type: 'flagged', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', supported: false, filename });
  }
  if (!extracted.extractionOk) {
    const reason = extracted.error === 'timeout' ? 'File extraction timed out before inspection completed' : 'File could not be inspected';
    const row = db.createQuery({ status: 'file_blocked_unscanned', user, orgId, destination, source, channel, sensor,
      filename, processor: extracted.processor, redactedPrompt: '[unreadable file] ' + filename,
      findings: [], categories: [], entityCounts: {}, riskScore: 0, maxSeverity: 0, maxSeverityLabel: 'none',
      reasons: [reason] });
    db.appendAudit({ action: 'FILE_BLOCKED_UNREADABLE', queryId: row.id, actor: user, detail: `${filename}: ${extracted.error || 'extract_failed'}` });
    emitSecurityAlert(row, 'FILE_BLOCKED_UNREADABLE');
    broadcast('query', { type: 'file_blocked_unscanned', query: publicQuery(row) });
    broadcast('stats', db.stats());
    return res.json({
      id: row.id,
      decision: 'block',
      mode: 'block',
      status: 'file_blocked_unscanned',
      supported: true,
      inspected: false,
      filename,
      processor: extracted.processor,
      reasons: [reason],
    });
  }

  const analysis = detector.analyze(extracted.text, policy.analyzeOpts(pol));
  const verdict = policy.evaluate(analysis, pol);
  const findings = analysis.findings.map((x) => ({ type: x.type, severity: x.severity, score: x.score, masked: detector.maskValue(x.type, x.value) }));
  const categories = (analysis.categories || []).map((c) => c.category);
  const preview = safePreview(extracted.text, analysis, '[file:' + filename + '] ');
  const base = { user, orgId, destination, source, channel, sensor, filename, processor: extracted.processor,
    redactedPrompt: preview, findings, categories, entityCounts: analysis.entityCounts,
    riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity, maxSeverityLabel: analysis.maxSeverityLabel, reasons: verdict.reasons };

  if (verdict.decision === 'allow') {
    const row = db.createQuery({ status: 'allowed', ...base });
    db.appendAudit({ action: 'FILE_ALLOWED', queryId: row.id, actor: user, detail: filename + ' risk ' + analysis.riskScore });
    emitSecurityAlert(row, 'FILE_ALLOWED');
    broadcast('query', { type: 'allowed', query: publicQuery(row) }); broadcast('stats', db.stats());
    return res.json({ id: row.id, decision: 'allow', supported: true, filename, riskScore: analysis.riskScore, findings, categories });
  }
  const hardStop = analysis.findings.some((x) => pol.alwaysBlock.includes(x.type));
  const mode = pol.enforcementMode === 'redact' ? 'redact' : (hardStop ? 'block' : (pol.enforcementMode || 'block'));
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
  const row = db.createQuery({ status, mode, ...base, _rawPrompt: rawToStore(rawFile, status, pol), _tokenVault: tokenVault, tokenizedPrompt });
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
  const { text, user = 'unknown', destination = 'unknown', source = 'api', orgId = null, sensor = null } = req.body || {};
  if (typeof text !== 'string' || !text.trim()) return res.status(400).json({ error: 'text (string) required' });
  const pol = policy.loadPolicy();
  const analysis = detector.analyze(text, policy.analyzeOpts(pol));
  const findings = analysis.findings.map((f) => ({ type: f.type, severity: f.severity, score: f.score, masked: detector.maskValue(f.type, f.value) }));
  const categories = (analysis.categories || []).map((c) => c.category);
  const redacted = safePreview(text, analysis);
  const leaked = findings.length > 0 || categories.length > 0;
  if (leaked) {
    const row = db.createQuery({ status: 'response_flagged', user, orgId, destination, source, channel: 'ai_response', sensor,
      redactedPrompt: '[AI response] ' + redacted, findings, categories, entityCounts: analysis.entityCounts,
      riskScore: analysis.riskScore, maxSeverity: analysis.maxSeverity, maxSeverityLabel: analysis.maxSeverityLabel,
      reasons: ['Sensitive data present in AI response'] });
    db.appendAudit({ action: 'RESPONSE_FLAGGED', queryId: row.id, actor: user, detail: `${source}: ${findings.map((f) => f.type).join(', ') || categories.join(', ')}` });
    emitSecurityAlert(row, 'RESPONSE_FLAGGED');
    broadcast('query', { type: 'response_flagged', query: publicQuery(row) });
    broadcast('stats', db.stats());
  }
  res.json({ leaked, findings, categories, redacted });
});

// Client polls for release decision.
app.get('/api/v1/status/:id', checkIngestKey, (req, res) => {
  const q = db.getQuery(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
  const released = q.status === 'approved' || q.status === 'allowed';
  res.json({ id: q.id, status: q.status, released });
});

// =============================================================================
// AUTH
// =============================================================================
app.post('/api/login', validation.validateBody(validation.loginSchema), (req, res) => {
  const { user, password } = req.body || {};
  const key = (user || '?') + '|' + (req.ip || (req.connection && req.connection.remoteAddress) || '');
  const st = auth.loginStatus(key);
  if (st.locked) {
    db.appendAudit({ action: 'LOGIN_LOCKED', actor: user || '?', detail: 'too many attempts' });
    return res.status(429).json({ error: 'too many attempts — temporarily locked', retryMs: st.retryMs });
  }
  if (!auth.verifyPassword(user, password)) {
    const r = auth.registerFail(key);
    db.appendAudit({ action: 'LOGIN_FAILED', actor: user || '?', detail: r.locked ? 'locked out' : (r.remaining + ' attempts left') });
    return res.status(401).json({ error: 'invalid credentials', remaining: r.remaining });
  }
  auth.registerSuccess(key);
  const token = auth.createSession(user);
  res.cookie('sentinel_session', token, SESSION_COOKIE_OPTIONS);
  db.appendAudit({ action: 'ADMIN_LOGIN', actor: user });
  res.json({ ok: true, user, role: 'security_admin' });
});

const adminWrite = [auth.requireAuth, auth.requireCsrf];

app.get('/api/csrf', auth.requireAuth, (req, res) => {
  res.json({ csrfToken: auth.createCsrfToken(req.cookies && req.cookies.sentinel_session) });
});

app.post('/api/logout', ...adminWrite, (req, res) => {
  res.clearCookie('sentinel_session', {
    path: SESSION_COOKIE_OPTIONS.path,
    sameSite: SESSION_COOKIE_OPTIONS.sameSite,
    secure: SESSION_COOKIE_OPTIONS.secure,
  });
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

app.get('/api/me', auth.requireAuth, (req, res) => {
  res.json({ user: req.user.user, role: req.user.role, defaultPassword: auth.ADMIN_PASSWORD_IS_DEFAULT });
});

// =============================================================================
// ADMIN API (session-protected)
// =============================================================================
function publicQuery(q, { includeRaw = false } = {}) {
  const { _rawPrompt, _tokenVault, ...rest } = q;
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
  ...adminWrite,
  validation.validateBody(validation.approveSchema),
  requireApprovePassword,
  (req, res) => {
    const q = db.getQuery(req.params.id);
    if (!q) return res.status(404).json({ error: 'not found' });
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

app.post('/api/queries/:id/deny', ...adminWrite, validation.validateBody(validation.noteSchema), (req, res) => {
  const q = db.getQuery(req.params.id);
  if (!q) return res.status(404).json({ error: 'not found' });
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

// Ops metrics (admin) — counts + live audit-integrity, for dashboards/monitoring.
app.get('/api/metrics', auth.requireAuth, (req, res) => {
  const integ = db.verifyAuditChain();
  res.json({ uptimeSec: Math.round(process.uptime()), ...db.stats(), auditOk: integ.ok, auditCount: integ.count, ts: new Date().toISOString() });
});

app.get('/api/preflight', auth.requireAuth, (req, res) => res.json(currentPreflight()));

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
  res.json(evidence.buildEvidencePack({
    version: require('./package.json').version,
    queryLimit,
    auditLimit,
    policy: policy.loadPolicy(),
    stats: db.stats(),
    auditIntegrity: db.verifyAuditChain(),
    detectors: detector.listDetectors(),
    queries: db.listQueries({ limit: queryLimit }),
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
  db.appendAudit({ action: 'POLICY_UPDATED', actor: req.user.user, detail: policy.policyChangeDetail(before, merged) });
  res.json(merged);
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
  console.log(`PromptSentinel running on http://localhost:${port}`);
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
  const server = app.listen(port, () => {
    const address = server.address();
    logStartup(address && address.port ? address.port : port);
  });
  const retentionTimer = setInterval(() => runRetentionPurge(), 60 * 60 * 1000);
  retentionTimer.unref();
  server.on('close', () => clearInterval(retentionTimer));
  return server;
}

if (require.main === module) {
  startServer();
}

app.startServer = startServer;
app.runRetentionPurge = runRetentionPurge;

module.exports = app;
