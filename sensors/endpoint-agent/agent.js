'use strict';
require('../../server/env').loadEnv();
/**
 * RedactWall endpoint agent (reference implementation).
 *
 * Catches sensitive FILES headed to desktop AI apps that a browser extension
 * cannot see. Watches a folder, extracts and detects locally using the same
 * engine as the other sensors, then reports sanitized evidence to the control
 * plane. Respects scanner ignore-lists.
 *
 * Usage: node agent.js [watchDir]
 *   REDACTWALL_URL (or legacy PROMPTWALL_URL/SENTINEL_URL, default http://localhost:4000),
 *   INGEST_API_KEY or REDACTWALL_INGEST_API_KEY (required for control-plane calls)
 *   ENDPOINT_AGENT_WATCH_DIR or REDACTWALL_ENDPOINT_AGENT_WATCH_DIR
 *   ENDPOINT_AGENT_HANDOFF_SECRET or REDACTWALL_ENDPOINT_AGENT_HANDOFF_SECRET enables signed native file-flow handoff events
 *   ENDPOINT_AGENT_FILE_FLOW_PROFILES or REDACTWALL_ENDPOINT_AGENT_FILE_FLOW_PROFILES enables named extra watch roots
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { withEnvAliases } = require('../../server/env');
const nativeHandoff = require('./native-handoff');
const fileFlowProfiles = require('./file-flow-profiles');
const desktopAppFlow = require('./collectors/desktop-app-flow');
const endpointOcr = require('./ocr');
const processors = require('../../server/processors');
const parsePool = require('../../server/parse-pool');
const policyEngine = require('../../server/policy');
const D = require('../../detection-engine/detect');
const VERSION = require('../../package.json').version;
const { secureServerUrl } = require('../shared/server-url');
const { cancelResponseBody, readBoundedJson } = require('../shared/bounded-response');
const signedPolicy = require('../shared/signed-policy');
const { securePrivatePath } = require('../../server/private-path');

const bool = (v) => ['1', 'true', 'yes', 'on'].includes(String(v || '').toLowerCase());
// Refuse a cleartext connection to a REMOTE control plane — the ingest key
// would travel in the clear. Loopback (the local default) stays fine; an
// development-only REDACTWALL_ALLOW_INSECURE_SERVER=1 is the escape hatch.
const RAW_SERVER = process.env.REDACTWALL_URL || 'http://localhost:4000';
const PRODUCTION = String(process.env.NODE_ENV || '').trim().toLowerCase() === 'production';
const SERVER = secureServerUrl(RAW_SERVER, !PRODUCTION && bool(process.env.REDACTWALL_ALLOW_INSECURE_SERVER));
if (!SERVER) {
  console.error('[endpoint-agent] refusing insecure or invalid control-plane URL: use https:// for a remote plane (the insecure override is development-only).');
  process.exit(1);
}
const KEY = process.env.INGEST_API_KEY || '';
function defaultWatchDir(argv = process.argv, env = process.env) {
  return argv[2] || env.ENDPOINT_AGENT_WATCH_DIR || env.REDACTWALL_ENDPOINT_AGENT_WATCH_DIR || path.join(os.tmpdir(), 'redactwall-watch');
}
const WATCH = defaultWatchDir();
const HANDOFF_DIR = nativeHandoff.defaultHandoffDir();
const HANDOFF_SECRET = nativeHandoff.configuredHandoffSecret();

const DEFAULT_SCANNER = {
  ignoreDirectories: ['node_modules', '.git', 'Library', 'Applications', 'AppData'],
  ignoreFilenames: ['thumbs.db', '.ds_store', 'package.json', 'package-lock.json'],
  ignoreExtensions: ['.lock'],
  maxFileBytes: Math.round(6.3 * 1024 * 1024),
};
const REDACTION_HANDOFF_DIR = '.redactwall-redacted';
const REDACTION_HANDOFF_SUFFIX = '.redactwall-redacted.txt';
const LEGACY_REDACTION_HANDOFF_DIR = '.promptwall-redacted';
const LEGACY_REDACTION_HANDOFF_SUFFIX = '.promptwall-redacted.txt';
const POLICY_REFRESH_MS = 5 * 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10000;
const DEFAULT_CONTROL_PLANE_RESPONSE_BYTES = 512 * 1024;
const NODE_TEST_CONTEXT = String(process.env.NODE_TEST_CONTEXT || '');
const HANDOFF_RETRY_DELAY_MS = 200;
const HANDOFF_AUDIT_RETRY_MAX_MS = 60000;
const DEFAULT_FILE_SETTLE_MS = 150;
const MAX_FILE_SETTLE_POLLS = 40;
const FILE_READ_CHUNK_BYTES = 64 * 1024;
let scannerState = scannerConfig(DEFAULT_SCANNER);
let policyState = sensorPolicy(policyEngine.DEFAULT_POLICY);
let policyTrusted = false;
let policyExpiresAt = 0;
const nativeHandoffJobs = new Map();
const nativeHandoffRetryTimers = new Map();
const TENANT_CONTEXT_ID = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const SENSITIVE_TENANT_CODE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\d{12,19})/;
const PERMITTED_TENANT_FINDINGS = new Set(['EMAIL_ADDRESS', 'IP_ADDRESS', 'IPV6_ADDRESS']);

function configuredValue(value) {
  return value != null && String(value).trim() !== '';
}

function normalizedEndpointTenant(value) {
  if (typeof value !== 'string') {
    const error = new Error('endpoint tenant context is invalid');
    error.code = 'REDACTWALL_TENANT_CONTEXT_INVALID';
    throw error;
  }
  const normalized = value.trim().toLowerCase();
  const candidates = [normalized];
  for (let i = 0; i < normalized.length && candidates.length < 24; i += 1) {
    if (!/[ ._:/\\+@-]/.test(normalized[i])) continue;
    const suffix = normalized.slice(i + 1);
    if (suffix.length >= 4 && !candidates.includes(suffix)) candidates.push(suffix);
  }
  const regulated = SENSITIVE_TENANT_CODE.test(normalized) || candidates.some((candidate) => (
    D.analyze(candidate).findings.some((finding) => !PERMITTED_TENANT_FINDINGS.has(finding.type))
  ));
  if (!TENANT_CONTEXT_ID.test(normalized) || regulated) {
    const error = new Error('endpoint tenant context is invalid');
    error.code = 'REDACTWALL_TENANT_CONTEXT_INVALID';
    throw error;
  }
  return normalized;
}

function withEndpointTenantContext(body = {}, opts = {}) {
  if (configuredValue(body.orgId)) {
    return { ...body, orgId: normalizedEndpointTenant(body.orgId) };
  }
  if (configuredValue(opts.orgId)) {
    return { ...body, orgId: normalizedEndpointTenant(opts.orgId) };
  }
  const env = withEnvAliases(opts.env || process.env);
  if (!configuredValue(env.REDACTWALL_TENANT_ID)) return body;
  return { ...body, orgId: normalizedEndpointTenant(env.REDACTWALL_TENANT_ID) };
}

if (!fs.existsSync(WATCH)) fs.mkdirSync(WATCH, { recursive: true });

function configuredKey(opts = {}) {
  const value = Object.prototype.hasOwnProperty.call(opts, 'key') ? opts.key : KEY;
  return typeof value === 'string' ? value.trim() : '';
}

function configuredServer(opts = {}) {
  const raw = opts.server || SERVER;
  const production = String(opts.nodeEnv ?? process.env.NODE_ENV ?? '').trim().toLowerCase() === 'production';
  const allowInsecure = !production
    && (opts.allowInsecureServer === true || bool(process.env.REDACTWALL_ALLOW_INSECURE_SERVER));
  return secureServerUrl(raw, allowInsecure) || '';
}

function controlPlaneResponseBytes(opts = {}) {
  const n = Number(opts.maxResponseBytes ?? opts.maxControlPlaneResponseBytes ?? DEFAULT_CONTROL_PLANE_RESPONSE_BYTES);
  if (!Number.isFinite(n)) return DEFAULT_CONTROL_PLANE_RESPONSE_BYTES;
  return Math.max(1024, Math.min(8 * 1024 * 1024, Math.floor(n)));
}

async function readControlPlaneJson(response, opts, label) {
  const parsed = await readBoundedJson(response, {
    maxBytes: controlPlaneResponseBytes(opts),
    timeoutMs: requestTimeoutMs(opts),
    label,
  });
  return parsed.json;
}

function handoffSecretReady(secret) {
  return typeof secret === 'string' && secret.trim().length >= 32;
}

function lowerList(value, fallback = []) {
  const src = Array.isArray(value) ? value : value instanceof Set ? Array.from(value) : fallback;
  return src
    .filter((item) => typeof item === 'string' && item.trim())
    .map((item) => item.trim().toLowerCase());
}

function detectorList(value, fallback = []) {
  const src = Array.isArray(value) ? value : fallback;
  return src.filter((item) => typeof item === 'string' && item.trim()).map((item) => item.trim());
}

function scannerConfig(input = {}) {
  const merged = { ...DEFAULT_SCANNER, ...(input || {}) };
  const maxFileBytes = Number(merged.maxFileBytes);
  return {
    ignoreDirectories: new Set(lowerList(merged.ignoreDirectories, DEFAULT_SCANNER.ignoreDirectories)),
    ignoreFilenames: new Set(lowerList(merged.ignoreFilenames, DEFAULT_SCANNER.ignoreFilenames)),
    ignoreExtensions: new Set(lowerList(merged.ignoreExtensions, DEFAULT_SCANNER.ignoreExtensions).map((ext) => (
      ext.startsWith('.') ? ext : `.${ext}`
    ))),
    maxFileBytes: Number.isFinite(maxFileBytes) && maxFileBytes > 0 ? Math.round(maxFileBytes) : DEFAULT_SCANNER.maxFileBytes,
  };
}

function boundedNumber(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function sensorPolicy(input = {}) {
  const defaults = policyEngine.DEFAULT_POLICY;
  const merged = { ...defaults, ...(input || {}) };
  const alwaysBlock = policyEngine.mandatoryAlwaysBlock(merged.alwaysBlock);
  const hardStops = new Set(alwaysBlock);
  return {
    enforcementMode: ['block', 'warn', 'justify', 'redact'].includes(merged.enforcementMode) ? merged.enforcementMode : defaults.enforcementMode,
    blockMinSeverity: boundedNumber(merged.blockMinSeverity, defaults.blockMinSeverity, 1, 4),
    blockRiskScore: boundedNumber(merged.blockRiskScore, defaults.blockRiskScore, 0, 100),
    alwaysBlock,
    ignore: detectorList(merged.ignore, defaults.ignore).filter((type) => !hardStops.has(type)),
    disabledDetectors: detectorList(merged.disabledDetectors, defaults.disabledDetectors)
      .filter((type) => !hardStops.has(type)),
    customDetectors: Array.isArray(merged.customDetectors) ? merged.customDetectors : [],
    exactMatch: merged.exactMatch && typeof merged.exactMatch === 'object' && !Array.isArray(merged.exactMatch)
      ? merged.exactMatch : undefined,
    governedDestinations: lowerList(merged.governedDestinations, defaults.governedDestinations),
    allowedDestinations: lowerList(merged.allowedDestinations, defaults.allowedDestinations),
    blockedDestinations: lowerList(merged.blockedDestinations, defaults.blockedDestinations),
    blockedFileUploadDestinations: lowerList(merged.blockedFileUploadDestinations, defaults.blockedFileUploadDestinations),
    blockUnapprovedAiDestinations: merged.blockUnapprovedAiDestinations !== false,
    desktopCollectorDestination: String(merged.desktopCollectorDestination || defaults.desktopCollectorDestination || 'Desktop AI').trim().slice(0, 80) || 'Desktop AI',
    scanner: scannerConfig(merged.scanner || DEFAULT_SCANNER),
  };
}

function testPolicyOverride(opts = {}) {
  // Inline policies exist only as a Node test-runner fixture. Production
  // callers must install a verified signed bundle into policyState.
  if (!NODE_TEST_CONTEXT) return null;
  if (!Object.prototype.hasOwnProperty.call(opts, 'policy')) return null;
  return sensorPolicy(opts.policy || {});
}

function ignoredByScanner(file, scanner) {
  const lower = String(file || '').toLowerCase();
  const parts = lower.split(/[\\/]+/).filter(Boolean);
  if (isRedactionHandoffPath(lower)) return true;
  if (parts.some((part) => scanner.ignoreDirectories.has(part))) return true;
  if (scanner.ignoreFilenames.has(path.basename(lower))) return true;
  return scanner.ignoreExtensions.has(path.extname(lower));
}

function isRedactionHandoffPath(file) {
  const lower = String(file || '').toLowerCase();
  const parts = lower.split(/[\\/]+/).filter(Boolean);
  const base = path.basename(lower);
  return parts.includes(REDACTION_HANDOFF_DIR)
    || parts.includes(LEGACY_REDACTION_HANDOFF_DIR)
    || base.endsWith(REDACTION_HANDOFF_SUFFIX)
    || base.endsWith(LEGACY_REDACTION_HANDOFF_SUFFIX);
}

function fileMode(analysis, pol = policyState) {
  if (analysis && analysis.opaqueEncoded === true) return 'block';
  const hardStop = (analysis.findings || []).some((f) => pol.alwaysBlock.includes(f.type));
  if (pol.enforcementMode === 'redact') return 'redact';
  return hardStop ? 'block' : (pol.enforcementMode || 'block');
}

function canTokenizeAllSensitivity(analysis) {
  return !!(analysis && analysis.opaqueEncoded !== true
    && (analysis.findings || []).length && !(analysis.categories || []).length);
}

function publicFindings(analysis) {
  return (analysis.findings || []).map((f) => ({
    type: f.type,
    severity: f.severity,
    score: f.score,
    masked: D.maskValue(f.type, f.value),
    ...(f.vendor ? { vendor: f.vendor, vendorLabel: f.vendorLabel } : {}),
  }));
}

function publicCategories(analysis) {
  return (analysis.categories || []).map((c) => ({ category: c.category, score: c.score }));
}

function sensitivityLabels(analysis) {
  const labels = (analysis.findings || []).map((f) => f.type).concat((analysis.categories || []).map((c) => c.category));
  if (analysis && analysis.opaqueEncoded === true) labels.push('OPAQUE_ENCODED_CONTENT');
  return [...new Set(labels)];
}

function safeFileLabel(file) {
  const base = path.basename(String(file || 'file')).replace(/[\r\n\t]/g, ' ').slice(0, 128).trim() || 'file';
  const analysis = D.analyze(base);
  return sensitivityLabels(analysis).length ? '[sensitive filename]' : base;
}

function safeCompanionName(file) {
  const label = safeFileLabel(file);
  if (label === '[sensitive filename]') {
    return `redacted-${crypto.randomBytes(6).toString('hex')}${REDACTION_HANDOFF_SUFFIX}`;
  }
  const stem = path.parse(label).name
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'file';
  return `${stem}${REDACTION_HANDOFF_SUFFIX}`;
}

function uniqueCompanionPath(dir, baseName) {
  const parsed = path.parse(baseName);
  for (let i = 0; i < 100; i += 1) {
    const suffix = i ? `-${i + 1}` : '';
    const candidate = path.join(dir, `${parsed.name}${suffix}${parsed.ext}`);
    if (!fs.existsSync(candidate)) return candidate;
  }
  return path.join(dir, `${parsed.name}-${crypto.randomBytes(4).toString('hex')}${parsed.ext}`);
}

function sensorMetadata() {
  return { name: 'endpoint_agent', version: VERSION, platform: process.platform };
}

async function fetchPolicy(opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const trustOptions = { ...opts, sensorId: opts.sensorId || 'endpoint-agent' };
  const cached = () => {
    const result = signedPolicy.readCachedSignedPolicy(trustOptions);
    if (result.ok) policyExpiresAt = Date.parse(result.bundle.expiresAt);
    return result.ok ? result.policy : null;
  };
  if (!fetchImpl) return cached();
  const server = configuredServer(opts);
  const key = configuredKey(opts);
  if (!server || !key) return cached();
  try {
    const r = await fetchWithTimeout(fetchImpl, server + '/api/v1/policy/bundle', {
      headers: { 'x-api-key': key },
    }, opts);
    if (!r || !r.ok) {
      if (r) await cancelResponseBody(r);
      return cached();
    }
    const bundle = await readControlPlaneJson(r, opts, 'endpoint policy response');
    const accepted = signedPolicy.acceptSignedPolicyBundle(bundle, trustOptions);
    if (accepted.ok) policyExpiresAt = Date.parse(accepted.bundle.expiresAt);
    return accepted.ok ? accepted.policy : cached();
  } catch (e) {
    if (!opts.silent) console.error('  policy refresh failed:', e.message);
    return cached();
  }
}

async function refreshPolicy(opts = {}) {
  const pol = await fetchPolicy(opts);
  if (pol) {
    policyState = sensorPolicy(pol);
    scannerState = policyState.scanner;
    policyTrusted = policyExpiresAt > Date.now();
  } else {
    policyTrusted = false;
    policyExpiresAt = 0;
  }
  return scannerState;
}

function requestTimeoutMs(opts = {}) {
  const n = Number(opts.timeoutMs ?? process.env.REDACTWALL_REQUEST_TIMEOUT_MS ?? DEFAULT_REQUEST_TIMEOUT_MS);
  if (!Number.isFinite(n)) return DEFAULT_REQUEST_TIMEOUT_MS;
  return Math.max(50, Math.min(120000, n));
}

async function fetchWithTimeout(fetchImpl, url, options, opts = {}) {
  const timeout = requestTimeoutMs(opts);
  const requestOptions = { ...(options || {}), redirect: 'error' };
  if (!globalThis.AbortController) return fetchImpl(url, requestOptions);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetchImpl(url, { ...requestOptions, signal: controller.signal });
  } catch (e) {
    if (e && e.name === 'AbortError') e.code = 'REDACTWALL_TIMEOUT';
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

async function postJson(apiPath, body, opts = {}) {
  const server = configuredServer(opts);
  const key = configuredKey(opts);
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const requestBody = apiPath === '/api/v1/gate' || apiPath === '/api/v1/heartbeat'
    ? withEndpointTenantContext(body, opts)
    : body;
  if (!fetchImpl || !server || !key) return null;
  try {
    const r = await fetchWithTimeout(fetchImpl, server + apiPath, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': key }, body: JSON.stringify(requestBody),
    }, opts);
    const parsed = await readControlPlaneJson(r, opts, 'endpoint control-plane response').catch(() => null);
    if (!r.ok) {
      const recordedBlock = parsed && parsed.decision === 'block'
        && typeof parsed.status === 'string'
        && typeof parsed.id === 'string' && parsed.id;
      return recordedBlock ? parsed : null;
    }
    return parsed;
  } catch (e) { console.error('  report failed:', e.message); return null; }
}

async function report(rec, opts = {}) {
  return postJson('/api/v1/gate', rec, opts);
}

// Presence heartbeat: registers this agent with the control plane and learns
// which companion sensors (browser extension, MCP guard) cover the same user.
async function sendHeartbeat(opts = {}) {
  const user = opts.user || os.userInfo().username;
  const body = { user, source: 'endpoint_agent', sensor: sensorMetadata() };
  const response = await postJson('/api/v1/heartbeat', body, opts);
  const companions = response && response.companions;
  if (companions && companions.browser_extension && companions.browser_extension !== 'active') {
    (opts.console || console).log('  coverage gap: browser extension is ' + companions.browser_extension + ' for ' + user + ' (reported to console)');
  }
  return response;
}

function unscannedFileEvent(filename, user, outcome, note, opts = {}) {
  return {
    prompt: '[file blocked unscanned] ' + safeFileLabel(filename),
    user, destination: opts.destination || 'desktop-ai-app', source: 'endpoint_agent', channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: outcome,
    note,
  };
}

function destinationBlockedEvent(user, opts = {}) {
  const destination = opts.destination || 'desktop-ai-app';
  return {
    prompt: '[destination blocked] ' + policyEngine.normalizeDestination(destination),
    user,
    destination,
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: 'destination_blocked',
    note: 'blocked locally: destination blocked by policy',
  };
}

function withRecordedId(result, recorded) {
  if (!recorded || typeof recorded.id !== 'string' || !recorded.id) return result;
  return { ...result, id: recorded.id };
}

function committedNativeReplay(recorded) {
  if (!recorded || recorded.idempotentReplay !== true) return null;
  if (typeof recorded.id !== 'string' || !recorded.id) return null;
  if (typeof recorded.decision !== 'string' || typeof recorded.status !== 'string') return null;
  return recorded;
}

function withRecordedOutcome(result, recorded) {
  return committedNativeReplay(recorded) || withRecordedId(result, recorded);
}

async function blockDestinationFile(file, user, opts = {}) {
  console.log(`[BLOCK] ${safeFileLabel(file)} destination blocked by policy`);
  const recorded = await (opts.report || report)(destinationBlockedEvent(user, opts), opts);
  return withRecordedOutcome({ decision: 'block', status: 'destination_blocked', supported: true, inspected: false }, recorded);
}

function fileUploadBlockedEvent(user, opts = {}) {
  const destination = opts.destination || 'desktop-ai-app';
  return {
    prompt: '[file upload blocked] ' + policyEngine.normalizeDestination(destination),
    user,
    destination,
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: 'file_upload_blocked',
    note: 'blocked locally: file upload blocked by policy',
  };
}

async function blockFileUpload(file, user, opts = {}) {
  console.log(`[BLOCK] ${safeFileLabel(file)} file upload blocked by policy`);
  const recorded = await (opts.report || report)(fileUploadBlockedEvent(user, opts), opts);
  return withRecordedOutcome({ decision: 'block', status: 'file_upload_blocked', supported: true, inspected: false }, recorded);
}

async function blockScanUnavailable(file, user, opts = {}) {
  const label = safeFileLabel(file);
  console.log(`[BLOCK] ${label} could not be recorded by RedactWall`);
  const recorded = await (opts.report || report)(unscannedFileEvent(
    file,
    user,
    'scan_unavailable',
    'blocked locally: control plane decision logging unavailable',
    opts,
  ), opts);
  return withRecordedOutcome({ decision: 'block', status: 'scan_unavailable', supported: true }, recorded);
}

function localFileRecord(file, user, safePrompt, analysis, outcome, note, opts = {}) {
  const label = safeFileLabel(file);
  const base = {
    prompt: String(safePrompt || '').slice(0, 1000),
    user,
    destination: opts.destination || 'desktop-ai-app',
    source: 'endpoint_agent',
    channel: 'file_upload',
    sensor: sensorMetadata(),
    clientOutcome: outcome || undefined,
    note: note || `endpoint agent inspected ${label} locally`,
  };
  if (analysis && analysis.opaqueEncoded === true) return base;
  if (!sensitivityLabels(analysis).length) return base;
  return {
    ...base,
    clientPreRedacted: true,
    clientFindings: publicFindings(analysis),
    clientCategories: publicCategories(analysis),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
  };
}

function safeFilePrompt(file, text, analysis, mode) {
  const label = safeFileLabel(file);
  const labels = sensitivityLabels(analysis);
  const prefix = `[file:${label}] `;
  if (!labels.length) return `[file inspected locally] ${label}`;
  if ((analysis.categories || []).length) return prefix + '[REDACTED: ' + labels.join(', ') + ']';
  if (mode === 'redact' && canTokenizeAllSensitivity(analysis)) {
    return prefix + Object.keys(D.tokenize(text, analysis.findings).map).join(' ');
  }
  return prefix + '[REDACTED: ' + labels.join(', ') + ']';
}

function hasRawFindingValue(text, findings) {
  return (findings || []).some((f) => f && f.value && String(text).includes(f.value));
}

function writeRedactionHandoff(file, text, analysis, opts = {}) {
  if (!canTokenizeAllSensitivity(analysis)) return null;
  const tokenized = D.tokenize(text || '', analysis.findings || []);
  const label = safeFileLabel(file);
  const body = [
    'RedactWall redacted companion file',
    `Original file: ${label}`,
    `Generated: ${new Date().toISOString()}`,
    '',
    tokenized.text,
    '',
  ].join('\n');
  if (hasRawFindingValue(body, analysis.findings)) {
    throw new Error('redaction handoff still contains a detected value');
  }
  const root = path.resolve(opts.watchDir || WATCH);
  const dir = path.join(root, REDACTION_HANDOFF_DIR);
  fs.mkdirSync(dir, { recursive: true });
  const fullPath = uniqueCompanionPath(dir, safeCompanionName(file));
  fs.writeFileSync(fullPath, body, { encoding: 'utf8', flag: 'wx' });
  return {
    path: fullPath,
    relativePath: path.relative(root, fullPath),
    tokenCount: tokenized.tokens,
    bytes: Buffer.byteLength(body, 'utf8'),
  };
}

function removeRedactionHandoff(handoff) {
  if (!handoff || !handoff.path) return;
  try { fs.rmSync(handoff.path, { force: true }); } catch {}
}

function prepareRedactionHandoff(file, text, analysis, mode, opts = {}) {
  if (mode !== 'redact' || !canTokenizeAllSensitivity(analysis)) {
    return { handoff: null, handoffError: null, outcome: null };
  }
  try {
    const handoff = writeRedactionHandoff(file, text, analysis, opts);
    return { handoff, handoffError: null, outcome: handoff ? 'redacted_available' : 'awaiting_approval' };
  } catch (e) {
    return { handoff: null, handoffError: e, outcome: 'awaiting_approval' };
  }
}

function handoffNote(handoff, handoffError) {
  if (handoff) return `; redacted companion ${handoff.relativePath}`;
  return handoffError ? '; redacted companion unavailable' : '';
}

function localFileResponse(res, analysis, handoff) {
  const keptHandoff = handoff && (res.status === 'redacted' || res.decision === 'redact');
  if (handoff && !keptHandoff) removeRedactionHandoff(handoff);
  return {
    ...res,
    inspectedLocally: true,
    localAnalysis: analysis,
    ...(keptHandoff ? { redactionHandoff: handoff } : {}),
  };
}

async function reportLocalFile(file, user, extracted, pol, opts = {}) {
  const analysis = D.analyze(extracted.text || '', {
    ignore: pol.ignore,
    disabledDetectors: pol.disabledDetectors,
    customDetectors: pol.customDetectors,
    exactMatch: pol.exactMatch,
    opaqueEncodedContent: true,
  });
  const verdict = policyEngine.evaluate(analysis, pol);
  if (verdict.decision === 'allow') {
    const res = await (opts.report || report)(localFileRecord(file, user, safeFilePrompt(file, '', analysis), analysis, 'allowed', undefined, opts), opts);
    if (res) return { ...res, inspectedLocally: true, localAnalysis: analysis };
    return { ...(await blockScanUnavailable(file, user, opts)), inspectedLocally: true, localAnalysis: analysis };
  }
  const mode = fileMode(analysis, pol);
  const { handoff, handoffError, outcome } = prepareRedactionHandoff(file, extracted.text || '', analysis, mode, opts);
  const safePrompt = safeFilePrompt(file, extracted.text || '', analysis, mode);
  const handoffSource = opts.nativeHandoff && opts.nativeHandoff.id ? `; native handoff ${opts.nativeHandoff.id}` : '';
  const note = `endpoint agent inspected ${safeFileLabel(file)} locally: ${verdict.reasons.join('; ')}` +
    handoffNote(handoff, handoffError) + handoffSource;
  const localOutcome = analysis.opaqueEncoded === true ? 'action_blocked' : outcome;
  const res = await (opts.report || report)(localFileRecord(file, user, safePrompt, analysis, localOutcome, note, opts), opts);
  if (res) return localFileResponse(res, analysis, handoff);
  removeRedactionHandoff(handoff);
  return { ...(await blockScanUnavailable(file, user, opts)), inspectedLocally: true, localAnalysis: analysis };
}

function decisionSummary(res) {
  const localLabels = sensitivityLabels(res.localAnalysis || {});
  const responseLabels = (res.findings || []).map((f) => f.type).concat(
    (res.categories || []).map((c) => (typeof c === 'string' ? c : c.category))
  );
  return {
    labels: localLabels.length ? localLabels : responseLabels.filter(Boolean),
    riskScore: res.riskScore ?? (res.localAnalysis && res.localAnalysis.riskScore),
  };
}

async function extractEndpointOcrSnapshot(file, buf, opts = {}, deps = {}) {
  const fsImpl = deps.fs || fs;
  const secure = deps.securePrivatePath || securePrivatePath;
  const security = { ...(deps.privatePathSecurity || {}), fs: fsImpl };
  const extractImageFile = deps.extractImageFile || endpointOcr.extractImageFile;
  const dir = fsImpl.mkdtempSync(path.join(deps.tmpdir || os.tmpdir(), 'redactwall-ocr-'));
  const snapshot = path.join(dir, `snapshot${path.extname(file).toLowerCase()}`);
  let fd;
  try {
    secure(dir, { ...security, directory: true });
    fd = fsImpl.openSync(snapshot, 'wx', 0o600);
    secure(snapshot, { ...security, directory: false });
    fsImpl.writeFileSync(fd, buf);
    fsImpl.closeSync(fd);
    fd = undefined;
    return await extractImageFile(file, snapshot, opts);
  } finally {
    if (fd !== undefined) { try { fsImpl.closeSync(fd); } catch {} }
    fsImpl.rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  }
}

async function extractEndpointFile(file, buf, opts = {}) {
  // Route parsing through the killable parse pool so a crafted file (zip/pdf
  // bomb) is preempted with SIGKILL instead of wedging the agent's event loop.
  // Same extractText contract as processors; OCR-required types delegate back.
  const extracted = await parsePool.extractText(file, buf, opts.extract || {});
  const needsOcr = !extracted.extractionOk && (extracted.error === 'ocr_required' || extracted.ocrRequired === true);
  if (!needsOcr) return extracted;
  return extractEndpointOcrSnapshot(file, buf, opts.ocr || {});
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Wait until a file's size is stable across two polls before inspecting it, so a
// file still being copied is scanned on its final bytes, not a partial prefix.
// Off (single stat) unless a caller opts in with settleMs>0 — the file watchers
// do, since a 'rename' can fire mid-copy; direct API scans keep prior behavior.
async function statStableFile(full, opts = {}) {
  const settleMs = boundedNumber(opts.settleMs, 0, 0, 5000);
  const wait = opts.sleep || sleep;
  let prev;
  for (let i = 0; i < MAX_FILE_SETTLE_POLLS; i += 1) {
    let stat; try { stat = fs.statSync(full); } catch { return null; }
    if (!stat.isFile()) return stat;
    if (settleMs <= 0 || (prev !== undefined && stat.size === prev)) return stat;
    prev = stat.size;
    await wait(settleMs);
  }
  try { return fs.statSync(full); } catch { return null; }
}

function pathWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}

function sameFileIdentity(left, right) {
  if (!left || !right) return false;
  if (left.dev !== right.dev) return false;
  if (left.ino && right.ino && left.ino !== right.ino) return false;
  return true;
}

function sameFileSnapshot(left, right) {
  return sameFileIdentity(left, right)
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

function pathHasLink(root, full) {
  const relative = path.relative(root, full);
  const entries = [root];
  let current = root;
  for (const part of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    entries.push(current);
  }
  return entries.some((entry) => fs.lstatSync(entry).isSymbolicLink());
}

function safeOpenPath(full, root, openedStat) {
  if (!pathWithin(root, full) || pathHasLink(root, full)) return false;
  const realRoot = fs.realpathSync(root);
  const realFile = fs.realpathSync(full);
  if (!pathWithin(realRoot, realFile)) return false;
  return sameFileIdentity(openedStat, fs.statSync(full));
}

function readBoundedFd(fd, maxBytes) {
  const chunks = [];
  let total = 0;
  while (total <= maxBytes) {
    const size = Math.min(FILE_READ_CHUNK_BYTES, maxBytes + 1 - total);
    const chunk = Buffer.allocUnsafe(size);
    const bytes = fs.readSync(fd, chunk, 0, size, null);
    if (!bytes) break;
    chunks.push(chunk.subarray(0, bytes));
    total += bytes;
  }
  return Buffer.concat(chunks, total);
}

async function readStableFileSnapshot(full, root, maxBytes, opts = {}) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  let fd;
  try {
    fd = fs.openSync(full, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(fd);
    if (!before.isFile() || !safeOpenPath(full, root, before)) return { error: 'unsafe_file_reference' };
    if (before.size > maxBytes) return { error: 'file_too_large' };
    if (typeof opts.onFileOpened === 'function') await opts.onFileOpened({ fd, full, stat: before });
    const buffer = readBoundedFd(fd, maxBytes);
    const after = fs.fstatSync(fd);
    if (buffer.length > maxBytes || after.size > maxBytes) return { error: 'file_too_large' };
    if (!sameFileSnapshot(before, after) || buffer.length !== after.size) return { error: 'file_changed_during_inspection' };
    if (!safeOpenPath(full, root, after)) return { error: 'file_changed_during_inspection' };
    return { buffer, stat: after };
  } catch {
    return { error: 'unsafe_file_reference' };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

async function blockUnreadableFile(file, user, status, opts = {}) {
  const tooLarge = status === 'file_too_large';
  const clientOutcome = tooLarge ? status : 'scan_unavailable';
  const note = tooLarge ? 'blocked locally: file too large to inspect' : `blocked locally: ${status}`;
  console.log(`[BLOCK] ${safeFileLabel(file)} could not be safely inspected`);
  const recorded = await (opts.report || report)(unscannedFileEvent(file, user, clientOutcome, note, opts), opts);
  return withRecordedOutcome({
    decision: 'block',
    status,
  }, recorded);
}

async function scanResolvedFile(file, full, root, opts = {}) {
  const override = testPolicyOverride(opts);
  if (!override && (!policyTrusted || policyExpiresAt <= Date.now())) {
    const user = opts.user || os.userInfo().username;
    const recorded = await (opts.report || report)(unscannedFileEvent(
      file,
      user,
      'scan_unavailable',
      'blocked locally: no trusted signed policy',
      opts,
    ), opts);
    return withRecordedOutcome({ decision: 'block', status: 'policy_unavailable', supported: false, inspected: false }, recorded);
  }
  const pol = override || policyState;
  const scanner = opts.scanner ? scannerConfig(opts.scanner) : pol.scanner || scannerState;
  const maxBytes = opts.maxBytes || scanner.maxFileBytes;
  const label = safeFileLabel(file);
  const user = opts.user || os.userInfo().username;
  const stat = await statStableFile(full, opts);
  if (!stat) return blockUnreadableFile(file, user, 'file_missing_or_unreadable', opts);
  if (!stat.isFile()) return blockUnreadableFile(file, user, 'not_a_regular_file', opts);
  if (policyEngine.destinationBlocked(opts.destination || 'desktop-ai-app', pol)) {
    return blockDestinationFile(file, user, opts);
  }
  if (policyEngine.fileUploadBlocked(opts.destination || 'desktop-ai-app', pol)) {
    return blockFileUpload(file, user, opts);
  }
  if (ignoredByScanner(file, scanner)) {
    return opts.nativeHandoff
      ? blockUnreadableFile(file, user, 'scanner_excluded_file', opts)
      : undefined;
  }

  if (!processors.supported(file)) {
    console.log(`[BLOCK] ${label} is unsupported and was not uploaded for scanning`);
    const recorded = await (opts.report || report)(unscannedFileEvent(file, user, 'file_unsupported', 'blocked locally: unsupported file type', opts), opts);
    return withRecordedOutcome({ decision: 'block', status: 'file_unsupported', supported: false }, recorded);
  }
  const snapshot = await readStableFileSnapshot(full, root, maxBytes, opts);
  if (snapshot.error) return blockUnreadableFile(file, user, snapshot.error, opts);
  const extracted = await extractEndpointFile(file, snapshot.buffer, opts);
  if (!extracted.extractionOk) {
    const ocrRequired = extracted.error === 'ocr_required' || extracted.ocrRequired === true;
    const outcome = ocrRequired ? 'ocr_required' : 'scan_unavailable';
    const note = ocrRequired ? 'blocked locally: OCR required before inspection'
      : `blocked locally: ${extracted.error || 'extract_failed'}`;
    console.log(`[BLOCK] ${label} could not be inspected locally`);
    const recorded = await (opts.report || report)(unscannedFileEvent(file, user, outcome, note, opts), opts);
    return withRecordedOutcome({
      decision: 'block',
      status: outcome,
      supported: true,
      inspected: false,
      ...(ocrRequired ? { ocrRequired: true } : {}),
    }, recorded);
  }
  const res = await reportLocalFile(file, user, extracted, pol, { ...opts, watchDir: opts.redactionRoot || opts.watchDir || root });
  if (res.decision === 'allow') {
    console.log(`[ok]   ${label} -- clean`);
    return res;
  }
  if (res.decision === 'redact' && res.redactionHandoff) {
    console.log(`[ok]   ${label} -> redacted companion ${res.redactionHandoff.relativePath}`);
    return res;
  }
  const summary = decisionSummary(res);
  console.log(`[FLAG] ${label} -> ${summary.labels.join(', ') || 'sensitive content'} (risk ${summary.riskScore ?? 'unknown'})`);
  if (res && res.decision === 'block') console.log(`        held by policy (${res.mode || 'local'}) -> ${res.id || 'unrecorded'}`);
  return res;
}

async function scanFile(file, opts = {}) {
  const watchDir = opts.watchDir || WATCH;
  const root = path.resolve(watchDir);
  const full = path.resolve(root, file);
  if (full !== root && !full.startsWith(root + path.sep)) return;
  return scanResolvedFile(file, full, root, opts);
}

async function scanAbsoluteFile(filePath, opts = {}) {
  const full = path.resolve(String(filePath || ''));
  const root = path.dirname(full);
  return scanResolvedFile(path.basename(full), full, root, opts);
}

function removeHandoffEventFile(file, opts = {}) {
  try {
    fs.rmSync(file, { force: true });
  } catch {
    if (!opts.silent) console.error('  native handoff cleanup failed');
  }
}

async function processNativeHandoffFile(file, opts = {}) {
  let event;
  try {
    event = nativeHandoff.readHandoffFile(file, opts);
  } catch (e) {
    if (e && e.message === 'native handoff event is outside the allowed time window') {
      try {
        const acceptedEarlier = nativeHandoff.readHandoffFile(file, {
          ...opts,
          ttlMs: Number.MAX_SAFE_INTEGER,
          now: new Date(),
        });
        const prior = nativeHandoff.readHandoffClaim(acceptedEarlier, file, opts);
        if (prior && (prior.state === 'claimed' || prior.state === 'terminal')) event = acceptedEarlier;
      } catch {}
    }
    if (!event) {
      if (!opts.silent) console.error('  native handoff rejected:', e.message);
      if (opts.removeRejected) removeHandoffEventFile(file, opts);
      return { status: 'rejected', reason: e.message };
    }
    // A signature-valid event accepted while fresh may finish after its
    // freshness window. Its durable opaque claim proves this is a retry, not
    // first-use replay.
  }
  const claim = await nativeHandoff.withHandoffClaim(event, file, async () => {
    const reportImpl = opts.report || report;
    const idempotency = nativeHandoff.ingestIdempotency(event, opts);
    const result = await scanAbsoluteFile(event.filePath, {
      ...opts,
      user: event.user || opts.user,
      destination: nativeHandoff.publicDestination(event.destination),
      nativeHandoff: event,
      redactionRoot: opts.redactionRoot || path.dirname(file),
      report: (record, reportOpts) => reportImpl({ ...record, idempotency }, reportOpts),
    });
    if (!result || typeof result.id !== 'string' || !result.id) {
      const error = new Error('native handoff terminal audit evidence was not recorded');
      error.code = 'REDACTWALL_HANDOFF_AUDIT_UNAVAILABLE';
      throw error;
    }
    return result;
  }, opts);
  if (!claim.claimed) {
    if (!opts.keepHandoffFile) removeHandoffEventFile(file, opts);
    return { status: 'replayed', reason: 'native handoff event was already consumed', terminal: claim.terminal };
  }
  if (!opts.keepHandoffFile) removeHandoffEventFile(file, opts);
  return { status: 'processed', event, result: claim.result, terminal: claim.terminal };
}

function handoffAuditRetryDelay(attempt, opts = {}) {
  const requested = Number(opts.handoffAuditRetryMs);
  const base = Number.isFinite(requested) ? Math.max(10, Math.min(60000, Math.floor(requested))) : 1000;
  return Math.min(HANDOFF_AUDIT_RETRY_MAX_MS, base * (2 ** Math.min(10, Math.max(0, attempt))));
}

function scheduleNativeHandoffRetry(file, opts, attempt) {
  const key = path.resolve(file);
  if (opts.retryNativeHandoff === false) return;
  if (nativeHandoffRetryTimers.has(key) || !fs.existsSync(key)) return;
  const schedule = opts.setTimeout || setTimeout;
  const timer = schedule(() => {
    nativeHandoffRetryTimers.delete(key);
    if (fs.existsSync(key)) processNativeHandoffFileSafe(key, opts, attempt);
  }, handoffAuditRetryDelay(attempt, opts));
  if (timer && typeof timer.unref === 'function') timer.unref();
  nativeHandoffRetryTimers.set(key, timer);
}

function processNativeHandoffFileSafe(file, opts = {}, attempt = 0) {
  const key = path.resolve(file);
  const pendingTimer = nativeHandoffRetryTimers.get(key);
  if (pendingTimer !== undefined) {
    (opts.clearTimeout || clearTimeout)(pendingTimer);
    nativeHandoffRetryTimers.delete(key);
  }
  if (nativeHandoffJobs.has(key)) return nativeHandoffJobs.get(key);
  const job = Promise.resolve(processNativeHandoffFile(key, opts)).catch((e) => {
    if (!opts.silent) console.error('  native handoff failed:', e.message);
    scheduleNativeHandoffRetry(key, opts, attempt + 1);
    return { status: 'retry_scheduled', reason: e.code || 'native_handoff_failed' };
  }).finally(() => {
    if (nativeHandoffJobs.get(key) === job) nativeHandoffJobs.delete(key);
  });
  nativeHandoffJobs.set(key, job);
  return job;
}

function processHandoffDirectory(dir = HANDOFF_DIR, opts = {}) {
  if (!handoffSecretReady(nativeHandoff.configuredHandoffSecret(opts))) return;
  nativeHandoff.ensurePrivateDirectory(dir);
  for (const entry of fs.readdirSync(dir)) {
    if (entry.toLowerCase().endsWith('.json')) processNativeHandoffFileSafe(path.join(dir, entry), { ...opts, silent: true });
  }
  return fs.watch(dir, (event, filename) => {
    if (filename && event === 'rename' && filename.toLowerCase().endsWith('.json')) {
      const handoffFile = path.join(dir, filename);
      setTimeout(() => {
        if (fs.existsSync(handoffFile)) processNativeHandoffFileSafe(handoffFile, opts);
      }, HANDOFF_RETRY_DELAY_MS);
    }
  });
}

function watchScheduler(scan, opts = {}) {
  const setTimer = opts.setTimeout || setTimeout;
  const clearTimer = opts.clearTimeout || clearTimeout;
  const delayMs = opts.delayMs || HANDOFF_RETRY_DELAY_MS;
  const pending = new Map();
  return function schedule(event, filename) {
    if (!filename || (event !== 'rename' && event !== 'change')) return;
    const key = String(filename);
    const prior = pending.get(key);
    if (prior !== undefined) clearTimer(prior);
    let firedSynchronously = false;
    const timer = setTimer(() => {
      firedSynchronously = true;
      pending.delete(key);
      const result = scan(key);
      Promise.resolve(result).catch(() => {});
      return result;
    }, delayMs);
    if (!firedSynchronously) pending.set(key, timer);
  };
}

function startWatchedRoot(profile, deps = {}) {
  const readDir = deps.readdirSync || fs.readdirSync;
  const watch = deps.watch || fs.watch;
  const setTimeoutFn = deps.setTimeout || setTimeout;
  const clearTimeoutFn = deps.clearTimeout || clearTimeout;
  const scan = deps.scanFile || scanFile;
  const io = deps.console || console;
  const scanOpts = {
    settleMs: DEFAULT_FILE_SETTLE_MS,
    ...(profile.scanOptions || {}),
    watchDir: profile.dir,
    destination: profile.destination,
    ...(profile.user ? { user: profile.user } : {}),
  };
  const scanQueuedFile = (filename) => scan(filename, scanOpts);
  const scheduleScan = watchScheduler(scanQueuedFile, {
    setTimeout: setTimeoutFn,
    clearTimeout: clearTimeoutFn,
    delayMs: HANDOFF_RETRY_DELAY_MS,
  });
  // A configured profile dir may not exist yet (fresh machine, unmounted share).
  // Degrade that one profile instead of aborting start() and dropping every
  // other watcher. Log the id only — never the directory path.
  try {
    for (const f of readDir(profile.dir)) scanQueuedFile(f);
    return watch(profile.dir, scheduleScan);
  } catch (e) {
    io.error(`  file-flow profile ${profile.id} unavailable (${e.code || 'error'})`);
    return null;
  }
}

function start(opts = {}) {
  const io = opts.console || console;
  const watchDir = opts.watchDir || WATCH;
  const server = Object.prototype.hasOwnProperty.call(opts, 'server') ? opts.server : SERVER;
  const key = Object.prototype.hasOwnProperty.call(opts, 'key') ? opts.key : KEY;
  const handoffDir = opts.handoffDir || HANDOFF_DIR;
  const handoffSecret = Object.prototype.hasOwnProperty.call(opts, 'handoffSecret') ? opts.handoffSecret : HANDOFF_SECRET;
  const refresh = opts.refreshPolicy || refreshPolicy;
  const scan = opts.scanFile || scanFile;
  const processHandoff = opts.processHandoffDirectory || processHandoffDirectory;
  const watch = opts.watch || fs.watch;
  const readDir = opts.readdirSync || fs.readdirSync;
  const setIntervalFn = opts.setInterval || setInterval;
  const setTimeoutFn = opts.setTimeout || setTimeout;
  const clearTimeoutFn = opts.clearTimeout || clearTimeout;
  const scanOpts = opts.scanOptions
    || (opts.watchDir ? { watchDir, settleMs: DEFAULT_FILE_SETTLE_MS } : { settleMs: DEFAULT_FILE_SETTLE_MS });
  const scanQueuedFile = (filename) => (scanOpts ? scan(filename, scanOpts) : scan(filename));
  const scheduleScan = watchScheduler(scanQueuedFile, {
    setTimeout: setTimeoutFn,
    clearTimeout: clearTimeoutFn,
    delayMs: HANDOFF_RETRY_DELAY_MS,
  });
  const profiles = opts.fileFlowProfiles
    ? fileFlowProfiles.normalizeFileFlowProfiles(opts.fileFlowProfiles)
    : fileFlowProfiles.fileFlowProfilesFromEnv();
  const appFlowProfiles = Array.isArray(opts.appFlowProfiles)
    ? fileFlowProfiles.normalizeFileFlowProfiles(opts.appFlowProfiles)
    : desktopAppFlow.desktopAppFlowProfiles({ watchDir });

  io.log('RedactWall endpoint agent');
  io.log('  watching:', watchDir);
  io.log('  file-flow profiles:', profiles.length ? profiles.map((profile) => profile.id).join(', ') : 'disabled');
  io.log('  app file-flow:', appFlowProfiles.length ? appFlowProfiles.map((profile) => profile.id).join(', ') : 'disabled');
  io.log('  native handoff:', handoffSecretReady(handoffSecret) ? handoffDir : 'disabled (set 32+ char ENDPOINT_AGENT_HANDOFF_SECRET)');
  io.log('  server  :', server);
  io.log('  ingest  :', key ? 'configured' : 'not configured (control-plane calls disabled)');
  io.log('  Supported: pdf, docx, xlsx, pptx, and text files. Drop a file in to scan.\n');

  const heartbeat = opts.sendHeartbeat || sendHeartbeat;
  const initialRefresh = Promise.resolve(refresh({ silent: true })).finally(() => {
    for (const f of readDir(watchDir)) scanQueuedFile(f);
  }).catch(() => {});
  Promise.resolve(heartbeat({ server, key })).catch(() => {});
  const refreshTimer = setIntervalFn(() => {
    Promise.resolve(refresh({ silent: true })).catch(() => {});
    Promise.resolve(heartbeat({ server, key })).catch(() => {});
  }, POLICY_REFRESH_MS);
  if (refreshTimer.unref) refreshTimer.unref();
  const watcher = watch(watchDir, scheduleScan);
  const fileFlowWatchers = profiles.concat(appFlowProfiles).map((profile) => startWatchedRoot(profile, {
    readdirSync: readDir,
    watch,
    setTimeout: setTimeoutFn,
    clearTimeout: clearTimeoutFn,
    scanFile: scan,
  }));
  const handoffWatcher = handoffSecretReady(handoffSecret) ? processHandoff(handoffDir, { secret: handoffSecret }) : undefined;
  return { refreshTimer, watcher, fileFlowWatchers, handoffWatcher, initialRefresh };
}

if (require.main === module) start();

module.exports = {
  scanFile,
  scanAbsoluteFile,
  processNativeHandoffFile,
  processNativeHandoffFileSafe,
  processHandoffDirectory,
  report,
  sendHeartbeat,
  postJson,
  fetchPolicy,
  refreshPolicy,
  policyTrustState: () => ({ trusted: policyTrusted && policyExpiresAt > Date.now(), expiresAt: policyExpiresAt }),
  _setTrustedPolicyForTest: (value, expiresAt = Date.now() + 60 * 60 * 1000) => {
    policyState = sensorPolicy(value || {});
    scannerState = policyState.scanner;
    policyTrusted = true;
    policyExpiresAt = expiresAt;
  },
  _testPolicyOverride: testPolicyOverride,
  sensorPolicy,
  decisionSummary,
  scannerConfig,
  ignoredByScanner,
  publicFindings,
  publicCategories,
  safeFileLabel,
  requestTimeoutMs,
  fetchWithTimeout,
  defaultWatchDir,
  sensorMetadata,
  configuredKey,
  handoffSecretReady,
  nativeHandoff,
  fileFlowProfiles,
  desktopAppFlow,
  startWatchedRoot,
  watchScheduler,
  start,
  _internal: {
    extractEndpointOcrSnapshot,
    normalizedEndpointTenant,
    pathWithin,
    readBoundedFd,
    readStableFileSnapshot,
    safeOpenPath,
    sameFileIdentity,
    sameFileSnapshot,
    withEndpointTenantContext,
  },
};
