'use strict';
require('../server/env').loadEnv();
/**
 * Monitor-only AI chat proxy lab.
 *
 * This is a thin spike, not a production TLS interception proxy. It observes
 * captured cleartext HTTP request bodies for known AI chat domains, scans them
 * locally, sends only pre-redacted evidence to RedactWall, and always forwards
 * the request path from the proxy's point of view.
 */
const http = require('node:http');
const { URL } = require('node:url');
const adapters = require('../detection-engine/adapters');
const detector = require('../server/detector');
const policy = require('../server/policy');
const { extractPrompt, fetchWithTimeout } = require('./squid-icap-bridge');

const REDACTWALL = process.env.REDACTWALL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const DEFAULT_PORT = 4181;
const DEFAULT_MAX_BODY_BYTES = 256 * 1024;
const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function safeEvidencePrompt(destination, analysis = {}) {
  const labels = unique([
    ...(analysis.findings || []).map((f) => f.type),
    ...(analysis.categories || []).map((c) => c.category),
  ]);
  if (!labels.length) return `[proxy observed] ${destination}`;
  return `[REDACTED: ${labels.join(', ')}]`;
}

function clientEvidenceFromAnalysis(analysis = {}) {
  return {
    clientFindings: (analysis.findings || []).map((f) => ({
      type: f.type,
      severity: f.severity,
      score: f.score,
      masked: f.masked || detector.maskValue(f.type, f.value || ''),
    })),
    clientCategories: (analysis.categories || []).map((c) => ({
      category: c.category,
      score: c.score,
    })),
    clientEntityCounts: analysis.entityCounts || {},
    clientRiskScore: analysis.riskScore || 0,
    clientMaxSeverity: analysis.maxSeverity || 0,
    clientMaxSeverityLabel: analysis.maxSeverityLabel || 'none',
  };
}

function hostFromUrlOrHeader(url, hostHeader) {
  try {
    if (url && /^https?:\/\//i.test(url)) return new URL(url).hostname;
  } catch {}
  return hostHeader || 'unknown';
}

function shouldInspectRequest({ method = 'GET', host }) {
  const normalized = adapters.normalizeHost(host);
  return BODY_METHODS.has(String(method || '').toUpperCase()) && adapters.isAiHost(normalized);
}

function buildMonitorPayload({
  host,
  user = 'unknown',
  sourceIp = null,
  contentType = '',
  body = '',
  sensor = null,
} = {}) {
  const destination = adapters.normalizeHost(host);
  const prompt = extractPrompt(destination, contentType, String(body || ''));
  if (!String(prompt || '').trim()) return { destination, payload: null, reason: 'no_prompt' };

  const analysis = detector.analyze(prompt, policy.analyzeOpts());
  return {
    destination,
    payload: {
      prompt: safeEvidencePrompt(destination, analysis),
      user,
      destination,
      sourceIp,
      source: 'proxy',
      channel: 'proxy_monitor',
      sensor: sensor || { name: 'ai_chat_dlp_proxy_lab', version: '0.1.0', platform: 'node_http_lab' },
      clientOutcome: 'proxy_observed',
      clientPreRedacted: true,
      ...clientEvidenceFromAnalysis(analysis),
    },
    evidence: {
      destination,
      riskScore: analysis.riskScore || 0,
      maxSeverity: analysis.maxSeverity || 0,
      findings: (analysis.findings || []).map((f) => ({ type: f.type, masked: f.masked || detector.maskValue(f.type, f.value || '') })),
      categories: (analysis.categories || []).map((c) => c.category),
    },
  };
}

function sanitizeControlPlaneBody(body = {}) {
  return {
    id: body.id || null,
    decision: body.decision || null,
    status: body.status || null,
    mode: body.mode || null,
    riskScore: body.riskScore || 0,
    findings: (body.findings || []).map((f) => ({ type: f.type, severity: f.severity, score: f.score, masked: f.masked })),
    categories: body.categories || [],
    reasons: body.reasons || [],
    error: body.error || null,
  };
}

async function postMonitorEvidence(payload, {
  redactwall = REDACTWALL,
  key = KEY,
  fetchImpl = globalThis.fetch,
  timeoutMs,
} = {}) {
  if (!fetchImpl) return { ok: false, status: 0, reason: 'fetch_unavailable' };
  try {
    const res = await fetchWithTimeout(fetchImpl, `${redactwall}/api/v1/gate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': key },
      body: JSON.stringify(payload),
    }, { timeoutMs });
    const body = await res.json().catch(() => ({}));
    return { ok: !!(res && res.ok), status: res ? res.status : 0, body: sanitizeControlPlaneBody(body) };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      reason: e && e.code === 'REDACTWALL_TIMEOUT' ? 'gate_timeout' : 'gate_unreachable',
    };
  }
}

async function observeAiChatRequest(input = {}, opts = {}) {
  const host = hostFromUrlOrHeader(input.url, input.host || (input.headers && input.headers.host));
  const destination = adapters.normalizeHost(host);
  if (!shouldInspectRequest({ method: input.method, host: destination })) {
    return { forward: true, monitored: false, destination, reason: 'not_ai_chat_body_request' };
  }

  const built = buildMonitorPayload({
    host: destination,
    user: input.user || (input.headers && (input.headers['x-redactwall-user'] || input.headers['x-user'])) || 'unknown',
    sourceIp: input.sourceIp || null,
    contentType: input.contentType || (input.headers && input.headers['content-type']) || '',
    body: input.body || '',
    sensor: input.sensor || null,
  });
  if (!built.payload) return { forward: true, monitored: false, destination, reason: built.reason || 'no_prompt' };

  const controlPlane = await postMonitorEvidence(built.payload, opts);
  return {
    forward: true,
    monitored: true,
    destination,
    evidence: built.evidence,
    controlPlane,
  };
}

function stripHopByHopHeaders(headers = {}) {
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    if (!HOP_BY_HOP_HEADERS.has(String(key).toLowerCase())) out[key] = value;
  }
  return out;
}

function targetUrlFromRequest(req) {
  if (/^https?:\/\//i.test(req.url)) return new URL(req.url);
  return new URL(`http://${req.headers.host || 'unknown'}${req.url || '/'}`);
}

function rejectConnect(socket) {
  const body = JSON.stringify({ error: 'CONNECT is outside this monitor-only lab slice' });
  socket.write([
    'HTTP/1.1 501 Not Implemented',
    'content-type: application/json',
    `content-length: ${Buffer.byteLength(body)}`,
    'connection: close',
    '',
    body,
  ].join('\r\n'));
  socket.end();
}

function collectBody(req, maxBodyBytes = DEFAULT_MAX_BODY_BYTES) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let truncated = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size <= maxBodyBytes) chunks.push(chunk);
      else truncated = true;
    });
    req.on('end', () => resolve({ body: Buffer.concat(chunks), truncated }));
    req.on('error', reject);
  });
}

async function forwardRequest(req, res, targetUrl, body, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (!fetchImpl) {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'upstream fetch unavailable' }));
    return;
  }
  try {
    const upstream = await fetchImpl(targetUrl.href, {
      method: req.method,
      headers: stripHopByHopHeaders(req.headers),
      body: body && body.length ? body : undefined,
      redirect: 'manual',
    });
    const responseHeaders = {};
    upstream.headers.forEach((value, key) => {
      if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) responseHeaders[key] = value;
    });
    res.writeHead(upstream.status, responseHeaders);
    res.end(Buffer.from(await upstream.arrayBuffer()));
  } catch {
    res.writeHead(502, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'upstream unavailable' }));
  }
}

function createProxyServer(opts = {}) {
  const server = http.createServer(async (req, res) => {
    let targetUrl;
    try {
      targetUrl = targetUrlFromRequest(req);
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'invalid proxy target' }));
      return;
    }

    const { body, truncated } = await collectBody(req, opts.maxBodyBytes || DEFAULT_MAX_BODY_BYTES);
    if (!truncated) {
      await observeAiChatRequest({
        method: req.method,
        url: targetUrl.href,
        host: targetUrl.hostname,
        headers: req.headers,
        sourceIp: req.socket && req.socket.remoteAddress,
        body: body.toString('utf8'),
      }, opts);
    }
    await forwardRequest(req, res, targetUrl, body, opts);
  });
  server.on('connect', (req, socket) => rejectConnect(socket));
  return server;
}

function parseArgs(argv = process.argv.slice(2)) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (item === '--sample') out.sample = true;
    else if (item === '--port') out.port = Number(argv[++i]);
    else if (item === '--host') out.host = argv[++i];
    else if (item === '--prompt') out.prompt = argv[++i];
    else if (item === '--redactwall' || item === '--sentinel') out.redactwall = argv[++i];
    else if (item === '--key') out.key = argv[++i];
  }
  return out;
}

async function main(argv = process.argv.slice(2), io = process) {
  const args = parseArgs(argv);
  if (args.sample) {
    const result = await observeAiChatRequest({
      method: 'POST',
      host: args.host || 'chatgpt.com',
      contentType: 'application/json',
      body: JSON.stringify({ prompt: args.prompt || 'Synthetic member SSN 524-71-9043 for lab validation.' }),
      user: 'proxy-lab@example.test',
      sourceIp: '127.0.0.1',
    }, { redactwall: args.redactwall || REDACTWALL, key: args.key || KEY });
    io.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return null;
  }

  const port = Number.isFinite(args.port) ? args.port : DEFAULT_PORT;
  return createProxyServer({ redactwall: args.redactwall || REDACTWALL, key: args.key || KEY })
    .listen(port, '127.0.0.1', () => {
      io.stdout.write(`RedactWall AI chat proxy lab listening on http://127.0.0.1:${port}\n`);
    });
}

if (require.main === module) main().catch((err) => { process.stderr.write(`${err && err.message ? err.message : err}\n`); process.exitCode = 1; });

module.exports = {
  buildMonitorPayload,
  clientEvidenceFromAnalysis,
  createProxyServer,
  main,
  observeAiChatRequest,
  parseArgs,
  postMonitorEvidence,
  safeEvidencePrompt,
  shouldInspectRequest,
};
