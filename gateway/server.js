'use strict';
/**
 * RedactWall AI Gateway — an OpenAI-compatible reverse proxy that gates every
 * prompt and scans every response through the RedactWall control plane before
 * anything reaches the upstream model or returns to the caller.
 *
 * Fail-closed: if the control plane is unreachable, the request is blocked — it
 * never silently reaches upstream. Streaming responses are BUFFERED and scanned
 * before release, so model output cannot reach the caller until it passes.
 *
 * Surface (OpenAI-compatible):
 *   POST /v1/chat/completions
 *   POST /v1/completions
 *   POST /v1/embeddings
 *   GET  /healthz   GET /readyz   GET /metrics
 */
const express = require('express');
const detect = require('../detection-engine/detect');
const { config } = require('./config');
const { makeClient } = require('./client');
const { getAdapter } = require('./adapters');
const tokens = require('./tokens');
const canonical = require('./canonical');

// Role-faithful local redaction: tokenize EVERY message/content (system,
// assistant, user) with a shared value->token map so no raw PII in any role
// reaches the upstream model, and the response can be rehydrated locally. This
// replaces relying on the control plane's single joined tokenized string, which
// dropped non-user roles.
function redactBodyLocally(body) {
  const byValue = new Map();
  const map = {};
  const counters = {};
  function tokenFor(type, value) {
    if (byValue.has(value)) return byValue.get(value);
    const n = (counters[type] = (counters[type] || 0) + 1);
    const t = '[[' + type + '_' + n + ']]';
    byValue.set(value, t); map[t] = value;
    return t;
  }
  function tok(text) {
    if (typeof text !== 'string' || !text) return text;
    const findings = detect.analyze(text).findings;
    if (!findings.length) return text;
    let out = text;
    for (const f of findings.slice().sort((a, b) => b.start - a.start)) {
      out = out.slice(0, f.start) + tokenFor(f.type, f.value) + out.slice(f.end);
    }
    return out;
  }
  // Tokenize every scannable surface so no raw PII in any message reaches
  // upstream — string content, array text parts, and tool/function-call
  // arguments (all of which requestText/messageText also scan).
  function tokMessage(m) {
    if (!m || typeof m !== 'object') return m;
    let next = m;
    const patch = (obj, key, val) => { if (next === obj) next = { ...obj }; next[key] = val; };
    if (typeof m.content === 'string') patch(m, 'content', tok(m.content));
    else if (Array.isArray(m.content)) {
      let touched = false;
      const parts = m.content.map((part) => {
        if (part && typeof part.text === 'string') { touched = true; return { ...part, text: tok(part.text) }; }
        return part;
      });
      if (touched) patch(m, 'content', parts);
    }
    if (Array.isArray(m.tool_calls)) {
      let touched = false;
      const calls = m.tool_calls.map((tc) => {
        const args = tc && tc.function && tc.function.arguments;
        if (typeof args === 'string' && args) { touched = true; return { ...tc, function: { ...tc.function, arguments: tok(args) } }; }
        return tc;
      });
      if (touched) patch(m, 'tool_calls', calls);
    }
    if (m.function_call && typeof m.function_call.arguments === 'string') {
      patch(m, 'function_call', { ...m.function_call, arguments: tok(m.function_call.arguments) });
    }
    return next;
  }
  const tokArray = (arr) => arr.map((p) => (typeof p === 'string' ? tok(p) : p));
  // Tokenize PII in tool/function DEFINITIONS (description + parameters schema)
  // so a redact verdict doesn't forward raw PII embedded in a tool spec. The
  // function NAME is left intact — tokens contain `[` `]` which are invalid in
  // OpenAI function names — and the residual check in handle() fails closed if
  // any untokenized field still carries PII.
  function tokDeep(v) {
    if (typeof v === 'string') return tok(v);
    if (Array.isArray(v)) return v.map(tokDeep);
    if (v && typeof v === 'object') { const o = {}; for (const k of Object.keys(v)) o[k] = tokDeep(v[k]); return o; }
    return v;
  }
  function tokFnDef(fn) {
    if (!fn || typeof fn !== 'object') return fn;
    const nextFn = { ...fn };
    if (typeof fn.description === 'string') nextFn.description = tok(fn.description);
    if (fn.parameters != null) nextFn.parameters = tokDeep(fn.parameters);
    return nextFn;
  }
  const out = { ...body };
  if (Array.isArray(body.messages)) {
    out.messages = body.messages.map(tokMessage);
  } else if (typeof body.prompt === 'string') { out.prompt = tok(body.prompt); }
  else if (Array.isArray(body.prompt)) { out.prompt = tokArray(body.prompt); }
  else if (typeof body.input === 'string') { out.input = tok(body.input); }
  else if (Array.isArray(body.input)) { out.input = tokArray(body.input); }
  if (Array.isArray(body.tools)) out.tools = body.tools.map((t) => (t && t.function ? { ...t, function: tokFnDef(t.function) } : t));
  if (Array.isArray(body.functions)) out.functions = body.functions.map(tokFnDef);
  return { body: out, map, tokenCount: Object.keys(map).length };
}

// Count findings by detector TYPE. A raw total is not enough: the control plane
// analyzes under policy options (disabled/custom detectors, exact-match/EDM) the
// gateway's default analyze cannot see, so a custom/EDM hit and an extra
// default-detectable hit both count as "1" and a count-only check would let the
// unreproduced type through. Comparing per type catches exactly the finding the
// gateway can't redact locally.
function findingTypeCounts(findings) {
  const counts = new Map();
  for (const f of (Array.isArray(findings) ? findings : [])) {
    if (!f || typeof f.type !== 'string') continue;
    counts.set(f.type, (counts.get(f.type) || 0) + 1);
  }
  return counts;
}

// True only when local default analysis reproduces every reported finding type
// at least as many times as the plane reported it.
function localReproducesTypes(localText, reported) {
  if (!reported.size) return true;
  const local = findingTypeCounts(detect.analyze(localText).findings);
  for (const [type, n] of reported) {
    if ((local.get(type) || 0) < n) return false;
  }
  return true;
}

// A redact verdict must never forward raw PII the control plane flagged. The
// gateway redacts locally with DEFAULT detector options, so custom-detector /
// exact-match (EDM) hits — which fired under the control plane's policy options
// but are invisible to a default analyze — would otherwise slip through. Fail
// closed when local redaction can't reproduce every reported finding type, or
// when a redact verdict extracted text yet tokenized nothing.
function redactionCoversVerdict(promptText, redacted, verdict) {
  const reported = findingTypeCounts(verdict.findings);
  if (!reported.size) return true; // no detector-level findings to reproduce
  if (redacted.tokenCount === 0) return false;
  return localReproducesTypes(promptText, reported);
}

// The gateway redacts a leaked response locally (full length, per choice). That
// is only safe when local default detection reproduces everything the control
// plane flagged. A semantic category or custom/EDM detector the gateway can't
// see means local redaction would leave raw values in the body — withhold it.
function responseRedactionCovers(respText, scan) {
  if (Array.isArray(scan.categories) && scan.categories.length) return false;
  return localReproducesTypes(respText, findingTypeCounts(scan.findings));
}

const BLOCK_STATUSES = new Set([
  'control_plane_unavailable', 'destination_blocked', 'injection_blocked',
  'file_blocked_unscanned', 'file_upload_blocked', 'pending', 'pending_justification',
]);

function openAiError(message, type, reasons) {
  return { error: { message, type: type || 'redactwall_block', code: type || 'redactwall_block', reasons: reasons || [] } };
}

function createGateway(overrides = {}) {
  const cfg = { ...config(), ...overrides };
  // Client/adapter are injectable for deterministic tests (no network).
  const client = overrides.client || makeClient(cfg);
  const adapter = overrides.adapter || getAdapter(cfg.provider);
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: cfg.maxBodyBytes }));

  const metrics = { requests: 0, allowed: 0, redacted: 0, blocked: 0, responseBlocked: 0, responseRedacted: 0, upstreamErrors: 0, failClosed: 0 };
  const buckets = new Map(); // token id -> { count, resetAt }

  function rateLimited(id) {
    const now = Date.now();
    const b = buckets.get(id);
    if (!b || now >= b.resetAt) {
      // Opportunistically evict expired buckets so the map cannot grow without
      // bound on a long-lived process serving many distinct callers.
      if (buckets.size > 1000) for (const [k, v] of buckets) if (now >= v.resetAt) buckets.delete(k);
      buckets.set(id, { count: 1, resetAt: now + 60000 });
      return false;
    }
    b.count += 1;
    return b.count > cfg.rateLimitPerMin;
  }

  function authenticate(req, res, next) {
    const raw = (req.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
    const identity = raw ? tokens.resolveToken(raw, cfg.agentTokensPath) : null;
    if (!identity) {
      if (cfg.requireAgentToken) return res.status(401).json(openAiError('Missing or invalid gateway agent token', 'invalid_agent_token'));
      req.agentIdentity = { id: 'anonymous', user: 'unattributed@gateway', orgId: null };
    } else {
      req.agentIdentity = identity;
    }
    if (rateLimited(req.agentIdentity.id)) return res.status(429).json(openAiError('Rate limit exceeded', 'rate_limited'));
    next();
  }

  function destinationLabel() {
    return 'gateway:' + cfg.provider;
  }

  async function handle(kind, req, res) {
    metrics.requests += 1;
    const identity = req.agentIdentity;
    const body = req.body || {};
    const wantsStream = body.stream === true && kind !== 'embeddings';
    const promptText = adapter.requestText(body);

    // Fail closed on ANY content the gateway cannot scan (image/binary parts,
    // token-id arrays) — even when other parts carry scannable text, so a PII
    // image alongside a caption is never forwarded ungated.
    if (canonical.carriesUnscannableContent(body)) {
      metrics.blocked += 1;
      metrics.failClosed += 1;
      return res.status(403).json(openAiError('Request carries content RedactWall could not scan; blocked', 'unscannable_content'));
    }

    // 1. Gate the prompt (fail-closed).
    let redactMap = null;
    let outboundBody = body;
    if (promptText && promptText.trim()) {
      const verdict = await client.gate({
        prompt: promptText, user: identity.user, orgId: identity.orgId,
        destination: destinationLabel(), source: 'ai_gateway', channel: 'gateway',
      });
      if (verdict._failClosed) metrics.failClosed += 1;
      const blocked = verdict.decision === 'block' || BLOCK_STATUSES.has(verdict.status);
      if (blocked && verdict.decision !== 'redact') {
        metrics.blocked += 1;
        return res.status(403).json(openAiError('Prompt blocked by RedactWall policy', 'blocked_by_redactwall', verdict.reasons));
      }
      if (verdict.decision === 'redact') {
        // Tokenize every role locally so no raw PII in any message reaches upstream.
        const redacted = redactBodyLocally(body);
        if (!redactionCoversVerdict(promptText, redacted, verdict)) {
          // Local redaction could not reproduce what the plane flagged (custom
          // detectors / EDM, or an unhandled shape). Never forward raw PII.
          metrics.blocked += 1;
          metrics.failClosed += 1;
          return res.status(403).json(openAiError('Prompt requires redaction the gateway could not fully apply; blocked', 'incomplete_redaction', verdict.reasons));
        }
        // Residual safety net: verify the OUTBOUND body carries no raw PII in
        // ANY field (e.g. a tool name we deliberately don't tokenize). If local
        // default analysis still finds something, fail closed rather than leak.
        if (detect.analyze(adapter.requestText(redacted.body)).findings.length) {
          metrics.blocked += 1;
          metrics.failClosed += 1;
          return res.status(403).json(openAiError('Prompt requires redaction the gateway could not fully apply; blocked', 'incomplete_redaction', verdict.reasons));
        }
        outboundBody = redacted.body;
        redactMap = redacted.tokenCount ? redacted.map : null;
        metrics.redacted += 1;
      } else {
        metrics.allowed += 1;
      }
    } else {
      metrics.allowed += 1;
    }

    // 2. Forward to upstream (force non-streaming upstream; we buffer + scan).
    const up = await adapter.callUpstream(kind, { ...outboundBody, stream: false }, cfg);
    if (!up.ok || !up.json) {
      metrics.upstreamErrors += 1;
      return res.status(502).json(openAiError('Upstream provider error', 'upstream_error', up && up.status ? ['upstream status ' + up.status] : []));
    }

    // 3. Scan the model output BEFORE it reaches the caller (fail-closed).
    let outJson = up.json;
    const respText = adapter.responseText(outJson);
    if (respText && respText.trim()) {
      const scan = await client.scanResponse({
        text: respText, user: identity.user, orgId: identity.orgId,
        destination: destinationLabel(), source: 'ai_gateway',
      });
      if (scan.blocked || scan.decision === 'block') {
        metrics.responseBlocked += 1;
        return res.status(403).json(openAiError('Model response blocked by RedactWall policy', 'response_blocked_by_redactwall', scan.reasons));
      }
      if (scan.decision === 'redact') {
        // Redact the FULL output locally, per choice — NOT the control plane's
        // `redacted` field, which is a 600-char audit preview (truncates long
        // answers) applied only to choices[0] (leaves n>1 choices raw). Withhold
        // the whole response if the plane flagged a semantic category or
        // detectors the gateway cannot reproduce locally.
        if (!responseRedactionCovers(respText, scan)) {
          metrics.responseBlocked += 1;
          return res.status(403).json(openAiError('Model response withheld by RedactWall policy', 'response_blocked_by_redactwall', scan.reasons));
        }
        outJson = canonical.mapResponseText(outJson, (t) => detect.redact(t, detect.analyze(t).findings));
        metrics.responseRedacted += 1;
      }
    }

    // 4. If the request was tokenized, rehydrate the (scanned) response locally,
    // in every choice — the token map never left the gateway.
    if (redactMap) {
      outJson = canonical.mapResponseText(outJson, (t) => detect.detokenize(t, redactMap));
    }

    if (wantsStream) return streamJson(res, outJson, kind);
    return res.json(outJson);
  }

  // Emit a buffered, already-scanned result as OpenAI SSE chunks so streaming
  // clients work while preserving "nothing reaches the caller until scanned".
  function streamJson(res, json, kind) {
    res.setHeader('content-type', 'text/event-stream');
    res.setHeader('cache-control', 'no-cache');
    res.setHeader('connection', 'keep-alive');
    const choice = (json.choices && json.choices[0]) || {};
    const content = (choice.message && choice.message.content) || choice.text || '';
    const model = json.model || 'redactwall-gateway';
    const base = { id: json.id || 'gw', object: kind === 'completions' ? 'text_completion' : 'chat.completion.chunk', model };
    const delta = kind === 'completions' ? { text: content } : { choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }] };
    const stop = kind === 'completions' ? { index: 0, text: '', finish_reason: 'stop' } : { index: 0, delta: {}, finish_reason: 'stop' };
    res.write('data: ' + JSON.stringify({ ...base, ...(kind === 'completions' ? { choices: [{ index: 0, text: content, finish_reason: null }] } : delta) }) + '\n\n');
    res.write('data: ' + JSON.stringify({ ...base, choices: [stop] }) + '\n\n');
    res.write('data: [DONE]\n\n');
    res.end();
  }

  app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'redactwall-gateway', provider: cfg.provider }));
  // Readiness probe WITHOUT creating control-plane records. A real gate() call
  // logs an 'allowed' query, audit entry, receipt and SSE broadcast on every
  // k8s/LB probe (and, being unauthenticated, is a write-amplification vector).
  // Prefer a non-persisting health check; fall back to gate() only for injected
  // test clients that predate health().
  async function probeReady() {
    if (typeof client.health === 'function') {
      const h = await client.health();
      return !!(h && h.ok);
    }
    const verdict = await client.gate({ prompt: 'redactwall gateway readiness probe', user: 'gateway@readyz', destination: destinationLabel(), source: 'ai_gateway', channel: 'readyz' });
    return !verdict._failClosed;
  }
  app.get('/readyz', async (req, res) => {
    const ready = await probeReady();
    res.status(ready ? 200 : 503).json({ ready, controlPlane: ready });
  });
  app.get('/metrics', (req, res) => res.json({ uptimeSec: Math.round(process.uptime()), provider: cfg.provider, ...metrics }));

  app.post('/v1/chat/completions', authenticate, (req, res) => handle('chat', req, res).catch((e) => res.status(500).json(openAiError('gateway error', 'gateway_error', [String(e && e.message || e)]))));
  app.post('/v1/completions', authenticate, (req, res) => handle('completions', req, res).catch((e) => res.status(500).json(openAiError('gateway error', 'gateway_error', [String(e && e.message || e)]))));
  app.post('/v1/embeddings', authenticate, (req, res) => handle('embeddings', req, res).catch((e) => res.status(500).json(openAiError('gateway error', 'gateway_error', [String(e && e.message || e)]))));

  app.locals.metrics = metrics;
  return { app, cfg, metrics };
}

function startGateway(overrides = {}) {
  const { app, cfg } = createGateway(overrides);
  const server = app.listen(cfg.port, () => {
    // eslint-disable-next-line no-console
    console.log(`RedactWall AI Gateway on :${cfg.port} → provider=${cfg.provider} control-plane=${cfg.controlPlaneUrl}`);
  });
  return server;
}

if (require.main === module) startGateway();

module.exports = { createGateway, startGateway, redactBodyLocally };
