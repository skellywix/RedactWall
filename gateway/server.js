'use strict';
/**
 * PromptWall AI Gateway — an OpenAI-compatible reverse proxy that gates every
 * prompt and scans every response through the PromptWall control plane before
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
  const out = { ...body };
  if (Array.isArray(body.messages)) {
    out.messages = body.messages.map((m) => (m && typeof m.content === 'string' ? { ...m, content: tok(m.content) } : m));
  } else if (typeof body.prompt === 'string') { out.prompt = tok(body.prompt); }
  else if (typeof body.input === 'string') { out.input = tok(body.input); }
  return { body: out, map, tokenCount: Object.keys(map).length };
}

const BLOCK_STATUSES = new Set([
  'control_plane_unavailable', 'destination_blocked', 'injection_blocked',
  'file_blocked_unscanned', 'file_upload_blocked', 'pending', 'pending_justification',
]);

function openAiError(message, type, reasons) {
  return { error: { message, type: type || 'promptwall_block', code: type || 'promptwall_block', reasons: reasons || [] } };
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
    if (!b || now >= b.resetAt) { buckets.set(id, { count: 1, resetAt: now + 60000 }); return false; }
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
        return res.status(403).json(openAiError('Prompt blocked by PromptWall policy', 'blocked_by_promptwall', verdict.reasons));
      }
      if (verdict.decision === 'redact') {
        // Tokenize every role locally so no raw PII in any message reaches upstream.
        const redacted = redactBodyLocally(body);
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
    let respText = adapter.responseText(outJson);
    if (respText && respText.trim()) {
      const scan = await client.scanResponse({
        text: respText, user: identity.user, orgId: identity.orgId,
        destination: destinationLabel(), source: 'ai_gateway',
      });
      if (scan.blocked) {
        metrics.responseBlocked += 1;
        return res.status(403).json(openAiError('Model response blocked by PromptWall policy', 'response_blocked_by_promptwall', scan.reasons));
      }
      if (scan.decision === 'redact' && typeof scan.redacted === 'string') {
        outJson = adapter.applyResponseText(outJson, scan.redacted);
        respText = scan.redacted;
        metrics.responseRedacted += 1;
      }
    }

    // 4. If the request was tokenized, rehydrate the (scanned) response locally —
    // the token map never left the gateway.
    if (redactMap) {
      const rehydrated = detect.detokenize(respText, redactMap);
      if (rehydrated !== respText) outJson = adapter.applyResponseText(outJson, rehydrated);
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
    const model = json.model || 'promptwall-gateway';
    const base = { id: json.id || 'gw', object: kind === 'completions' ? 'text_completion' : 'chat.completion.chunk', model };
    const delta = kind === 'completions' ? { text: content } : { choices: [{ index: 0, delta: { role: 'assistant', content }, finish_reason: null }] };
    res.write('data: ' + JSON.stringify({ ...base, ...(kind === 'completions' ? { choices: [{ index: 0, text: content, finish_reason: null }] } : delta) }) + '\n\n');
    res.write('data: ' + JSON.stringify({ ...base, choices: [{ index: 0, delta: {}, finish_reason: 'stop' }] }) + '\n\n');
    res.write('data: [DONE]\n\n');
    res.end();
  }

  app.get('/healthz', (req, res) => res.json({ status: 'ok', service: 'promptwall-gateway', provider: cfg.provider }));
  app.get('/readyz', async (req, res) => {
    const verdict = await client.gate({ prompt: 'promptwall gateway readiness probe', user: 'gateway@readyz', destination: destinationLabel(), source: 'ai_gateway', channel: 'readyz' });
    const ready = !verdict._failClosed;
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
    console.log(`PromptWall AI Gateway on :${cfg.port} → provider=${cfg.provider} control-plane=${cfg.controlPlaneUrl}`);
  });
  return server;
}

if (require.main === module) startGateway();

module.exports = { createGateway, startGateway };
