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
const { validateProviderConfig, validateProviderCredentials } = require('./providers');
const { requestBodyDeadline, requestBodyDeadlineExpired } = require('../server/request-body-deadline');
const tokens = require('./tokens');
const canonical = require('./canonical');
const { classifyRequestVerdict, classifyResponseVerdict } = require('./verdict');

function tokenizingMapper() {
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
  function tokenizeText(text) {
    if (typeof text !== 'string' || !text) return text;
    const findings = detect.analyze(text).findings;
    if (!findings.length) return text;
    let out = text;
    for (const f of findings.slice().sort((a, b) => b.start - a.start)) {
      out = out.slice(0, f.start) + tokenFor(f.type, f.value) + out.slice(f.end);
    }
    return out;
  }
  return { tokenizeText, map };
}

// Tokenize every string that will cross the gateway boundary, including
// provider-specific and future metadata fields. A field the gateway does not
// know about therefore cannot bypass the same scan/redact rule as messages.
function redactBodyLocally(body) {
  const mapper = tokenizingMapper();
  const redacted = canonical.mapStrings(body, mapper.tokenizeText);
  return { body: redacted, map: mapper.map, tokenCount: Object.keys(mapper.map).length };
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
  const localAnalysis = detect.analyze(promptText);
  // Semantic categories describe whole-chunk sensitivity. The local mapper can
  // replace only structured finding spans, so forwarding a category-only (or
  // mixed) redact verdict would leave the confidential prose unchanged.
  if ((Array.isArray(verdict.categories) && verdict.categories.length)
      || (localAnalysis.categories || []).length) return false;
  if (redacted.tokenCount === 0) return false;
  // Older/injected control planes may omit finding metadata. Local structured
  // findings still make the transformation provably useful, but a no-op never
  // satisfies a redact verdict.
  if (!reported.size) return localAnalysis.findings.length > 0;
  return localReproducesTypes(promptText, reported);
}

// The gateway redacts a leaked response locally (full length, per choice). That
// is only safe when local default detection reproduces everything the control
// plane flagged. A semantic category or custom/EDM detector the gateway can't
// see means local redaction would leave raw values in the body — withhold it.
function responseRedactionCovers(respText, scan) {
  if (Array.isArray(scan.categories) && scan.categories.length) return false;
  if ((detect.analyze(respText).categories || []).length) return false;
  return localReproducesTypes(respText, findingTypeCounts(scan.findings));
}

function hasLocalSensitivity(text) {
  const analysis = detect.analyze(text);
  return analysis.findings.length > 0 || (analysis.categories || []).length > 0;
}

function carriesOpaqueSensitiveContent(value) {
  return canonical.carriesNumericContent(value, { rootIsContent: true })
    || canonical.carriesEncodedSensitiveText(value, (text, options) => detect.analyze(text, options));
}

function openAiError(message, type, reasons) {
  return { error: { message, type: type || 'redactwall_block', code: type || 'redactwall_block', reasons: reasons || [] } };
}

function createGateway(overrides = {}) {
  const cfg = { ...config(), ...overrides };
  cfg.provider = validateProviderConfig(cfg.provider, cfg.upstreamBaseUrl, {
    production: String(process.env.NODE_ENV || '').toLowerCase() === 'production',
  });
  if (!overrides.adapter) validateProviderCredentials(cfg.provider, cfg.upstreamApiKey);
  // Client/adapter are injectable for deterministic tests (no network).
  const client = overrides.client || makeClient(cfg);
  const adapter = overrides.adapter || getAdapter(cfg.provider);
  const app = express();
  app.disable('x-powered-by');
  app.use(requestBodyDeadline({
    timeoutMs: () => cfg.requestBodyTimeoutMs,
    fallbackMs: 15000,
    onTimeout: (_req, res) => res.status(408)
      .json(openAiError('Request body deadline exceeded', 'request_timeout')),
  }));
  app.use((req, _res, next) => {
    req.redactwallJsonBytes = 0;
    next();
  });
  app.use(express.json({
    limit: cfg.maxBodyBytes,
    verify(req, _res, buffer) {
      req.redactwallJsonBytes = buffer.length;
    },
  }));
  app.use((error, req, res, next) => {
    if (requestBodyDeadlineExpired(req)) return undefined;
    if (!error) return next();
    if (error.type === 'entity.parse.failed' || error.type === 'entity.too.large') {
      return res.status(error.type === 'entity.too.large' ? 413 : 400)
        .json(openAiError('Request body must be a bounded JSON object', 'invalid_request'));
    }
    return next(error);
  });

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
    const body = req.body;
    if (!req.redactwallJsonBytes || !body || typeof body !== 'object' || Array.isArray(body)
        || (Object.getPrototypeOf(body) !== Object.prototype && Object.getPrototypeOf(body) !== null)) {
      metrics.blocked += 1;
      metrics.failClosed += 1;
      return res.status(400).json(openAiError('Request body must be a JSON object', 'invalid_request'));
    }
    try {
      if (typeof adapter.validateRequest === 'function') adapter.validateRequest(kind, body);
    } catch {
      metrics.blocked += 1;
      metrics.failClosed += 1;
      return res.status(400).json(openAiError('Request shape is not supported by the configured provider', 'invalid_request'));
    }
    const wantsStream = body.stream === true && kind !== 'embeddings';
    const promptText = canonical.forwardedRequestText(body);

    // Fail closed on ANY content the gateway cannot scan (image/binary parts,
    // token-id arrays) — even when other parts carry scannable text, so a PII
    // image alongside a caption is never forwarded ungated.
    if (canonical.carriesExplicitBinary(body)
        || canonical.carriesUnscannableContent(body)
        || carriesOpaqueSensitiveContent(body)) {
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
      const requestAction = classifyRequestVerdict(verdict);
      if (requestAction === 'invalid') {
        metrics.blocked += 1;
        metrics.failClosed += 1;
        return res.status(403).json(openAiError('Prompt blocked because RedactWall returned an invalid verdict', 'blocked_by_redactwall'));
      }
      if (verdict._failClosed) metrics.failClosed += 1;
      if (requestAction === 'block') {
        metrics.blocked += 1;
        return res.status(403).json(openAiError('Prompt blocked by RedactWall policy', 'blocked_by_redactwall', verdict.reasons));
      }
      if (requestAction === 'redact') {
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
        if (hasLocalSensitivity(canonical.deepText(redacted.body))) {
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
    if (canonical.carriesExplicitBinary(outJson) || carriesOpaqueSensitiveContent(outJson)) {
      metrics.responseBlocked += 1;
      metrics.failClosed += 1;
      return res.status(403).json(openAiError('Model response blocked by RedactWall policy', 'response_blocked_by_redactwall'));
    }
    const respText = canonical.deepText(outJson);
    if (respText && respText.trim()) {
      const scan = await client.scanResponse({
        text: respText, user: identity.user, orgId: identity.orgId,
        destination: destinationLabel(), source: 'ai_gateway',
      });
      const responseAction = classifyResponseVerdict(scan);
      if (responseAction === 'invalid') {
        metrics.responseBlocked += 1;
        metrics.failClosed += 1;
        return res.status(403).json(openAiError('Model response withheld because RedactWall returned an invalid verdict', 'response_blocked_by_redactwall'));
      }
      if (responseAction === 'block') {
        metrics.responseBlocked += 1;
        return res.status(403).json(openAiError('Model response blocked by RedactWall policy', 'response_blocked_by_redactwall', scan.reasons));
      }
      if (responseAction === 'redact') {
        // Redact the FULL output locally, per choice — NOT the control plane's
        // `redacted` field, which is a 600-char audit preview (truncates long
        // answers) applied only to choices[0] (leaves n>1 choices raw). Withhold
        // the whole response if the plane flagged a semantic category or
        // detectors the gateway cannot reproduce locally.
        if (!responseRedactionCovers(respText, scan)) {
          metrics.responseBlocked += 1;
          return res.status(403).json(openAiError('Model response withheld by RedactWall policy', 'response_blocked_by_redactwall', scan.reasons));
        }
        outJson = canonical.mapStrings(outJson, (t) => detect.redact(t, detect.analyze(t).findings));
        if (hasLocalSensitivity(canonical.deepText(outJson))) {
          metrics.responseBlocked += 1;
          return res.status(403).json(openAiError('Model response withheld by RedactWall policy', 'response_blocked_by_redactwall', scan.reasons));
        }
        metrics.responseRedacted += 1;
      }
    }

    // 4. If the request was tokenized, rehydrate the (scanned) response locally,
    // in content-bearing response fields only. Provider ids and metadata are
    // never rehydration targets because they may contain attacker-controlled
    // token strings. Scan the complete rehydrated envelope once more before it
    // reaches the caller because the first scan saw opaque tokens, not values.
    if (redactMap) {
      outJson = canonical.mapResponseText(outJson, (t) => detect.detokenize(t, redactMap));
      if (canonical.carriesExplicitBinary(outJson) || carriesOpaqueSensitiveContent(outJson)) {
        metrics.responseBlocked += 1;
        metrics.failClosed += 1;
        return res.status(403).json(openAiError('Model response blocked by RedactWall policy', 'response_blocked_by_redactwall'));
      }
      const finalText = canonical.deepText(outJson);
      const finalScan = await client.scanResponse({
        text: finalText, user: identity.user, orgId: identity.orgId,
        destination: destinationLabel(), source: 'ai_gateway',
      });
      const finalAction = classifyResponseVerdict(finalScan);
      if (finalAction === 'invalid') {
        metrics.responseBlocked += 1;
        metrics.failClosed += 1;
        return res.status(403).json(openAiError('Model response withheld because RedactWall returned an invalid verdict', 'response_blocked_by_redactwall'));
      }
      if (finalAction === 'block') {
        metrics.responseBlocked += 1;
        return res.status(403).json(openAiError('Model response blocked by RedactWall policy', 'response_blocked_by_redactwall', finalScan.reasons));
      }
      if (finalAction === 'redact') {
        if (!responseRedactionCovers(finalText, finalScan)) {
          metrics.responseBlocked += 1;
          return res.status(403).json(openAiError('Model response withheld by RedactWall policy', 'response_blocked_by_redactwall', finalScan.reasons));
        }
        outJson = canonical.mapResponseText(outJson, (t) => detect.redact(t, detect.analyze(t).findings));
        if (hasLocalSensitivity(canonical.deepText(outJson))) {
          metrics.responseBlocked += 1;
          return res.status(403).json(openAiError('Model response withheld by RedactWall policy', 'response_blocked_by_redactwall', finalScan.reasons));
        }
        metrics.responseRedacted += 1;
      }
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
    const choices = Array.isArray(json.choices) && json.choices.length ? json.choices : [{}];
    const model = json.model || 'redactwall-gateway';
    const base = {
      id: json.id || 'gw',
      object: kind === 'completions' ? 'text_completion' : 'chat.completion.chunk',
      model,
      ...(json.created != null ? { created: json.created } : {}),
      ...(json.system_fingerprint != null ? { system_fingerprint: json.system_fingerprint } : {}),
    };
    const contentChoices = choices.map((choice, choiceIndex) => {
      const index = choice.index ?? choiceIndex;
      if (kind === 'completions') {
        return {
          index,
          text: typeof choice.text === 'string' ? choice.text : '',
          finish_reason: null,
          ...(choice.logprobs != null ? { logprobs: choice.logprobs } : {}),
        };
      }
      const message = choice.message && typeof choice.message === 'object' ? choice.message : {};
      const delta = { role: message.role || 'assistant' };
      if (typeof message.content === 'string') delta.content = message.content;
      if (Array.isArray(message.tool_calls)) {
        delta.tool_calls = message.tool_calls.map((tool, toolIndex) => ({ index: tool.index ?? toolIndex, ...tool }));
      }
      if (message.function_call) delta.function_call = message.function_call;
      return {
        index,
        delta,
        finish_reason: null,
        ...(choice.logprobs != null ? { logprobs: choice.logprobs } : {}),
      };
    });
    const terminalChoices = choices.map((choice, choiceIndex) => ({
      index: choice.index ?? choiceIndex,
      ...(kind === 'completions' ? { text: '' } : { delta: {} }),
      finish_reason: choice.finish_reason || 'stop',
    }));
    res.write('data: ' + JSON.stringify({ ...base, choices: contentChoices }) + '\n\n');
    res.write('data: ' + JSON.stringify({ ...base, choices: terminalChoices, ...(json.usage ? { usage: json.usage } : {}) }) + '\n\n');
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
    const localStorage = typeof tokens.storageHealth === 'function'
      ? tokens.storageHealth()
      : { ok: true };
    if (!localStorage.ok) {
      return res.status(503).json({
        ready: false,
        controlPlane: false,
        durableStorage: false,
        error: 'gateway_token_storage_cleanup_degraded',
      });
    }
    const ready = await probeReady();
    return res.status(ready ? 200 : 503).json({ ready, controlPlane: ready });
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
  validateProviderCredentials(cfg.provider, cfg.upstreamApiKey);
  const server = app.listen(cfg.port, () => {
    // eslint-disable-next-line no-console
    console.log(`RedactWall AI Gateway on :${cfg.port} → provider=${cfg.provider} control-plane=${cfg.controlPlaneUrl}`);
  });
  return server;
}

if (require.main === module) startGateway();

module.exports = { createGateway, startGateway, redactBodyLocally };
