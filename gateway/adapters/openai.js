'use strict';
/**
 * OpenAI-compatible upstream adapter.
 *
 * Forwards the (already gated/redacted) OpenAI-shaped body to an
 * OpenAI-compatible endpoint. Works for OpenAI and compatible internal
 * gateways. Azure OpenAI has a different path/query/auth contract and is not
 * advertised as this adapter.
 */
const canonical = require('../canonical');
const { normalizeGatewayUrl } = require('../config');
const { validateProviderConfig, validateProviderCredentials } = require('../providers');
const { readBoundedText } = require('../../sensors/shared/bounded-response');

function pathFor(kind) {
  if (kind === 'completions') return '/v1/completions';
  if (kind === 'embeddings') return '/v1/embeddings';
  return '/v1/chat/completions';
}

async function callUpstream(kind, body, ctx) {
  validateProviderConfig(ctx && ctx.provider, ctx && ctx.upstreamBaseUrl, {
    production: String(process.env.NODE_ENV || '').toLowerCase() === 'production',
  });
  validateProviderCredentials((ctx && ctx.provider) || 'openai', ctx && ctx.upstreamApiKey);
  const base = normalizeGatewayUrl(ctx.upstreamBaseUrl || 'https://api.openai.com', {
    label: 'gateway upstream URL',
    allowInsecureDev: ctx.allowInsecureHttp === true,
    production: String(process.env.NODE_ENV || '').toLowerCase() === 'production',
  });
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ctx.requestTimeoutMs);
  try {
    const res = await fetch(base + pathFor(kind), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(ctx.upstreamApiKey ? { authorization: 'Bearer ' + ctx.upstreamApiKey } : {}),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      redirect: 'error',
    });
    const { text } = await readBoundedText(res, {
      maxBytes: ctx.maxUpstreamResponseBytes,
      timeoutMs: ctx.requestTimeoutMs,
      label: 'gateway upstream response',
    });
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { json = null; }
    return { ok: res.ok, status: res.status, json, rawText: text };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  name: 'openai',
  requestText: canonical.requestText,
  applyRedactedRequest: canonical.applyRedactedRequest,
  responseText: canonical.responseText,
  applyResponseText: canonical.applyResponseText,
  callUpstream,
};
