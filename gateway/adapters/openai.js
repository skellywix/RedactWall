'use strict';
/**
 * OpenAI-compatible upstream adapter.
 *
 * Forwards the (already gated/redacted) OpenAI-shaped body to an
 * OpenAI-compatible endpoint. Works for OpenAI, Azure OpenAI (with base URL),
 * and any OpenAI-API-compatible internal gateway. Auth is a bearer key.
 */
const canonical = require('../canonical');

function pathFor(kind) {
  if (kind === 'completions') return '/v1/completions';
  if (kind === 'embeddings') return '/v1/embeddings';
  return '/v1/chat/completions';
}

async function callUpstream(kind, body, ctx) {
  const base = String(ctx.upstreamBaseUrl || 'https://api.openai.com').replace(/\/+$/, '');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ctx.requestTimeoutMs);
  try {
    const res = await fetch(base + pathFor(kind), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer ' + (ctx.upstreamApiKey || ''),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await res.text();
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
