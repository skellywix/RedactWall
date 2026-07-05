'use strict';
/**
 * Anthropic Messages API upstream adapter.
 *
 * Demonstrates the provider-translation seam: the gateway speaks OpenAI on the
 * front, this adapter maps to/from Anthropic's /v1/messages shape so one policy
 * governs an Anthropic upstream too. Text extraction reuses the canonical
 * OpenAI-side helpers (the gateway still receives OpenAI-shaped requests).
 */
const canonical = require('../canonical');

function toAnthropic(body) {
  const messages = Array.isArray(body.messages) ? body.messages : [];
  const system = messages.filter((m) => m && m.role === 'system').map(canonical.messageText).join('\n') || undefined;
  const turns = messages.filter((m) => m && (m.role === 'user' || m.role === 'assistant'))
    .map((m) => ({ role: m.role, content: canonical.messageText(m) }));
  return {
    model: body.model || 'claude-sonnet-4',
    system,
    messages: turns.length ? turns : [{ role: 'user', content: canonical.requestText(body) }],
    max_tokens: body.max_tokens || 1024,
  };
}

// Map an Anthropic response back into an OpenAI-shaped response for the caller.
function fromAnthropic(json) {
  const text = json && Array.isArray(json.content)
    ? json.content.map((p) => (p && typeof p.text === 'string' ? p.text : '')).join('')
    : '';
  return {
    id: (json && json.id) || 'gw-anthropic',
    object: 'chat.completion',
    model: (json && json.model) || 'anthropic',
    choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: (json && json.stop_reason) || 'stop' }],
  };
}

async function callUpstream(kind, body, ctx) {
  const base = String(ctx.upstreamBaseUrl || 'https://api.anthropic.com').replace(/\/+$/, '');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ctx.requestTimeoutMs);
  try {
    const res = await fetch(base + '/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': ctx.upstreamApiKey || '',
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(toAnthropic(body)),
      signal: controller.signal,
    });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch (e) { json = null; }
    return { ok: res.ok, status: res.status, json: json ? fromAnthropic(json) : null, rawText: text };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  name: 'anthropic',
  requestText: canonical.requestText,
  applyRedactedRequest: canonical.applyRedactedRequest,
  responseText: canonical.responseText,
  applyResponseText: canonical.applyResponseText,
  callUpstream,
  toAnthropic,
  fromAnthropic,
};
