'use strict';
/**
 * Reference ICAP-side bridge (sketch).
 *
 * In production, a c-icap service module receives each REQMOD request from
 * Squid, extracts the user's prompt from the HTTP body, and calls PromptSentinel.
 * This file shows the HTTP call the ICAP module makes, and how it enforces the
 * verdict inline (hold the request until released).
 *
 * It is intentionally transport-agnostic so it can be wired into c-icap (C),
 * a Node ICAP shim, or an explicit-proxy plugin.
 */
const SENTINEL = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';

/** Extract the user prompt from a captured request body for known AI endpoints. */
function extractPrompt(host, contentType, body) {
  try {
    if (contentType && contentType.includes('application/json')) {
      const j = JSON.parse(body);
      // OpenAI / Anthropic style chat payloads
      if (Array.isArray(j.messages)) {
        return j.messages.filter(m => m.role === 'user').map(m =>
          typeof m.content === 'string' ? m.content
            : Array.isArray(m.content) ? m.content.map(c => c.text || '').join(' ') : ''
        ).join('\n');
      }
      if (typeof j.prompt === 'string') return j.prompt;
      if (typeof j.input === 'string') return j.input;
    }
  } catch { /* fall through */ }
  // Web-UI form posts vary; fall back to raw body text.
  return body;
}

async function gate({ host, user, sourceIp, contentType, body }) {
  const prompt = extractPrompt(host, contentType, body);
  const r = await fetch(SENTINEL + '/api/v1/gate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify({ prompt, user, destination: host, sourceIp }),
  });
  return r.json(); // { id, decision, status, ... }
}

/** Block inline: poll until the admin releases, or time out (deny by default). */
async function awaitRelease(id, { timeoutMs = 5 * 60 * 1000, intervalMs = 2000 } = {}) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = await fetch(`${SENTINEL}/api/v1/status/${id}`, { headers: { 'x-api-key': KEY } });
    const s = await r.json();
    if (s.status === 'approved' || s.status === 'allowed') return { released: true };
    if (s.status === 'denied') return { released: false, reason: 'denied' };
    await new Promise((res) => setTimeout(res, intervalMs));
  }
  return { released: false, reason: 'timeout' };
}

/**
 * ICAP REQMOD handler outline:
 *   const verdict = await gate({...});
 *   if (verdict.decision === 'allow') return ICAP_ALLOW;       // forward unchanged
 *   const rel = await awaitRelease(verdict.id);                // hold the request
 *   return rel.released ? ICAP_ALLOW : ICAP_BLOCK_403;         // release or block
 */
module.exports = { extractPrompt, gate, awaitRelease };
