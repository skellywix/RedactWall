'use strict';
/**
 * Mock upstream adapter — no network.
 *
 * Returns a deterministic OpenAI-shaped completion whose content echoes the last
 * user text (optionally prefixed with `ECHO:`). Used for local/CI verification of
 * the gateway's request- and response-scanning paths without a real LLM: a test
 * can seed sensitive data into the "model output" by putting it in the prompt.
 */
const canonical = require('../canonical');

async function callUpstream(kind, body, _ctx) {
  const text = canonical.requestText(body);
  if (kind === 'embeddings') {
    return { ok: true, status: 200, json: { object: 'list', data: [{ object: 'embedding', index: 0, embedding: [0, 0, 0] }], model: body.model || 'mock' } };
  }
  const content = 'ECHO: ' + text;
  const json = kind === 'completions'
    ? { id: 'gw-mock', object: 'text_completion', model: body.model || 'mock', choices: [{ index: 0, text: content, finish_reason: 'stop' }] }
    : { id: 'gw-mock', object: 'chat.completion', model: body.model || 'mock', choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }] };
  return { ok: true, status: 200, json, rawText: JSON.stringify(json) };
}

module.exports = {
  name: 'mock',
  requestText: canonical.requestText,
  applyRedactedRequest: canonical.applyRedactedRequest,
  responseText: canonical.responseText,
  applyResponseText: canonical.applyResponseText,
  callUpstream,
};
