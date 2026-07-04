'use strict';
/**
 * Canonical request/response text helpers shared by gateway adapters.
 *
 * The gateway surface is OpenAI-compatible. These helpers extract the text the
 * control plane must scan from a request body, and re-insert redacted/tokenized
 * text, independent of which upstream provider ultimately serves the call.
 */

// Pull the scannable text out of an OpenAI-style request body.
function requestText(body) {
  if (!body || typeof body !== 'object') return '';
  if (Array.isArray(body.messages)) {
    return body.messages.map((m) => messageText(m)).filter(Boolean).join('\n');
  }
  if (typeof body.prompt === 'string') return body.prompt;
  if (Array.isArray(body.prompt)) return body.prompt.filter((p) => typeof p === 'string').join('\n');
  if (typeof body.input === 'string') return body.input;
  if (Array.isArray(body.input)) return body.input.filter((p) => typeof p === 'string').join('\n');
  return '';
}

function messageText(m) {
  if (!m) return '';
  if (typeof m.content === 'string') return m.content;
  if (Array.isArray(m.content)) {
    return m.content.map((part) => (part && typeof part.text === 'string' ? part.text : '')).filter(Boolean).join('\n');
  }
  return '';
}

// Replace user-authored content with the tokenized text. System/assistant
// messages are preserved; the user turns are collapsed to one tokenized turn so
// no real PII leaves, while instructions the model needs are kept.
function applyRedactedRequest(body, tokenizedText) {
  const out = { ...body };
  if (Array.isArray(body.messages)) {
    const preserved = body.messages.filter((m) => m && m.role && m.role !== 'user');
    out.messages = preserved.concat([{ role: 'user', content: tokenizedText }]);
    return out;
  }
  if (body.prompt !== undefined) { out.prompt = tokenizedText; return out; }
  if (body.input !== undefined) { out.input = tokenizedText; return out; }
  out.messages = [{ role: 'user', content: tokenizedText }];
  return out;
}

// Extract the model's output text from an OpenAI-style response.
function responseText(json) {
  if (!json || typeof json !== 'object') return '';
  if (Array.isArray(json.choices)) {
    return json.choices.map((c) => {
      if (c && c.message && typeof c.message.content === 'string') return c.message.content;
      if (c && typeof c.text === 'string') return c.text;
      return '';
    }).filter(Boolean).join('\n');
  }
  if (Array.isArray(json.data)) return ''; // embeddings: no text to scan
  return '';
}

// Replace the model's output text (used for redacted/rehydrated responses).
function applyResponseText(json, newText) {
  if (!json || !Array.isArray(json.choices)) return json;
  const out = { ...json, choices: json.choices.map((c) => ({ ...c })) };
  let replaced = false;
  for (const c of out.choices) {
    if (!replaced && c.message && typeof c.message.content === 'string') { c.message = { ...c.message, content: newText }; replaced = true; }
    else if (!replaced && typeof c.text === 'string') { c.text = newText; replaced = true; }
  }
  return out;
}

module.exports = { requestText, messageText, applyRedactedRequest, responseText, applyResponseText };
