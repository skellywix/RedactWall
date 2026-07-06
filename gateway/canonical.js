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
  const parts = [];
  if (typeof m.content === 'string') parts.push(m.content);
  else if (Array.isArray(m.content)) {
    for (const part of m.content) if (part && typeof part.text === 'string') parts.push(part.text);
  }
  // Tool/function-call arguments are user-influenced JSON strings that can carry
  // PII; they must be scanned (and tokenized) too, not forwarded raw upstream.
  if (Array.isArray(m.tool_calls)) {
    for (const tc of m.tool_calls) {
      const args = tc && tc.function && tc.function.arguments;
      if (typeof args === 'string' && args) parts.push(args);
    }
  }
  if (m.function_call && typeof m.function_call.arguments === 'string') parts.push(m.function_call.arguments);
  return parts.filter(Boolean).join('\n');
}

// True when a request carries content the gateway cannot scan — image/binary
// content parts, or prompt/input arrays holding non-strings (e.g. token-id
// arrays) — even when other parts DO carry scannable text. The gateway must fail
// closed rather than forward any such content ungated.
function carriesUnscannableContent(body) {
  if (!body || typeof body !== 'object') return false;
  if (Array.isArray(body.messages)) {
    return body.messages.some((m) => {
      if (!m || m.role === 'system' || m.role === 'assistant') return false;
      if (typeof m.content === 'string') return false;
      // A content array is unscannable when ANY part lacks a scannable text
      // field (an image/file part alongside text still leaks the image).
      if (Array.isArray(m.content)) return m.content.some((p) => !(p && typeof p.text === 'string'));
      return m.content != null;
    });
  }
  // Legacy prompt/input arrays: strings are scannable (requestText joins them),
  // but token-id arrays or other non-strings decode to content the gateway never
  // saw — treat those as unscannable.
  for (const key of ['prompt', 'input']) {
    const v = body[key];
    if (Array.isArray(v) && v.length && v.some((p) => typeof p !== 'string')) return true;
  }
  return false;
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

// Apply a per-choice text transform to EVERY choice's output. Redaction and
// detokenization must touch every choice: with n>1 the control plane scans the
// join of all choices, so rewriting only the first (applyResponseText) would
// leave choices[1..] carrying raw PII returned to the caller.
function mapResponseText(json, fn) {
  if (!json || !Array.isArray(json.choices)) return json;
  return {
    ...json,
    choices: json.choices.map((c) => {
      if (c && c.message && typeof c.message.content === 'string') return { ...c, message: { ...c.message, content: fn(c.message.content) } };
      if (c && typeof c.text === 'string') return { ...c, text: fn(c.text) };
      return c;
    }),
  };
}

module.exports = { requestText, messageText, carriesUnscannableContent, applyRedactedRequest, responseText, applyResponseText, mapResponseText };
