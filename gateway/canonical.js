'use strict';
const {
  carriesEncodedSensitiveText,
  carriesNumericContent,
} = require('../sensors/shared/opaque-content');
/**
 * Canonical request/response text helpers shared by gateway adapters.
 *
 * The gateway surface is OpenAI-compatible. These helpers extract the text the
 * control plane must scan from a request body, and re-insert redacted/tokenized
 * text, independent of which upstream provider ultimately serves the call.
 */

// Collect every string value and object property name in an arbitrarily nested
// value. Provider-specific metadata keys can be user-controlled just like their
// values, and both cross the same upstream trust boundary.
const MAX_TEXT_DEPTH = 64;
const UNSCANNABLE_PART_TYPE = /^(?:(?:input|output)_)?(?:image|audio|video|file|binary|blob|base64)(?:_(?:url|data))?$/i;
const UNSCANNABLE_PART_KEY = /^(?:image_?url|image|audio|video|file|file_?data|binary|blob|base64|b64_?json|content_?base64|bytes)$/i;
const EXPLICIT_BINARY_KEY = /^(?:base64|b64_?json|content_?base64|file_?data|bytes|blob|binary)$/i;
const MIME_PAYLOAD_KEY = /^(?:data|content|source|payload|body|value|bytes|blob|binary|base64|b64_?json|content_?base64|file_?data)$/i;
const BINARY_DATA_URL = /^data:[^,]*;base64,/i;
const NON_TEXT_MIME = /^(?:image|audio|video)\/|^application\/(?:octet-stream|pdf|zip|gzip)$/i;

function collectStrings(v, out, depth = 0) {
  if (depth > MAX_TEXT_DEPTH) throw new Error('text nesting exceeds gateway limit');
  if (typeof v === 'string') { if (v) out.push(v); return; }
  if (Array.isArray(v)) { for (const x of v) collectStrings(x, out, depth + 1); return; }
  if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) {
      if (k) out.push(k);
      collectStrings(v[k], out, depth + 1);
    }
  }
}

// Every string value in the JSON that will cross the gateway trust boundary.
// Provider APIs grow new optional fields frequently, so an allowlist extractor
// can silently miss user metadata or future content-bearing fields. Structural
// strings (model, role, ids) are harmless under normal input and scanning them
// gives unknown fields a fail-closed default.
function deepText(value) {
  const out = [];
  collectStrings(value, out);
  return out.join('\n');
}

function forwardedRequestText(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return '';
  // Even structural string fields such as model are forwarded verbatim and can
  // be attacker-controlled. Scan the complete JSON object. Boolean transport
  // fields such as stream naturally contribute no text.
  return deepText(body);
}

function mapStrings(value, fn, depth = 0) {
  if (depth > MAX_TEXT_DEPTH) throw new Error('text nesting exceeds gateway limit');
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value)) return value.map((item) => mapStrings(item, fn, depth + 1));
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const key of Object.keys(value)) {
    // Define data properties explicitly so a JSON key named "__proto__" stays
    // ordinary provider data instead of invoking Object.prototype's setter.
    Object.defineProperty(out, key, {
      value: mapStrings(value[key], fn, depth + 1),
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return out;
}

function explicitBinaryValue(value) {
  if (value == null || value === false || value === '') return false;
  return true;
}

// Find opaque bytes in any provider-specific request or response field. Text
// scanning cannot validate base64 or other binary encodings, so unknown JSON
// fields get the same fail-closed treatment as known multimodal content parts.
// Exact type matching deliberately excludes harmless tool types such as
// `file_search`; their ordinary definition metadata remains scannable text.
function carriesExplicitBinary(value, depth = 0) {
  if (depth > MAX_TEXT_DEPTH) return true;
  if (typeof value === 'string') return BINARY_DATA_URL.test(value.trim());
  if (!value || typeof value !== 'object') return false;
  if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) return true;
  if (typeof ArrayBuffer !== 'undefined'
    && (value instanceof ArrayBuffer || ArrayBuffer.isView(value))) return true;
  if (Array.isArray(value)) return value.some((item) => carriesExplicitBinary(item, depth + 1));

  if (typeof value.type === 'string' && UNSCANNABLE_PART_TYPE.test(value.type.trim())) return true;
  const mime = value.mimeType || value.mime_type || value.mime;
  if (typeof mime === 'string' && NON_TEXT_MIME.test(mime.trim())) {
    for (const key of Object.keys(value)) {
      if (MIME_PAYLOAD_KEY.test(key) && explicitBinaryValue(value[key])) return true;
    }
  }
  for (const key of Object.keys(value)) {
    if (EXPLICIT_BINARY_KEY.test(key) && explicitBinaryValue(value[key])) return true;
    if (carriesExplicitBinary(value[key], depth + 1)) return true;
  }
  return false;
}

function carriesPartOnlyData(value, depth = 0) {
  if (depth > MAX_TEXT_DEPTH) return true;
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some((item) => carriesPartOnlyData(item, depth + 1));
  const mime = value.mimeType || value.mime_type || value.mime;
  if (typeof mime === 'string' && NON_TEXT_MIME.test(mime.trim())) return true;
  for (const key of Object.keys(value)) {
    if (UNSCANNABLE_PART_KEY.test(key) && value[key] != null) return true;
    if (carriesPartOnlyData(value[key], depth + 1)) return true;
  }
  return false;
}

function carriesUnscannablePartData(value, depth = 0) {
  return carriesExplicitBinary(value, depth) || carriesPartOnlyData(value, depth);
}

function scannableTextPart(part) {
  return !!(part && typeof part === 'object' && !Array.isArray(part)
    && typeof part.text === 'string' && !carriesUnscannablePartData(part));
}

// Text carried by tool/function DEFINITIONS (name, description, parameters
// schema) and legacy `functions`. These are user-influenced and routinely
// templated from customer data, so they must be scanned like message content —
// not forwarded to the provider unread.
function toolDefsText(body) {
  const out = [];
  const pushFn = (fn) => {
    if (!fn || typeof fn !== 'object') return;
    if (typeof fn.name === 'string') out.push(fn.name);
    if (typeof fn.description === 'string') out.push(fn.description);
    if (fn.parameters != null) collectStrings(fn.parameters, out);
  };
  if (Array.isArray(body.tools)) for (const t of body.tools) pushFn(t && t.function);
  if (Array.isArray(body.functions)) for (const fn of body.functions) pushFn(fn);
  return out.filter(Boolean).join('\n');
}

// Pull the scannable text out of an OpenAI-style request body.
function requestText(body) {
  if (!body || typeof body !== 'object') return '';
  const parts = [];
  if (Array.isArray(body.messages)) parts.push(body.messages.map((m) => messageText(m)).filter(Boolean).join('\n'));
  else if (typeof body.prompt === 'string') parts.push(body.prompt);
  else if (Array.isArray(body.prompt)) parts.push(body.prompt.filter((p) => typeof p === 'string').join('\n'));
  else if (typeof body.input === 'string') parts.push(body.input);
  else if (Array.isArray(body.input)) parts.push(body.input.filter((p) => typeof p === 'string').join('\n'));
  const tools = toolDefsText(body);
  if (tools) parts.push(tools);
  return parts.filter(Boolean).join('\n');
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
// closed rather than forward any such content ungated. The check is symmetric
// across roles: an image/binary part in a system or assistant message is
// forwarded upstream just like one in a user message, so it must gate too.
function carriesUnscannableContent(body) {
  if (!body || typeof body !== 'object') return false;
  if (Array.isArray(body.messages)) {
    return body.messages.some((m) => {
      if (!m) return false;
      // Non-string tool-call / function-call arguments (e.g. an object) decode
      // to content the gateway never scanned — fail closed regardless of the
      // message's own content field.
      if (Array.isArray(m.tool_calls) && m.tool_calls.some((tc) => tc && tc.function && tc.function.arguments != null && typeof tc.function.arguments !== 'string')) return true;
      if (m.function_call && m.function_call.arguments != null && typeof m.function_call.arguments !== 'string') return true;
      if (typeof m.content === 'string') return false;
      // A content array is unscannable when ANY part lacks a scannable text
      // field (an image/file part alongside text still leaks the image).
      if (Array.isArray(m.content)) return m.content.some((p) => !scannableTextPart(p));
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

// Extract the model's output text from an OpenAI-style response. Includes the
// model-emitted tool_calls / function_call arguments — the model can return PII
// there just as it can in content, and it reaches the caller either way.
function responseText(json) {
  if (!json || typeof json !== 'object') return '';
  if (Array.isArray(json.choices)) {
    return json.choices.map((c) => {
      const parts = [];
      if (c && c.message) {
        if (typeof c.message.content === 'string') parts.push(c.message.content);
        if (Array.isArray(c.message.tool_calls)) {
          for (const tc of c.message.tool_calls) {
            const a = tc && tc.function && tc.function.arguments;
            if (typeof a === 'string' && a) parts.push(a);
          }
        }
        if (c.message.function_call && typeof c.message.function_call.arguments === 'string') parts.push(c.message.function_call.arguments);
      }
      if (c && typeof c.text === 'string') parts.push(c.text);
      return parts.filter(Boolean).join('\n');
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
      if (!c) return c;
      let next = c;
      if (c.message && typeof c.message.content === 'string') next = { ...next, message: { ...next.message, content: fn(c.message.content) } };
      if (c.message && Array.isArray(c.message.tool_calls)) {
        next = { ...next, message: { ...next.message, tool_calls: c.message.tool_calls.map((tc) => {
          const a = tc && tc.function && tc.function.arguments;
          return (typeof a === 'string') ? { ...tc, function: { ...tc.function, arguments: fn(a) } } : tc;
        }) } };
      }
      if (c.message && c.message.function_call && typeof c.message.function_call.arguments === 'string') {
        next = { ...next, message: { ...next.message, function_call: { ...c.message.function_call, arguments: fn(c.message.function_call.arguments) } } };
      }
      if (typeof c.text === 'string') next = { ...next, text: fn(c.text) };
      return next;
    }),
  };
}

module.exports = {
  requestText,
  messageText,
  deepText,
  forwardedRequestText,
  mapStrings,
  carriesExplicitBinary,
  carriesEncodedSensitiveText,
  carriesNumericContent,
  carriesUnscannableContent,
  applyRedactedRequest,
  responseText,
  applyResponseText,
  mapResponseText,
};
