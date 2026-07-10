'use strict';

// Reversible text encodings and token/byte arrays are opaque to ordinary text
// extraction. The browser-safe shared detector owns strict bounded decoding;
// this helper applies its encoded-only result recursively to JSON envelopes.
const MAX_DEPTH = 64;
const MAX_NODES = 10000;
const MAX_ENCODED_CHARS = 64 * 1024;
const MIN_BASE64_CHARS = 12;
const ENCODED_TOKEN = /[A-Za-z0-9+/_-]{12,}={0,2}|[0-9A-Fa-f]{16,}/g;
const CONTENT_ARRAY_KEY = /^(?:content|prompt|input|input_?text|output|output_?text|text|completion|body|payload|bytes?|tokens?|token_?ids?|input_?ids?|output_?ids?)$/i;
const STRUCTURAL_METADATA_KEY = /(?:^|_)(?:id|ids|identifier|identifiers)$|(?:id|ids)$/i;
const STRUCTURAL_METADATA_NAME = /^(?:metadata|provider_?metadata|model|role|type|name|status|state|object|index|created(?:_?at)?|updated(?:_?at)?|timestamp|finish_?reason|stop_?reason|system_?fingerprint|usage|logprobs?|headers?|url|uri|mime(?:_?type)?|source|destination|provider|channel|version)$/i;
const NUMERIC_METADATA_NAME = /^(?:embedding|embeddings|metrics|rows|records|coordinates|dimensions|counts?|totals?|scores?|probabilities|logprobs?|usage)$/i;
const TEXT_PART_KEY = /^(?:text|input_?text|output_?text|completion)$/i;
const ENCODED_FRAGMENT = /^[A-Za-z0-9+/_=-]+$/;

function encodedTokens(value) {
  const text = String(value || '').trim();
  if (!text) return [];
  const tokens = text.match(ENCODED_TOKEN) || [];
  // Base64 is often line-wrapped. Only compact an otherwise Base64-shaped
  // value; decoded bytes still must be printable and detector-positive.
  if (/\s/.test(text) && /^[A-Za-z0-9+/_=\s-]+$/.test(text)) {
    const compact = text.replace(/\s+/g, '');
    if (compact.length >= MIN_BASE64_CHARS) tokens.push(compact);
  }
  return [...new Set(tokens)];
}

function analysisHasEncodedSensitivity(analysis) {
  return !!(analysis && (
    analysis.opaqueEncoded === true
    || (Array.isArray(analysis.findings) && analysis.findings.some((finding) => !!finding.encoded))
  ));
}

function encodedStringIsSensitive(value, analyze, contentContext, depth, progress) {
  const tokens = encodedTokens(value);
  if (tokens.some((token) => token.length > MAX_ENCODED_CHARS)) return true;
  try {
    if (analysisHasEncodedSensitivity(analyze(value, { opaqueEncodedContent: contentContext === true }))) return true;
  } catch {
    return true;
  }
  const text = value.trim();
  if ((text.startsWith('{') || text.startsWith('[')) && text.length <= MAX_ENCODED_CHARS) {
    try {
      return carriesEncodedSensitiveTextAt(JSON.parse(text), analyze, false, depth + 1, progress);
    } catch {
      return false;
    }
  }
  return false;
}

function adjacentEncodedTextIsSensitive(value, analyze, depth, progress, arrayContentContext) {
  let fragments = [];
  const flush = () => {
    if (fragments.length < 2) { fragments = []; return false; }
    const compact = fragments.map((item) => item.trim());
    fragments = [];
    if (compact.some((item) => !item || !ENCODED_FRAGMENT.test(item))) return false;
    const total = compact.reduce((sum, item) => sum + item.length, 0);
    if (total > MAX_ENCODED_CHARS) return true;
    if (total < MIN_BASE64_CHARS) return false;
    progress.nodes += 1;
    if (progress.nodes > MAX_NODES) return true;
    return encodedStringIsSensitive(compact.join(''), analyze, true, depth + 1, progress);
  };
  for (const item of value) {
    let text = null;
    if (arrayContentContext && typeof item === 'string') text = item;
    else if (item && typeof item === 'object' && !Array.isArray(item)) {
      const key = Object.keys(item).find((name) => TEXT_PART_KEY.test(name) && typeof item[name] === 'string');
      if (key) text = item[key];
    }
    if (text === null) {
      if (flush()) return true;
    } else {
      fragments.push(text);
    }
  }
  return flush();
}

function carriesEncodedSensitiveTextAt(value, analyze, contentContext, depth, progress) {
  progress.nodes += 1;
  if (depth > MAX_DEPTH || progress.nodes > MAX_NODES) return true;
  if (typeof value === 'string') return encodedStringIsSensitive(value, analyze, contentContext, depth, progress);
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) {
    if (adjacentEncodedTextIsSensitive(value, analyze, depth, progress, contentContext)) return true;
    return value.some((item) => carriesEncodedSensitiveTextAt(item, analyze, contentContext, depth + 1, progress));
  }
  for (const key of Object.keys(value)) {
    if (carriesEncodedSensitiveTextAt(key, analyze, false, depth + 1, progress)) return true;
    // Provider schemas grow new fields. Unknown values cross the same trust
    // boundary as known content and therefore default to content context;
    // bounded structural metadata and opaque identifiers remain exempt so
    // request ids and model labels do not become binary false positives.
    const childContext = childCarriesContent(contentContext, key);
    if (carriesEncodedSensitiveTextAt(value[key], analyze, childContext, depth + 1, progress)) return true;
  }
  return false;
}

function childCarriesContent(parentContext, key, numeric = false) {
  if (numeric && NUMERIC_METADATA_NAME.test(key)) return false;
  if (STRUCTURAL_METADATA_KEY.test(key) || STRUCTURAL_METADATA_NAME.test(key)) return false;
  return true;
}

function carriesEncodedSensitiveText(value, analyze) {
  const rootContent = typeof value === 'string' || Array.isArray(value);
  return carriesEncodedSensitiveTextAt(value, analyze, rootContent, 0, { nodes: 0 });
}

function numericTokenArray(value) {
  return Array.isArray(value) && value.length > 0
    && value.every((item) => Number.isSafeInteger(item) && item >= 0);
}

// Only arrays occupying a content-bearing field are opaque. Numeric database
// rows, counters, coordinates, and embedding vectors remain ordinary structured
// data unless a provider places them in an explicit content/token/byte field.
function carriesNumericContentAt(value, contentContext, depth = 0) {
  if (depth > MAX_DEPTH) return true;
  if (numericTokenArray(value) && contentContext) return true;
  if (typeof value === 'string') {
    const text = value.trim();
    if ((text.startsWith('{') || text.startsWith('[')) && text.length <= MAX_ENCODED_CHARS) {
      try {
        return carriesNumericContentAt(JSON.parse(text), contentContext, depth + 1);
      } catch {
        return false;
      }
    }
    return false;
  }
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) {
    return value.some((item) => carriesNumericContentAt(item, contentContext, depth + 1));
  }
  for (const childKey of Object.keys(value)) {
    const childContext = childCarriesContent(contentContext, childKey, true);
    if (carriesNumericContentAt(value[childKey], childContext, depth + 1)) return true;
  }
  return false;
}

function carriesNumericContent(value, options = {}) {
  // `rootIsContent` applies only when the returned value itself is a numeric
  // array. A structured response object is an envelope, not a declaration that
  // every numeric record nested anywhere inside it is model content.
  if (options.rootIsContent === true && typeof value === 'string') {
    const text = value.trim();
    if ((text.startsWith('{') || text.startsWith('[')) && text.length <= MAX_ENCODED_CHARS) {
      try {
        const parsed = JSON.parse(text);
        return carriesNumericContentAt(parsed, Array.isArray(parsed));
      } catch { /* ordinary text */ }
    }
  }
  const rootContext = options.rootIsContent === true && Array.isArray(value);
  return carriesNumericContentAt(value, rootContext);
}

module.exports = {
  carriesEncodedSensitiveText,
  carriesNumericContent,
};
