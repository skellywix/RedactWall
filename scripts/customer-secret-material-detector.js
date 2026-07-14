'use strict';

const crypto = require('node:crypto');
const path = require('node:path');

const CREDENTIAL_FILE_NAMES = new Set([
  '.env', '.my.cnf', '.netrc', '.npmrc', '.pgpass', '_netrc',
  'application_default_credentials.json', 'credentials', 'credentials.json',
  'id_dsa', 'id_ecdsa', 'id_ed25519', 'id_rsa', 'secring.gpg',
]);
const CREDENTIAL_FILE_EXTENSIONS = new Set([
  '.jks', '.key', '.keystore', '.p12', '.p8', '.pfx', '.pk8', '.pkcs12',
]);
const JWK_FIELDS = new Set(['kty', 'crv', 'x', 'y', 'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'k']);
const JS_IDENTIFIER_START = /^[$_\p{ID_Start}]$/u;
const JS_IDENTIFIER_PART = /^[$_\u200c\u200d\p{ID_Continue}]$/u;
const MAX_JWK_FIELD_BYTES = 16384;
const MAX_JWK_PARSE_STEPS = 8192;
const MAX_JWK_ENCODED_LAYERS = 16;
const MAX_JWK_RETAINED_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 256 * 1024 * 1024;
const MAX_JWK_MARKERS = 1024;
const JWK_WINDOW_BYTES = 96 * 1024;
const PEM_BEGIN = Buffer.from('-----BEGIN ');
const BLOCK_COMMENT_END = Buffer.from('*/');
const SIMPLE_STRING_ESCAPES = Object.freeze({
  b: '\b', f: '\f', n: '\n', r: '\r', t: '\t',
});
const PRIVATE_PEM = /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----([\s\S]*?)-----END \1-----/g;
const PGP_PRIVATE_ARMOR = /-----BEGIN PGP PRIVATE KEY BLOCK-----\r?\n([\s\S]*?)\r?\n-----END PGP PRIVATE KEY BLOCK-----/g;

function normalizedRelativePath(relativePath) {
  return String(relativePath).replaceAll('\\', '/');
}

function credentialFilename(relativePath) {
  const normalized = normalizedRelativePath(relativePath);
  const base = path.posix.basename(normalized).toLowerCase();
  const extension = path.posix.extname(base);
  return CREDENTIAL_FILE_NAMES.has(base)
    || CREDENTIAL_FILE_EXTENSIONS.has(extension)
    || base.startsWith('.env.')
    || (/^client_secret.*\.json$/.test(base))
    || (/^service[-_]account.*\.json$/.test(base))
    || normalized.split('/').some((part) => part.toLowerCase() === 'private-keys-v1.d');
}

function plausibleArmoredPrivateKey(block, payload) {
  try {
    crypto.createPrivateKey(block);
    return true;
  } catch (_) {
    const compact = payload.replace(/\s/g, '');
    return compact.length >= 64
      && compact.length % 4 === 0
      && /^[A-Za-z0-9+/]+={0,2}$/.test(compact);
  }
}

function pgpPacketTag(firstByte) {
  if ((firstByte & 0x80) === 0) return -1;
  return (firstByte & 0x40) !== 0 ? firstByte & 0x3f : (firstByte >> 2) & 0x0f;
}

function plausiblePgpPrivateBlock(contents) {
  const lines = contents.split(/\r?\n/);
  const payload = [];
  let bodyStarted = false;
  for (const line of lines) {
    const value = line.trim();
    if (!bodyStarted && !value) {
      bodyStarted = true;
      continue;
    }
    if (!bodyStarted && /^[A-Za-z0-9-]+:\s*.*$/.test(value)) continue;
    bodyStarted = true;
    if (!value || /^=[A-Za-z0-9+/]{4}$/.test(value)) continue;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false;
    payload.push(value);
  }
  const compact = payload.join('');
  if (compact.length < 16 || compact.length % 4 !== 0) return false;
  const decoded = Buffer.from(compact, 'base64');
  return decoded.length >= 8 && [5, 7].includes(pgpPacketTag(decoded[0]));
}

function containsPgpPrivateArmor(text) {
  PGP_PRIVATE_ARMOR.lastIndex = 0;
  let match;
  while ((match = PGP_PRIVATE_ARMOR.exec(text))) {
    if (plausiblePgpPrivateBlock(match[1])) {
      PGP_PRIVATE_ARMOR.lastIndex = 0;
      return true;
    }
  }
  PGP_PRIVATE_ARMOR.lastIndex = 0;
  return false;
}

function containsPrivatePem(body) {
  if (!body.includes(PEM_BEGIN)) return false;
  const text = body.toString('utf8');
  if (containsPgpPrivateArmor(text)) return true;
  PRIVATE_PEM.lastIndex = 0;
  let match;
  while ((match = PRIVATE_PEM.exec(text))) {
    if (plausibleArmoredPrivateKey(match[0], match[2])) {
      PRIVATE_PEM.lastIndex = 0;
      return true;
    }
  }
  PRIVATE_PEM.lastIndex = 0;
  return false;
}

function containsDerPrivateKey(body) {
  if (body.length < 48 || body.length > 1024 * 1024 || body[0] !== 0x30) return false;
  for (const type of ['pkcs8', 'pkcs1', 'sec1']) {
    try {
      crypto.createPrivateKey({ key: body, format: 'der', type });
      return true;
    } catch (_) {
      // Try the next standard private-key envelope.
    }
  }
  return false;
}

function base64urlBytes(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length > 0 && decoded.toString('base64url') === value ? decoded : null;
}

function hexDigitValue(characterCode) {
  if (characterCode >= 0x30 && characterCode <= 0x39) return characterCode - 0x30;
  if (characterCode >= 0x41 && characterCode <= 0x46) return characterCode - 0x41 + 10;
  if (characterCode >= 0x61 && characterCode <= 0x66) return characterCode - 0x61 + 10;
  return -1;
}

function fixedHexValue(value, start, width, characterCodeAt) {
  let decoded = 0;
  for (let offset = 0; offset < width; offset += 1) {
    const digit = hexDigitValue(characterCodeAt(value, start + offset));
    if (digit < 0) return -1;
    decoded = (decoded * 16) + digit;
  }
  return decoded;
}

function unicodeIdentifierEscape(value, start, characterCodeAt) {
  if (characterCodeAt(value, start) !== 0x5c || characterCodeAt(value, start + 1) !== 0x75) {
    return { status: 'malformed', end: Math.min(value.length, start + 1) };
  }
  if (characterCodeAt(value, start + 2) !== 0x7b) {
    const codePoint = fixedHexValue(value, start + 2, 4, characterCodeAt);
    return codePoint < 0
      ? { status: 'malformed', end: Math.min(value.length, start + 6) }
      : { status: 'value', codePoint, end: start + 6 };
  }
  let codePoint = 0;
  let digits = 0;
  let index = start + 3;
  while (index < value.length && characterCodeAt(value, index) !== 0x7d) {
    const digit = hexDigitValue(characterCodeAt(value, index));
    if (digit < 0 || digits >= 6) {
      return { status: 'malformed', end: Math.min(value.length, index + 1) };
    }
    codePoint = (codePoint * 16) + digit;
    digits += 1;
    index += 1;
  }
  if (digits === 0 || characterCodeAt(value, index) !== 0x7d || codePoint > 0x10ffff) {
    return { status: 'malformed', end: Math.min(value.length, index + 1) };
  }
  return { status: 'value', codePoint, end: index + 1 };
}

function identifierEscape(value, start, characterCodeAt) {
  const unicode = unicodeIdentifierEscape(value, start, characterCodeAt);
  if (unicode.status === 'value' || characterCodeAt(value, start + 1) !== 0x78) return unicode;
  const codePoint = fixedHexValue(value, start + 2, 2, characterCodeAt);
  return codePoint < 0
    ? unicode
    : { status: 'value', codePoint, end: start + 4, nonstandard: true };
}

function textCodePointAt(value, index) {
  const codePoint = value.codePointAt(index);
  if (codePoint === undefined) return { status: 'malformed', end: value.length };
  return { status: 'value', codePoint, end: index + (codePoint > 0xffff ? 2 : 1) };
}

function bufferCodePointAt(value, index) {
  const first = value[index];
  if (first === undefined) return { status: 'malformed', end: value.length };
  if (first <= 0x7f) return { status: 'value', codePoint: first, end: index + 1 };
  let length;
  let codePoint;
  let minimum;
  if (first >= 0xc2 && first <= 0xdf) {
    length = 2;
    codePoint = first & 0x1f;
    minimum = 0x80;
  } else if (first >= 0xe0 && first <= 0xef) {
    length = 3;
    codePoint = first & 0x0f;
    minimum = 0x800;
  } else if (first >= 0xf0 && first <= 0xf4) {
    length = 4;
    codePoint = first & 0x07;
    minimum = 0x10000;
  } else return { status: 'malformed', end: index + 1 };
  if (index + length > value.length) return { status: 'malformed', end: value.length };
  for (let offset = 1; offset < length; offset += 1) {
    const continuation = value[index + offset];
    if ((continuation & 0xc0) !== 0x80) return { status: 'malformed', end: index + offset + 1 };
    codePoint = (codePoint * 0x40) + (continuation & 0x3f);
  }
  if (codePoint < minimum
    || codePoint > 0x10ffff
    || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
    return { status: 'malformed', end: index + length };
  }
  return { status: 'value', codePoint, end: index + length };
}

function identifierCodePoint(codePoint, first) {
  if (codePoint < 0 || codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
    return false;
  }
  const character = String.fromCodePoint(codePoint);
  return (first ? JS_IDENTIFIER_START : JS_IDENTIFIER_PART).test(character);
}

function codePointUtf8Bytes(codePoint) {
  if (codePoint <= 0x7f) return 1;
  if (codePoint <= 0x7ff) return 2;
  if (codePoint <= 0xffff) return 3;
  return 4;
}

function readIdentifier(value, start, characterCodeAt, rawCodePointAt) {
  let candidate = '';
  let decodedBytes = 0;
  let first = true;
  let index = start;
  let nonstandard = false;
  while (index < value.length) {
    const escaped = characterCodeAt(value, index) === 0x5c;
    const token = escaped
      ? identifierEscape(value, index, characterCodeAt)
      : rawCodePointAt(value, index);
    if (token.status !== 'value') {
      return { status: 'malformed', value: '', end: Math.max(index + 1, token.end) };
    }
    if (!identifierCodePoint(token.codePoint, first)) {
      if (escaped) return { status: 'malformed', value: '', end: token.end };
      if (first) return null;
      break;
    }
    decodedBytes += codePointUtf8Bytes(token.codePoint);
    nonstandard ||= token.nonstandard === true;
    if (candidate !== null) {
      candidate += String.fromCodePoint(token.codePoint);
      if (candidate.length > 3) candidate = null;
    }
    first = false;
    index = token.end;
  }
  if (first) return null;
  let status = 'value';
  if (decodedBytes > MAX_JWK_FIELD_BYTES) status = 'overflow';
  else if (nonstandard) status = 'malformed';
  return {
    status,
    value: decodedBytes <= MAX_JWK_FIELD_BYTES && candidate !== null ? candidate : '',
    end: index,
  };
}

function encodedAsciiEnd(value, start, expectedCode, characterCodeAt) {
  if (characterCodeAt(value, start) === expectedCode) return start + 1;
  if (characterCodeAt(value, start) !== 0x5c) return -1;
  let escapeTypeIndex = start + 1;
  let slashCount = 1;
  while (characterCodeAt(value, escapeTypeIndex) === 0x5c) {
    slashCount += 1;
    if (slashCount > MAX_JWK_PARSE_STEPS) return -1;
    escapeTypeIndex += 1;
  }
  const escapeType = characterCodeAt(value, escapeTypeIndex);
  if (escapeType === 0x75 && characterCodeAt(value, escapeTypeIndex + 1) === 0x7b) {
    const decoded = unicodeIdentifierEscape(value, escapeTypeIndex - 1, characterCodeAt);
    return decoded.status === 'value' && decoded.codePoint === expectedCode ? decoded.end : -1;
  }
  const width = escapeType === 0x75 ? 4 : escapeType === 0x78 ? 2 : 0;
  if (width === 0 || escapeTypeIndex + 1 + width > value.length) return -1;
  return fixedHexValue(value, escapeTypeIndex + 1, width, characterCodeAt) === expectedCode
    ? escapeTypeIndex + 1 + width
    : -1;
}

function encodedKtyEnd(value, start, characterCodeAt) {
  const afterK = encodedAsciiEnd(value, start, 0x6b, characterCodeAt);
  if (afterK < 0) return -1;
  const afterT = encodedAsciiEnd(value, afterK, 0x74, characterCodeAt);
  if (afterT < 0) return -1;
  return encodedAsciiEnd(value, afterT, 0x79, characterCodeAt);
}

function textCharacterCodeAt(value, index) {
  return index < value.length ? value.charCodeAt(index) : -1;
}

function bufferCharacterCodeAt(value, index) {
  return index < value.length ? value[index] : -1;
}

function findNextEncodedKty(value, start, characterCodeAt) {
  for (let index = start; index < value.length; index += 1) {
    const end = encodedKtyEnd(value, index, characterCodeAt);
    if (end >= 0) return { start: index, end };
    if (characterCodeAt(value, index) === 0x5c) {
      let slashEnd = index + 1;
      while (slashEnd < value.length
        && slashEnd - index < MAX_JWK_PARSE_STEPS
        && characterCodeAt(value, slashEnd) === 0x5c) {
        slashEnd += 1;
      }
      index = slashEnd - 1;
    }
  }
  return null;
}

function skipJsTrivia(text, start) {
  let index = start;
  while (index < text.length) {
    if (/\s/.test(text[index])) {
      index += 1;
      continue;
    }
    if (text.startsWith('//', index)) {
      const newline = text.indexOf('\n', index + 2);
      index = newline < 0 ? text.length : newline + 1;
      continue;
    }
    if (text.startsWith('/*', index)) {
      const end = text.indexOf('*/', index + 2);
      if (end < 0) return { status: 'malformed', end: text.length };
      index = end + 2;
      continue;
    }
    break;
  }
  return { status: 'value', end: index };
}

function decodedEscape(text, index) {
  const character = text[index];
  if (Object.prototype.hasOwnProperty.call(SIMPLE_STRING_ESCAPES, character)) {
    return { value: SIMPLE_STRING_ESCAPES[character], end: index + 1 };
  }
  if (['"', "'", '\\', '/'].includes(character)) {
    return { value: character, end: index + 1 };
  }
  const width = character === 'u' ? 4 : character === 'x' ? 2 : 0;
  if (!width || index + 1 + width > text.length) return null;
  const decoded = fixedHexValue(text, index + 1, width, textCharacterCodeAt);
  if (decoded >= 0) return { value: String.fromCodePoint(decoded), end: index + 1 + width };
  return null;
}

function readJsString(text, start, maxBytes = MAX_JWK_FIELD_BYTES, capture = true) {
  const quote = text[start];
  if (quote !== '"' && quote !== "'") return { status: 'not_string', end: start };
  const fragments = capture ? [] : null;
  let valueBytes = 0;
  let status = 'value';
  for (let index = start + 1; index < text.length;) {
    const character = text[index];
    if (character === quote) {
      return {
        status,
        value: status === 'value' && fragments ? fragments.join('') : '',
        end: index + 1,
      };
    }
    if (character === '\n' || character === '\r') {
      if (status === 'value') status = 'malformed';
      index += 1;
      continue;
    }
    let fragment;
    if (character !== '\\') {
      const codePoint = text.codePointAt(index);
      fragment = String.fromCodePoint(codePoint);
      index += fragment.length;
    } else {
      const decoded = decodedEscape(text, index + 1);
      if (!decoded) {
        if (status === 'value') status = 'malformed';
        index = Math.min(text.length, index + 2);
        continue;
      }
      fragment = decoded.value;
      index = decoded.end;
    }
    valueBytes += Buffer.byteLength(fragment, 'utf8');
    if (valueBytes > maxBytes) status = 'overflow';
    else if (status === 'value' && fragments) fragments.push(fragment);
  }
  return { status: status === 'overflow' ? status : 'malformed', value: '', end: text.length };
}

function readJsPropertyName(text, start) {
  const quoted = readJsString(text, start);
  if (quoted.status !== 'not_string') return quoted;
  return readIdentifier(text, start, textCharacterCodeAt, textCodePointAt)
    || { status: 'malformed', value: '', end: start };
}

function matchingDelimiter(opening, closing) {
  return (opening === '{' && closing === '}')
    || (opening === '[' && closing === ']')
    || (opening === '(' && closing === ')');
}

function lexicalContextAt(text, markerIndex) {
  const stack = [];
  let quote = '';
  let quoteStart = -1;
  let comment = '';
  let commentStart = -1;
  let unsafe = false;
  for (let index = 0; index < markerIndex;) {
    const character = text[index];
    if (comment === 'line') {
      if (character === '\n' || character === '\r') {
        comment = '';
        commentStart = -1;
      }
      index += 1;
      continue;
    }
    if (comment === 'block') {
      if (text.startsWith('*/', index)) {
        comment = '';
        commentStart = -1;
        index += 2;
      } else index += 1;
      continue;
    }
    if (quote) {
      if (character === '\\') {
        index = Math.min(markerIndex, index + 2);
        continue;
      }
      if (character === quote) {
        quote = '';
        quoteStart = -1;
      } else if (character === '\n' || character === '\r') {
        unsafe = true;
        quote = '';
        quoteStart = -1;
      }
      index += 1;
      continue;
    }
    if (text.startsWith('//', index)) {
      comment = 'line';
      commentStart = index;
      index += 2;
    } else if (text.startsWith('/*', index)) {
      comment = 'block';
      commentStart = index;
      index += 2;
    } else if (character === '"' || character === "'") {
      quote = character;
      quoteStart = index;
      index += 1;
    } else if (character === '{' || character === '[' || character === '(') {
      stack.push({ character, index });
      index += 1;
    } else if (character === '}' || character === ']' || character === ')') {
      if (!stack.length || !matchingDelimiter(stack.at(-1).character, character)) unsafe = true;
      else stack.pop();
      index += 1;
    } else index += 1;
  }
  return { comment, commentStart, quote, quoteStart, stack, unsafe };
}

function scanJsValue(text, start) {
  const stack = [];
  let index = start;
  let steps = 0;
  let sawContent = false;
  while (index < text.length) {
    steps += 1;
    if (steps > MAX_JWK_PARSE_STEPS) return { status: 'overflow', end: index };
    const trivia = skipJsTrivia(text, index);
    if (trivia.status !== 'value') return { status: 'syntax', end: trivia.end };
    if (trivia.end !== index) {
      index = trivia.end;
      continue;
    }
    const quoted = readJsString(text, index);
    if (quoted.status === 'value') {
      sawContent = true;
      index = quoted.end;
      continue;
    }
    if (quoted.status === 'malformed' || quoted.status === 'overflow') return quoted;
    const character = text[index];
    if (character === '{' || character === '[' || character === '(') {
      stack.push(character);
      if (stack.length > MAX_JWK_PARSE_STEPS) return { status: 'overflow', end: index };
      sawContent = true;
    } else if (character === '}' || character === ']' || character === ')') {
      if (!stack.length) {
        return character === '}' && sawContent
          ? { status: 'value', end: index }
          : { status: 'syntax', end: index };
      }
      if (!matchingDelimiter(stack.at(-1), character)) return { status: 'syntax', end: index };
      stack.pop();
    } else if (character === ',' && !stack.length) {
      return sawContent ? { status: 'value', end: index } : { status: 'syntax', end: index };
    } else if (!/\s/.test(character)) sawContent = true;
    index += 1;
  }
  return { status: 'truncated', end: text.length };
}

function topLevelStringProperties(text, objectStart) {
  const fields = {};
  let index = objectStart + 1;
  let steps = 0;
  let failure = null;
  let sawAsymmetricPrivateField = false;
  let sawSymmetricPrivateField = false;
  while (index < text.length) {
    steps += 1;
    if (steps > MAX_JWK_PARSE_STEPS) {
      return { fields, failure: 'overflow', sawAsymmetricPrivateField, sawSymmetricPrivateField };
    }
    const leadingTrivia = skipJsTrivia(text, index);
    if (leadingTrivia.status !== 'value') {
      return { fields, failure: 'syntax', sawAsymmetricPrivateField, sawSymmetricPrivateField };
    }
    index = leadingTrivia.end;
    if (text[index] === '}') {
      return { fields, failure, sawAsymmetricPrivateField, sawSymmetricPrivateField };
    }
    const property = readJsPropertyName(text, index);
    if (property.status !== 'value') {
      return {
        fields,
        failure: property.status === 'overflow' ? 'overflow' : 'syntax',
        sawAsymmetricPrivateField,
        sawSymmetricPrivateField,
      };
    }
    if (property.value === 'd') sawAsymmetricPrivateField = true;
    if (property.value === 'k') sawSymmetricPrivateField = true;
    const propertyTrivia = skipJsTrivia(text, property.end);
    if (propertyTrivia.status !== 'value' || text[propertyTrivia.end] !== ':') {
      return { fields, failure: 'syntax', sawAsymmetricPrivateField, sawSymmetricPrivateField };
    }
    const valueTrivia = skipJsTrivia(text, propertyTrivia.end + 1);
    if (valueTrivia.status !== 'value') {
      return { fields, failure: 'syntax', sawAsymmetricPrivateField, sawSymmetricPrivateField };
    }
    const valueStart = valueTrivia.end;
    const retainValue = JWK_FIELDS.has(property.value);
    const stringValue = readJsString(
      text,
      valueStart,
      retainValue ? MAX_JWK_FIELD_BYTES : MAX_JWK_RETAINED_BYTES,
      retainValue,
    );
    let valueEnd;
    if (stringValue.status === 'value') {
      if (retainValue) fields[property.value] = stringValue.value;
      valueEnd = stringValue.end;
    } else if (stringValue.status === 'malformed' || stringValue.status === 'overflow') {
      if (retainValue) {
        return {
          fields,
          failure: stringValue.status,
          sawAsymmetricPrivateField,
          sawSymmetricPrivateField,
        };
      }
      failure ||= stringValue.status;
      valueEnd = stringValue.end;
    } else {
      const scannedValue = scanJsValue(text, valueStart);
      if (scannedValue.status !== 'value') {
        return {
          fields,
          failure: scannedValue.status,
          sawAsymmetricPrivateField,
          sawSymmetricPrivateField,
        };
      }
      valueEnd = scannedValue.end;
    }
    const trailingTrivia = skipJsTrivia(text, valueEnd);
    if (trailingTrivia.status !== 'value') {
      return { fields, failure: 'syntax', sawAsymmetricPrivateField, sawSymmetricPrivateField };
    }
    index = trailingTrivia.end;
    if (text[index] === ',') index += 1;
    else if (text[index] === '}') {
      return { fields, failure, sawAsymmetricPrivateField, sawSymmetricPrivateField };
    } else return { fields, failure: 'syntax', sawAsymmetricPrivateField, sawSymmetricPrivateField };
  }
  return { fields, failure: 'truncated', sawAsymmetricPrivateField, sawSymmetricPrivateField };
}

function privateJwkFields(fields) {
  if (fields.kty === 'oct') {
    const secret = typeof fields.k === 'string' ? base64urlBytes(fields.k) : null;
    return Boolean(secret && secret.length >= 16);
  }
  if (typeof fields.kty !== 'string' || typeof fields.d !== 'string') return false;
  try {
    crypto.createPrivateKey({ key: fields, format: 'jwk' });
    return true;
  } catch (_) {
    return false;
  }
}

function decodedBufferEscape(body, index) {
  const character = body[index];
  const simpleCharacter = String.fromCharCode(character);
  if (Object.prototype.hasOwnProperty.call(SIMPLE_STRING_ESCAPES, simpleCharacter)) {
    return { value: SIMPLE_STRING_ESCAPES[simpleCharacter], end: index + 1 };
  }
  if ([0x22, 0x27, 0x2f, 0x5c].includes(character)) {
    return { value: String.fromCharCode(character), end: index + 1 };
  }
  const width = character === 0x75 ? 4 : character === 0x78 ? 2 : 0;
  if (!width || index + 1 + width > body.length) return null;
  const decoded = fixedHexValue(body, index + 1, width, bufferCharacterCodeAt);
  return decoded < 0 ? null : { value: String.fromCodePoint(decoded), end: index + 1 + width };
}

function readBufferString(body, start, capture) {
  const quote = body[start];
  const fragments = capture ? [] : null;
  let valueBytes = 0;
  let status = 'value';
  for (let index = start + 1; index < body.length;) {
    const character = body[index];
    if (character === quote) {
      return { status, value: status === 'value' && fragments ? fragments.join('') : '', end: index + 1 };
    }
    let fragment = '';
    if (character === 0x0a || character === 0x0d) {
      status = status === 'overflow' ? status : 'malformed';
      index += 1;
    } else if (character === 0x5c) {
      const decoded = decodedBufferEscape(body, index + 1);
      if (!decoded) {
        status = status === 'overflow' ? status : 'malformed';
        index = Math.min(body.length, index + 2);
      } else {
        fragment = decoded.value;
        index = decoded.end;
      }
    } else {
      fragment = String.fromCharCode(character);
      index += 1;
    }
    valueBytes += fragment ? Buffer.byteLength(fragment, 'utf8') : 0;
    if (valueBytes > MAX_JWK_FIELD_BYTES) status = 'overflow';
    else if (capture && fragment) fragments.push(fragment);
  }
  return { status: status === 'overflow' ? status : 'malformed', value: '', end: body.length };
}

function streamObjectFrame(scanner) {
  return scanner.stack.at(-1)?.type === 'object' ? scanner.stack.at(-1).frame : null;
}

function streamRetainField(scanner, frame, property, value) {
  const priorBytes = typeof frame.fields[property] === 'string'
    ? Buffer.byteLength(frame.fields[property], 'utf8')
    : 0;
  const nextBytes = Buffer.byteLength(value, 'utf8');
  const retainedDelta = nextBytes - priorBytes;
  if (scanner.retainedBytes + retainedDelta > MAX_JWK_RETAINED_BYTES) {
    frame.malformed = true;
    if (property === 'kty') frame.ktyUnusable = true;
    return;
  }
  frame.fields[property] = value;
  frame.retainedBytes += retainedDelta;
  scanner.retainedBytes += retainedDelta;
}

function streamHandleProperty(scanner, frame, token) {
  frame.propertyCount += 1;
  if (frame.propertyCount > MAX_JWK_PARSE_STEPS || token.status !== 'value') frame.malformed = true;
  frame.property = token.status === 'value' ? token.value : '';
  if (frame.property === 'k' || frame.property === 'd') frame.privateNames.add(frame.property);
  if (frame.property === 'kty') {
    frame.sawKtyProperty = true;
    scanner.markers += 1;
    if (scanner.markers > MAX_JWK_MARKERS) scanner.found = true;
  }
  frame.state = 'colon';
}

function streamHandleStringValue(scanner, frame, token) {
  const property = frame.property;
  if (token.status !== 'value') {
    frame.malformed = true;
    if (property === 'kty') frame.ktyUnusable = true;
  } else if (JWK_FIELDS.has(property)) streamRetainField(scanner, frame, property, token.value);
  frame.state = 'after_value';
}

function streamBeginContainer(scanner, type) {
  const parentFrame = streamObjectFrame(scanner);
  let parent = null;
  if (parentFrame?.state === 'value') {
    if (parentFrame.property === 'kty') parentFrame.ktyUnusable = true;
    parentFrame.state = 'nested_value';
    parent = parentFrame;
  } else if (parentFrame && parentFrame.state !== 'primitive') parentFrame.malformed = true;
  const entry = { parent, type };
  if (type === 'object') entry.frame = newObjectFrame();
  scanner.stack.push(entry);
  if (scanner.stack.length > MAX_JWK_PARSE_STEPS) scanner.found = true;
}

function streamMarkMalformed(scanner) {
  const frame = streamObjectFrame(scanner);
  if (frame) frame.malformed = true;
}

function streamCloseContainer(scanner, type) {
  const entry = scanner.stack.at(-1);
  if (!entry || entry.type !== type) {
    streamMarkMalformed(scanner);
    return;
  }
  scanner.stack.pop();
  if (entry.type === 'object') {
    scanner.retainedBytes -= entry.frame.retainedBytes;
    if (structuredFramePrivate(entry.frame, true)) scanner.found = true;
  }
  if (entry.parent?.state === 'nested_value') entry.parent.state = 'after_value';
}

function streamBeginString(scanner, quote) {
  const frame = streamObjectFrame(scanner);
  const role = frame?.state === 'property' ? 'property'
    : frame?.state === 'value' ? 'value' : 'other';
  const capture = role === 'property'
    || (role === 'value' && JWK_FIELDS.has(frame.property));
  scanner.string = {
    bytes: 0,
    capture,
    escape: null,
    frame,
    fragments: capture ? [] : null,
    nested: scanner.depth < MAX_JWK_ENCODED_LAYERS
      ? createDecodedPrivateJwkScanner(scanner.depth + 1, scanner.commentDepth) : null,
    quote,
    role,
    status: 'value',
  };
  scanner.mode = 'string';
}

function streamAppendStringFragment(token, fragment) {
  if (!fragment) return;
  if (token.nested) token.nested.feed(fragment);
  token.bytes += Buffer.byteLength(fragment, 'utf8');
  if (token.capture && token.bytes > MAX_JWK_FIELD_BYTES) token.status = 'overflow';
  else if (token.capture && token.status === 'value') token.fragments.push(fragment);
}

function streamFinishString(scanner, closed) {
  const current = scanner.string;
  if (!closed && current.status === 'value') current.status = 'malformed';
  if (closed && current.status !== 'malformed' && current.nested?.finish()) scanner.found = true;
  const token = {
    status: current.status,
    value: current.status === 'value' && current.fragments ? current.fragments.join('') : '',
  };
  if (current.role === 'property' && current.frame) streamHandleProperty(scanner, current.frame, token);
  else if (current.role === 'value' && current.frame) streamHandleStringValue(scanner, current.frame, token);
  else if (current.frame && token.status !== 'value') current.frame.malformed = true;
  scanner.string = null;
  scanner.mode = 'normal';
}

function streamStringEscape(scanner, character) {
  const token = scanner.string;
  if (token.escape === 'start') {
    if (Object.prototype.hasOwnProperty.call(SIMPLE_STRING_ESCAPES, character)) {
      streamAppendStringFragment(token, SIMPLE_STRING_ESCAPES[character]);
      token.escape = null;
    } else if (['"', "'", '\\', '/'].includes(character)) {
      streamAppendStringFragment(token, character);
      token.escape = null;
    } else if (character === 'u' || character === 'x') {
      token.escape = { digits: '', remaining: character === 'u' ? 4 : 2 };
    } else {
      if (token.status === 'value') token.status = 'malformed';
      token.escape = null;
    }
    return;
  }
  const digit = hexDigitValue(character.charCodeAt(0));
  if (digit < 0) {
    if (token.status === 'value') token.status = 'malformed';
    token.escape = null;
    return;
  }
  token.escape.digits += character;
  token.escape.remaining -= 1;
  if (token.escape.remaining === 0) {
    streamAppendStringFragment(token, String.fromCodePoint(parseInt(token.escape.digits, 16)));
    token.escape = null;
  }
}

function streamStringCharacter(scanner, character) {
  const token = scanner.string;
  if (token.escape) {
    streamStringEscape(scanner, character);
    return;
  }
  if (character === token.quote) {
    streamFinishString(scanner, true);
    return;
  }
  if (character === '\\') {
    token.escape = 'start';
    return;
  }
  if ((character === '\n' || character === '\r') && token.status === 'value') {
    token.status = 'malformed';
  }
  streamAppendStringFragment(token, character);
}

function streamFinishIdentifier(scanner) {
  const state = scanner.identifier;
  const parsed = state.status === 'value'
    ? readIdentifier(state.raw, 0, textCharacterCodeAt, textCodePointAt)
    : null;
  const token = parsed?.status === 'value' && parsed.end === state.raw.length
    ? { status: 'value', value: parsed.value }
    : { status: state.status === 'overflow' ? 'overflow' : 'malformed', value: '' };
  streamHandleProperty(scanner, state.frame, token);
  scanner.identifier = null;
  scanner.mode = 'normal';
}

function streamIdentifierCharacter(scanner, character) {
  if (/[:\s,\/]/.test(character)) {
    streamFinishIdentifier(scanner);
    return false;
  }
  if (scanner.identifier.raw.length < 128) scanner.identifier.raw += character;
  else scanner.identifier.status = 'overflow';
  return true;
}

function streamPrimitiveCharacter(scanner) {
  const frame = streamObjectFrame(scanner);
  if (!frame) return;
  if (frame.state === 'value') {
    if (frame.property === 'kty') frame.ktyUnusable = true;
    frame.state = 'primitive';
  } else if (frame.state === 'colon' || frame.state === 'property') frame.malformed = true;
}

function streamNormalCharacter(scanner, character) {
  const frame = streamObjectFrame(scanner);
  if (character === '"' || character === "'") streamBeginString(scanner, character);
  else if (character === '{') streamBeginContainer(scanner, 'object');
  else if (character === '[' || character === '(') {
    streamBeginContainer(scanner, character === '[' ? 'array' : 'paren');
  } else if (character === '}' || character === ']' || character === ')') {
    streamCloseContainer(scanner, character === '}' ? 'object' : character === ']' ? 'array' : 'paren');
  } else if (character === ':') {
    if (frame?.state === 'colon') frame.state = 'value';
    else if (frame) frame.malformed = true;
  } else if (character === ',') {
    if (frame) {
      if (!['after_value', 'primitive'].includes(frame.state)) frame.malformed = true;
      frame.property = '';
      frame.state = 'property';
    }
  } else if (frame?.state === 'property' && (/^[$_A-Za-z]$/.test(character) || character === '\\')) {
    scanner.identifier = { frame, raw: character, status: 'value' };
    scanner.mode = 'identifier';
  } else if (!/\s/.test(character)) streamPrimitiveCharacter(scanner);
}

function streamBeginComment(scanner, mode) {
  scanner.mode = mode;
  scanner.blockAsterisk = false;
  scanner.comment = scanner.commentDepth < MAX_JWK_ENCODED_LAYERS
    ? createDecodedPrivateJwkScanner(scanner.depth, scanner.commentDepth + 1) : null;
}

function streamFinishComment(scanner) {
  if (scanner.comment?.finish()) scanner.found = true;
  scanner.comment = null;
  scanner.mode = 'normal';
  scanner.blockAsterisk = false;
}

function streamLineCommentCharacter(scanner, character) {
  if (character === '\n' || character === '\r') streamFinishComment(scanner);
  else if (scanner.comment) scanner.comment.feed(character);
}

function streamBlockCommentCharacter(scanner, character) {
  if (scanner.blockAsterisk) {
    if (character === '/') {
      streamFinishComment(scanner);
      return;
    }
    if (scanner.comment) scanner.comment.feed('*');
    scanner.blockAsterisk = false;
  }
  if (character === '*') scanner.blockAsterisk = true;
  else if (scanner.comment) scanner.comment.feed(character);
}

function streamDecodedCharacter(scanner, character) {
  if (scanner.found) return;
  if (scanner.mode === 'string') {
    streamStringCharacter(scanner, character);
    return;
  }
  if (scanner.mode === 'identifier' && streamIdentifierCharacter(scanner, character)) return;
  if (scanner.mode === 'line_comment') {
    streamLineCommentCharacter(scanner, character);
    return;
  }
  if (scanner.mode === 'block_comment') {
    streamBlockCommentCharacter(scanner, character);
    return;
  }
  if (scanner.pendingSlash) {
    scanner.pendingSlash = false;
    if (character === '/') {
      streamBeginComment(scanner, 'line_comment');
      return;
    }
    if (character === '*') {
      streamBeginComment(scanner, 'block_comment');
      return;
    }
    streamPrimitiveCharacter(scanner);
  }
  if (character === '/') scanner.pendingSlash = true;
  else streamNormalCharacter(scanner, character);
}

function createDecodedPrivateJwkScanner(depth = 1, commentDepth = 0) {
  const scanner = {
    blockAsterisk: false,
    comment: null,
    commentDepth,
    depth,
    found: false,
    identifier: null,
    markers: 0,
    mode: 'normal',
    pendingSlash: false,
    retainedBytes: 0,
    stack: [],
    string: null,
  };
  return {
    feed(text) {
      for (const character of text) streamDecodedCharacter(scanner, character);
    },
    finish() {
      if (scanner.mode === 'identifier') streamFinishIdentifier(scanner);
      if (scanner.mode === 'string') streamFinishString(scanner, false);
      const unterminatedBlockComment = scanner.mode === 'block_comment';
      if (scanner.mode === 'block_comment' && scanner.blockAsterisk && scanner.comment) {
        scanner.comment.feed('*');
      }
      if (scanner.mode === 'block_comment' || scanner.mode === 'line_comment') {
        streamFinishComment(scanner);
      }
      if (unterminatedBlockComment) streamMarkMalformed(scanner);
      for (const entry of scanner.stack) {
        if (entry.type === 'object' && structuredFramePrivate(entry.frame, false)) scanner.found = true;
      }
      return scanner.found;
    },
  };
}

function feedDecodedBufferRange(scanner, body, start, end) {
  const chunkBytes = 64 * 1024;
  for (let offset = start; offset < end;) {
    let next = Math.min(end, offset + chunkBytes);
    if (next < end) {
      while (next > offset && (body[next] & 0xc0) === 0x80) next -= 1;
      if (next === offset) next = Math.min(end, offset + chunkBytes);
    }
    scanner.feed(body.subarray(offset, next).toString('utf8'));
    offset = next;
  }
}

function readCompleteBufferString(body, start) {
  const quote = body[start];
  let output = Buffer.allocUnsafe(Math.min(256, MAX_JWK_RETAINED_BYTES));
  let outputLength = 0;
  let rawStart = start + 1;
  let status = 'value';
  let overflowScanner = null;
  const beginOverflow = () => {
    if (overflowScanner) return;
    overflowScanner = createDecodedPrivateJwkScanner();
    feedDecodedBufferRange(overflowScanner, output, 0, outputLength);
    status = 'overflow';
  };
  const ensureCapacity = (required) => {
    if (required > MAX_JWK_RETAINED_BYTES) {
      beginOverflow();
      return false;
    }
    if (required <= output.length) return true;
    const nextLength = Math.min(
      MAX_JWK_RETAINED_BYTES,
      Math.max(required, output.length * 2),
    );
    const next = Buffer.allocUnsafe(nextLength);
    output.copy(next, 0, 0, outputLength);
    output = next;
    return true;
  };
  const appendRaw = (end) => {
    if (status === 'overflow') {
      feedDecodedBufferRange(overflowScanner, body, rawStart, end);
      return;
    }
    if (status !== 'value') return;
    const length = end - rawStart;
    if (!ensureCapacity(outputLength + length)) {
      feedDecodedBufferRange(overflowScanner, body, rawStart, end);
      return;
    }
    body.copy(output, outputLength, rawStart, end);
    outputLength += length;
  };
  const appendDecoded = (value) => {
    if (status === 'overflow') {
      overflowScanner.feed(value);
      return;
    }
    if (status !== 'value') return;
    const decoded = Buffer.from(value, 'utf8');
    if (!ensureCapacity(outputLength + decoded.length)) {
      overflowScanner.feed(value);
      return;
    }
    decoded.copy(output, outputLength);
    outputLength += decoded.length;
  };

  for (let index = start + 1; index < body.length;) {
    const character = body[index];
    if (character === quote) {
      appendRaw(index);
      return {
        status,
        value: status === 'value' ? output.subarray(0, outputLength).toString('utf8') : '',
        overflowPrivateJwk: status === 'overflow' && overflowScanner.finish(),
        end: index + 1,
      };
    }
    if (character === 0x0a || character === 0x0d) {
      if (status === 'value') status = 'malformed';
      index += 1;
      continue;
    }
    if (character !== 0x5c) {
      index += 1;
      continue;
    }
    appendRaw(index);
    const decoded = decodedBufferEscape(body, index + 1);
    if (!decoded) {
      if (status === 'value') status = 'malformed';
      index = Math.min(body.length, index + 2);
    } else {
      appendDecoded(decoded.value);
      index = decoded.end;
    }
    rawStart = index;
  }
  appendRaw(body.length);
  return {
    status: status === 'overflow' ? status : 'malformed',
    value: '',
    overflowPrivateJwk: status === 'overflow' && overflowScanner.finish(),
    end: body.length,
  };
}

function containsCompleteEncodedPrivateJwk(body) {
  for (let index = 0; index < body.length;) {
    const character = body[index];
    if (character === 0x2f && body[index + 1] === 0x2f) {
      const newline = body.indexOf(0x0a, index + 2);
      index = newline < 0 ? body.length : newline + 1;
      continue;
    }
    if (character === 0x2f && body[index + 1] === 0x2a) {
      const end = body.indexOf(BLOCK_COMMENT_END, index + 2);
      index = end < 0 ? body.length : end + 2;
      continue;
    }
    if (character === 0x22 || character === 0x27) {
      const token = readCompleteBufferString(body, index);
      if (token.status === 'value' && containsPrivateJwkText(token.value, 1)) return true;
      if (token.status === 'overflow' && token.overflowPrivateJwk) return true;
      index = token.end;
      continue;
    }
    index += 1;
  }
  return false;
}

function identifierStartByte(character) {
  return (character >= 0x41 && character <= 0x5a)
    || (character >= 0x61 && character <= 0x7a)
    || character === 0x24
    || character === 0x5f
    || character >= 0x80;
}

function readBufferIdentifier(body, start) {
  return readIdentifier(body, start, bufferCharacterCodeAt, bufferCodePointAt);
}

function newObjectFrame() {
  return {
    fields: Object.create(null),
    ktyUnusable: false,
    malformed: false,
    privateNames: new Set(),
    property: '',
    propertyCount: 0,
    retainedBytes: 0,
    sawKtyProperty: false,
    state: 'property',
  };
}

function structuredFramePrivate(frame, closed) {
  if (privateJwkFields(frame.fields)) return true;
  if (frame.sawKtyProperty && frame.ktyUnusable && frame.privateNames.size > 0) return true;
  const privateName = frame.fields.kty === 'oct' ? 'k' : 'd';
  return Boolean(frame.fields.kty
    && frame.privateNames.has(privateName)
    && (frame.malformed || !closed));
}

function containsStructuredPrivateJwk(body) {
  const stack = [];
  let markers = 0;
  let retainedBytes = 0;
  const currentObject = () => stack.at(-1)?.type === 'object' ? stack.at(-1).frame : null;
  const markMalformed = () => {
    for (let index = stack.length - 1; index >= 0; index -= 1) {
      if (stack[index].type !== 'object') continue;
      stack[index].frame.malformed = true;
      return;
    }
  };
  const retainField = (frame, property, value) => {
    const priorBytes = typeof frame.fields[property] === 'string'
      ? Buffer.byteLength(frame.fields[property], 'utf8')
      : 0;
    const nextBytes = Buffer.byteLength(value, 'utf8');
    const retainedDelta = nextBytes - priorBytes;
    if (retainedBytes + retainedDelta > MAX_JWK_RETAINED_BYTES) {
      frame.malformed = true;
      if (property === 'kty') frame.ktyUnusable = true;
      return;
    }
    frame.fields[property] = value;
    frame.retainedBytes += retainedDelta;
    retainedBytes += retainedDelta;
  };
  const handleProperty = (frame, token) => {
    frame.propertyCount += 1;
    if (frame.propertyCount > MAX_JWK_PARSE_STEPS || token.status !== 'value') frame.malformed = true;
    const malformedCandidate = JWK_FIELDS.has(token.value) ? token.value : '';
    frame.property = token.status === 'value' ? token.value : malformedCandidate;
    if (frame.property === 'k' || frame.property === 'd') frame.privateNames.add(frame.property);
    if (frame.property === 'kty') {
      frame.sawKtyProperty = true;
      if (token.status !== 'value') frame.ktyUnusable = true;
      markers += 1;
      if (markers > MAX_JWK_MARKERS) return false;
    }
    frame.state = 'colon';
    return true;
  };
  const handleStringValue = (frame, token) => {
    const property = frame.property;
    if (token.status !== 'value') {
      frame.malformed = true;
      if (property === 'kty') frame.ktyUnusable = true;
    } else if (JWK_FIELDS.has(property)) retainField(frame, property, token.value);
    frame.state = 'after_value';
    return true;
  };
  const beginContainer = (type) => {
    const parentFrame = currentObject();
    let parent = null;
    if (parentFrame?.state === 'value') {
      if (parentFrame.property === 'kty') parentFrame.ktyUnusable = true;
      parentFrame.state = 'nested_value';
      parent = parentFrame;
    } else if (parentFrame && parentFrame.state !== 'primitive') parentFrame.malformed = true;
    const entry = { parent, type };
    if (type === 'object') entry.frame = newObjectFrame();
    stack.push(entry);
    return stack.length <= MAX_JWK_PARSE_STEPS;
  };
  const closeContainer = (type) => {
    const entry = stack.at(-1);
    if (!entry || entry.type !== type) {
      markMalformed();
      return false;
    }
    stack.pop();
    if (entry.type === 'object') {
      retainedBytes -= entry.frame.retainedBytes;
      if (structuredFramePrivate(entry.frame, true)) return true;
    }
    if (entry.parent?.state === 'nested_value') entry.parent.state = 'after_value';
    return false;
  };

  for (let index = 0; index < body.length;) {
    const character = body[index];
    if (character === 0x2f && body[index + 1] === 0x2f) {
      const newline = body.indexOf(0x0a, index + 2);
      index = newline < 0 ? body.length : newline + 1;
      continue;
    }
    if (character === 0x2f && body[index + 1] === 0x2a) {
      const end = body.indexOf(BLOCK_COMMENT_END, index + 2);
      if (end < 0) {
        markMalformed();
        break;
      }
      index = end + 2;
      continue;
    }
    const frame = currentObject();
    if (character === 0x22 || character === 0x27) {
      const capture = Boolean(frame && (frame.state === 'property'
        || (frame.state === 'value' && JWK_FIELDS.has(frame.property))));
      const token = readBufferString(body, index, capture);
      if (frame?.state === 'property') {
        if (!handleProperty(frame, token)) return true;
      } else if (frame?.state === 'value') {
        if (!handleStringValue(frame, token)) return true;
      } else if (frame && token.status !== 'value') frame.malformed = true;
      index = token.end;
      continue;
    }
    if (character === 0x7b) {
      if (!beginContainer('object')) return true;
      index += 1;
      continue;
    }
    if (character === 0x5b || character === 0x28) {
      if (!beginContainer(character === 0x5b ? 'array' : 'paren')) return true;
      index += 1;
      continue;
    }
    if (character === 0x7d || character === 0x5d || character === 0x29) {
      const type = character === 0x7d ? 'object' : character === 0x5d ? 'array' : 'paren';
      if (closeContainer(type)) return true;
      index += 1;
      continue;
    }
    if (character === 0x3a) {
      if (frame?.state === 'colon') frame.state = 'value';
      else if (frame) frame.malformed = true;
      index += 1;
      continue;
    }
    if (character === 0x2c) {
      if (frame) {
        if (!['after_value', 'primitive'].includes(frame.state)) frame.malformed = true;
        frame.property = '';
        frame.state = 'property';
      }
      index += 1;
      continue;
    }
    if (frame?.state === 'property' && (identifierStartByte(character) || character === 0x5c)) {
      const token = readBufferIdentifier(body, index);
      if (token) {
        if (!handleProperty(frame, token)) return true;
        index = token.end;
        continue;
      }
    }
    if (frame && ![0x09, 0x0a, 0x0d, 0x20].includes(character)) {
      if (frame.state === 'value') {
        if (frame.property === 'kty') frame.ktyUnusable = true;
        frame.state = 'primitive';
      } else if (frame.state === 'colon' || frame.state === 'property') frame.malformed = true;
    }
    index += 1;
  }
  for (const entry of stack) {
    if (entry.type === 'object' && structuredFramePrivate(entry.frame, false)) return true;
  }
  return false;
}

function markerPropertyAt(text, markerIndex, context) {
  const markerEnd = encodedKtyEnd(text, markerIndex, textCharacterCodeAt);
  if (markerEnd < 0) return null;
  const possibleQuoteStart = context.quoteStart >= 0
    ? context.quoteStart
    : markerIndex > 0 && ['"', "'"].includes(text[markerIndex - 1])
      ? markerIndex - 1
      : -1;
  if (possibleQuoteStart >= 0) {
    const quoted = readJsString(text, possibleQuoteStart);
    if (quoted.status === 'value'
      && quoted.value === 'kty'
      && markerIndex > possibleQuoteStart
      && markerEnd < quoted.end) {
      const trivia = skipJsTrivia(text, quoted.end);
      if (trivia.status === 'value' && text[trivia.end] === ':') {
        return { end: quoted.end, valueStart: trivia.end + 1 };
      }
    }
  }
  if (context.quote || /[A-Za-z0-9_$]/.test(text[markerIndex - 1] || '')) return null;
  if (/[A-Za-z0-9_$]/.test(text[markerEnd] || '')) return null;
  const trivia = skipJsTrivia(text, markerEnd);
  return trivia.status === 'value' && text[trivia.end] === ':'
    ? { end: markerEnd, valueStart: trivia.end + 1 }
    : null;
}

function commentContents(text, context) {
  if (context.comment === 'line') {
    const end = text.indexOf('\n', context.commentStart + 2);
    return text.slice(context.commentStart + 2, end < 0 ? text.length : end);
  }
  const end = text.indexOf('*/', context.commentStart + 2);
  return text.slice(context.commentStart + 2, end < 0 ? text.length : end);
}

function containsPrivateJwkText(text, recursionDepth, commentDepth = 0) {
  let offset = 0;
  let markers = 0;
  while (offset < text.length) {
    const marker = findNextEncodedKty(text, offset, textCharacterCodeAt);
    if (!marker) return false;
    markers += 1;
    if (markers > MAX_JWK_MARKERS) return true;
    if (privateJwkCandidate(text, marker.start, recursionDepth, commentDepth)) return true;
    offset = marker.end;
  }
  return false;
}

function privateJwkCandidate(text, markerIndex, recursionDepth, commentDepth) {
  const context = lexicalContextAt(text, markerIndex);
  if (context.comment) {
    if (commentDepth >= MAX_JWK_ENCODED_LAYERS) return false;
    const contents = commentContents(text, context);
    return containsPrivateJwkText(contents, recursionDepth, commentDepth + 1);
  }
  const property = markerPropertyAt(text, markerIndex, context);
  if (!property) {
    if (!context.quote) return false;
    if (recursionDepth >= MAX_JWK_ENCODED_LAYERS) return false;
    const quoted = readJsString(text, context.quoteStart, MAX_JWK_RETAINED_BYTES);
    return quoted.status === 'value'
      && containsPrivateJwkText(quoted.value, recursionDepth + 1, commentDepth);
  }
  const nearestDelimiter = context.stack.at(-1);
  const boundedObject = nearestDelimiter?.character === '{';
  const valueTrivia = skipJsTrivia(text, property.valueStart);
  if (valueTrivia.status !== 'value') return false;
  const ktyValue = readJsString(text, valueTrivia.end);
  if (ktyValue.status !== 'value') return false;
  if (context.unsafe || !boundedObject) return false;
  const parsed = topLevelStringProperties(text, nearestDelimiter.index);
  if (privateJwkFields(parsed.fields)) return true;
  if (parsed.failure) {
    const parsedPrivateField = parsed.sawAsymmetricPrivateField
      || (ktyValue.value === 'oct' && parsed.sawSymmetricPrivateField);
    return parsedPrivateField;
  }
  return false;
}

function containsPrivateJwk(body) {
  if (containsStructuredPrivateJwk(body)) return true;
  if (containsCompleteEncodedPrivateJwk(body)) return true;
  let offset = 0;
  let markers = 0;
  while (offset < body.length) {
    const marker = findNextEncodedKty(body, offset, bufferCharacterCodeAt);
    if (!marker) return false;
    markers += 1;
    if (markers > MAX_JWK_MARKERS) return true;
    const start = Math.max(0, marker.start - JWK_WINDOW_BYTES);
    const end = Math.min(body.length, marker.start + JWK_WINDOW_BYTES);
    const before = body.subarray(start, marker.start).toString('utf8');
    const after = body.subarray(marker.start, end).toString('utf8');
    if (privateJwkCandidate(
      `${before}${after}`,
      before.length,
      0,
    )) return true;
    offset = marker.end;
  }
  return false;
}

function inspectCustomerArtifact(relativePath, body) {
  if (!Buffer.isBuffer(body)) throw new TypeError('customer artifact body must be a Buffer');
  if (credentialFilename(relativePath)) return Object.freeze({ kind: 'credential_file' });
  if (body.length > MAX_ARTIFACT_BYTES) return Object.freeze({ kind: 'oversized_artifact' });
  if (containsPrivatePem(body) || containsDerPrivateKey(body) || containsPrivateJwk(body)) {
    return Object.freeze({ kind: 'private_key_material' });
  }
  return null;
}

module.exports = {
  CREDENTIAL_FILE_EXTENSIONS,
  CREDENTIAL_FILE_NAMES,
  JWK_WINDOW_BYTES,
  MAX_ARTIFACT_BYTES,
  MAX_JWK_MARKERS,
  containsDerPrivateKey,
  containsPgpPrivateArmor,
  containsPrivateJwk,
  containsPrivatePem,
  credentialFilename,
  inspectCustomerArtifact,
};
