'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Engine = require('../detection-engine/detect');
const BrowserEngine = require('../sensors/browser-extension/lib/detect');

const ESCAPED_SSNS = [
  String.raw`\u0031\u0032\u0033\u002d\u0034\u0035\u002d\u0036\u0037\u0038\u0039`,
  '&#49;&#50;&#51;&#45;&#52;&#53;&#45;&#54;&#55;&#56;&#57;',
  '&#x31;&#x32;&#x33;&#x2d;&#x34;&#x35;&#x2d;&#x36;&#x37;&#x38;&#x39;',
  '%31%32%33%2D%34%35%2D%36%37%38%39',
  '%31%32%33%E2%80%91%34%35%E2%80%91%36%37%38%39',
  '123&nbsp;45&nbsp;6789',
  '123&hyphen;45&hyphen;6789',
  String.raw`\uff11\uff12\uff13\u002d\uff14\uff15\u002d\uff16\uff17\uff18\uff19`,
  '&#xff11;&#xff12;&#xff13;&#45;&#xff14;&#xff15;&#45;&#xff16;&#xff17;&#xff18;&#xff19;',
  '%EF%BC%91%EF%BC%92%EF%BC%93%2D%EF%BC%94%EF%BC%95%2D%EF%BC%96%EF%BC%97%EF%BC%98%EF%BC%99',
];

const NESTED_ESCAPED_SSNS = [
  ESCAPED_SSNS[0].replace(/\\/g, String.raw`\u005c`),
  ESCAPED_SSNS[1].replace(/&/g, '&#38;'),
  ESCAPED_SSNS[3].replace(/%/g, '%25'),
];

const UNICODE_SSNS = [
  `1\u200b2\u200c3\u2060-4\u00ad5-6789`,
  `123\u201145\u20116789`,
  `123\u201345\u20136789`,
  `123\u00a045\u00a06789`,
  `1\u200d2\ufeff3-45-6789`,
  `123\u202f45\u202f6789`,
  `123\u201445\u20146789`,
];

function assertExactMappedSsn(engine, encoded) {
  const prefix = '🙂 member SSN: ';
  const input = `${prefix}${encoded} after`;
  const analysis = engine.analyze(input);
  const finding = analysis.findings.find((item) => item.type === 'US_SSN');

  assert.ok(finding, encoded);
  assert.strictEqual(finding.start, prefix.length, encoded);
  assert.strictEqual(finding.end, prefix.length + encoded.length, encoded);
  assert.strictEqual(finding.value, encoded, encoded);
  assert.strictEqual(engine.redact(input, analysis.findings).includes(encoded), false, encoded);

  const tokenized = engine.tokenize(input, analysis.findings);
  assert.strictEqual(tokenized.text.includes(encoded), false, encoded);
  assert.strictEqual(engine.detokenize(tokenized.text, tokenized.map), input, encoded);
}

test('JSON, numeric-entity, and percent escapes map to their exact source span', () => {
  for (const encoded of ESCAPED_SSNS.concat(NESTED_ESCAPED_SSNS)) assertExactMappedSsn(Engine, encoded);
});

test('format characters, alternate dashes, and NBSP cannot split a structured value', () => {
  for (const encoded of UNICODE_SSNS) assertExactMappedSsn(Engine, encoded);
});

test('canonicalization applies to checksum-validated structured values too', () => {
  const encoded = String.raw`4111&#x20;1111%201111\u00a01111`;
  const prefix = 'payment card: ';
  const input = `${prefix}${encoded} after`;
  const finding = Engine.analyze(input).findings.find((item) => item.type === 'CREDIT_CARD');

  assert.ok(finding);
  assert.strictEqual(finding.start, prefix.length);
  assert.strictEqual(finding.end, prefix.length + encoded.length);
  assert.strictEqual(finding.value, encoded);
});

test('canonicalized Base64 and hex are decoded with the outer source span intact', () => {
  const split = (value) => value.match(/.{1,4}/g).join('\u200b');
  for (const encoded of [
    split(Buffer.from('SSN 123-45-6789').toString('base64')),
    split(Buffer.from('SSN 123-45-6789').toString('hex')),
  ]) {
    const analysis = Engine.analyze(encoded);
    const finding = analysis.findings.find((item) => item.type === 'US_SSN');
    assert.ok(finding, encoded);
    assert.strictEqual(finding.start, 0);
    assert.strictEqual(finding.end, encoded.length);
    assert.strictEqual(finding.value, encoded);
  }
});

test('semantic classification also sees the bounded canonical view', () => {
  const raw = 'CONFIDENTIAL internal only, do not share externally';
  const encoded = [...Buffer.from(raw)].map((byte) => `%${byte.toString(16).padStart(2, '0')}`).join('');
  const analysis = Engine.analyze(encoded);
  assert.ok(analysis.categories.some((item) => item.category === 'CONFIDENTIAL_BUSINESS'));
});

test('canonicalization stays precise on benign escaped content', () => {
  const benign = [
    String.raw`release \u0032\u0030\u0032\u0036 notes`,
    'HTML tutorial: &#49; is the decimal entity for one.',
    'URL parameter page=%31 in the example.',
    `release\u200bnotes for sprint 2026`,
    `range 1\u20113 is an editorial notation`,
  ];

  for (const input of benign) {
    const analysis = Engine.analyze(input);
    assert.deepStrictEqual(analysis.findings, [], input);
    assert.deepStrictEqual(analysis.categories, [], input);
  }
});

test('canonicalization is a bounded linear pass on escape-heavy input', () => {
  const unit = String.raw`field=\u0061&#97;%61 `;
  const input = unit.repeat(Math.ceil((200 * 1024) / unit.length)).slice(0, 200 * 1024);
  const started = Date.now();
  const analysis = Engine.analyze(input);
  const elapsed = Date.now() - started;

  assert.deepStrictEqual(analysis.findings, []);
  assert.ok(elapsed < 2000, `canonicalization took ${elapsed}ms`);
});

test('canonical nesting beyond the depth budget is surfaced as opaque', () => {
  let encoded = ESCAPED_SSNS[3];
  for (let depth = 0; depth < 4; depth++) encoded = encoded.replace(/%/g, '%25');
  const analysis = Engine.analyze(`member SSN: ${encoded}`);

  assert.strictEqual(analysis.opaqueEncoded, true);
  assert.ok(analysis.opaqueEncodedSpans.some((span) => span.kind === 'canonicalize_limit'));
});

test('browser copy stays in parity for every canonicalized structured value', () => {
  for (const encoded of ESCAPED_SSNS.concat(NESTED_ESCAPED_SSNS, UNICODE_SSNS)) {
    const input = `🙂 member SSN: ${encoded} after`;
    assert.deepStrictEqual(BrowserEngine.analyze(input), Engine.analyze(input), encoded);
  }
});
