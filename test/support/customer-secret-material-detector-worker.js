'use strict';

const crypto = require('node:crypto');
const { containsPrivateJwk } = require('../../scripts/customer-secret-material-detector');

const OCT_SECRET = Buffer.alloc(32, 0x41).toString('base64url');
const PUBLIC_X = '11qYAYdk9JtS3U4Jx_FV2A-zxRGhZ2aZ8cF8wK9f1TI';

function detectCases(cases) {
  return {
    count: cases.length,
    detections: cases.map((value) => containsPrivateJwk(Buffer.from(value))),
  };
}

function fixedLengthOctObject(ktyFirst) {
  const targetBytes = 61_549;
  const prefix = ktyFirst
    ? '{"kty":"oct","padding":"'
    : `{"k":"${OCT_SECRET}","padding":"`;
  const suffix = ktyFirst
    ? `","k":"${OCT_SECRET}"}`
    : '","kty":"oct"}';
  const paddingBytes = targetBytes - Buffer.byteLength(prefix) - Buffer.byteLength(suffix);
  const result = `${prefix}${'P'.repeat(paddingBytes)}${suffix}`;
  if (Buffer.byteLength(result) !== targetBytes) throw new Error('fixed JWK fixture size drift');
  return result;
}

function nestedJsonString(value, layers) {
  let result = JSON.stringify(value);
  for (let layer = 0; layer < layers; layer += 1) result = JSON.stringify(result);
  return result;
}

function encodeTextLayers(value, layers) {
  let result = value;
  for (let layer = 0; layer < layers; layer += 1) result = JSON.stringify(result);
  return result;
}

function generatedEd25519Jwk() {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  return privateKey.export({ format: 'jwk' });
}

function escapedIdentifierCases() {
  const ed = generatedEd25519Jwk();
  const edValues = `crv:${JSON.stringify(ed.crv)},x:${JSON.stringify(ed.x)}`;
  const edPrivate = JSON.stringify(ed.d);
  const octEscapedK = `{kty:"oct",\\u006b:"${OCT_SECRET}"}`;
  const edEscapedD = `{kty:"OKP",${edValues},\\u{64}:${edPrivate}}`;
  return [
    octEscapedK,
    `{\\u006B:"${OCT_SECRET}",\\u006bt\\u{79}:"oct"}`,
    `{k\\u0074\\u0079:"oct",\\u{6b}:"${OCT_SECRET}"}`,
    edEscapedD,
    `{\\u0064:${edPrivate},k\\u0074\\u{79}:"OKP",${edValues}}`,
    `/* generated private object ${octEscapedK} */`,
    `// generated private object ${edEscapedD}\nconst safe=true;`,
    nestedJsonString(octEscapedK, 2),
    nestedJsonString(edEscapedD, 2),
    nestedJsonString(`{\\u006bt\\u{79}:"oct",\\u{6b}:"${OCT_SECRET}"}`, 2),
    `{kty:"oct",\\u00G0:"${OCT_SECRET}"}`,
    `{kty:"oct",\\u006:"${OCT_SECRET}"}`,
    `{kty:"oct",\\uD800:"${OCT_SECRET}"}`,
    `{kty:"oct",\\u{6b:"${OCT_SECRET}"}`,
    `[{kty:"oct"},{\\u006b:"${OCT_SECRET}"}]`,
    `{kty:"OKP",${edValues},extension:{\\u0064:${edPrivate}}}`,
  ];
}

function lostKtyEvidenceCases() {
  const exactKty = 'A'.repeat(16_384);
  const overflowKty = 'A'.repeat(16_385);
  const overflowPrivate = 'A'.repeat(16_385);
  return [
    `{kty:"${exactKty}",k:"${OCT_SECRET}"}`,
    `{kty:"${overflowKty}",k:"${OCT_SECRET}"}`,
    `{k:"${OCT_SECRET}",kty:"${overflowKty}"}`,
    `{kty:"\\q",k:"${OCT_SECRET}"}`,
    `{d:"${OCT_SECRET}",kty:"\\q"}`,
    `{kty:unknown,k:"${OCT_SECRET}"}`,
    `{kty:"oct",k:"${overflowPrivate}"}`,
    `{kty:"${overflowKty}",note:"no private field"}`,
    `{kty:"${overflowKty}",extension:{k:"${OCT_SECRET}"}}`,
    `[{kty:"${overflowKty}"},{k:"${OCT_SECRET}"}]`,
  ];
}

function deepObjectOwnershipCases() {
  const ed = generatedEd25519Jwk();
  const publicEd = { kty: ed.kty, crv: ed.crv, x: ed.x };
  const privateEd = { ...publicEd, d: ed.d };
  const siblingArray = [publicEd, { d: ed.d }];
  const siblingObject = { publicKey: publicEd, unrelated: { d: ed.d } };
  return [
    JSON.stringify(siblingArray),
    nestedJsonString(siblingArray, 6),
    nestedJsonString(siblingObject, 12),
    nestedJsonString({ kty: 'oct', k: OCT_SECRET }, 6),
    nestedJsonString(privateEd, 12),
  ];
}

function deepWindowBoundaryCases() {
  const privateOct = { kty: 'oct', k: OCT_SECRET };
  const publicOct = { kty: 'oct' };
  const siblingOct = { publicKey: publicOct, unrelated: { k: OCT_SECRET } };
  return [
    nestedJsonString(privateOct, 13),
    nestedJsonString(privateOct, 14),
    nestedJsonString(publicOct, 13),
    nestedJsonString(publicOct, 14),
    nestedJsonString(siblingOct, 13),
    nestedJsonString(siblingOct, 14),
  ];
}

function encodedOversizedExtensionCases() {
  const padding = 'A'.repeat(16_385);
  const privateOct = { kty: 'oct', padding, k: OCT_SECRET };
  const privateOctReverse = { k: OCT_SECRET, padding, kty: 'oct' };
  const privateOctLeading = { padding, kty: 'oct', k: OCT_SECRET };
  const privateJwks = { keys: [privateOct] };
  const publicEd = { kty: 'OKP', padding, crv: 'Ed25519', x: PUBLIC_X };
  const sibling = { publicKey: { kty: 'oct', padding }, unrelated: { k: OCT_SECRET } };
  return [privateOct, privateOctReverse, privateOctLeading, privateJwks, publicEd, sibling]
    .map((value) => nestedJsonString(value, 1));
}

function encodedMalformedExtensionCases() {
  const malformedEscape = `{kty:"oct",note:"\\q",k:"${OCT_SECRET}"}`;
  const literalNewline = `{kty:"oct",note:"line one\nline two",k:"${OCT_SECRET}"}`;
  const unterminatedAfterPrivate = `{kty:"oct",k:"${OCT_SECRET}",note:"unterminated`;
  const jwks = `{keys:[${malformedEscape}]}`;
  const publicMalformed = `{kty:"OKP",note:"\\q",crv:"Ed25519",x:"${PUBLIC_X}"}`;
  const sibling = `{publicKey:{kty:"oct",note:"\\q"},unrelated:{k:"${OCT_SECRET}"}}`;
  return [malformedEscape, literalNewline, unterminatedAfterPrivate, jwks, publicMalformed, sibling]
    .map((value) => JSON.stringify(value));
}

function encodedRetentionOverflowCases() {
  const padding = 'A'.repeat((1024 * 1024) + 1);
  const privateKtyFirst = `{kty:"oct",padding:"${padding}",k:"${OCT_SECRET}"}`;
  const privateKtyLast = `{k:"${OCT_SECRET}",padding:"${padding}",kty:"oct"}`;
  const privateJwks = `{keys:[${privateKtyFirst}]}`;
  const privateLeadingExtension = `{padding:"${padding}",kty:"oct",k:"${OCT_SECRET}"}`;
  const publicKey = `{kty:"OKP",padding:"${padding}",crv:"Ed25519",x:"${PUBLIC_X}"}`;
  const sibling = `{publicKey:{kty:"oct",padding:"${padding}"},unrelated:{k:"${OCT_SECRET}"}}`;
  return [privateKtyFirst, privateKtyLast, privateJwks, privateLeadingExtension, publicKey, sibling]
    .map((value) => JSON.stringify(value));
}

function nestedRetentionOverflowFactories() {
  const padding = 'A'.repeat((1024 * 1024) + 1);
  const privateFirst = `{kty:"oct",padding:"${padding}",k:"${OCT_SECRET}"}`;
  const privateLast = `{k:"${OCT_SECRET}",padding:"${padding}",kty:"oct"}`;
  const privateJwks = `{keys:[${privateFirst}]}`;
  const privateComment = `/* ${privateFirst} */`;
  const publicKey = `{kty:"OKP",padding:"${padding}",crv:"Ed25519",x:"${PUBLIC_X}"}`;
  const sibling = `{publicKey:{kty:"oct",padding:"${padding}"},unrelated:{k:"${OCT_SECRET}"}}`;
  const cases = [privateFirst, privateLast, privateJwks, privateComment, publicKey, sibling];
  return [2, 16].flatMap((layers) => cases.map((value) => () => encodeTextLayers(value, layers)));
}

function detectGeneratedCases(factories) {
  const detections = [];
  for (const create of factories) detections.push(containsPrivateJwk(Buffer.from(create())));
  return { count: detections.length, detections };
}

function positionedExtensionObject(targetBytes, leadingFields, middleFields, trailingFields) {
  const keys = Array.from({ length: 700 }, (_, index) => `ext_${String(index).padStart(3, '0')}`);
  const emptyMembers = keys.map((key) => `${JSON.stringify(key)}:""`);
  const emptyPositioned = [
    leadingFields,
    ...emptyMembers.slice(0, 350),
    middleFields,
    ...emptyMembers.slice(350),
    trailingFields,
  ].filter(Boolean);
  const fixed = `{${emptyPositioned.join(',')}}`;
  const payloadBytes = targetBytes - Buffer.byteLength(fixed);
  const baseLength = Math.floor(payloadBytes / keys.length);
  const extraValues = payloadBytes % keys.length;
  if (baseLength < 1 || baseLength > 1024) throw new Error('extension fixture member bound drift');
  const members = keys.map((key, index) => (
    `${JSON.stringify(key)}:${JSON.stringify('E'.repeat(baseLength + Number(index < extraValues)))}`
  ));
  const positioned = [
    leadingFields,
    ...members.slice(0, 350),
    middleFields,
    ...members.slice(350),
    trailingFields,
  ].filter(Boolean);
  const result = `{${positioned.join(',')}}`;
  if (Buffer.byteLength(result) !== targetBytes) throw new Error('extension fixture size drift');
  return result;
}

function boundedExtensionObject(targetBytes, leadingFields, trailingFields) {
  const result = positionedExtensionObject(targetBytes, leadingFields, '', trailingFields);
  const values = [...result.matchAll(/"ext_\d{3}":"([E]+)"/g)].map((match) => match[1].length);
  if (values.length !== 700 || Math.min(...values) < 70 || Math.max(...values) > 80) {
    throw new Error('bounded extension fixture member drift');
  }
  return result;
}

function extensionWindowCases() {
  const privateLeading = boundedExtensionObject(
    61_549,
    '"kty":"oct"',
    `"k":"${OCT_SECRET}"`,
  );
  const privateTrailing = boundedExtensionObject(
    61_549,
    `"k":"${OCT_SECRET}"`,
    '"kty":"oct"',
  );
  const publicLeading = boundedExtensionObject(
    61_563,
    `"kty":"OKP","crv":"Ed25519","x":"${PUBLIC_X}"`,
    '',
  );
  const publicTrailing = boundedExtensionObject(
    61_563,
    `"crv":"Ed25519","x":"${PUBLIC_X}"`,
    '"kty":"OKP"',
  );
  return [
    privateLeading,
    privateTrailing,
    publicLeading,
    publicTrailing,
    `${'benign prose without object delimiters '.repeat(1_700)}\nkty:"OKP"`,
  ];
}

function boundaryMatrixCases() {
  const sizes = [(96 * 1024) - 1, 96 * 1024, (96 * 1024) + 1];
  const privateCases = [];
  const publicCases = [];
  for (const size of sizes) {
    privateCases.push(
      positionedExtensionObject(size, '"kty":"oct"', '', `"k":"${OCT_SECRET}"`),
      positionedExtensionObject(size, `"k":"${OCT_SECRET}"`, '"kty":"oct"', ''),
      positionedExtensionObject(size, `"k":"${OCT_SECRET}"`, '', '"kty":"oct"'),
    );
    publicCases.push(
      positionedExtensionObject(size, `"kty":"OKP","crv":"Ed25519","x":"${PUBLIC_X}"`, '', ''),
      positionedExtensionObject(size, `"crv":"Ed25519","x":"${PUBLIC_X}"`, '"kty":"OKP"', ''),
      positionedExtensionObject(size, `"crv":"Ed25519","x":"${PUBLIC_X}"`, '', '"kty":"OKP"'),
    );
  }
  return [
    ...privateCases,
    ...publicCases,
    `${'bounded benign prose '.repeat(5_200)} kty:"OKP"`,
  ];
}

function objectAtMarkerDistance(distance, privateBefore, nestedOnly = false) {
  const privateField = nestedOnly
    ? `"extension":{"d":"${OCT_SECRET}"}`
    : `"k":"${OCT_SECRET}"`;
  const ktyField = nestedOnly
    ? `"kty":"OKP","crv":"Ed25519","x":"${PUBLIC_X}"`
    : '"kty":"oct"';
  const leading = privateBefore ? privateField : ktyField;
  const trailing = privateBefore ? ktyField : privateField;
  let targetBytes = distance + 256;
  let result = positionedExtensionObject(targetBytes, leading, '', trailing);
  const ktyIndex = result.indexOf('"kty"') + 1;
  const privateIndex = nestedOnly
    ? result.indexOf('"d"', result.indexOf('"extension"')) + 1
    : result.indexOf('"k"') + 1;
  const actualDistance = Math.abs(ktyIndex - privateIndex);
  targetBytes += distance - actualDistance;
  result = positionedExtensionObject(targetBytes, leading, '', trailing);
  const finalKtyIndex = result.indexOf('"kty"') + 1;
  const finalPrivateIndex = nestedOnly
    ? result.indexOf('"d"', result.indexOf('"extension"')) + 1
    : result.indexOf('"k"') + 1;
  if (Math.abs(finalKtyIndex - finalPrivateIndex) !== distance) {
    throw new Error('held-out marker distance drift');
  }
  return result;
}

function proseAtMarkerDistance(distance) {
  const prefix = 'kty:"OKP" ';
  const suffix = `d:"${OCT_SECRET}"`;
  const currentDistance = prefix.length;
  return `${prefix}${'P'.repeat(distance - currentDistance)}${suffix}`;
}

function heldoutDistanceCases() {
  const distances = [(96 * 1024) - 1, 96 * 1024, (96 * 1024) + 1];
  return [
    ...distances.map((distance) => objectAtMarkerDistance(distance, false)),
    ...distances.map((distance) => objectAtMarkerDistance(distance, true)),
    ...distances.map((distance) => objectAtMarkerDistance(distance, false, true)),
    ...distances.map((distance) => objectAtMarkerDistance(distance, true, true)),
    ...distances.map((distance) => proseAtMarkerDistance(distance)),
  ];
}

function malformedCorpus() {
  const endings = [']', ')', ',', ':', '/*', '// no newline', '\\', '"', "'"];
  const prefixes = ['{', 'prefix={', '[{', 'call({', '/* outer */{'];
  const cases = [];
  for (const prefix of prefixes) {
    for (const ending of endings) cases.push(`${prefix}kty:"OKP"${ending}`);
  }
  for (let index = 0; index < 512; index += 1) {
    const delimiter = endings[index % endings.length];
    cases.push(`{field${index}:{kty:"OKP"${delimiter}`);
  }
  let state = 0x5a17c0de;
  const tokens = [
    '{', '}', '[', ']', '(', ')', ',', ':', 'kty', '"OKP"', "'OKP'",
    'field', '/* comment */', '// comment\n', '\\', '"', "'", ' ', '\t', '\n',
  ];
  for (let caseIndex = 0; caseIndex < 2048; caseIndex += 1) {
    let value = 'kty';
    const tokenCount = 8 + (caseIndex % 48);
    for (let tokenIndex = 0; tokenIndex < tokenCount; tokenIndex += 1) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      value += tokens[state % tokens.length];
    }
    cases.push(value);
  }
  return cases;
}

function expensiveMalformedInput() {
  const oversizedValue = 'A'.repeat(16_384);
  return Array.from({ length: 256 }, () => `{kty:"${oversizedValue}"`).join('');
}

function retentionOverflowPrivateInput() {
  const retainedValue = 'A'.repeat(16_384);
  const ancestors = Array.from({ length: 64 }, () => `{kty:"${retainedValue}",child:`).join('');
  return `${ancestors}{kty:"oct",k:"${OCT_SECRET}"}${'}'.repeat(64)}`;
}

function run(mode) {
  if (mode === 'exact') {
    return { count: 1, detections: Number(containsPrivateJwk(Buffer.from('{kty:"OKP"]'))) };
  }
  if (mode === 'corpus') {
    const corpus = malformedCorpus();
    let detections = 0;
    for (const value of corpus) detections += Number(containsPrivateJwk(Buffer.from(value)));
    detections += Number(containsPrivateJwk(Buffer.from(expensiveMalformedInput())));
    return { count: corpus.length + 1, detections };
  }
  if (mode === 'escaped-markers') {
    return detectCases([
      `{"k\\u0074y":"oct","k":"${OCT_SECRET}"}`,
      `{"\\u006b\\u0074\\u0079":"oct","k":"${OCT_SECRET}"}`,
      `{'\\x6b\\x74\\x79':'oct',k:'${OCT_SECRET}'}`,
      `{\\u006bt\\x79:"oct",k:"${OCT_SECRET}"}`,
      `const embedded="{\\"\\\\u006b\\\\u0074\\\\u0079\\":\\"oct\\",\\"k\\":\\"${OCT_SECRET}\\"}";`,
      `const overCap=${nestedJsonString({ kty: 'oct', k: OCT_SECRET }, 6)};`,
      `const oversizedOverCap=${nestedJsonString({ kty: 'oct', k: OCT_SECRET }, 12)};`,
    ]);
  }
  if (mode === 'lexical-boundaries') {
    return detectCases([
      `{note:"literal { brace",kty:"oct",k:"${OCT_SECRET}"}`,
      `{ext:{note:"nested object"},kty:"oct",k:"${OCT_SECRET}"}`,
      `{/* fake { object } */kty:"oct",k:"${OCT_SECRET}"}`,
      `{// fake { object\nkty:"oct",k:"${OCT_SECRET}"}`,
      `{note:"multibyte π雪é",kty:"oct",k:"${OCT_SECRET}"}`,
    ]);
  }
  if (mode === 'fail-closed') {
    return detectCases([
      `{kty:"oct",k:"${'A'.repeat(16_385)}"}`,
      `{kty:"oct",note:"${'A'.repeat(16_385)}",k:"${OCT_SECRET}"}`,
      `{kty:"oct",note:"\\q",k:"${OCT_SECRET}"}`,
      `{kty:"oct",note:"\\u00G0",k:"${OCT_SECRET}"}`,
      `{kty:"oct",note:"line one\nline two",k:"${OCT_SECRET}"}`,
      `{"${'a'.repeat(16_385)}":"ignored",kty:"oct",k:"${OCT_SECRET}"}`,
      `{] unsafe resync, kty:"oct",k:"${OCT_SECRET}"}`,
    ]);
  }
  if (mode === 'truncation') {
    return detectCases([fixedLengthOctObject(true), fixedLengthOctObject(false)]);
  }
  if (mode === 'non-findings') {
    return detectCases([
      `{"\\u006b\\u0074\\u0079":"OKP","crv":"Ed25519","x":"${PUBLIC_X}"}`,
      `{note:"literal { brace and kty label",kty:"OKP",crv:"Ed25519",x:"${PUBLIC_X}"}`,
      `/* brace noise { kty label } */ const publicKey={kty:"OKP",crv:"Ed25519",x:"${PUBLIC_X}"};`,
      `{note:"multibyte π雪 {",ext:{label:"é"},kty:"OKP",crv:"Ed25519",x:"${PUBLIC_X}"}`,
      `const overCapPublic=${nestedJsonString({ kty: 'OKP', crv: 'Ed25519', x: PUBLIC_X }, 6)};`,
      `const oversizedOverCapPublic=${nestedJsonString({ kty: 'OKP', crv: 'Ed25519', x: PUBLIC_X }, 12)};`,
    ]);
  }
  if (mode === 'ceilings') {
    return detectCases([
      'kty '.repeat(1_025),
      `{kty:"oct",calculation:${'1+'.repeat(9_000)}0,k:"${OCT_SECRET}"}`,
      retentionOverflowPrivateInput(),
    ]);
  }
  if (mode === 'extension-windows') return detectCases(extensionWindowCases());
  if (mode === 'boundary-matrix') return detectCases(boundaryMatrixCases());
  if (mode === 'heldout-distances') return detectCases(heldoutDistanceCases());
  if (mode === 'escaped-identifiers') return detectCases(escapedIdentifierCases());
  if (mode === 'lost-kty-evidence') return detectCases(lostKtyEvidenceCases());
  if (mode === 'deep-object-ownership') return detectCases(deepObjectOwnershipCases());
  if (mode === 'deep-window-boundary') return detectCases(deepWindowBoundaryCases());
  if (mode === 'encoded-oversized-extension') {
    return detectCases(encodedOversizedExtensionCases());
  }
  if (mode === 'encoded-malformed-extension') {
    return detectCases(encodedMalformedExtensionCases());
  }
  if (mode === 'encoded-retention-overflow') {
    return detectCases(encodedRetentionOverflowCases());
  }
  if (mode === 'nested-retention-overflow') {
    return detectGeneratedCases(nestedRetentionOverflowFactories());
  }
  throw new Error('unknown detector worker mode');
}

try {
  process.stdout.write(`${JSON.stringify(run(process.argv[2]))}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
