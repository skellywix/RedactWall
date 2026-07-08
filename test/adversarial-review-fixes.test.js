'use strict';
/**
 * Regression guards for the adversarial code review (2026-07).
 *
 * Every test below FAILS on the pre-fix tree and PASSES after the matching fix.
 * They exist so a confirmed leak/bypass can never silently come back. Finding
 * IDs match the review report. Synthetic PII only.
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const AdmZip = require('adm-zip');
const Database = require('better-sqlite3');

const D = require('../detection-engine/detect');
const processors = require('../server/processors');
const alerts = require('../server/alerts');
const integrity = require('../server/audit-integrity');

const types = (text) => D.analyze(text).findings.map((f) => f.type);
const hasType = (text, t) => types(text).includes(t);

// ---------------------------------------------------------------------------
// D1 — Unicode digit normalization. Fullwidth / Arabic-Indic digits used to
// bypass EVERY structured detector (incl. alwaysBlock) → allow in all modes.
// The fold is length-preserving so tokenize/redact offsets stay valid.
// ---------------------------------------------------------------------------
test('D1: fullwidth digits no longer bypass structured detection', () => {
  assert.ok(hasType('１２３-４５-６７８９', 'US_SSN'), 'fullwidth SSN caught');
  assert.ok(hasType('card 4111 1111 1111 1111'.replace(/[0-9]/g, (d) => String.fromCharCode(0xff10 + Number(d))), 'CREDIT_CARD'), 'fullwidth Visa caught');
});
test('D1: Arabic-Indic digits no longer bypass structured detection', () => {
  assert.ok(hasType('١٢٣-٤٥-٦٧٨٩', 'US_SSN'), 'arabic-indic SSN caught');
});
test('D1: the fold is length-preserving so tokenization still lines up', () => {
  const s = '１２３-４５-６７８９';
  const a = D.analyze(s);
  const f = a.findings.find((x) => x.type === 'US_SSN');
  assert.ok(f, 'ssn found');
  // start/end index into the ORIGINAL string; a length-preserving fold keeps
  // them valid, so the sliced span is exactly the 11-char SSN.
  assert.strictEqual(s.slice(f.start, f.end).length, '123-45-6789'.length);
});
test('D1: benign ASCII prompt is unaffected (no new false positives)', () => {
  assert.deepStrictEqual(types('please summarize the quarterly plan for the team'), []);
});

// ---------------------------------------------------------------------------
// D4 — a lowercase IBAN (an alwaysBlock type) was never detected: allow in all
// modes. The validator already accepts lowercase; only the regex casing gated.
// ---------------------------------------------------------------------------
test('D4: a lowercase IBAN is detected', () => {
  assert.ok(hasType('please wire to gb82west12345698765432 today', 'IBAN'), 'lowercase IBAN caught');
  assert.ok(hasType('International wire uses IBAN GB82 WEST 1234 5698 7654 32', 'IBAN'), 'uppercase still works');
});
test('D4: an invalid lowercase IBAN-shaped token does NOT fire (no false positive)', () => {
  assert.ok(!hasType('the seat is ab12 in row c', 'IBAN'), 'validator still gates');
});

// ---------------------------------------------------------------------------
// D3 — PRIVATE_KEY (alwaysBlock) missed ENCRYPTED / DSA PEM labels → warn-mode
// leak. Any standard PEM private-key label must hard-stop.
// ---------------------------------------------------------------------------
test('D3: ENCRYPTED / DSA private key headers hard-stop like RSA', () => {
  assert.ok(hasType('-----BEGIN ENCRYPTED PRIVATE KEY-----', 'PRIVATE_KEY'), 'ENCRYPTED');
  assert.ok(hasType('-----BEGIN DSA PRIVATE KEY-----', 'PRIVATE_KEY'), 'DSA');
  assert.ok(hasType('-----BEGIN RSA PRIVATE KEY-----', 'PRIVATE_KEY'), 'RSA (control)');
});

// ---------------------------------------------------------------------------
// N1 — the custom-detector ReDoS guard missed brace-quantified overlapping
// alternation, so `(a|aa){2,80}c` could wedge the per-keystroke hot path.
// ---------------------------------------------------------------------------
test('N1: brace-quantified overlapping alternation is rejected', () => {
  assert.strictEqual(D.normalizeCustomDetectors([{ id: 'EVILX', pattern: '(a|aa){2,80}c' }]).length, 0, 'evil pattern dropped');
});
test('N1: a well-formed bounded custom detector is still accepted', () => {
  assert.strictEqual(D.normalizeCustomDetectors([{ id: 'OKX', pattern: 'X-[0-9]{2,8}' }]).length, 1, 'legit pattern kept');
});
test('N1: analyze does not hang on the pathological input', () => {
  const started = Date.now();
  D.analyze('a'.repeat(46), { customDetectors: [{ id: 'EVILX', pattern: '(a|aa){2,80}c' }] });
  assert.ok(Date.now() - started < 2000, 'analyze returned promptly');
});

// ---------------------------------------------------------------------------
// N9 — an image-only / empty-text Office (or PDF) file extracted '' and was
// marked extractionOk:true → the file was ALLOWED instead of held for OCR.
// ---------------------------------------------------------------------------
function docx(parts) {
  const zip = new AdmZip();
  for (const [name, content] of Object.entries(parts)) zip.addFile(name, Buffer.from(content, 'utf8'));
  return zip.toBuffer();
}
test('N9: an Office file with no extractable text is held for OCR, not allowed', async () => {
  const buf = docx({ 'word/document.xml': '<w:document><w:body></w:body></w:document>' });
  const r = await processors.extractText('image-only.docx', buf);
  assert.strictEqual(r.extractionOk, false, 'empty extraction fails closed');
  assert.strictEqual(r.error, 'ocr_required', 'routed to OCR hold');
});

// ---------------------------------------------------------------------------
// N10 — PII in a Word comment / footnote / endnote was never scanned because
// those parts were outside the extraction whitelist.
// ---------------------------------------------------------------------------
test('N10: PII inside a Word comment is extracted and detected', async () => {
  const buf = docx({
    'word/document.xml': '<w:document><w:body><w:p><w:r><w:t>cover letter</w:t></w:r></w:p></w:body></w:document>',
    'word/comments.xml': '<w:comments><w:comment><w:p><w:r><w:t>reviewer note SSN 123-45-6789</w:t></w:r></w:p></w:comment></w:comments>',
  });
  const r = await processors.extractText('with-comment.docx', buf);
  assert.strictEqual(r.extractionOk, true, 'extraction succeeded');
  assert.ok(hasType(r.text, 'US_SSN'), 'SSN in the comment is caught');
});

// ---------------------------------------------------------------------------
// N4 — shadow-AI / self-block / paste-flag security events were dropped from
// SIEM whenever the prompt itself was clean (risk 0), because shouldAlert's
// status whitelist omitted them.
// ---------------------------------------------------------------------------
test('N4: clean shadow-AI / self-block / paste events still alert', () => {
  for (const status of ['shadow_ai', 'blocked_by_user', 'paste_flagged', 'proxy_observed']) {
    assert.ok(alerts.shouldAlert({ status, riskScore: 0, maxSeverity: 0 }), `${status} alerts`);
  }
});

// ---------------------------------------------------------------------------
// C3 — verifyAuditChain treated a DELETED evidence row as "unchanged", so
// bound decision evidence could vanish while the chain still verified ok.
// ---------------------------------------------------------------------------
function seededAuditDb() {
  const db = new Database(':memory:');
  db.exec('CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT NOT NULL)');
  db.exec('CREATE TABLE queries(id TEXT PRIMARY KEY, data TEXT NOT NULL)');
  const qData = { id: 'q1', status: 'pending', findings: [{ type: 'US_SSN' }], _rawPrompt: 'sealed:abc' };
  db.prepare('INSERT INTO queries(id, data) VALUES (?, ?)').run('q1', JSON.stringify(qData));
  const contentHash = integrity.sha(integrity.canonical(qData));
  const body = { id: 'a1', ts: '2026-07-01T00:00:00.000Z', prevHash: integrity.ZERO, action: 'BLOCKED', queryId: 'q1', actor: 'system', detail: 'held', contentHash };
  const entry = { ...body, hash: integrity.sha(integrity.canonical(body)) };
  db.prepare('INSERT INTO audit(entry) VALUES (?)').run(JSON.stringify(entry));
  return db;
}
test('C3: deleting a bound evidence row is detected as tampering', () => {
  const db = seededAuditDb();
  assert.strictEqual(integrity.verifyAuditChainForDatabase(db).ok, true, 'intact chain verifies');
  db.prepare('DELETE FROM queries WHERE id = ?').run('q1');
  const after = integrity.verifyAuditChainForDatabase(db);
  assert.strictEqual(after.ok, false, 'vanished evidence is a verification failure');
});

// ---------------------------------------------------------------------------
// G1 — the gateway scanned message content + message tool-call args, but NOT
// top-level tools[]/functions[] DEFINITIONS, so PII in a function description
// reached the provider. Non-string tool-call args also skipped the gate.
// ---------------------------------------------------------------------------
const canonical = require('../gateway/canonical');
const gwServer = require('../gateway/server');

test('G1: tool/function definition text is included in the scanned request text', () => {
  const body = { messages: [{ role: 'user', content: 'hi' }],
    tools: [{ type: 'function', function: { name: 'lookup', description: 'member SSN is 123-45-6789', parameters: { properties: { note: { default: 'card 4111 1111 1111 1111' } } } } }] };
  const text = canonical.requestText(body);
  assert.ok(/123-45-6789/.test(text), 'function description is scanned');
  assert.ok(/4111 1111 1111 1111/.test(text), 'parameter string is scanned');
});
test('G1: non-string tool-call arguments are treated as unscannable (fail closed)', () => {
  const body = { messages: [{ role: 'assistant', content: null, tool_calls: [{ function: { name: 'x', arguments: { ssn: '123-45-6789' } } }] }] };
  assert.strictEqual(canonical.carriesUnscannableContent(body), true, 'object tool args are unscannable');
});
test('G1: a normal string tool-call is still scannable (not over-blocked)', () => {
  const body = { messages: [{ role: 'assistant', content: null, tool_calls: [{ function: { name: 'x', arguments: '{"q":"weather"}' } }] }] };
  assert.strictEqual(canonical.carriesUnscannableContent(body), false, 'string tool args remain scannable');
});
test('G1: local redaction tokenizes PII inside a tool definition (no raw leak upstream)', () => {
  const body = { messages: [{ role: 'user', content: 'run the tool' }],
    tools: [{ type: 'function', function: { name: 'lookup', description: 'member SSN is 123-45-6789', parameters: { properties: { note: { default: 'wire GB82WEST12345698765432' } } } } }] };
  const { body: out } = gwServer.redactBodyLocally(body);
  const serialized = JSON.stringify(out);
  assert.ok(!/123-45-6789/.test(serialized), 'SSN in the tool description is tokenized');
  assert.ok(!/GB82WEST12345698765432/.test(serialized), 'IBAN in the tool parameters is tokenized');
});

// ---------------------------------------------------------------------------
// G4 — the model's response tool_calls / function_call.arguments were never
// scanned or redacted: PII the model emitted there reached the caller raw.
// ---------------------------------------------------------------------------
test('G4: response tool-call arguments are included in the scanned response text', () => {
  const resp = { choices: [{ message: { content: null, tool_calls: [{ function: { name: 'save', arguments: '{"ssn":"123-45-6789"}' } }] } }] };
  assert.ok(/123-45-6789/.test(canonical.responseText(resp)), 'tool-call args are scanned');
});
test('G4: redacting the response also rewrites tool-call arguments', () => {
  const resp = { choices: [{ message: { content: null, tool_calls: [{ function: { name: 'save', arguments: '{"ssn":"123-45-6789"}' } }] } }] };
  const out = canonical.mapResponseText(resp, (t) => t.replace(/123-45-6789/g, '[REDACTED]'));
  assert.ok(!/123-45-6789/.test(JSON.stringify(out)), 'tool-call args are redacted, not passed through');
});

// ---------------------------------------------------------------------------
// R1 — the SSRF denylist only matched dotted-quad literals, so decimal / octal
// / hex / short IPv4 encodings of loopback and the cloud-metadata address
// slipped past. (DNS-rebinding + redirect re-validation remain follow-ups.)
// ---------------------------------------------------------------------------
const urlPolicy = require('../server/url-policy');
test('R1: alternate IPv4 encodings of loopback/metadata are blocked', () => {
  for (const host of ['2130706433', '0177.0.0.1', '127.1', '0x7f.0.0.1', '0x7f000001']) {
    assert.strictEqual(urlPolicy.isBlockedHost(host), true, `${host} (loopback) blocked`);
    assert.strictEqual(urlPolicy.outboundHttpsUrl(`https://${host}/hook`), '', `${host} URL rejected`);
  }
  for (const host of ['2852039166', '0xA9FE0001', '169.254.169.254']) {
    assert.strictEqual(urlPolicy.isBlockedHost(host), true, `${host} (metadata/link-local) blocked`);
  }
});
test('R1: legitimate public and RFC1918 hosts are still allowed', () => {
  for (const host of ['example.com', '8.8.8.8', '10.0.0.5', '192.168.1.10', '172.16.4.4']) {
    assert.strictEqual(urlPolicy.isBlockedHost(host), false, `${host} allowed`);
  }
  assert.ok(urlPolicy.outboundHttpsUrl('https://siem.internal.example.com/ingest'), 'internal SIEM host allowed');
});

// ---------------------------------------------------------------------------
// E1 — the server trusted a sensor-supplied `masked` string verbatim on the
// pre-redacted / proxy ingest paths, so a non-conforming sensor could smuggle a
// raw value into SIEM/evidence through the `masked` field.
// ---------------------------------------------------------------------------
const validation = require('../server/validation');
const hasPii = (s) => D.analyze(s).findings.length > 0;
test('E1: a client masked value that still contains PII is dropped', () => {
  assert.strictEqual(validation.sanitizeClientMask('123-45-6789', hasPii), undefined, 'raw SSN dropped');
  assert.strictEqual(validation.sanitizeClientMask('4111 1111 1111 1111', hasPii), undefined, 'raw card dropped');
});
test('E1: a conforming masked value passes through unchanged', () => {
  assert.strictEqual(validation.sanitizeClientMask('•••• 6789', hasPii), '•••• 6789');
  assert.strictEqual(validation.sanitizeClientMask('j***@example.com', hasPii), 'j***@example.com');
  assert.strictEqual(validation.sanitizeClientMask(undefined, hasPii), undefined);
});
