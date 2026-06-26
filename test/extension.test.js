'use strict';
/** Static regression checks for MV3 extension wiring. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const content = fs.readFileSync(path.join(root, 'extension', 'content.js'), 'utf8');
const background = fs.readFileSync(path.join(root, 'extension', 'background.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'extension', 'manifest.json'), 'utf8'));

test('redacted browser sends report tokenized text, not original prompt', () => {
  assert.match(content, /report\(t\.text,\s*verdict\.analysis,\s*'submit',\s*'redacted_sent'/);
  assert.doesNotMatch(content, /report\(text,\s*verdict\.analysis,\s*'submit',\s*'redacted_sent'/);
  assert.match(content, /clientPreRedacted:\s*true/);
  assert.match(background, /clientFindings:\s*msg\.payload\.clientFindings/);
});

test('redact mode blocks category-only hits that cannot be tokenized', () => {
  assert.match(content, /action:\s*a\.findings\.length \? 'redact' : 'block'/);
});

test('active content scripts receive policy updates from storage', () => {
  assert.match(content, /if \(c\.policy\) POLICY = \{ \.\.\.POLICY, \.\.\.c\.policy\.newValue \};/);
});

test('browser file uploads use scan-file API with base64 content', () => {
  assert.match(content, /type:\s*'scanFile'/);
  assert.match(content, /contentBase64:\s*bytesToBase64/);
  assert.match(background, /\/api\/v1\/scan-file/);
});

test('manifest grants alarms permission used for policy refresh', () => {
  assert.ok(manifest.permissions.includes('alarms'));
});
