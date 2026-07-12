'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');

const apiSource = fs.readFileSync(path.join(__dirname, '..', 'console', 'src', 'lib', 'api.ts'), 'utf8');
const boundedSource = fs.readFileSync(path.join(__dirname, '..', 'console', 'src', 'lib', 'bounded-response.ts'), 'utf8');

test('console error responses use one bounded streamed decoder', () => {
  assert.match(apiSource, /ERROR_BODY_MAX_BYTES\s*=\s*8\s*\*\s*1024/);
  assert.match(apiSource, /ERROR_BODY_TIMEOUT_MS\s*=\s*2_000/);
  assert.match(apiSource, /from '\.\/bounded-response'/);
  assert.match(boundedSource, /response\.body\?\.getReader\(\)/);
  assert.match(boundedSource, /total\s*>\s*maxBytes/);
  assert.match(boundedSource, /Promise\.race\(\[reader\.read\(\), timeout\]\)/);
  assert.match(apiSource, /const errorBodyCache = new WeakMap<Response/);
  assert.match(apiSource, /const cached = errorBodyCache\.get\(response\)/);
  assert.match(apiSource, /errorBodyCache\.set\(response, pending\)/);
  assert.match(apiSource, /const body = await boundedErrorBody\(res\)/);
  assert.match(apiSource, /const body = await boundedErrorBody\(response\)/);
  assert.match(apiSource, /export async function apiJsonBounded/);
  assert.match(apiSource, /export async function responseJsonBounded/);
  assert.match(apiSource, /export async function responseBytesBounded/);
  assert.doesNotMatch(apiSource, /\.clone\(\)\.json\(/);
});

test('successful JSON responses use the bounded decoder by default', () => {
  assert.match(apiSource, /DEFAULT_JSON_BODY_MAX_BYTES\s*=\s*1024\s*\*\s*1024/);
  assert.match(apiSource, /function apiJson<[\s\S]{0,220}apiJsonBounded<T>\(path, DEFAULT_JSON_BODY_MAX_BYTES, opts\)/);
  assert.match(apiSource, /initCsrf[\s\S]{0,220}apiJsonBounded<\{ csrfToken\?: string \}>\('\/api\/csrf', 16 \* 1024\)/);
  assert.doesNotMatch(apiSource, /\.json\(\)/);
});

test('unauthenticated redirects cancel the unread response body', () => {
  assert.match(apiSource, /res\.status === 401[\s\S]{0,160}cancelResponseBody\(res\)[\s\S]{0,160}location\.href = '\/login\.html'/);
});

test('authenticated API requests reject network redirects', () => {
  assert.match(apiSource, /fetch\(path, \{ \.\.\.fetchOpts, headers, redirect: 'error' \}\)/);
});
