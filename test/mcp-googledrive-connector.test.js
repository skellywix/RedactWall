'use strict';
/** Google Drive MCP connector must sanitize Drive content before model use. */
const test = require('node:test');
const assert = require('node:assert');
const {
  buildFileContentUrl,
  createFileContentTool,
  fetchFileContent,
  driveScopes,
  googleDriveConnectorHealth,
  sanitizeFileContent,
} = require('../sensors/mcp-guard/connectors/googledrive');

function headers(values = {}) {
  const lower = Object.fromEntries(Object.entries(values).map(([k, v]) => [k.toLowerCase(), v]));
  return { get: (name) => lower[String(name).toLowerCase()] || '' };
}

function response(text, opts = {}) {
  const status = opts.status || 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: headers({ 'content-type': opts.contentType || 'text/plain; charset=utf-8', 'content-length': opts.contentLength || String(Buffer.byteLength(text, 'utf8')) }),
    text: async () => text,
  };
}

test('buildFileContentUrl targets files.get alt=media and files.export for native docs', () => {
  assert.strictEqual(buildFileContentUrl({ fileId: 'abc123' }), 'https://www.googleapis.com/drive/v3/files/abc123?alt=media');
  assert.strictEqual(
    buildFileContentUrl({ fileId: 'doc1', mimeType: 'application/vnd.google-apps.document' }),
    'https://www.googleapis.com/drive/v3/files/doc1/export?mimeType=text%2Fplain',
  );
  assert.throws(() => buildFileContentUrl({ fileId: 'a/b' }), /opaque id/);
  assert.throws(() => buildFileContentUrl({ fileId: '' }), /fileId is required/);
  assert.throws(() => buildFileContentUrl({ fileId: 'a' }, { driveRoot: 'http://drive.test' }), /must use https/);
});

test('fetchFileContent downloads text-readable Drive content with bearer auth', async () => {
  let request;
  const result = await fetchFileContent({ fileId: 'file1' }, {
    accessToken: 'unit-drive-token',
    fetchImpl: async (url, opts = {}) => { request = { url, headers: opts.headers }; return response('Public newsletter copy.'); },
  });
  assert.match(request.url, /files\/file1\?alt=media/);
  assert.strictEqual(request.headers.Authorization, 'Bearer unit-drive-token');
  assert.strictEqual(result.content[0].text, 'Public newsletter copy.');
  assert.strictEqual(result.structuredContent.connector, 'googledrive');
});

test('fetchFileContent rejects non-text content and oversized bodies', async () => {
  await assert.rejects(fetchFileContent({ fileId: 'f' }, { accessToken: 't', fetchImpl: async () => response('x', { contentType: 'application/octet-stream' }) }), /not text-readable/);
  await assert.rejects(fetchFileContent({ fileId: 'f' }, { accessToken: 't', maxBytes: 4, fetchImpl: async () => response('too many bytes here', { contentLength: '9999' }) }), /byte limit/);
  await assert.rejects(fetchFileContent({ fileId: 'f' }, { accessToken: '', fetchImpl: async () => response('x') }), /access token is required/);
});

test('sanitizeFileContent redacts sensitive data BEFORE the model sees it', async () => {
  const sanitized = await sanitizeFileContent({ fileId: 'f' }, {
    accessToken: 't',
    fetchImpl: async () => response('Member SSN is 412-22-7843 and card 4012888888881881.'),
  });
  const text = JSON.stringify(sanitized.result);
  assert.ok(!text.includes('412-22-7843'), 'SSN must not reach the model');
  assert.ok(!text.includes('4012888888881881'), 'card must not reach the model');
  assert.ok(/\[US_SSN\]|US_SSN/.test(text) || /REDACT/i.test(text), 'redaction marker present');
});

test('connector health and scopes are sanitized metadata', () => {
  const health = googleDriveConnectorHealth({ scopes: ['https://www.googleapis.com/auth/drive.readonly'] });
  assert.ok(health && typeof health === 'object');
  assert.deepStrictEqual(driveScopes({ scopes: ['a', 'b'] }), ['a', 'b']);
  assert.ok(typeof createFileContentTool({}) === 'function');
});
