'use strict';
/** Google Drive MCP connector must sanitize Drive content before model use. */
const test = require('node:test');
const assert = require('node:assert');
const {
  buildDriveFileExportUrl,
  buildDriveFileMediaUrl,
  buildDriveFileMetadataUrl,
  createDriveFileContentTool,
  driveFileMetadata,
  driveScopes,
  exportMimeTypeFor,
  fetchDriveFileContent,
  googleDriveConnectorHealth,
  sanitizeDriveFileContent,
} = require('../sensors/mcp-guard/connectors/google-drive');

function headers(values = {}) {
  const lower = Object.fromEntries(Object.entries(values).map(([key, value]) => [key.toLowerCase(), value]));
  return { get: (name) => lower[String(name).toLowerCase()] || '' };
}

function response(text, opts = {}) {
  const status = opts.status || 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: headers({
      'content-type': opts.contentType || 'text/plain; charset=utf-8',
      'content-length': opts.contentLength || String(Buffer.byteLength(text, 'utf8')),
    }),
    text: async () => text,
    json: async () => JSON.parse(text),
  };
}

function streamResponse(chunks, opts = {}) {
  const encoder = new TextEncoder();
  const encoded = chunks.map((chunk) => encoder.encode(chunk));
  let index = 0;
  return {
    ok: true,
    status: 200,
    headers: headers({
      'content-type': opts.contentType || 'text/plain',
      'content-length': opts.contentLength || '',
    }),
    body: {
      getReader: () => ({
        read: async () => {
          if (index >= encoded.length) return { done: true };
          return { done: false, value: encoded[index++] };
        },
      }),
    },
  };
}

test('buildDriveFile URLs target Drive API and encode opaque ids only', () => {
  assert.strictEqual(
    buildDriveFileMetadataUrl({ fileId: 'file with spaces' }, { driveRoot: 'https://www.googleapis.com/drive/v3/' }),
    'https://www.googleapis.com/drive/v3/files/file%20with%20spaces?fields=id,mimeType,name,size,modifiedTime'
  );
  assert.strictEqual(
    buildDriveFileMediaUrl({ fileId: 'file_123' }),
    'https://www.googleapis.com/drive/v3/files/file_123?alt=media'
  );
  assert.strictEqual(
    buildDriveFileExportUrl({ fileId: 'doc_123', mimeType: 'application/vnd.google-apps.spreadsheet' }),
    'https://www.googleapis.com/drive/v3/files/doc_123/export?mimeType=text%2Fcsv'
  );

  assert.throws(() => buildDriveFileMediaUrl({ fileId: 'folder/file' }), /opaque id/);
  assert.throws(() => buildDriveFileMediaUrl({ fileId: '' }), /fileId is required/);
  assert.throws(() => buildDriveFileMediaUrl({ fileId: 'file' }, { driveRoot: 'http://drive.test/v3' }), /must use https/);
});

test('fetchDriveFileContent exports Google Workspace documents after metadata lookup', async () => {
  const requests = [];
  const result = await fetchDriveFileContent({ fileId: 'doc1' }, {
    accessToken: 'unit-google-token',
    fetchImpl: async (url, opts = {}) => {
      requests.push({ url, headers: opts.headers });
      if (url.includes('fields=id')) {
        return response(JSON.stringify({ mimeType: 'application/vnd.google-apps.document', name: 'Member Notes' }), {
          contentType: 'application/json',
        });
      }
      return response('Public branch hours.');
    },
  });

  assert.deepStrictEqual(requests.map((item) => item.url), [
    'https://www.googleapis.com/drive/v3/files/doc1?fields=id,mimeType,name,size,modifiedTime',
    'https://www.googleapis.com/drive/v3/files/doc1/export?mimeType=text%2Fplain',
  ]);
  assert.strictEqual(requests[0].headers.Authorization, 'Bearer unit-google-token');
  assert.strictEqual(requests[1].headers.Authorization, 'Bearer unit-google-token');
  assert.strictEqual(result.content[0].text, 'Public branch hours.');
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'google_drive',
    operation: 'files.export',
    contentType: 'text/plain',
    sizeBytes: 20,
    transferMode: 'export',
    mimeType: 'application/vnd.google-apps.document',
  });
});

test('fetchDriveFileContent downloads text-readable blob files with alt media', async () => {
  let request;
  const result = await fetchDriveFileContent({
    fileId: 'file1',
    mimeType: 'text/plain',
  }, {
    accessToken: 'unit-google-token',
    fetchImpl: async (url, opts = {}) => {
      request = { url, headers: opts.headers };
      return streamResponse(['branch ', 'hours']);
    },
  });

  assert.strictEqual(request.url, 'https://www.googleapis.com/drive/v3/files/file1?alt=media');
  assert.strictEqual(request.headers.Authorization, 'Bearer unit-google-token');
  assert.strictEqual(result.content[0].text, 'branch hours');
  assert.strictEqual(result.structuredContent.operation, 'files.get');
  assert.strictEqual(result.structuredContent.sizeBytes, 12);
});

test('driveFileMetadata supports injected fetch and keeps metadata separate from content output', async () => {
  const metadata = await driveFileMetadata({ fileId: 'meta1' }, {
    accessToken: 'unit-google-token',
    fetchImpl: async () => response(JSON.stringify({
      id: 'meta1',
      mimeType: 'text/plain',
      name: 'Private Customer File',
    }), { contentType: 'application/json' }),
  });
  assert.strictEqual(metadata.mimeType, 'text/plain');
  assert.strictEqual(metadata.name, 'Private Customer File');
});

test('sanitizeDriveFileContent redacts Drive content before returning MCP output', async () => {
  let outbound;
  const sanitized = await sanitizeDriveFileContent({
    fileId: 'doc1',
    mimeType: 'application/vnd.google-apps.document',
  }, {
    accessToken: 'unit-google-token',
    fetchImpl: async (url) => {
      assert.ok(url.includes('/export?mimeType=text%2Fplain'));
      return response('Google Drive record: SSN 524-71-9043 and card 4111 1111 1111 1111.');
    },
    guardOptions: {
      server: 'http://sentinel.test',
      key: 'unit-ingest-key',
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async (url, opts = {}) => {
        outbound = { url, body: JSON.parse(opts.body), headers: opts.headers };
        return { ok: true };
      },
    },
  });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(sanitized.findings.includes('CREDIT_CARD'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.ok(!JSON.stringify(sanitized.result).includes('4111 1111 1111 1111'));
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'google_drive.files.export');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));
  assert.ok(!JSON.stringify(outbound.body).includes('4111 1111 1111 1111'));
  assert.ok(!JSON.stringify(outbound.body).includes('unit-google-token'));
});

test('createDriveFileContentTool returns sanitized MCP result only', async () => {
  const tool = createDriveFileContentTool({
    accessToken: 'unit-google-token',
    fetchImpl: async () => response('Member SSN 524-71-9043.'),
    guardOptions: {
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async () => ({ ok: true }),
    },
  });

  const result = await tool({ fileId: 'file1', mimeType: 'text/plain' });
  assert.ok(result.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(result).includes('524-71-9043'));
});

test('connector refuses unsupported or oversized Drive content without leaking body data', async () => {
  await assert.rejects(
    () => fetchDriveFileContent({ fileId: 'file1', mimeType: 'text/plain' }, {
      accessToken: 'unit-google-token',
      fetchImpl: async () => response('SSN 524-71-9043', { status: 403 }),
    }),
    (err) => {
      assert.match(err.message, /HTTP 403/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('unit-google-token'));
      return true;
    }
  );

  await assert.rejects(
    () => fetchDriveFileContent({ fileId: 'file1', mimeType: 'application/octet-stream' }, {
      accessToken: 'unit-google-token',
      fetchImpl: async () => response('SSN 524-71-9043', { contentType: 'application/octet-stream' }),
    }),
    (err) => {
      assert.match(err.message, /not text-readable/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('unit-google-token'));
      return true;
    }
  );

  await assert.rejects(
    () => fetchDriveFileContent({ fileId: 'file1', mimeType: 'text/plain' }, {
      accessToken: 'unit-google-token',
      maxBytes: 4,
      fetchImpl: async () => response('public body', { contentLength: '999' }),
    }),
    /exceeds 4 byte limit/
  );
});

test('Drive connector errors and health evidence are secret-free', async () => {
  await assert.rejects(
    () => fetchDriveFileContent({ fileId: 'file1', mimeType: 'text/plain' }, {
      env: {},
      fetchImpl: async () => response('unused'),
    }),
    /access token is required/
  );

  const check = googleDriveConnectorHealth({
    workspaceDomain: 'cu.example',
    scopes: ['https://www.googleapis.com/auth/drive.readonly'],
    accessToken: 'should-not-appear',
  }, true, 'OAuth probe ok');

  assert.strictEqual(check.id, 'mcp_connector_google_drive');
  assert.strictEqual(check.ok, true);
  assert.ok(check.detail.includes('tenant:cu.example'));
  assert.ok(check.detail.includes('scopes:1'));
  assert.ok(!JSON.stringify(check).includes('should-not-appear'));
});

test('driveScopes defaults to least-privileged read-only Drive scope', () => {
  assert.deepStrictEqual(driveScopes({ env: {} }), ['https://www.googleapis.com/auth/drive.readonly']);
  assert.deepStrictEqual(driveScopes({ env: { GOOGLE_DRIVE_SCOPES: 'drive.readonly drive.metadata.readonly' } }), ['drive.readonly', 'drive.metadata.readonly']);
  assert.strictEqual(exportMimeTypeFor('application/vnd.google-apps.spreadsheet'), 'text/csv');
});
