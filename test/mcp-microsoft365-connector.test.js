'use strict';
/** Microsoft 365 MCP connector must sanitize Graph content before model use. */
const test = require('node:test');
const assert = require('node:assert');
const {
  buildDriveItemContentUrl,
  createDriveItemContentTool,
  fetchDriveItemContent,
  graphScopes,
  microsoft365ConnectorHealth,
  sanitizeDriveItemContent,
} = require('../sensors/mcp-guard/connectors/microsoft365');

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

test('buildDriveItemContentUrl targets Graph driveItem content and encodes ids', () => {
  assert.strictEqual(
    buildDriveItemContentUrl({
      driveId: 'drive!id',
      itemId: 'item with spaces',
    }, {
      graphRoot: 'https://graph.microsoft.com/v1.0/',
    }),
    'https://graph.microsoft.com/v1.0/drives/drive!id/items/item%20with%20spaces/content'
  );

  assert.throws(() => buildDriveItemContentUrl({ driveId: 'drive/path', itemId: 'item' }), /opaque id/);
  assert.throws(() => buildDriveItemContentUrl({ driveId: 'drive', itemId: '' }), /itemId is required/);
  assert.throws(
    () => buildDriveItemContentUrl({ driveId: 'drive', itemId: 'item' }, { graphRoot: 'http://graph.test/v1.0' }),
    /must use https/
  );
});

test('fetchDriveItemContent downloads text-readable Graph file content with bearer auth', async () => {
  let request;
  const result = await fetchDriveItemContent({
    driveId: 'drive1',
    itemId: 'item1',
  }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async (url, opts = {}) => {
      request = { url, headers: opts.headers };
      return response('Public branch hours.');
    },
  });

  assert.strictEqual(request.url, 'https://graph.microsoft.com/v1.0/drives/drive1/items/item1/content');
  assert.strictEqual(request.headers.Authorization, 'Bearer unit-graph-token');
  assert.strictEqual(result.content[0].text, 'Public branch hours.');
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'microsoft365',
    operation: 'driveItem.getContent',
    contentType: 'text/plain',
    sizeBytes: 20,
  });
});

test('fetchDriveItemContent reads bounded streaming and arrayBuffer Graph responses', async () => {
  const streamed = await fetchDriveItemContent({
    driveId: 'drive-stream',
    itemId: 'item-stream',
  }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async () => streamResponse(['branch ', 'hours']),
  });
  assert.strictEqual(streamed.content[0].text, 'branch hours');
  assert.strictEqual(streamed.structuredContent.sizeBytes, 12);

  const buffered = await fetchDriveItemContent({
    driveId: 'drive-buffer',
    itemId: 'item-buffer',
  }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      headers: headers({ 'content-type': 'application/json' }),
      arrayBuffer: async () => Buffer.from('{"status":"public"}', 'utf8'),
    }),
  });
  assert.strictEqual(buffered.content[0].text, '{"status":"public"}');
  assert.strictEqual(buffered.structuredContent.contentType, 'application/json');
  assert.strictEqual(buffered.structuredContent.sizeBytes, 19);
});

test('sanitizeDriveItemContent redacts Graph content before returning MCP output', async () => {
  let graphRequest;
  let outbound;
  const sanitized = await sanitizeDriveItemContent({
    driveId: 'drive1',
    itemId: 'item1',
  }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async (url, opts = {}) => {
      graphRequest = { url, headers: opts.headers };
      return response('SharePoint record: SSN 524-71-9043 and card 4111 1111 1111 1111.');
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

  assert.strictEqual(graphRequest.headers.Authorization, 'Bearer unit-graph-token');
  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(sanitized.findings.includes('CREDIT_CARD'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.ok(!JSON.stringify(sanitized.result).includes('4111 1111 1111 1111'));
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'microsoft365.driveItem.getContent');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));
  assert.ok(!JSON.stringify(outbound.body).includes('4111 1111 1111 1111'));
  assert.ok(!JSON.stringify(outbound.body).includes('unit-graph-token'));
});

test('createDriveItemContentTool returns sanitized MCP result only', async () => {
  const tool = createDriveItemContentTool({
    accessToken: 'unit-graph-token',
    fetchImpl: async () => response('Member SSN 524-71-9043.'),
    guardOptions: {
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async () => ({ ok: true }),
    },
  });

  const result = await tool({ driveId: 'drive1', itemId: 'item1' });
  assert.ok(result.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(result).includes('524-71-9043'));
});

test('connector refuses unsupported or oversized content without returning body data', async () => {
  await assert.rejects(
    () => fetchDriveItemContent({ driveId: 'drive1', itemId: 'item1' }, {
      accessToken: 'unit-graph-token',
      fetchImpl: async () => response('SSN 524-71-9043', { status: 403 }),
    }),
    (err) => {
      assert.match(err.message, /HTTP 403/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('unit-graph-token'));
      return true;
    }
  );

  await assert.rejects(
    () => fetchDriveItemContent({ driveId: 'drive1', itemId: 'item1' }, {
      accessToken: 'unit-graph-token',
      fetchImpl: async () => response('SSN 524-71-9043', { contentType: 'application/octet-stream' }),
    }),
    (err) => {
      assert.match(err.message, /not text-readable/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('unit-graph-token'));
      return true;
    }
  );

  await assert.rejects(
    () => fetchDriveItemContent({ driveId: 'drive1', itemId: 'item1' }, {
      accessToken: 'unit-graph-token',
      maxBytes: 4,
      fetchImpl: async () => response('public body', { contentLength: '999' }),
    }),
    /exceeds 4 byte limit/
  );
});

test('connector errors and health evidence are secret-free', async () => {
  await assert.rejects(
    () => fetchDriveItemContent({ driveId: 'drive1', itemId: 'item1' }, {
      env: {},
      fetchImpl: async () => response('unused'),
    }),
    /access token is required/
  );

  const check = microsoft365ConnectorHealth({
    tenantId: 'cu-acme',
    scopes: ['Files.Read', 'Sites.Selected'],
    accessToken: 'should-not-appear',
  }, true, 'OAuth probe ok');

  assert.strictEqual(check.id, 'mcp_connector_microsoft_365_graph');
  assert.strictEqual(check.ok, true);
  assert.ok(check.detail.includes('tenant:cu-acme'));
  assert.ok(check.detail.includes('scopes:2'));
  assert.ok(!JSON.stringify(check).includes('should-not-appear'));
});

test('graphScopes defaults to least-privileged delegated file read scope', () => {
  assert.deepStrictEqual(graphScopes({ env: {} }), ['Files.Read']);
  assert.deepStrictEqual(graphScopes({ env: { M365_GRAPH_SCOPES: 'Files.Read.All Sites.Selected' } }), ['Files.Read.All', 'Sites.Selected']);
});
