'use strict';
/** Microsoft 365 MCP connector must sanitize Graph content before model use. */
const test = require('node:test');
const assert = require('node:assert');
const {
  buildDriveItemContentUrl,
  buildListItemUrl,
  buildSitePageUrl,
  createDriveItemContentTool,
  createListItemFieldsTool,
  createSitePageContentTool,
  fetchDriveItemContent,
  fetchListItemFields,
  fetchSitePageContent,
  graphScopes,
  microsoft365ConnectorHealth,
  sanitizeDriveItemContent,
  sanitizeListItemFields,
  sanitizeSitePageContent,
} = require('../sensors/mcp-guard/connectors/microsoft365');

const SITE_ID = 'contoso.sharepoint.com,b6f9a1c2-1111-2222-3333-444455556666,7788aabb-9900-1122-3344-556677889900';
const PAGE_ID = 'a1b2c3d4-1111-2222-3333-abcdefabcdef';
const LIST_ID = 'e5f6a7b8-4444-5555-6666-777788889999';

function jsonResponse(value, opts = {}) {
  return response(JSON.stringify(value), { contentType: 'application/json', ...opts });
}

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
      server: 'http://sentinel.test',
      key: 'unit-ingest-key',
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

  const defaults = microsoft365ConnectorHealth({ env: {}, tenantId: 'cu-acme' });
  assert.ok(defaults.detail.includes('driveItem.getContent'));
  assert.ok(defaults.detail.includes('sites.page.get'));
  assert.ok(defaults.detail.includes('sites.listItem.get'));
});

test('graphScopes defaults to least-privileged delegated file read scope', () => {
  assert.deepStrictEqual(graphScopes({ env: {} }), ['Files.Read']);
  assert.deepStrictEqual(graphScopes({ env: { M365_GRAPH_SCOPES: 'Files.Read.All Sites.Selected' } }), ['Files.Read.All', 'Sites.Selected']);
});

test('buildSitePageUrl and buildListItemUrl target SharePoint Graph resources with strict ids', () => {
  assert.strictEqual(
    buildSitePageUrl({ siteId: SITE_ID, pageId: PAGE_ID }, { graphRoot: 'https://graph.microsoft.com/v1.0/' }),
    `https://graph.microsoft.com/v1.0/sites/${SITE_ID}/pages/${PAGE_ID}/microsoft.graph.sitePage?$expand=canvasLayout`
  );
  assert.strictEqual(
    buildListItemUrl({ siteId: SITE_ID, listId: LIST_ID, itemId: '42' }),
    `https://graph.microsoft.com/v1.0/sites/${SITE_ID}/lists/${LIST_ID}/items/42?$expand=fields`
  );

  assert.throws(() => buildSitePageUrl({ siteId: 'sites/../root', pageId: PAGE_ID }), /siteId contains unsupported characters/);
  assert.throws(() => buildSitePageUrl({ siteId: '..', pageId: PAGE_ID }), /siteId contains unsupported characters/);
  assert.throws(() => buildSitePageUrl({ siteId: '', pageId: PAGE_ID }), /siteId is required/);
  assert.throws(() => buildSitePageUrl({ siteId: SITE_ID, pageId: '../../etc/passwd' }), /pageId must be a numeric or GUID id/);
  assert.throws(() => buildListItemUrl({ siteId: SITE_ID, listId: 'not a guid', itemId: '42' }), /listId must be a numeric or GUID id/);
  assert.throws(() => buildListItemUrl({ siteId: SITE_ID, listId: LIST_ID, itemId: '42;drop' }), /itemId must be a numeric or GUID id/);
  assert.throws(
    () => buildSitePageUrl({ siteId: SITE_ID, pageId: PAGE_ID }, { graphRoot: 'http://graph.test/v1.0' }),
    /must use https/
  );
});

test('fetchSitePageContent extracts canvasLayout web part text with bearer auth', async () => {
  let request;
  const result = await fetchSitePageContent({ siteId: SITE_ID, pageId: PAGE_ID }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async (url, opts = {}) => {
      request = { url, headers: opts.headers };
      return jsonResponse({
        title: 'Member Onboarding',
        canvasLayout: {
          horizontalSections: [{ columns: [{ webparts: [
            { '@odata.type': '#microsoft.graph.textWebPart', innerHtml: '<p>Welcome &amp; branch hours</p>' },
          ] }] }],
          verticalSection: { webparts: [{ innerHtml: '<div>Contact operations</div>' }] },
        },
      });
    },
  });

  assert.strictEqual(request.url, `https://graph.microsoft.com/v1.0/sites/${SITE_ID}/pages/${PAGE_ID}/microsoft.graph.sitePage?$expand=canvasLayout`);
  assert.strictEqual(request.headers.Authorization, 'Bearer unit-graph-token');
  const expected = 'Title: Member Onboarding\n\nWelcome & branch hours\n\nContact operations';
  assert.strictEqual(result.content[0].text, expected);
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'microsoft365',
    operation: 'sites.page.get',
    contentType: 'text/plain',
    sizeBytes: Buffer.byteLength(expected, 'utf8'),
    webPartCount: 2,
  });
});

test('fetchListItemFields serializes value fields and excludes system fields', async () => {
  let request;
  const result = await fetchListItemFields({ siteId: SITE_ID, listId: LIST_ID, itemId: '42' }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async (url, opts = {}) => {
      request = { url, headers: opts.headers };
      return jsonResponse({
        id: '42',
        fields: {
          '@odata.etag': 'etag-should-not-appear',
          id: '42',
          ContentType: 'Item',
          Edit: '',
          LinkTitle: 'Lobby',
          LinkTitleNoMenu: 'Lobby',
          Title: 'Branch lobby hours',
          Hours: 'Mon-Fri 9-5',
          Seats: 24,
          Open: true,
          Details: { nested: 'objects are skipped' },
        },
      });
    },
  });

  assert.strictEqual(request.url, `https://graph.microsoft.com/v1.0/sites/${SITE_ID}/lists/${LIST_ID}/items/42?$expand=fields`);
  assert.strictEqual(request.headers.Authorization, 'Bearer unit-graph-token');
  const expected = 'Title: Branch lobby hours\nHours: Mon-Fri 9-5\nSeats: 24\nOpen: true';
  assert.strictEqual(result.content[0].text, expected);
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'microsoft365',
    operation: 'sites.listItem.get',
    contentType: 'text/plain',
    sizeBytes: Buffer.byteLength(expected, 'utf8'),
    fieldCount: 4,
  });
  assert.ok(!JSON.stringify(result).includes('etag-should-not-appear'));
  assert.ok(!JSON.stringify(result).includes('Lobby'));
  assert.ok(!JSON.stringify(result).includes('objects are skipped'));
});

test('sanitizeSitePageContent redacts SharePoint page text before returning MCP output', async () => {
  let outbound;
  const sanitized = await sanitizeSitePageContent({ siteId: SITE_ID, pageId: PAGE_ID }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async () => jsonResponse({
      title: 'Member Record',
      canvasLayout: {
        horizontalSections: [{ columns: [{ webparts: [
          { innerHtml: '<p>Member SSN 524-71-9043 on file.</p>' },
        ] }] }],
      },
    }),
    guardOptions: {
      server: 'http://sentinel.test',
      key: 'unit-ingest-key',
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async (url, opts = {}) => {
        outbound = { url, body: JSON.parse(opts.body) };
        return { ok: true };
      },
    },
  });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'microsoft365.sites.page.get');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));
  assert.ok(!JSON.stringify(outbound.body).includes('unit-graph-token'));
});

test('sanitizeListItemFields redacts SharePoint list item fields before returning MCP output', async () => {
  let outbound;
  const sanitized = await sanitizeListItemFields({ siteId: SITE_ID, listId: LIST_ID, itemId: '42' }, {
    accessToken: 'unit-graph-token',
    fetchImpl: async () => jsonResponse({
      fields: { Title: 'Member record', MemberSSN: 'SSN 524-71-9043' },
    }),
    guardOptions: {
      server: 'http://sentinel.test',
      key: 'unit-ingest-key',
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async (url, opts = {}) => {
        outbound = { url, body: JSON.parse(opts.body) };
        return { ok: true };
      },
    },
  });

  assert.strictEqual(sanitized.redacted, true);
  assert.ok(sanitized.findings.includes('US_SSN'));
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.strictEqual(outbound.url, 'http://sentinel.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'microsoft365.sites.listItem.get');
  assert.ok(!JSON.stringify(outbound.body).includes('524-71-9043'));
  assert.ok(!JSON.stringify(outbound.body).includes('unit-graph-token'));
});

test('createSitePageContentTool and createListItemFieldsTool return sanitized MCP results only', async () => {
  const guardOptions = {
    server: 'http://sentinel.test',
    key: 'unit-ingest-key',
    policy: { ignore: [], disabledDetectors: [] },
    fetchImpl: async () => ({ ok: true }),
  };

  const pageTool = createSitePageContentTool({
    accessToken: 'unit-graph-token',
    fetchImpl: async () => jsonResponse({
      canvasLayout: { horizontalSections: [{ columns: [{ webparts: [{ innerHtml: '<p>Member SSN 524-71-9043.</p>' }] }] }] },
    }),
    guardOptions,
  });
  const pageResult = await pageTool({ siteId: SITE_ID, pageId: PAGE_ID });
  assert.ok(pageResult.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(pageResult).includes('524-71-9043'));

  const itemTool = createListItemFieldsTool({
    accessToken: 'unit-graph-token',
    fetchImpl: async () => jsonResponse({ fields: { MemberSSN: 'SSN 524-71-9043' } }),
    guardOptions,
  });
  const itemResult = await itemTool({ siteId: SITE_ID, listId: LIST_ID, itemId: '42' });
  assert.ok(itemResult.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(itemResult).includes('524-71-9043'));
});

test('SharePoint operations refuse failed, error, or oversized responses without leaking data', async () => {
  await assert.rejects(
    () => fetchSitePageContent({ siteId: SITE_ID, pageId: PAGE_ID }, {
      accessToken: 'unit-graph-token',
      fetchImpl: async () => jsonResponse({ note: 'SSN 524-71-9043' }, { status: 403 }),
    }),
    (err) => {
      assert.match(err.message, /sites\.page\.get failed with HTTP 403/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('unit-graph-token'));
      return true;
    }
  );

  await assert.rejects(
    () => fetchListItemFields({ siteId: SITE_ID, listId: LIST_ID, itemId: '42' }, {
      accessToken: 'unit-graph-token',
      fetchImpl: async () => jsonResponse({ error: { code: 'accessDenied', message: 'secret detail 524-71-9043' } }),
    }),
    (err) => {
      assert.match(err.message, /sites\.listItem\.get failed: accessDenied/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('secret detail'));
      return true;
    }
  );

  await assert.rejects(
    () => fetchSitePageContent({ siteId: SITE_ID, pageId: PAGE_ID }, {
      accessToken: 'unit-graph-token',
      maxBytes: 4,
      fetchImpl: async () => jsonResponse({ title: 'public' }, { contentLength: '999' }),
    }),
    /exceeds 4 byte limit/
  );

  await assert.rejects(
    () => fetchListItemFields({ siteId: SITE_ID, listId: LIST_ID, itemId: '42' }, {
      env: {},
      fetchImpl: async () => jsonResponse({}),
    }),
    /access token is required/
  );
});
