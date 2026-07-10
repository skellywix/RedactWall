'use strict';
/** Slack MCP connector must sanitize Slack messages and files before model use. */
const test = require('node:test');
const assert = require('node:assert');
const {
  buildConversationHistoryUrl,
  buildFileInfoUrl,
  createSlackConversationHistoryTool,
  createSlackFileContentTool,
  fetchConversationHistory,
  fetchSlackFileContent,
  isAllowedSlackFileUrl,
  messagesToText,
  sanitizeConversationHistory,
  sanitizeSlackFileContent,
  slackConnectorHealth,
  slackScopes,
} = require('../sensors/mcp-guard/connectors/slack');

function headers(values = {}) {
  const lower = Object.fromEntries(Object.entries(values).map(([key, value]) => [key.toLowerCase(), value]));
  return { get: (name) => lower[String(name).toLowerCase()] || '' };
}

function response(text, opts = {}) {
  const status = opts.status || 200;
  return new Response(text, {
    status,
    headers: {
      'content-type': opts.contentType || 'text/plain; charset=utf-8',
      'content-length': opts.contentLength || String(Buffer.byteLength(text, 'utf8')),
    },
  });
}

function jsonResponse(body, opts = {}) {
  return response(JSON.stringify(body), { ...opts, contentType: 'application/json' });
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

test('Slack URL builders target official methods and reject unsafe ids', () => {
  assert.strictEqual(
    buildConversationHistoryUrl({
      channel: 'C123',
      limit: 999,
      cursor: 'next_cursor',
      oldest: '1719940000.123456',
      inclusive: true,
    }, { slackRoot: 'https://slack.test/api/' }),
    'https://slack.test/api/conversations.history?channel=C123&limit=100&cursor=next_cursor&oldest=1719940000.123456&inclusive=true'
  );
  assert.strictEqual(
    buildFileInfoUrl({ fileId: 'F123' }),
    'https://slack.com/api/files.info?file=F123'
  );

  assert.throws(() => buildConversationHistoryUrl({ channel: 'C123/../../admin' }), /opaque id/);
  assert.throws(() => buildFileInfoUrl({ fileId: '' }), /file is required/);
  assert.throws(() => buildConversationHistoryUrl({ channel: 'C123', oldest: 'yesterday' }), /Slack oldest/);
  assert.throws(() => buildFileInfoUrl({ fileId: 'F123' }, { slackRoot: 'http://slack.test/api' }), /must use https/);
});

test('fetchConversationHistory reads Slack messages without exposing Slack metadata ids', async () => {
  let request;
  const result = await fetchConversationHistory({ channel: 'C123', limit: 15 }, {
    accessToken: 'fixture-unit-slack-token',
    fetchImpl: async (url, opts = {}) => {
      request = { url, headers: opts.headers };
      return jsonResponse({
        ok: true,
        has_more: true,
        messages: [
          { user: 'U111', ts: '1719940000.111111', text: 'Loan queue for <@U222> is clear.' },
          { user: 'U333', ts: '1719940001.111111', text: 'Branch hours are public.' },
        ],
      });
    },
  });

  assert.strictEqual(request.url, 'https://slack.com/api/conversations.history?channel=C123&limit=15');
  assert.strictEqual(request.headers.Authorization, 'Bearer fixture-unit-slack-token');
  assert.strictEqual(result.content[0].text, 'Loan queue for [slack_user] is clear.\n\nBranch hours are public.');
  assert.ok(!JSON.stringify(result).includes('U222'));
  assert.ok(!JSON.stringify(result).includes('C123'));
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'slack',
    operation: 'conversations.history',
    contentType: 'text/plain',
    sizeBytes: 63,
    messageCount: 2,
    hasMore: true,
  });
});

test('sanitizeConversationHistory redacts Slack message text before returning MCP output', async () => {
  let outbound;
  const sanitized = await sanitizeConversationHistory({ channel: 'C999' }, {
    accessToken: 'fixture-unit-slack-token',
    fetchImpl: async () => jsonResponse({
      ok: true,
      messages: [
        { text: 'Slack paste: SSN 524-71-9043 and card 4111 1111 1111 1111.' },
      ],
    }),
    guardOptions: {
      server: 'https://redactwall.test',
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
  assert.strictEqual(outbound.url, 'https://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'slack.conversations.history');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.ok(!JSON.stringify(outbound.body).includes('fixture-unit-slack-token'));
});

test('Slack file connector downloads only allowed private Slack text URLs', async () => {
  const requests = [];
  const result = await fetchSlackFileContent({ fileId: 'F123' }, {
    accessToken: 'fixture-unit-slack-token',
    fetchImpl: async (url, opts = {}) => {
      requests.push({ url, headers: opts.headers, redirect: opts.redirect });
      if (url.includes('/files.info')) {
        return jsonResponse({
          ok: true,
          file: {
            mimetype: 'text/plain',
            url_private: 'https://files.slack.com/files-pri/T123-F123/member-note.txt',
          },
        });
      }
      assert.strictEqual(url, 'https://files.slack.com/files-pri/T123-F123/member-note.txt');
      return streamResponse(['public ', 'branch note']);
    },
  });

  assert.strictEqual(requests.length, 2);
  assert.strictEqual(requests[0].url, 'https://slack.com/api/files.info?file=F123');
  assert.strictEqual(requests[0].headers.Authorization, 'Bearer fixture-unit-slack-token');
  assert.strictEqual(requests[1].headers.Authorization, 'Bearer fixture-unit-slack-token');
  assert.strictEqual(requests[1].redirect, 'error');
  assert.strictEqual(result.content[0].text, 'public branch note');
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'slack',
    operation: 'files.info',
    contentType: 'text/plain',
    sizeBytes: 18,
    mimetype: 'text/plain',
    transferMode: 'url_private',
  });
});

test('Slack connector refuses oversized history, non-Slack private URLs, and unsafe file content', async () => {
  await assert.rejects(
    () => fetchConversationHistory({ channel: 'C123' }, {
      accessToken: 'fixture-unit-slack-token',
      maxBytes: 4,
      fetchImpl: async () => jsonResponse({
        ok: true,
        messages: [{ text: 'public body' }],
      }),
    }),
    /conversation content exceeds 4 byte limit/
  );

  const unsafeRequests = [];
  await assert.rejects(
    () => fetchSlackFileContent({ fileId: 'F123' }, {
      accessToken: 'fixture-unit-slack-token',
      fetchImpl: async (url) => {
        unsafeRequests.push(url);
        return jsonResponse({
          ok: true,
          file: { url_private: 'https://metadata.google.internal/latest' },
        });
      },
    }),
    /private URL host is not allowed/
  );
  assert.strictEqual(unsafeRequests.length, 1);

  await assert.rejects(
    () => fetchSlackFileContent({ fileId: 'F123' }, {
      accessToken: 'fixture-unit-slack-token',
      fetchImpl: async (url) => {
        if (url.includes('/files.info')) {
          return jsonResponse({
            ok: true,
            file: {
              mimetype: 'application/octet-stream',
              url_private_download: 'https://files.slack.com/files-pri/T123-F123/blob.bin',
            },
          });
        }
        return response('SSN 524-71-9043', { contentType: 'application/octet-stream' });
      },
    }),
    (err) => {
      assert.match(err.message, /not text-readable/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('fixture-unit-slack-token'));
      return true;
    }
  );

  await assert.rejects(
    () => fetchSlackFileContent({ fileId: 'F123' }, {
      accessToken: 'fixture-unit-slack-token',
      maxBytes: 4,
      fetchImpl: async (url) => {
        if (url.includes('/files.info')) {
          return jsonResponse({
            ok: true,
            file: { url_private: 'https://files.slack.com/files-pri/T123-F123/note.txt' },
          });
        }
        return response('public body', { contentLength: '999' });
      },
    }),
    /exceeds 4 byte limit/
  );
});

test('sanitizeSlackFileContent and file tool return sanitized MCP results only', async () => {
  let outbound;
  const opts = {
    accessToken: 'fixture-unit-slack-token',
    fetchImpl: async (url) => {
      if (url.includes('/files.info')) {
        return jsonResponse({
          ok: true,
          file: {
            mimetype: 'text/plain',
            url_private: 'https://files.slack.com/files-pri/T123-F123/member.txt',
          },
        });
      }
      return response('Slack file includes SSN 524-71-9043.');
    },
    guardOptions: {
      server: 'https://redactwall.test',
      key: 'unit-ingest-key',
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async (url, request = {}) => {
        outbound = { url, body: request.body };
        return { ok: true };
      },
    },
  };
  const sanitized = await sanitizeSlackFileContent({ fileId: 'F123' }, opts);
  assert.strictEqual(sanitized.redacted, true);
  assert.ok(!JSON.stringify(sanitized.result).includes('524-71-9043'));
  assert.strictEqual(JSON.parse(outbound.body).destination, 'slack.files.info');

  const fileTool = createSlackFileContentTool(opts);
  const fileResult = await fileTool({ fileId: 'F123' });
  assert.ok(fileResult.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(fileResult).includes('524-71-9043'));
});

test('createSlackConversationHistoryTool returns sanitized MCP result only', async () => {
  const tool = createSlackConversationHistoryTool({
    accessToken: 'fixture-unit-slack-token',
    fetchImpl: async () => jsonResponse({
      ok: true,
      messages: [{ text: 'Member SSN 524-71-9043.' }],
    }),
    guardOptions: {
      policy: { ignore: [], disabledDetectors: [] },
      fetchImpl: async () => ({ ok: true }),
    },
  });

  const result = await tool({ channel: 'C123' });
  assert.ok(result.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(result).includes('524-71-9043'));
});

test('Slack connector errors, text extraction, URL allowlist, and health evidence are secret-free', async () => {
  assert.strictEqual(
    messagesToText([{ blocks: [{ elements: [{ elements: [{ text: 'Block text <@U123>' }] }] }] }]),
    'Block text [slack_user]'
  );
  assert.strictEqual(isAllowedSlackFileUrl('https://files.slack.com/files-pri/T/F/a.txt'), true);
  assert.strictEqual(isAllowedSlackFileUrl('https://cdn.evil.example/files-pri/T/F/a.txt'), false);

  await assert.rejects(
    () => fetchConversationHistory({ channel: 'C123' }, {
      env: {},
      fetchImpl: async () => jsonResponse({ ok: true, messages: [] }),
    }),
    /access token is required/
  );
  await assert.rejects(
    () => fetchConversationHistory({ channel: 'C123' }, {
      accessToken: 'fixture-unit-slack-token',
      fetchImpl: async () => jsonResponse({ ok: false, error: 'missing_scope' }),
    }),
    (err) => {
      assert.match(err.message, /missing_scope/);
      assert.ok(!err.message.includes('fixture-unit-slack-token'));
      return true;
    }
  );

  const check = slackConnectorHealth({
    teamId: 'T123',
    scopes: ['channels:history', 'files:read'],
    accessToken: 'should-not-appear',
  }, true, 'OAuth probe ok');

  assert.strictEqual(check.id, 'mcp_connector_slack');
  assert.strictEqual(check.ok, true);
  assert.ok(check.detail.includes('tenant:T123'));
  assert.ok(check.detail.includes('scopes:2'));
  assert.ok(!JSON.stringify(check).includes('should-not-appear'));
  assert.deepStrictEqual(slackScopes({ env: {} }), ['channels:history', 'groups:history', 'files:read']);
  assert.deepStrictEqual(slackScopes({ env: { SLACK_SCOPES: 'channels:history,files:read' } }), ['channels:history', 'files:read']);
});

test('Slack API JSON enforces declared response bounds before parsing', async () => {
  let jsonCalled = false;
  await assert.rejects(() => fetchConversationHistory({ channel: 'C123' }, {
    accessToken: 'fixture-unit-slack-token',
    maxJsonBytes: 16,
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      headers: headers({ 'content-length': '50000000' }),
      json: async () => { jsonCalled = true; return { ok: true, messages: [] }; },
    }),
  }), /exceeds 16 byte limit/);
  assert.strictEqual(jsonCalled, false);
});
