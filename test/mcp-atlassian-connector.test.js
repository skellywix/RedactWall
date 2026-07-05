'use strict';
/** Atlassian MCP connector must sanitize Jira and Confluence content before model use. */
const test = require('node:test');
const assert = require('node:assert');
const {
  atlassianConnectorHealth,
  atlassianScopes,
  buildConfluencePageUrl,
  buildJiraIssueUrl,
  confluencePageToText,
  createConfluencePageTool,
  createJiraIssueTool,
  fetchConfluencePage,
  fetchJiraIssue,
  htmlToText,
  jiraIssueToText,
  sanitizeConfluencePage,
  sanitizeJiraIssue,
} = require('../sensors/mcp-guard/connectors/atlassian');

function headers(values = {}) {
  const lower = Object.fromEntries(Object.entries(values).map(([key, value]) => [key.toLowerCase(), value]));
  return { get: (name) => lower[String(name).toLowerCase()] || '' };
}

function response(body, opts = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const status = opts.status || 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: headers({
      'content-type': opts.contentType || 'application/json',
      'content-length': opts.contentLength || String(Buffer.byteLength(text, 'utf8')),
    }),
    text: async () => text,
  };
}

function adfText(text) {
  return {
    type: 'doc',
    content: [
      { type: 'paragraph', content: [{ type: 'text', text }] },
    ],
  };
}

test('Atlassian URL builders target Jira and Confluence read APIs safely', () => {
  assert.strictEqual(
    buildJiraIssueUrl({
      issueIdOrKey: 'CU-42',
      fields: ['summary', 'description', 'comment'],
    }, { siteUrl: 'https://acme.atlassian.net/' }),
    'https://acme.atlassian.net/rest/api/3/issue/CU-42?fields=summary%2Cdescription%2Ccomment&updateHistory=false'
  );
  assert.strictEqual(
    buildConfluencePageUrl({ pageId: '12345' }, { siteUrl: 'https://acme.atlassian.net' }),
    'https://acme.atlassian.net/wiki/api/v2/pages/12345?body-format=storage'
  );

  assert.throws(() => buildJiraIssueUrl({ issueIdOrKey: 'CU/42' }, { siteUrl: 'https://acme.atlassian.net' }), /opaque id/);
  assert.throws(() => buildConfluencePageUrl({ pageId: 'abc' }, { siteUrl: 'https://acme.atlassian.net' }), /numeric/);
  assert.throws(() => buildJiraIssueUrl({ issueIdOrKey: 'CU-42' }, { siteUrl: 'http://acme.atlassian.net' }), /must use https/);
});

test('fetchJiraIssue reads bounded issue fields without leaking ids in structured content', async () => {
  let request;
  const result = await fetchJiraIssue({ issueIdOrKey: 'CU-42' }, {
    siteUrl: 'https://acme.atlassian.net',
    email: 'admin@example.test',
    apiToken: 'unit-atlassian-token-000000000000000000001',
    fetchImpl: async (url, opts = {}) => {
      request = { url, headers: opts.headers };
      return response({
        key: 'CU-42',
        fields: {
          summary: 'Loan workflow runbook',
          description: adfText('Use public branch hours.'),
          comment: { comments: [{ body: adfText('Escalate to lending queue.') }] },
        },
      });
    },
  });

  assert.strictEqual(request.url, 'https://acme.atlassian.net/rest/api/3/issue/CU-42?fields=summary%2Cdescription%2Ccomment&updateHistory=false');
  assert.match(request.headers.Authorization, /^Basic /);
  assert.ok(result.content[0].text.includes('Summary: Loan workflow runbook'));
  assert.ok(result.content[0].text.includes('Escalate to lending queue.'));
  assert.ok(!JSON.stringify(result.structuredContent).includes('CU-42'));
  assert.deepStrictEqual(result.structuredContent, {
    connector: 'atlassian',
    operation: 'jira.issue.get',
    contentType: 'text/plain',
    sizeBytes: Buffer.byteLength(result.content[0].text, 'utf8'),
    commentCount: 1,
  });
});

test('fetchConfluencePage converts storage content to bounded text', async () => {
  const result = await fetchConfluencePage({ pageId: '123', bodyFormat: 'storage' }, {
    siteUrl: 'https://acme.atlassian.net',
    accessToken: 'unit-atlassian-token-000000000000000000001',
    fetchImpl: async (url, opts = {}) => {
      assert.strictEqual(url, 'https://acme.atlassian.net/wiki/api/v2/pages/123?body-format=storage');
      assert.strictEqual(opts.headers.Authorization, 'Bearer unit-atlassian-token-000000000000000000001');
      return response({
        id: '123',
        title: 'AI safe-use page',
        body: { storage: { representation: 'storage', value: '<p>Public policy &amp; branch hours<br/>Ready</p>' } },
      });
    },
  });

  assert.strictEqual(result.content[0].text, 'Title: AI safe-use page\n\nPublic policy & branch hours\nReady');
  assert.ok(!JSON.stringify(result.structuredContent).includes('123'));
  assert.strictEqual(result.structuredContent.operation, 'confluence.page.get');
});

test('sanitizeJiraIssue redacts Jira text before returning MCP output', async () => {
  let outbound;
  const sanitized = await sanitizeJiraIssue({ issueIdOrKey: 'CU-42' }, {
    siteUrl: 'https://acme.atlassian.net',
    accessToken: 'unit-atlassian-token-000000000000000000001',
    fetchImpl: async () => response({
      fields: {
        summary: 'Member exception',
        description: adfText('Member SSN 524-71-9043 and card 4111 1111 1111 1111.'),
        comment: { comments: [] },
      },
    }),
    guardOptions: {
      server: 'http://redactwall.test',
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
  assert.strictEqual(outbound.url, 'http://redactwall.test/api/v1/gate');
  assert.strictEqual(outbound.body.destination, 'atlassian.jira.issue.get');
  assert.strictEqual(outbound.body.source, 'mcp_guard');
  assert.ok(!JSON.stringify(outbound.body).includes('unit-atlassian-token'));
});

test('Atlassian connector tools return sanitized MCP results only', async () => {
  const jiraTool = createJiraIssueTool({
    siteUrl: 'https://acme.atlassian.net',
    accessToken: 'unit-atlassian-token-000000000000000000001',
    fetchImpl: async () => response({ fields: { summary: 'Member SSN 524-71-9043.' } }),
    guardOptions: { policy: { ignore: [], disabledDetectors: [] }, fetchImpl: async () => ({ ok: true }) },
  });
  const jiraResult = await jiraTool({ issueIdOrKey: 'CU-42' });
  assert.ok(jiraResult.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(jiraResult).includes('524-71-9043'));

  const pageTool = createConfluencePageTool({
    siteUrl: 'https://acme.atlassian.net',
    accessToken: 'unit-atlassian-token-000000000000000000001',
    fetchImpl: async () => response({ body: { storage: { value: '<p>Member SSN 524-71-9043.</p>' } } }),
    guardOptions: { policy: { ignore: [], disabledDetectors: [] }, fetchImpl: async () => ({ ok: true }) },
  });
  const pageResult = await pageTool({ pageId: '123' });
  assert.ok(pageResult.content[0].text.includes('[US_SSN]'));
  assert.ok(!JSON.stringify(pageResult).includes('524-71-9043'));
});

test('Atlassian connector errors and health evidence are secret-free', async () => {
  assert.strictEqual(htmlToText('<p>A&nbsp;&amp;&nbsp;B<br>C</p>'), 'A & B\nC');
  assert.ok(jiraIssueToText({ fields: { description: adfText('ADF body') } }).includes('ADF body'));
  assert.ok(confluencePageToText({ title: 'T', body: { storage: { value: '<p>Body</p>' } } }).includes('Body'));

  await assert.rejects(
    () => fetchJiraIssue({ issueIdOrKey: 'CU-42' }, {
      siteUrl: 'https://acme.atlassian.net',
      env: {},
      fetchImpl: async () => response({}),
    }),
    /access token is required/
  );

  await assert.rejects(
    () => fetchJiraIssue({ issueIdOrKey: 'CU-42' }, {
      siteUrl: 'https://acme.atlassian.net',
      accessToken: 'unit-atlassian-token-000000000000000000001',
      fetchImpl: async () => response({ errorMessages: ['SSN 524-71-9043'] }, { status: 403 }),
    }),
    (err) => {
      assert.match(err.message, /HTTP 403/);
      assert.ok(!err.message.includes('524-71-9043'));
      assert.ok(!err.message.includes('unit-atlassian-token'));
      return true;
    }
  );

  const check = atlassianConnectorHealth({
    siteUrl: 'https://acme.atlassian.net',
    scopes: ['read:jira-work', 'read:page:confluence'],
    accessToken: 'should-not-appear',
  }, true, 'OAuth probe ok');
  assert.strictEqual(check.id, 'mcp_connector_atlassian_jira_confluence');
  assert.ok(check.detail.includes('tenant:acme.atlassian.net'));
  assert.ok(check.detail.includes('scopes:2'));
  assert.ok(!JSON.stringify(check).includes('should-not-appear'));
  assert.deepStrictEqual(atlassianScopes({ env: {} }), ['read:jira-work', 'read:page:confluence']);
});
