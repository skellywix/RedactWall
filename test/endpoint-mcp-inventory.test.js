'use strict';
/**
 * Shadow-MCP inventory collector: enumerate MCP server configs across clients,
 * report metadata only, and — critically — never leak secrets from env blocks,
 * args, or URL query strings. Plus the heartbeat 80-check cap regression.
 */
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { collectMcpInventorySync, parseMcpServers, stripJsonComments, transportOf } = require('../sensors/endpoint-agent/collectors/mcp-inventory');
const validation = require('../server/validation');

const HOME = '/home/dev';
function fixtureFiles() {
  const claude = path.join(HOME, '.claude.json');
  const cursor = path.join(HOME, '.cursor', 'mcp.json');
  const windsurf = path.join(HOME, '.codeium', 'windsurf', 'mcp_config.json');
  const vscode = path.join(HOME, '.config', 'Code', 'User', 'settings.json');
  return {
    [claude]: JSON.stringify({ mcpServers: {
      'github-mcp': { command: '/usr/local/bin/github-mcp-server', args: ['--token', 'ghp_CANARYTOKEN1'], env: { GITHUB_TOKEN: 'ghp_CANARYENV2' } },
      'local-db': { command: 'node', args: ['db.js'], env: { PG_PASSWORD: 'canarypw3' } },
    } }),
    [cursor]: JSON.stringify({ mcpServers: {
      'remote-sse': { url: 'https://mcp.example.com/sse?apikey=CANARYQUERY4', type: 'sse' },
    } }),
    [windsurf]: JSON.stringify({ mcpServers: { 'ws-tool': { command: 'ws-mcp' } } }),
    [vscode]: '{ // vscode settings\n "editor.fontSize": 13,\n "mcp": { "servers": { "http-tool": { "url": "http://localhost:8080/mcp?secret=CANARY5" } } } }',
  };
}

function collect(env = {}) {
  const files = fixtureFiles();
  return collectMcpInventorySync({
    home: HOME, platform: 'linux', env,
    readFile: (p) => { if (files[p] != null) return files[p]; throw new Error('ENOENT'); },
  });
}

test('enumerates servers across clients with metadata only', () => {
  const { servers } = collect();
  const ids = servers.map((s) => s.id).sort();
  assert.deepStrictEqual(ids, ['github_mcp', 'http_tool', 'local_db', 'remote_sse', 'ws_tool']);
  const remote = servers.find((s) => s.id === 'remote_sse');
  assert.strictEqual(remote.transport, 'sse');
  assert.strictEqual(remote.detail, 'sse mcp.example.com'); // host only, no path/query
  const github = servers.find((s) => s.id === 'github_mcp');
  assert.strictEqual(github.detail, 'stdio github-mcp-server'); // basename only, no dir
});

test('canary: no secret from env, args, or URL query appears in the output', () => {
  const out = JSON.stringify(collect());
  for (const canary of ['ghp_CANARYTOKEN1', 'ghp_CANARYENV2', 'canarypw3', 'CANARYQUERY4', 'CANARY5', 'db.js', '/usr/local/bin', 'apikey=', 'secret=']) {
    assert.ok(!out.includes(canary), `output leaked: ${canary}`);
  }
});

test('unapproved servers are flagged when an approved list is set', () => {
  const { checks } = collect({ ENDPOINT_AGENT_APPROVED_MCP_SERVERS: 'github_mcp' });
  const byId = Object.fromEntries(checks.map((c) => [c.id, c]));
  assert.strictEqual(byId.mcp_server_github_mcp.ok, true);
  assert.strictEqual(byId.mcp_server_local_db.ok, false);
  assert.match(byId.mcp_server_local_db.detail, /^unapproved/);
});

test('malformed and comment-laden configs are skipped, not thrown', () => {
  assert.deepStrictEqual(parseMcpServers('{ not json', 'cursor'), []);
  assert.deepStrictEqual(parseMcpServers('{ "mcp": { "servers": { "a": {} } } } // trailing', 'vscode').map((s) => s.id), ['a']);
  assert.strictEqual(stripJsonComments('{"u":"http://x//y"}').includes('http://x//y'), true, 'must not strip // inside strings');
  assert.strictEqual(transportOf({ url: 'https://x/sse' }), 'sse');
});

test('heartbeat schema accepts up to 80 checks (MCP inventory overflow guard)', () => {
  const checks = Array.from({ length: 55 }, (_, i) => ({ id: `mcp_server_s${i}`, ok: true, detail: 'x' }));
  const ok = validation.heartbeatSchema.safeParse({ user: 'u', source: 'endpoint_agent', checks });
  assert.strictEqual(ok.success, true, ok.error && JSON.stringify(ok.error.issues));
  const tooMany = validation.heartbeatSchema.safeParse({ user: 'u', source: 'endpoint_agent', checks: Array.from({ length: 81 }, (_, i) => ({ id: `s${i}`, ok: true })) });
  assert.strictEqual(tooMany.success, false, 'over 80 checks must be rejected');
});
