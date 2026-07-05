'use strict';
/**
 * Sanitized endpoint MCP server inventory ("shadow MCP" discovery).
 *
 * Enumerates MCP server configurations declared by locally installed AI clients
 * (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code) and reports bounded
 * METADATA ONLY: a normalized server id, the client that declared it, the
 * transport (stdio/http/sse), and either the command basename or the URL host.
 *
 * It NEVER reads or returns env values, process arguments, headers, full URLs,
 * URL query strings, or filesystem paths — MCP config files are the most
 * secret-dense files on a developer machine, so the parser is deliberately
 * narrow and fails closed (a config it cannot parse is skipped, never thrown).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { normalizeToolId, parseApprovedTools, basenameAny } = require('./ai-tool-inventory');

const MAX_REPORTED_MCP_SERVERS = 12;
const SERVER_ID_RE = /^[a-z][a-z0-9_]{0,39}$/;

function normalizeServerId(value) {
  const id = String(value || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
  return SERVER_ID_RE.test(id) ? id : null;
}

function homeDir(opts = {}) { return opts.home || os.homedir(); }

function appSupportDir(home, platform) {
  if (platform === 'win32') return process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  if (platform === 'darwin') return path.join(home, 'Library', 'Application Support');
  return path.join(home, '.config');
}

function vscodeUserDir(home, platform) {
  if (platform === 'win32') return path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), 'Code', 'User');
  if (platform === 'darwin') return path.join(home, 'Library', 'Application Support', 'Code', 'User');
  return path.join(home, '.config', 'Code', 'User');
}

function wellKnownMcpConfigPaths(opts = {}) {
  const home = homeDir(opts);
  const platform = opts.platform || process.platform;
  const support = appSupportDir(home, platform);
  const code = vscodeUserDir(home, platform);
  const out = [
    { client: 'claude_code', file: path.join(home, '.claude.json') },
    { client: 'claude_code', file: path.join(home, '.claude', 'settings.json') },
    { client: 'claude_desktop', file: path.join(support, 'Claude', 'claude_desktop_config.json') },
    { client: 'cursor', file: path.join(home, '.cursor', 'mcp.json') },
    { client: 'windsurf', file: path.join(home, '.codeium', 'windsurf', 'mcp_config.json') },
    { client: 'vscode', file: path.join(code, 'settings.json') },
    { client: 'vscode', file: path.join(code, 'mcp.json') },
  ];
  const roots = String((opts.env && opts.env.ENDPOINT_AGENT_MCP_PROJECT_ROOTS)
    || process.env.ENDPOINT_AGENT_MCP_PROJECT_ROOTS || '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const root of roots) {
    out.push({ client: 'project', file: path.join(root, '.mcp.json') });
    out.push({ client: 'project', file: path.join(root, '.claude', 'settings.json') });
    out.push({ client: 'project', file: path.join(root, '.cursor', 'mcp.json') });
    out.push({ client: 'project', file: path.join(root, '.vscode', 'mcp.json') });
  }
  return out;
}

// Conservative JSONC comment stripper for VS Code settings. Only removes // and
// /* */ outside of strings; on any doubt the caller falls back to skipping.
function stripJsonComments(text) {
  let out = '';
  let inStr = false, esc = false, inLine = false, inBlock = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], n = text[i + 1];
    if (inLine) { if (c === '\n') { inLine = false; out += c; } continue; }
    if (inBlock) { if (c === '*' && n === '/') { inBlock = false; i++; } continue; }
    if (inStr) { out += c; if (esc) esc = false; else if (c === '\\') esc = true; else if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && n === '/') { inLine = true; i++; continue; }
    if (c === '/' && n === '*') { inBlock = true; i++; continue; }
    out += c;
  }
  return out;
}

function serverMap(parsed, client) {
  if (!parsed || typeof parsed !== 'object') return null;
  if (parsed.mcpServers && typeof parsed.mcpServers === 'object') return parsed.mcpServers;
  if (parsed.servers && typeof parsed.servers === 'object') return parsed.servers;       // VS Code mcp.json
  if (parsed.mcp && parsed.mcp.servers && typeof parsed.mcp.servers === 'object') return parsed.mcp.servers; // VS Code settings.json
  return null;
}

function transportOf(cfg) {
  if (!cfg || typeof cfg !== 'object') return 'stdio';
  const declared = String(cfg.type || cfg.transport || '').toLowerCase();
  if (declared.includes('sse')) return 'sse';
  if (declared.includes('http')) return 'http';
  if (cfg.url) return String(cfg.url).includes('/sse') ? 'sse' : 'http';
  return 'stdio';
}

function hostOnly(url) {
  try { return new URL(String(url)).hostname; } catch (_) { return ''; }
}

// Extract ONLY id / client / transport / command-basename-or-host. Never the
// args, env, headers, url path, or query.
function serverMetadata(name, cfg, client) {
  const id = normalizeServerId(name);
  if (!id) return null;
  const transport = transportOf(cfg);
  let detail = transport;
  if (transport === 'stdio' && cfg && cfg.command) detail = `stdio ${basenameAny(cfg.command)}`;
  else if (cfg && cfg.url) { const h = hostOnly(cfg.url); if (h) detail = `${transport} ${h}`; }
  return { id, client, transport, detail: detail.slice(0, 80) };
}

function parseMcpServers(jsonText, client) {
  let parsed;
  try { parsed = JSON.parse(jsonText); }
  catch (_) {
    if (client !== 'vscode') return [];
    try { parsed = JSON.parse(stripJsonComments(jsonText)); } catch (_2) { return []; }
  }
  const map = serverMap(parsed, client);
  if (!map) return [];
  const out = [];
  for (const name of Object.keys(map)) {
    const meta = serverMetadata(name, map[name], client);
    if (meta) out.push(meta);
  }
  return out;
}

function check(id, ok, detail) {
  return { id, ok: ok === true, detail: String(detail || (ok ? 'ok' : 'attention')).slice(0, 160) };
}

function collectMcpInventorySync(opts = {}) {
  const readFile = opts.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  const approved = opts.approvedServers instanceof Set
    ? opts.approvedServers
    : parseApprovedTools(opts.approvedServers || (opts.env && opts.env.ENDPOINT_AGENT_APPROVED_MCP_SERVERS) || process.env.ENDPOINT_AGENT_APPROVED_MCP_SERVERS || '');
  const seen = new Map();
  let configs = 0;
  for (const entry of wellKnownMcpConfigPaths(opts)) {
    let text;
    try { text = readFile(entry.file); } catch (_) { continue; }
    configs++;
    for (const server of parseMcpServers(text, entry.client)) {
      if (!seen.has(server.id)) seen.set(server.id, server); // first declaration wins
    }
  }
  const servers = [...seen.values()].sort((a, b) => a.id.localeCompare(b.id));
  const checks = [check('mcp_inventory', true, `detected:${servers.length} configs:${configs}`)];
  for (const s of servers.slice(0, MAX_REPORTED_MCP_SERVERS)) {
    const ok = !approved.size || approved.has(s.id);
    checks.push(check(`mcp_server_${s.id}`, ok, `${ok ? '' : 'unapproved '}${s.client} ${s.detail}`.trim()));
  }
  return { servers, checks };
}

module.exports = {
  collectMcpInventorySync,
  wellKnownMcpConfigPaths,
  parseMcpServers,
  stripJsonComments,
  normalizeServerId,
  serverMetadata,
  transportOf,
  MAX_REPORTED_MCP_SERVERS,
};
