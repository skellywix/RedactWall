'use strict';
/**
 * Sanitized endpoint AI tool inventory.
 *
 * The collector reports bounded tool ids only. It never returns executable
 * paths, process arguments, document names, prompt text, or file content.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);
const MAX_PROCESS_OUTPUT = 128 * 1024;
const DEFAULT_PROCESS_TIMEOUT_MS = 3000;
const MAX_DETECTED_TOOL_CHECKS = 25;
const TOOL_ID_RE = /^[a-z][a-z0-9_]{0,39}$/;

const KNOWN_AI_TOOLS = [
  {
    id: 'chatgpt_desktop',
    label: 'ChatGPT Desktop',
    executables: ['ChatGPT.exe', 'chatgpt'],
    processNames: ['ChatGPT.exe', 'ChatGPT'],
  },
  {
    id: 'claude_desktop',
    label: 'Claude Desktop',
    executables: ['Claude.exe', 'claude-desktop'],
    processNames: ['Claude.exe', 'Claude'],
  },
  {
    id: 'claude_code',
    label: 'Claude Code',
    executables: ['claude'],
    processNames: ['claude', 'claude.exe'],
  },
  {
    id: 'copilot',
    label: 'Microsoft Copilot',
    executables: ['Copilot.exe', 'copilot'],
    processNames: ['Copilot.exe', 'Copilot'],
  },
  {
    id: 'cursor',
    label: 'Cursor',
    executables: ['Cursor.exe', 'cursor'],
    processNames: ['Cursor.exe', 'Cursor', 'cursor'],
  },
  {
    id: 'windsurf',
    label: 'Windsurf',
    executables: ['Windsurf.exe', 'windsurf'],
    processNames: ['Windsurf.exe', 'Windsurf', 'windsurf'],
  },
  {
    id: 'gemini_cli',
    label: 'Gemini CLI',
    executables: ['gemini'],
    processNames: ['gemini', 'gemini.exe'],
  },
  {
    id: 'codex_cli',
    label: 'Codex CLI',
    executables: ['codex'],
    processNames: ['codex', 'codex.exe'],
  },
];

function normalizeToolId(value) {
  const id = String(value || '').trim().toLowerCase().replace(/[^a-z0-9_]+/g, '_').replace(/^_+|_+$/g, '');
  return TOOL_ID_RE.test(id) ? id : null;
}

function parseApprovedTools(value) {
  const out = new Set();
  for (const item of String(value || '').split(',')) {
    const id = normalizeToolId(item);
    if (id) out.add(id);
  }
  return out;
}

function basenameAny(value) {
  const text = String(value || '').trim();
  return path.basename(text.replace(/\\/g, '/'));
}

function pathEntries(env = process.env) {
  return String(env.PATH || env.Path || env.path || '').split(path.delimiter).filter(Boolean);
}

function executableCandidates(name, env = process.env, platform = process.platform) {
  if (path.isAbsolute(name) || name.includes(path.sep) || name.includes('/')) return [name];
  const entries = pathEntries(env);
  const exts = platform === 'win32'
    ? String(env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean)
    : [''];
  const names = platform === 'win32' && !path.extname(name)
    ? exts.map((ext) => name + ext.toLowerCase()).concat(exts.map((ext) => name + ext.toUpperCase()))
    : [name];
  return entries.flatMap((dir) => names.map((candidate) => path.join(dir, candidate)));
}

function findExecutable(name, opts = {}) {
  const env = opts.env || process.env;
  const platform = opts.platform || process.platform;
  return executableCandidates(name, env, platform).some((candidate) => {
    try {
      return fs.statSync(candidate).isFile();
    } catch {
      return false;
    }
  });
}

function normalizeProcessNames(processNames = []) {
  const out = new Set();
  for (const item of processNames || []) {
    const base = basenameAny(String(item || '').trim().split(/\s+/)[0]).toLowerCase();
    if (base) out.add(base);
  }
  return out;
}

function parseProcessList(stdout) {
  return String(stdout || '').split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return '';
      const csv = trimmed.match(/^"([^"]+)"/);
      return basenameAny(csv ? csv[1] : trimmed.split(/\s+/)[0]);
    })
    .filter(Boolean);
}

async function listProcessNames(opts = {}) {
  if (Array.isArray(opts.processNames)) return opts.processNames;
  const platform = opts.platform || process.platform;
  const runner = opts.execFileAsync || execFileAsync;
  const timeout = Number.isFinite(Number(opts.timeoutMs)) ? Number(opts.timeoutMs) : DEFAULT_PROCESS_TIMEOUT_MS;
  const command = platform === 'win32' ? 'tasklist.exe' : 'ps';
  const args = platform === 'win32' ? ['/fo', 'csv', '/nh'] : ['-eo', 'comm='];
  try {
    const result = await runner(command, args, {
      windowsHide: true,
      timeout,
      maxBuffer: MAX_PROCESS_OUTPUT,
    });
    return parseProcessList(result && result.stdout);
  } catch {
    return [];
  }
}

function toolDetected(tool, processNameSet, opts = {}) {
  const executableFound = (tool.executables || []).some((name) => findExecutable(name, opts));
  const processFound = (tool.processNames || []).some((name) => processNameSet.has(basenameAny(name).toLowerCase()));
  return executableFound || processFound;
}

function check(id, ok, detail) {
  return {
    id,
    ok: ok === true,
    detail: String(detail || (ok ? 'ok' : 'attention')).slice(0, 160),
  };
}

function buildInventory(processNameSet, opts = {}) {
  const tools = Array.isArray(opts.tools) ? opts.tools : KNOWN_AI_TOOLS;
  const approved = opts.approvedTools instanceof Set
    ? opts.approvedTools
    : parseApprovedTools(opts.approvedTools || '');
  const detected = [];
  for (const tool of tools) {
    const id = normalizeToolId(tool && tool.id);
    if (!id) continue;
    if (toolDetected(tool, processNameSet, opts)) {
      detected.push({ id, label: String(tool.label || id).slice(0, 80) });
    }
  }
  detected.sort((a, b) => a.id.localeCompare(b.id));
  const checks = [
    check('ai_tool_inventory', true, `detected:${detected.length}`),
  ];
  for (const item of detected.slice(0, MAX_DETECTED_TOOL_CHECKS)) {
    const approvedTool = !approved.size || approved.has(item.id);
    checks.push(check(`ai_tool_${item.id}`, approvedTool, approvedTool ? 'detected' : 'unapproved detected'));
  }
  return {
    detected,
    checks,
  };
}

function collectAiToolInventorySync(opts = {}) {
  return buildInventory(normalizeProcessNames(opts.processNames || []), opts);
}

async function collectAiToolInventory(opts = {}) {
  return buildInventory(normalizeProcessNames(await listProcessNames(opts)), opts);
}

module.exports = {
  KNOWN_AI_TOOLS,
  collectAiToolInventory,
  collectAiToolInventorySync,
  executableCandidates,
  listProcessNames,
  basenameAny,
  MAX_DETECTED_TOOL_CHECKS,
  normalizeProcessNames,
  normalizeToolId,
  parseApprovedTools,
  parseProcessList,
};
