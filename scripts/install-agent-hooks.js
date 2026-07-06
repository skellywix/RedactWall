'use strict';
/**
 * Install (or remove) the RedactWall agent hooks into Claude Code settings.
 *
 *   node scripts/install-agent-hooks.js            # merge into ~/.claude/settings.json
 *   node scripts/install-agent-hooks.js --project  # merge into ./.claude/settings.json
 *   node scripts/install-agent-hooks.js --print     # print the JSON snippet, write nothing
 *   node scripts/install-agent-hooks.js --uninstall # remove only RedactWall-owned entries
 *
 * Idempotent. NEVER writes the ingest key into settings.json — the hook reads
 * INGEST_API_KEY / REDACTWALL_URL from the environment (or ~/.redactwall/agent-hooks.env).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const HOOK_PATH = path.join(__dirname, '..', 'sensors', 'agent-hooks', 'hook.js');
const MARKER = 'agent-hooks/hook.js';

function hookCommand(hookPath = HOOK_PATH) {
  // Quote the path so install roots containing spaces (e.g. "/Users/Jane Doe/…")
  // don't break the shell command written into settings.json.
  return `node "${hookPath}" --quiet`;
}

function ownsEntry(entry) {
  return entry && Array.isArray(entry.hooks)
    && entry.hooks.some((h) => typeof h.command === 'string' && h.command.includes(MARKER));
}

function desiredConfig(hookPath = HOOK_PATH) {
  const cmd = { type: 'command', command: hookCommand(hookPath) };
  return {
    UserPromptSubmit: [{ hooks: [cmd] }],
    PreToolUse: [{ matcher: 'Bash|mcp__.*', hooks: [cmd] }],
  };
}

function mergeHooks(existing, hookPath = HOOK_PATH) {
  const settings = existing && typeof existing === 'object' ? { ...existing } : {};
  const hooks = { ...(settings.hooks || {}) };
  const desired = desiredConfig(hookPath);
  for (const event of Object.keys(desired)) {
    const current = Array.isArray(hooks[event]) ? hooks[event].filter((e) => !ownsEntry(e)) : [];
    hooks[event] = current.concat(desired[event]);
  }
  settings.hooks = hooks;
  return settings;
}

function removeHooks(existing) {
  const settings = existing && typeof existing === 'object' ? { ...existing } : {};
  const hooks = { ...(settings.hooks || {}) };
  for (const event of Object.keys(hooks)) {
    if (Array.isArray(hooks[event])) {
      hooks[event] = hooks[event].filter((e) => !ownsEntry(e));
      if (!hooks[event].length) delete hooks[event];
    }
  }
  if (Object.keys(hooks).length) settings.hooks = hooks; else delete settings.hooks;
  return settings;
}

function settingsPath(opts = {}) {
  if (opts.settingsPath) return opts.settingsPath;
  const base = opts.project ? path.join(process.cwd(), '.claude') : path.join(os.homedir(), '.claude');
  return path.join(base, 'settings.json');
}

function readSettings(file, deps = {}) {
  const read = deps.readFile || ((p) => fs.readFileSync(p, 'utf8'));
  try { return JSON.parse(read(file)); } catch (_) { return {}; }
}

function writeSettings(file, data, deps = {}) {
  const write = deps.writeFile || ((p, d) => {
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, d);
  });
  write(file, JSON.stringify(data, null, 2) + '\n');
}

function parseArgs(argv) {
  const opts = {};
  for (const a of argv) {
    if (a === '--project') opts.project = true;
    else if (a === '--print') opts.print = true;
    else if (a === '--uninstall') opts.uninstall = true;
  }
  return opts;
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const opts = { ...parseArgs(argv), ...deps.opts };
  if (opts.print) {
    io.log(JSON.stringify({ hooks: desiredConfig(deps.hookPath) }, null, 2));
    return null;
  }
  const file = settingsPath(opts);
  const existing = readSettings(file, deps);
  const next = opts.uninstall ? removeHooks(existing) : mergeHooks(existing, deps.hookPath);
  writeSettings(file, next, deps);
  io.log(`${opts.uninstall ? 'Removed' : 'Installed'} RedactWall agent hooks in ${file}`);
  return { file, settings: next };
}

if (require.main === module) main();

module.exports = { main, mergeHooks, removeHooks, desiredConfig, ownsEntry, settingsPath, hookCommand, parseArgs };
