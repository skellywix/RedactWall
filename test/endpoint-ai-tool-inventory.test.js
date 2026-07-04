'use strict';
/** Endpoint AI tool inventory reports sanitized ids, not local paths or args. */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const inventory = require('../sensors/endpoint-agent/collectors/ai-tool-inventory');

function tempDir(t, prefix = 'ps-ai-tool-inventory-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('AI tool inventory normalizes ids and approved tool lists', () => {
  assert.strictEqual(inventory.normalizeToolId('Claude Code'), 'claude_code');
  assert.strictEqual(inventory.normalizeToolId('../bad/path'), 'bad_path');
  assert.strictEqual(inventory.normalizeToolId(''), null);
  assert.deepStrictEqual([...inventory.parseApprovedTools('cursor, Claude Code, bad/path')], ['cursor', 'claude_code', 'bad_path']);
});

test('AI tool inventory parses process lists without paths or args', () => {
  assert.deepStrictEqual(inventory.parseProcessList('"Cursor.exe","1234","Console"\n"powershell.exe","5678","Console"'), ['Cursor.exe', 'powershell.exe']);
  assert.deepStrictEqual(inventory.parseProcessList('/usr/local/bin/claude --dangerous-arg\nnode'), ['claude', 'node']);
});

test('AI tool inventory emits bounded sanitized checks for detected tools', async (t) => {
  const bin = tempDir(t);
  const cursor = path.join(bin, process.platform === 'win32' ? 'cursor.exe' : 'cursor');
  fs.writeFileSync(cursor, '');

  const result = await inventory.collectAiToolInventory({
    env: { PATH: bin, PATHEXT: '.EXE' },
    platform: process.platform,
    processNames: ['Claude.exe', 'C:\\Users\\analyst\\AppData\\Local\\Programs\\Claude\\Claude.exe --profile secret'],
  });

  assert.ok(result.detected.some((tool) => tool.id === 'cursor'));
  assert.ok(result.detected.some((tool) => tool.id === 'claude_desktop'));
  assert.ok(result.checks.some((check) => check.id === 'ai_tool_inventory' && check.detail.startsWith('detected:')));
  assert.ok(result.checks.some((check) => check.id === 'ai_tool_cursor' && check.ok));
  assert.ok(result.checks.some((check) => check.id === 'ai_tool_claude_desktop' && check.ok));
  assert.ok(!JSON.stringify(result).includes('AppData'));
  assert.ok(!JSON.stringify(result).includes('secret'));
});

test('AI tool inventory marks detected tools as attention when an approval list excludes them', async () => {
  const result = await inventory.collectAiToolInventory({
    processNames: ['Cursor.exe', 'Claude.exe'],
    approvedTools: 'cursor',
  });

  assert.ok(result.checks.some((check) => check.id === 'ai_tool_cursor' && check.ok));
  assert.ok(result.checks.some((check) => check.id === 'ai_tool_claude_desktop' && !check.ok && check.detail === 'unapproved detected'));
});

test('AI tool inventory fails closed when process enumeration is unavailable', async () => {
  const processNames = await inventory.listProcessNames({
    platform: 'linux',
    execFileAsync: async (command, args, options) => {
      assert.strictEqual(command, 'ps');
      assert.deepStrictEqual(args, ['-eo', 'comm=']);
      assert.strictEqual(options.windowsHide, true);
      assert.strictEqual(options.maxBuffer > 0, true);
      throw new Error('process list unavailable: C:\\Users\\analyst\\secret.txt');
    },
  });
  assert.deepStrictEqual(processNames, []);

  const result = await inventory.collectAiToolInventory({
    env: { PATH: '' },
    platform: 'linux',
    execFileAsync: async () => {
      throw new Error('process list unavailable');
    },
  });
  assert.deepStrictEqual(result.detected, []);
  assert.deepStrictEqual(result.checks, [{
    id: 'ai_tool_inventory',
    ok: true,
    detail: 'detected:0',
  }]);
});

test('AI tool inventory caps per-tool checks for endpoint heartbeat budget', () => {
  const tools = Array.from({ length: 30 }, (_, index) => ({
    id: `tool_${index}`,
    label: `Tool ${index}`,
    executables: [],
    processNames: [`tool${index}.exe`],
  }));
  const result = inventory.collectAiToolInventorySync({
    tools,
    processNames: tools.map((tool) => tool.processNames[0]),
  });

  assert.strictEqual(inventory.MAX_DETECTED_TOOL_CHECKS, 25);
  assert.strictEqual(result.detected.length, 30);
  assert.strictEqual(result.checks.filter((check) => check.id.startsWith('ai_tool_tool_')).length, 25);
  assert.strictEqual(result.checks.length, 26);
});
