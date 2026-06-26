'use strict';
/**
 * PromptSentinel MCP guard (reference implementation).
 *
 * Sits between an MCP server and the model. When an AI agent pulls a document or
 * record through a tool call (SharePoint, Drive, a database), the guard scans
 * the tool RESPONSE and redacts sensitive content BEFORE the model ever sees it,
 * while logging the event to the control plane. This solves the "agent pulling
 * PII from a data source" problem.
 *
 * Wrap any tool handler with guardToolResult(). Same shared engine, same server.
 */
const D = require('../shared/detect');

const SERVER = process.env.SENTINEL_URL || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';

async function logEvent(rec) {
  try {
    await fetch(SERVER + '/api/v1/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
      body: JSON.stringify(rec),
    });
  } catch (e) { /* logging best-effort */ }
}

/**
 * Inspect+redact a tool result string before returning it to the model.
 * @returns {Promise<{ text:string, redacted:boolean, findings:string[] }>}
 */
async function guardToolResult(text, ctx = {}) {
  const a = D.analyze(text || '');
  const findings = [...new Set(a.findings.map(f => f.type).concat(a.categories.map(c => c.category)))];
  if (!a.findings.length && !a.categories.length) {
    return { text, redacted: false, findings: [] };
  }
  const safe = a.categories.length
    ? '[REDACTED: ' + findings.join(', ') + ']'
    : D.redact(text, a.findings); // structured PII replaced with [TYPE]
  await logEvent({
    prompt: safe.slice(0, 1000),
    user: ctx.agent || 'mcp-agent',
    destination: ctx.tool || 'mcp-tool',
    source: 'mcp_guard',
    channel: 'mcp_doc',
  });
  return { text: safe, redacted: true, findings };
}

/** Higher-order wrapper for an MCP tool handler. */
function wrapTool(handler, ctx = {}) {
  return async function (args) {
    const result = await handler(args);
    const asText = typeof result === 'string' ? result : JSON.stringify(result);
    const guarded = await guardToolResult(asText, ctx);
    return guarded.text;
  };
}

module.exports = { guardToolResult, wrapTool };

// ---- demo when run directly ------------------------------------------------
if (require.main === module) {
  (async () => {
    const fakeDoc = `Member record pulled from SharePoint:
Name: Sarah Jones
SSN: 524-71-9043
Card on file: 4111 1111 1111 1111
Notes: confidential — account under review, do not share externally.`;
    console.log('--- raw MCP tool result (what the model WOULD see) ---');
    console.log(fakeDoc);
    const g = await guardToolResult(fakeDoc, { agent: 'claude-desktop', tool: 'sharepoint.fetchDoc' });
    console.log('\n--- guarded result (what the model ACTUALLY sees) ---');
    console.log(g.text);
    console.log('\nredacted:', g.redacted, '| detected:', g.findings.join(', '));
  })();
}
