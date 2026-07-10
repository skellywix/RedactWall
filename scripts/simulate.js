'use strict';
require('../server/env').loadEnv();
/**
 * Simulates the network proxy / SDK calling the gate with realistic prompts.
 * Usage: node scripts/simulate.js [baseUrl]
 */
const BASE = process.argv[2] || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';
const { readBoundedJson } = require('../sensors/shared/bounded-response');
const { secureServerBase } = require('../sensors/shared/server-url');

const MAX_GATE_RESPONSE_BYTES = 512 * 1024;
const GATE_RESPONSE_TIMEOUT_MS = 10000;

const SAMPLES = [
  { user: 'jdoe',   dest: 'chatgpt.com', prompt: 'Summarize this email thread about our Q3 roadmap into 3 bullet points.' },
  { user: 'msmith', dest: 'claude.ai',   prompt: 'Draft a denial letter for member John Carter, SSN 524-71-9043, who applied for an auto loan.' },
  { user: 'rlopez', dest: 'chatgpt.com', prompt: 'Help me write a Python function to parse CSV files for our reporting tool.' },
  { user: 'kpatel', dest: 'gemini.google.com', prompt: 'Member wants to dispute charge on card 4111 1111 1111 1111, exp 09/27. Write the dispute summary.' },
  { user: 'jdoe',   dest: 'chatgpt.com', prompt: 'Our member Sarah Jones at 482 Oakwood Drive, phone 415-555-0182, needs a payoff letter.' },
  { user: 'devops', dest: 'claude.ai',   prompt: 'Debug this deploy script. Here is the AWS key AKIA1234567890ABCDEF and secret we use.' },
  { user: 'msmith', dest: 'perplexity.ai', prompt: 'What are best practices for NCUA examination preparation this year?' },
  { user: 'agarcia',dest: 'chatgpt.com', prompt: 'Reset login for user, temp password: Pass=Summer2026! and email agarcia@cu.org for confirmation.' },
];

async function post(path, body, opts = {}) {
  const base = secureServerBase(opts.base || BASE);
  if (!base) throw new Error('simulation base URL must use HTTPS or loopback HTTP without query parameters or fragments');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('fetch is not available');
  const r = await fetchImpl(base + path, {
    method: 'POST',
    redirect: 'error',
    headers: { 'Content-Type': 'application/json', 'x-api-key': opts.key || KEY },
    body: JSON.stringify(body),
  });
  const { json } = await readBoundedJson(r, {
    maxBytes: opts.maxResponseBytes || MAX_GATE_RESPONSE_BYTES,
    timeoutMs: opts.responseTimeoutMs || GATE_RESPONSE_TIMEOUT_MS,
    label: 'simulation gate response',
  });
  return { status: r.status, json };
}

async function main(opts = {}) {
  const base = opts.base || BASE;
  const io = opts.console || console;
  const wait = opts.wait || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  io.log(`Simulating prompts against ${base}\n`);
  for (const s of SAMPLES) {
    const { json } = await post('/api/v1/gate', { prompt: s.prompt, user: s.user, destination: s.dest, sourceIp: '10.0.4.' + (10 + Math.floor(Math.random() * 40)) }, opts);
    const tag = json.decision === 'allow' ? 'ALLOW ' : 'BLOCK ';
    io.log(`${tag} [risk ${String(json.riskScore).padStart(3)}] ${s.user} → ${s.dest}`);
    if (json.decision === 'block') io.log(`        held: ${json.id}  (${(json.findings || []).map(f => f.type).join(', ')})`);
    await wait(250);
  }
  io.log('\nDone. Open the dashboard to review the approval queue.');
}

if (require.main === module) main().catch((err) => {
  console.error(err && err.message ? err.message : err);
  process.exitCode = 1;
});

module.exports = { SAMPLES, main, post };
