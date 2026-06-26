'use strict';
require('../src/env').loadEnv();
/**
 * Simulates the network proxy / SDK calling the gate with realistic prompts.
 * Usage: node scripts/simulate.js [baseUrl]
 */
const BASE = process.argv[2] || 'http://localhost:4000';
const KEY = process.env.INGEST_API_KEY || 'dev-ingest-key';

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

async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify(body),
  });
  return { status: r.status, json: await r.json().catch(() => ({})) };
}

(async () => {
  console.log(`Simulating prompts against ${BASE}\n`);
  for (const s of SAMPLES) {
    const { json } = await post('/api/v1/gate', { prompt: s.prompt, user: s.user, destination: s.dest, sourceIp: '10.0.4.' + (10 + Math.floor(Math.random() * 40)) });
    const tag = json.decision === 'allow' ? 'ALLOW ' : 'BLOCK ';
    console.log(`${tag} [risk ${String(json.riskScore).padStart(3)}] ${s.user} → ${s.dest}`);
    if (json.decision === 'block') console.log(`        held: ${json.id}  (${(json.findings || []).map(f => f.type).join(', ')})`);
    await new Promise((r) => setTimeout(r, 250));
  }
  console.log('\nDone. Open the dashboard to review the approval queue.');
})();
