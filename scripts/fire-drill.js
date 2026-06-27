'use strict';
require('../server/env').loadEnv();
/**
 * Synthetic control fire drill: send a planted canary through the gate API and
 * fail if the system does not detect it or if the raw token leaks in response.
 */
const crypto = require('crypto');

function makeCanaryToken(seed = crypto.randomBytes(10).toString('hex').toUpperCase()) {
  return `PS-CANARY-${String(seed).replace(/[^A-Z0-9_-]/gi, '').toUpperCase().padEnd(12, 'X').slice(0, 40)}`;
}

function makePrompt(token) {
  return `Synthetic fire drill record. This planted value ${token} must not leave the institution.`;
}

function assertFireDrillResponse(body, token) {
  const findings = Array.isArray(body && body.findings) ? body.findings : [];
  const hasCanary = findings.some((f) => f && f.type === 'CANARY_TOKEN');
  if (!hasCanary) throw new Error('fire drill failed: CANARY_TOKEN was not detected');

  const decision = body && body.decision;
  if (!['block', 'redact'].includes(decision)) {
    throw new Error(`fire drill failed: expected block or redact decision, got ${decision || 'none'}`);
  }

  const wire = JSON.stringify(body || {});
  if (wire.includes(token)) throw new Error('fire drill failed: raw canary token appeared in the response');

  return {
    ok: true,
    id: body.id,
    decision,
    status: body.status,
    riskScore: body.riskScore,
    findings: findings.map((f) => f.type),
  };
}

async function runFireDrill({ baseUrl, ingestKey, fetchImpl = fetch, token = makeCanaryToken() }) {
  const url = String(baseUrl || 'http://localhost:4000').replace(/\/+$/, '');
  const key = ingestKey || process.env.INGEST_API_KEY || 'dev-ingest-key';
  const res = await fetchImpl(`${url}/api/v1/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': key },
    body: JSON.stringify({
      prompt: makePrompt(token),
      user: 'fire-drill',
      destination: 'chatgpt.com',
      source: 'fire_drill',
      channel: 'canary_control',
      orgId: 'synthetic',
    }),
  });
  if (!res.ok) throw new Error(`fire drill request failed: HTTP ${res.status}`);
  const body = await res.json();
  return assertFireDrillResponse(body, token);
}

async function main() {
  const baseUrl = process.argv[2] || process.env.SENTINEL_URL || 'http://localhost:4000';
  const result = await runFireDrill({ baseUrl });
  console.log(`FIRE_DRILL_OK ${result.id || ''} decision=${result.decision} status=${result.status || 'unknown'} risk=${result.riskScore}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exitCode = 1;
  });
}

module.exports = { makeCanaryToken, makePrompt, assertFireDrillResponse, runFireDrill };
