'use strict';
/**
 * Persistent AI app catalog + shadow-AI discovery + review workflow.
 *
 * Builds on:
 *  - server/ai-app-catalog.js — reviewed static risk metadata (seed + attributes)
 *  - server/db.js ai_apps table — persistence + discovery counters
 *  - detection-engine/adapters — host normalization + AI-host recognition
 *
 * Discovery is PROMPT-FREE by construction: a sighting is a host + counters +
 * timestamps + source, never any prompt/response content. The review workflow
 * reuses server/policy.reviewDestination so a decision writes the policy
 * destination lists atomically (the enforcement path the sensors already read).
 *
 * Risk score is a transparent, examiner-defensible formula (0-100 → 5 tiers,
 * cf. Netskope CCI), not an opaque model.
 */
const db = require('./db');
const seed = require('./ai-app-catalog');
const { normalizeHost, isAiHost } = require('../detection-engine/adapters');

const STATUS = ['under_review', 'sanctioned', 'tolerated', 'unsanctioned', 'blocked'];
const SOURCES = ['browser', 'gateway', 'endpoint', 'mcp', 'csv_import', 'manual'];

function nowIso() {
  return new Date().toISOString();
}

// Transparent 0-100 risk score from attributes → 5 tiers. Higher = riskier.
// The formula is examiner-defensible: provider risk tier dominates, then the
// two attributes buyers ask about most (trains-on-data, personal tier), then
// non-US data residency. An unseeded host is 'unrated' (50) until reviewed.
function scoreFor(risk) {
  if (!risk) return { score: 50, tier: 'unrated' };
  let score = (risk.riskTier || 2) * 15;              // 15/30/45/60 for tier 1-4
  if ((risk.flags || []).includes('trains_on_data')) score += 14;
  if ((risk.flags || []).includes('personal_account_tier')) score += 8;
  if (risk.region && risk.region !== 'US') score += 8;
  score = Math.max(0, Math.min(100, score));
  const tier = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'moderate' : score >= 20 ? 'low' : 'minimal';
  return { score, tier };
}

// A plausible domain: labels of valid chars separated by dots, a real TLD-ish
// tail. Rejects free text so a bad CSV row doesn't become a catalog entry.
const PLAUSIBLE_HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
function plausibleHost(host) {
  return typeof host === 'string' && PLAUSIBLE_HOST.test(host);
}

function seededRecord(host) {
  const risk = seed.riskAttributes(host) || null;
  const { score, tier } = scoreFor(risk);
  return {
    provider: risk ? risk.provider : null,
    region: risk ? risk.region : null,
    riskAttributes: risk ? { trainsOnData: risk.trainsOnData, personalTier: risk.personalTier, flags: risk.flags } : null,
    riskScore: score,
    riskTier: tier,
    knownAiHost: isAiHost(host),
  };
}

// Record a prompt-free sighting; creates or updates the catalog entry and bumps
// the per-source counter. Returns the stored record.
function recordSighting({ destination, source = 'browser', outcome = 'seen', at } = {}) {
  const host = normalizeHost(destination);
  if (!host) return null;
  const src = SOURCES.includes(source) ? source : 'manual';
  const now = at || nowIso();
  const existing = db.getAiApp(host);
  const sources = { ...(existing && existing.sources) };
  sources[src] = (sources[src] || 0) + 1;
  const patch = {
    ...(existing ? {} : seededRecord(host)),
    appName: (existing && existing.appName) || host,
    sanctionedStatus: (existing && existing.sanctionedStatus) || 'under_review',
    eventCount: ((existing && existing.eventCount) || 0) + 1,
    sources,
    lastOutcome: outcome,
  };
  return db.upsertAiApp(host, patch, now);
}

// Manual catalog entry (operator adds an app not yet seen).
function addManual({ destination, appName, sanctionedStatus } = {}) {
  const host = normalizeHost(destination);
  if (!host) return null;
  const now = nowIso();
  const existing = db.getAiApp(host);
  return db.upsertAiApp(host, {
    ...(existing ? {} : seededRecord(host)),
    appName: appName || (existing && existing.appName) || host,
    sanctionedStatus: STATUS.includes(sanctionedStatus) ? sanctionedStatus : (existing && existing.sanctionedStatus) || 'under_review',
    sources: { ...(existing && existing.sources), manual: ((existing && existing.sources && existing.sources.manual) || 0) + 1 },
  }, now);
}

// Bulk import from a DNS/proxy CSV — one host per line, or `host,count`. Bounded.
function importCsv(text, { source = 'csv_import', max = 5000 } = {}) {
  const lines = String(text || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  let imported = 0; let skipped = 0;
  for (const line of lines.slice(0, max)) {
    const host = normalizeHost(line.split(',')[0]);
    if (!plausibleHost(host)) { skipped += 1; continue; }
    recordSighting({ destination: host, source });
    imported += 1;
  }
  return { imported, skipped, total: lines.length };
}

// Set catalog metadata (owner/notes/status) without touching the policy lists.
function annotate(host, { owner, notes, sanctionedStatus } = {}) {
  const h = normalizeHost(host);
  const existing = db.getAiApp(h);
  if (!existing) return null;
  return db.upsertAiApp(h, {
    ...(owner !== undefined ? { owner: String(owner).slice(0, 200) } : {}),
    ...(notes !== undefined ? { notes: String(notes).slice(0, 2000) } : {}),
    ...(sanctionedStatus && STATUS.includes(sanctionedStatus) ? { sanctionedStatus } : {}),
  }, existing.lastSeen || nowIso());
}

// Sensor-safe public view of the whole catalog.
function publicCatalog() {
  return db.listAiApps().map((a) => ({
    id: a.id,
    destination: a.canonicalHost,
    appName: a.appName || a.canonicalHost,
    provider: a.provider || null,
    region: a.region || null,
    riskScore: typeof a.riskScore === 'number' ? a.riskScore : null,
    riskTier: a.riskTier || 'unrated',
    riskAttributes: a.riskAttributes || null,
    sanctionedStatus: a.sanctionedStatus || 'under_review',
    knownAiHost: !!a.knownAiHost,
    owner: a.owner || null,
    notes: a.notes || null,
    eventCount: a.eventCount || 0,
    sources: a.sources || {},
    firstSeen: a.firstSeen,
    lastSeen: a.lastSeen,
  }));
}

module.exports = { recordSighting, addManual, importCsv, annotate, publicCatalog, scoreFor, STATUS, SOURCES };
