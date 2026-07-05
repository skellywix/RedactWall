'use strict';
/**
 * Optional cloud semantic classifier seam (Nightfall/Strac-style).
 *
 * The on-device engine stays the default and the source of truth; when an
 * operator EXPLICITLY configures REDACTWALL_SEMANTIC_REMOTE_URL, gate-path
 * prompts are ALSO sent to that endpoint and its categories are max-combined
 * into the local analysis. Configuring this means prompt text leaves the box —
 * that is the operator's deliberate, documented choice. Any remote failure,
 * timeout, or malformed reply falls back to the untouched local analysis, so
 * detection never gets weaker than on-device.
 */
const D = require('../detection-engine/detect');
const { withEnvAliases } = require('./env');

const DEFAULT_TIMEOUT_MS = 1500;
const MAX_TEXT_CHARS = 20000;
const MAX_REMOTE_CATEGORIES = 12;

function remoteSettings(env = process.env) {
  const resolved = withEnvAliases(env);
  const url = String(resolved.REDACTWALL_SEMANTIC_REMOTE_URL || '').trim();
  if (!url || !/^https?:\/\//.test(url)) return { enabled: false };
  return {
    enabled: true,
    url,
    key: String(resolved.REDACTWALL_SEMANTIC_REMOTE_KEY || '').trim(),
    timeoutMs: Math.max(200, Math.min(10000, Number(resolved.REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS)),
  };
}

function normalizeRemoteCategories(payload) {
  const list = payload && Array.isArray(payload.categories) ? payload.categories : [];
  const out = [];
  for (const item of list.slice(0, MAX_REMOTE_CATEGORIES)) {
    const category = String((item && item.category) || '').trim().toUpperCase();
    const score = Number(item && item.score);
    if (!Object.prototype.hasOwnProperty.call(D.SEVERITY, category)) continue;
    if (!Number.isFinite(score) || score <= 0 || score > 1) continue;
    out.push({ category, score });
  }
  return out;
}

function confidenceTier(score) {
  return score >= 0.9 ? 3 : score >= 0.7 ? 2 : 1; // mirrors detect.js tiers
}

/** Max-combine remote categories into a local analysis (same math as analyze). */
function combineCategories(analysis, remoteCategories) {
  if (!remoteCategories.length) return analysis;
  const combined = { ...analysis, categories: [...analysis.categories], entityCounts: { ...analysis.entityCounts } };
  let riskDelta = 0;
  for (const remote of remoteCategories) {
    const severity = D.SEVERITY[remote.category] || 2;
    const existing = combined.categories.find((c) => c.category === remote.category);
    if (existing && existing.score >= remote.score) continue;
    const previousScore = existing ? existing.score : 0;
    riskDelta += severity * (remote.score - previousScore) * 7;
    const entry = {
      category: remote.category,
      score: remote.score,
      source: 'remote',
      confidence: confidenceTier(remote.score),
      confidenceLabel: D.CONFIDENCE_LABEL[confidenceTier(remote.score)],
    };
    if (existing) Object.assign(existing, entry);
    else combined.categories.push(entry);
    combined.entityCounts[remote.category] = 1;
    if (severity > combined.maxSeverity) {
      combined.maxSeverity = severity;
      combined.maxSeverityLabel = D.SEVERITY_LABEL[severity] || combined.maxSeverityLabel;
    }
  }
  combined.riskScore = Math.min(100, Math.round(combined.riskScore + riskDelta));
  return combined;
}

async function fetchRemoteCategories(text, settings, fetchImpl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), settings.timeoutMs);
  try {
    const res = await fetchImpl(settings.url, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(settings.key ? { Authorization: 'Bearer ' + settings.key } : {}),
      },
      body: JSON.stringify({ text: String(text || '').slice(0, MAX_TEXT_CHARS) }),
    });
    if (!res || !res.ok) return [];
    return normalizeRemoteCategories(await res.json());
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Augment a local analysis with the configured cloud classifier. Fail-closed
 * to local: whatever goes wrong, the caller gets the local analysis back.
 */
async function augmentAnalysis(text, analysis, opts = {}) {
  const settings = opts.settings || remoteSettings(opts.env);
  if (!settings.enabled || !text) return analysis;
  try {
    const remote = await fetchRemoteCategories(text, settings, opts.fetchImpl || fetch);
    return combineCategories(analysis, remote);
  } catch {
    return analysis; // remote outage never weakens on-device detection
  }
}

module.exports = {
  augmentAnalysis,
  combineCategories,
  normalizeRemoteCategories,
  remoteSettings,
};
