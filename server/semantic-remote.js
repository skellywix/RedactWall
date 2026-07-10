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
const { cancelResponseBody, readBoundedJson } = require('../sensors/shared/bounded-response');
// Single strict loopback definition, shared with the sensor transport guard so
// the two cannot drift. A prefix match like startsWith('127.') would accept an
// attacker host such as '127.0.0.1.evil.com' and leak prompt bodies over http.
const { isLoopbackHost } = require('../sensors/shared/server-url');

const DEFAULT_TIMEOUT_MS = 1500;
const MAX_TEXT_CHARS = 20000;
const MAX_REMOTE_CATEGORIES = 12;
const MAX_REMOTE_RESPONSE_BYTES = 128 * 1024;

function bool(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').toLowerCase());
}

// This path ships prompt text off the box, so it must be encrypted in transit.
// Allow HTTPS to any host; allow HTTP only to loopback (a local dev/test
// scanner) or, outside production, when the operator sets an explicit insecure
// override. Production never sends prompt bodies to a remote cleartext host.
function resolveRemoteUrl(raw, allowInsecure = false) {
  try {
    const url = new URL(String(raw || '').trim());
    if (url.username || url.password) return '';
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (isLoopbackHost(url.hostname) || allowInsecure))) return '';
    url.hash = '';
    return url.toString();
  } catch (_) { return ''; }
}

function remoteSettings(env = process.env) {
  const resolved = withEnvAliases(env);
  const allowInsecure = resolved.NODE_ENV !== 'production'
    && bool(resolved.REDACTWALL_SEMANTIC_REMOTE_ALLOW_INSECURE);
  const url = resolveRemoteUrl(resolved.REDACTWALL_SEMANTIC_REMOTE_URL || '', allowInsecure);
  if (!url) return { enabled: false };
  // Fail mode when the scanner is unreachable: 'degrade' (default) falls back to
  // on-device detection; 'hold' withholds the prompt for approval so nothing
  // proceeds un-vetted by the required second layer.
  const failMode = String(resolved.REDACTWALL_SEMANTIC_REMOTE_FAIL_MODE || 'degrade').toLowerCase() === 'hold' ? 'hold' : 'degrade';
  return {
    enabled: true,
    url,
    key: String(resolved.REDACTWALL_SEMANTIC_REMOTE_KEY || '').trim(),
    timeoutMs: Math.max(200, Math.min(10000, Number(resolved.REDACTWALL_SEMANTIC_REMOTE_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS)),
    failMode,
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

// Returns { ok, categories }. ok=false means the scanner was unreachable,
// errored, or returned an unparseable body — distinct from a clean {ok:true,
// categories:[]} — so the fail mode can decide degrade vs hold.
async function fetchRemote(text, settings, fetchImpl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), settings.timeoutMs);
  let res;
  try {
    res = await fetchImpl(settings.url, {
      method: 'POST',
      redirect: 'error',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(settings.key ? { Authorization: 'Bearer ' + settings.key } : {}),
      },
      body: JSON.stringify({ text: String(text || '').slice(0, MAX_TEXT_CHARS) }),
    });
  } catch (_) {
    return { ok: false, categories: [] };
  } finally {
    clearTimeout(timer);
  }
  if (!res || !res.ok) {
    await cancelResponseBody(res);
    return { ok: false, categories: [] };
  }
  try {
    const { json } = await readBoundedJson(res, {
      maxBytes: MAX_REMOTE_RESPONSE_BYTES,
      timeoutMs: settings.timeoutMs,
      label: 'semantic classifier response',
    });
    return { ok: true, categories: normalizeRemoteCategories(json) };
  } catch (_) {
    return { ok: false, categories: [] };
  }
}

/**
 * Augment a local analysis with the configured cloud classifier. Never weakens
 * on-device detection. On a scanner failure the fail mode decides: 'degrade'
 * (default) returns the untouched local analysis; 'hold' stamps
 * `remoteScanFailed` so the caller withholds the prompt for approval.
 */
async function augmentAnalysis(text, analysis, opts = {}) {
  const settings = opts.settings || remoteSettings(opts.env);
  if (!settings.enabled || !text) return analysis;
  const { ok, categories } = await fetchRemote(text, settings, opts.fetchImpl || fetch);
  if (ok) return combineCategories(analysis, categories);
  if (settings.failMode === 'hold') return { ...analysis, remoteScanFailed: true };
  return analysis; // degrade: remote outage never weakens on-device detection
}

module.exports = {
  augmentAnalysis,
  combineCategories,
  normalizeRemoteCategories,
  remoteSettings,
  resolveRemoteUrl,
};
