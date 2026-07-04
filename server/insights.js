'use strict';
/**
 * AI-usage analytics aggregation for the Insights dashboard.
 *
 * Turns the sanitized query/evidence rows into the time-series, distribution,
 * and top-N summaries the console charts render — the "AI activity dashboard"
 * surface (who / what / where / how risky) that Prompt Security, Netskope, and
 * Microsoft Purview lead with. Metadata only: counts, buckets, masked labels —
 * never prompt bodies, finding values, or vault content.
 */
const aiCatalog = require('./ai-app-catalog');

const DECISION_BY_STATUS = {
  allowed: 'allowed', warned: 'warned', warned_sent: 'allowed', justified: 'allowed',
  redacted: 'redacted', pending: 'blocked', denied: 'blocked', blocked_by_user: 'blocked',
  destination_blocked: 'blocked', file_upload_blocked: 'blocked', action_blocked: 'blocked',
  injection_blocked: 'blocked', file_blocked_unscanned: 'blocked', pending_justification: 'blocked',
  approved: 'allowed', paste_flagged: 'flagged', shadow_ai: 'shadow', flagged: 'flagged',
};

const RISK_BANDS = [
  { id: 'none', label: 'None (0)', min: 0, max: 0 },
  { id: 'low', label: 'Low (1-24)', min: 1, max: 24 },
  { id: 'medium', label: 'Medium (25-49)', min: 25, max: 49 },
  { id: 'high', label: 'High (50-74)', min: 50, max: 74 },
  { id: 'critical', label: 'Critical (75-100)', min: 75, max: 100 },
];

function decisionOf(status) {
  return DECISION_BY_STATUS[status] || 'other';
}

function dayKey(iso) {
  return String(iso || '').slice(0, 10);
}

function lastNDays(n, endIso) {
  const end = new Date((endIso || new Date().toISOString()).slice(0, 10) + 'T00:00:00Z');
  const days = [];
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(end.getTime() - i * 86400000);
    days.push(d.toISOString().slice(0, 10));
  }
  return days;
}

function bandFor(score) {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  return (RISK_BANDS.find((b) => s >= b.min && s <= b.max) || RISK_BANDS[0]).id;
}

function topEntries(map, limit) {
  return Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, limit).map(([key, count]) => ({ key, count }));
}

function isOperationalStatus(status) {
  return status === 'sensor_heartbeat' || status === 'ocr_required';
}

// Build the full insights payload from sanitized query rows.
function summarize(rows, options = {}) {
  const windowDays = Math.max(1, Math.min(90, Number(options.windowDays) || 30));
  const now = options.now || new Date().toISOString();
  const days = lastNDays(windowDays, now);
  const dayIndex = new Map(days.map((d, i) => [d, i]));
  const DECISIONS = ['allowed', 'redacted', 'warned', 'flagged', 'blocked', 'shadow'];

  const series = days.map((date) => ({ date, allowed: 0, redacted: 0, warned: 0, flagged: 0, blocked: 0, shadow: 0, total: 0 }));
  const decisionTotals = {};
  const riskBands = Object.fromEntries(RISK_BANDS.map((b) => [b.id, 0]));
  const confidence = { possible: 0, likely: 0, very_likely: 0 };
  const detectorCounts = {};
  const categoryCounts = {};
  const destinationCounts = {};
  const shadowByProvider = {};
  const userAgg = {};
  let scored = 0; let riskSum = 0; let considered = 0;

  for (const q of rows || []) {
    if (isOperationalStatus(q.status)) continue;
    considered++;
    const decision = decisionOf(q.status);
    decisionTotals[decision] = (decisionTotals[decision] || 0) + 1;
    const dk = dayKey(q.createdAt);
    if (dayIndex.has(dk) && series[dayIndex.get(dk)][decision] !== undefined) {
      series[dayIndex.get(dk)][decision]++;
      series[dayIndex.get(dk)].total++;
    }
    if (typeof q.riskScore === 'number') { riskSum += q.riskScore; scored++; riskBands[bandFor(q.riskScore)]++; }
    for (const f of q.findings || []) {
      if (f && f.type) detectorCounts[f.type] = (detectorCounts[f.type] || 0) + 1;
      const c = f && f.confidence;
      if (c && confidence[c] !== undefined) confidence[c]++;
    }
    for (const c of q.categories || []) { const name = c && (c.category || c); if (name) categoryCounts[name] = (categoryCounts[name] || 0) + 1; }
    const dest = q.destination && q.destination !== 'unknown' ? q.destination : null;
    if (dest) {
      destinationCounts[dest] = (destinationCounts[dest] || 0) + 1;
      if (decision === 'shadow') {
        const risk = aiCatalog.riskAttributes(dest);
        const provider = risk ? risk.provider : 'Unknown';
        shadowByProvider[provider] = (shadowByProvider[provider] || 0) + 1;
      }
    }
    const u = q.user || 'unknown';
    const ua = (userAgg[u] = userAgg[u] || { user: u, events: 0, blocked: 0, riskSum: 0, maxSeverity: 0 });
    ua.events++;
    if (decision === 'blocked') ua.blocked++;
    ua.riskSum += q.riskScore || 0;
    if ((q.maxSeverity || 0) > ua.maxSeverity) ua.maxSeverity = q.maxSeverity;
  }

  const topDestinations = topEntries(destinationCounts, 8).map((d) => {
    const risk = aiCatalog.riskAttributes(d.key);
    return { destination: d.key, count: d.count, risk: risk ? { provider: risk.provider, riskTier: risk.riskTier, riskTierLabel: risk.riskTierLabel, flags: risk.flags } : null };
  });
  const topUsers = Object.values(userAgg)
    .map((u) => ({ user: u.user, events: u.events, blocked: u.blocked, avgRisk: u.events ? Math.round(u.riskSum / u.events) : 0, maxSeverity: u.maxSeverity }))
    .sort((a, b) => (b.avgRisk * b.events) - (a.avgRisk * a.events))
    .slice(0, 8);

  return {
    generatedAt: now,
    windowDays,
    totals: {
      considered,
      scored,
      avgRisk: scored ? Math.round(riskSum / scored) : 0,
      blocked: decisionTotals.blocked || 0,
      redacted: decisionTotals.redacted || 0,
      allowed: decisionTotals.allowed || 0,
      shadow: decisionTotals.shadow || 0,
    },
    decisions: DECISIONS.map((id) => ({ id, count: decisionTotals[id] || 0 })),
    series,
    riskBands: RISK_BANDS.map((b) => ({ id: b.id, label: b.label, count: riskBands[b.id] })),
    confidence,
    topDetectors: topEntries(detectorCounts, 8),
    topCategories: topEntries(categoryCounts, 8),
    topDestinations,
    shadowByProvider: topEntries(shadowByProvider, 8),
    topUsers,
  };
}

module.exports = { summarize, decisionOf, RISK_BANDS };
