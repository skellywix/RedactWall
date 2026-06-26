'use strict';
/**
 * Policy engine. Decides allow / block-and-hold for each analyzed prompt, and
 * holds the scanner config (ignore-lists, disabled detectors) synced to sensors.
 */
const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, '..', 'config', 'policy.json');

const DEFAULT_POLICY = {
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 25,
  alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'],
  // When true, the raw prompt of an item held for approval is retained
  // (encrypted at rest) so an admin can review it. Set false for institutions
  // that forbid any server-side raw retention — reveal then shows redacted only.
  storeRawForApproval: true,
  ignore: [],
  disabledDetectors: [],
  governedDestinations: [
    'chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
    'gemini.google.com', 'copilot.microsoft.com', 'perplexity.ai', 'poe.com',
  ],
  scanner: {
    ignoreDirectories: ['node_modules', '.git', 'Library', 'Applications', 'AppData'],
    ignoreFilenames: ['thumbs.db', '.ds_store', 'package.json', 'package-lock.json'],
    ignoreExtensions: ['.tmp', '.log', '.lock'],
    maxFileBytes: 6.3 * 1024 * 1024,
  },
};

const AUDIT_FIELDS = [
  'enforcementMode',
  'blockMinSeverity',
  'blockRiskScore',
  'alwaysBlock',
  'storeRawForApproval',
  'ignore',
  'disabledDetectors',
  'governedDestinations',
  'scanner',
];

function normalizeForAudit(value) {
  if (Array.isArray(value)) {
    return value
      .map(normalizeForAudit)
      .sort((a, b) => String(JSON.stringify(a)).localeCompare(String(JSON.stringify(b))));
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, normalizeForAudit(value[key])]));
  }
  return value;
}

function policyChangeSummary(before, after, meta = {}) {
  const changed = [];
  for (const field of AUDIT_FIELDS) {
    const oldValue = normalizeForAudit(before && before[field]);
    const newValue = normalizeForAudit(after && after[field]);
    if (JSON.stringify(oldValue) !== JSON.stringify(newValue)) {
      changed.push({ field, before: oldValue, after: newValue });
    }
  }
  return {
    type: 'policy_change',
    ...(meta.templateId ? { templateId: String(meta.templateId) } : {}),
    changed,
  };
}

function policyChangeDetail(before, after, meta = {}) {
  return JSON.stringify(policyChangeSummary(before, after, meta));
}

function loadPolicy() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return { ...DEFAULT_POLICY, ...JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) };
    }
  } catch (e) { /* default */ }
  return { ...DEFAULT_POLICY };
}

function savePolicy(p) {
  const dir = path.dirname(CONFIG_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(p, null, 2));
}

function analyzeOpts(policy = loadPolicy()) {
  return { ignore: policy.ignore || [], disabledDetectors: policy.disabledDetectors || [] };
}

function evaluate(analysis, policy = loadPolicy()) {
  const reasons = [];
  const findings = (analysis.findings || []).filter((f) => !(policy.ignore || []).includes(f.type));
  const categories = (analysis.categories || []).filter((c) => !(policy.ignore || []).includes(c.category));

  if (findings.length === 0 && categories.length === 0) {
    return { decision: 'allow', reasons: ['Nothing sensitive detected'], policy };
  }
  if (categories.length) reasons.push('Sensitive content: ' + categories.map((c) => c.category).join(', '));
  const hardStop = findings.find((f) => (policy.alwaysBlock || []).includes(f.type));
  if (hardStop) reasons.push('Hard-stop entity present: ' + hardStop.type);
  if (analysis.maxSeverity >= policy.blockMinSeverity) reasons.push('Severity ' + analysis.maxSeverityLabel + ' >= policy minimum');
  if (analysis.riskScore >= policy.blockRiskScore) reasons.push('Risk score ' + analysis.riskScore + ' >= ' + policy.blockRiskScore);

  const decision = reasons.length ? 'block' : 'allow';
  if (decision === 'allow') reasons.push('Below blocking thresholds');
  return { decision, reasons, policy };
}

module.exports = { loadPolicy, savePolicy, evaluate, analyzeOpts, policyChangeSummary, policyChangeDetail, DEFAULT_POLICY };
