'use strict';
/**
 * Policy engine. Decides allow / block-and-hold for each analyzed prompt, and
 * holds the scanner config (ignore-lists, disabled detectors) synced to sensors.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');

const CONFIG_PATH = process.env.SENTINEL_POLICY_PATH || path.join(__dirname, '..', 'config', 'policy.json');

const DEFAULT_POLICY = {
  enforcementMode: 'block',
  blockMinSeverity: 2,
  blockRiskScore: 25,
  alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'],
  // When true, the raw prompt of an item held for approval is retained
  // (encrypted at rest) so an admin can review it. Set false for institutions
  // that forbid any server-side raw retention — reveal then shows redacted only.
  storeRawForApproval: true,
  rawRetentionDays: 30,
  ignore: [],
  disabledDetectors: [],
  governedDestinations: [
    'chatgpt.com', 'openai.com', 'claude.ai', 'anthropic.com',
    'gemini.google.com', 'copilot.microsoft.com', 'perplexity.ai', 'poe.com',
    'chat.deepseek.com', 'deepseek.com', 'chat.qwen.ai', 'qwen.ai', 'tongyi.aliyun.com',
    'kimi.com', 'kimi.moonshot.cn', 'doubao.com', 'yuanbao.tencent.com',
    'yiyan.baidu.com', 'ernie.baidu.com', 'chatglm.cn', 'z.ai',
  ],
  allowedDestinations: [],
  blockedDestinations: [],
  blockedFileUploadDestinations: [],
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
  'rawRetentionDays',
  'ignore',
  'disabledDetectors',
  'governedDestinations',
  'allowedDestinations',
  'blockedDestinations',
  'blockedFileUploadDestinations',
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

function rawRetentionDays(policy = loadPolicy()) {
  const n = Number(policy && policy.rawRetentionDays);
  if (!Number.isFinite(n)) return DEFAULT_POLICY.rawRetentionDays;
  return Math.max(0, Math.min(3650, Math.floor(n)));
}

function normalizeDestination(value) {
  const raw = String(value || '').trim().toLowerCase().replace(/\s+/g, '-');
  if (!raw) return 'unknown';
  try {
    const url = raw.includes('://') ? new URL(raw) : new URL(`https://${raw}`);
    return url.hostname.replace(/^www\./, '');
  } catch {
    return raw.replace(/^www\./, '').split(/[/?#]/)[0] || 'unknown';
  }
}

function destinationMatches(destination, patterns) {
  const host = normalizeDestination(destination);
  return (patterns || []).some((pattern) => {
    const target = normalizeDestination(pattern);
    if (!target || target === 'unknown') return false;
    if (target === '*') return true;
    if (target.startsWith('*.')) {
      const base = target.slice(2);
      return host.endsWith('.' + base);
    }
    if (target.startsWith('*')) {
      const base = target.slice(1).replace(/^\./, '');
      return host === base || host.endsWith('.' + base);
    }
    return host === target || host.endsWith('.' + target);
  });
}

function destinationBlocked(destination, policy = loadPolicy()) {
  if (destinationAllowed(destination, policy)) return false;
  return destinationMatches(destination, policy.blockedDestinations || []);
}

function fileUploadBlocked(destination, policy = loadPolicy()) {
  if (destinationAllowed(destination, policy)) return false;
  return destinationMatches(destination, policy.blockedFileUploadDestinations || []);
}

function destinationAllowed(destination, policy = loadPolicy()) {
  return destinationMatches(destination, policy.allowedDestinations || []);
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

module.exports = {
  loadPolicy,
  savePolicy,
  evaluate,
  analyzeOpts,
  rawRetentionDays,
  normalizeDestination,
  destinationMatches,
  destinationAllowed,
  destinationBlocked,
  fileUploadBlocked,
  policyChangeSummary,
  policyChangeDetail,
  DEFAULT_POLICY,
};
