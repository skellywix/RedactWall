'use strict';
/**
 * AI application risk catalog.
 *
 * Reviewed risk metadata for known AI destinations, so shadow-AI discovery and
 * destination review show WHY a tool is risky (does it train on submitted data,
 * is it a personal/free tier, where does data reside, who operates it) — the
 * "app risk attributes" surface that Harmonic / Palo Alto / Netskope market.
 *
 * Attributes are conservative, provider-published defaults for the enterprise
 * decision; an operator can still govern/allow/block any destination regardless.
 * Data only — no plaintext prompts, no scoring of individual events here.
 */
const { normalizeHost } = require('../detection-engine/adapters');

// riskTier: 1 low .. 4 critical. trainsOnData/personalTier are the two attributes
// buyers ask about most for shadow AI.
const CATALOG = [
  { host: 'chatgpt.com', provider: 'OpenAI', region: 'US', trainsOnData: 'consumer_default', personalTier: true, riskTier: 3 },
  { host: 'chat.openai.com', provider: 'OpenAI', region: 'US', trainsOnData: 'consumer_default', personalTier: true, riskTier: 3 },
  { host: 'claude.ai', provider: 'Anthropic', region: 'US', trainsOnData: 'opt_in', personalTier: true, riskTier: 2 },
  { host: 'gemini.google.com', provider: 'Google', region: 'US', trainsOnData: 'consumer_default', personalTier: true, riskTier: 3 },
  { host: 'copilot.microsoft.com', provider: 'Microsoft', region: 'US', trainsOnData: 'consumer_default', personalTier: true, riskTier: 3 },
  { host: 'perplexity.ai', provider: 'Perplexity', region: 'US', trainsOnData: 'consumer_default', personalTier: true, riskTier: 3 },
  { host: 'poe.com', provider: 'Quora', region: 'US', trainsOnData: 'unknown', personalTier: true, riskTier: 3 },
  { host: 'character.ai', provider: 'Character.AI', region: 'US', trainsOnData: 'consumer_default', personalTier: true, riskTier: 3 },
  { host: 'huggingface.co', provider: 'Hugging Face', region: 'US', trainsOnData: 'varies', personalTier: true, riskTier: 2 },
  { host: 'deepseek.com', provider: 'DeepSeek', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'chat.deepseek.com', provider: 'DeepSeek', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'qwen.ai', provider: 'Alibaba', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'chat.qwen.ai', provider: 'Alibaba', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'kimi.com', provider: 'Moonshot AI', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'doubao.com', provider: 'ByteDance', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'yiyan.baidu.com', provider: 'Baidu', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'ernie.baidu.com', provider: 'Baidu', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'chatglm.cn', provider: 'Zhipu AI', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'z.ai', provider: 'Zhipu AI', region: 'CN', trainsOnData: 'consumer_default', personalTier: true, riskTier: 4 },
  { host: 'mistral.ai', provider: 'Mistral', region: 'EU', trainsOnData: 'opt_in', personalTier: true, riskTier: 2 },
  { host: 'chat.mistral.ai', provider: 'Mistral', region: 'EU', trainsOnData: 'opt_in', personalTier: true, riskTier: 2 },
  { host: 'grok.com', provider: 'xAI', region: 'US', trainsOnData: 'consumer_default', personalTier: true, riskTier: 3 },
  { host: 'you.com', provider: 'You.com', region: 'US', trainsOnData: 'unknown', personalTier: true, riskTier: 3 },
  { host: 'pi.ai', provider: 'Inflection', region: 'US', trainsOnData: 'unknown', personalTier: true, riskTier: 3 },
];

let INDEX = null;
function index() {
  if (INDEX) return INDEX;
  INDEX = new Map();
  for (const entry of CATALOG) INDEX.set(normalizeHost(entry.host), entry);
  return INDEX;
}

const TIER_LABEL = { 1: 'low', 2: 'moderate', 3: 'elevated', 4: 'high' };

// Bounded, sensor-safe risk attributes for a destination, or null if unknown.
function riskAttributes(destination) {
  const host = normalizeHost(destination);
  if (!host) return null;
  const entry = index().get(host);
  if (!entry) return null;
  const flags = [];
  if (entry.trainsOnData === 'consumer_default') flags.push('trains_on_data');
  if (entry.personalTier) flags.push('personal_account_tier');
  if (entry.region && entry.region !== 'US') flags.push('data_residency_' + entry.region.toLowerCase());
  return {
    provider: entry.provider,
    region: entry.region,
    trainsOnData: entry.trainsOnData,
    personalTier: !!entry.personalTier,
    riskTier: entry.riskTier,
    riskTierLabel: TIER_LABEL[entry.riskTier] || 'unknown',
    flags,
  };
}

module.exports = { CATALOG, riskAttributes, TIER_LABEL };
