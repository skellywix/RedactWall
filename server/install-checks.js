'use strict';

const AI_TOOL_RESERVED_CHECKS = new Set(['ai_tool_inventory', 'ai_tool_inventory_runtime']);
const AI_TOOL_POLICY_CHECK_RE = /^ai_tool_[a-z][a-z0-9_]{0,39}$/;

function cleanCheckId(value) {
  return String(value || '').trim();
}

function isEndpointAiToolPolicyCheckId(value) {
  const id = cleanCheckId(value);
  return AI_TOOL_POLICY_CHECK_RE.test(id) && !AI_TOOL_RESERVED_CHECKS.has(id);
}

function failedInstallCheckIds(checks = []) {
  return (Array.isArray(checks) ? checks : [])
    .filter((check) => check && check.ok !== true && !isEndpointAiToolPolicyCheckId(check.id))
    .map((check) => cleanCheckId(check.id))
    .filter(Boolean);
}

function endpointAiToolAttentionIds(checks = []) {
  return (Array.isArray(checks) ? checks : [])
    .filter((check) => check && check.ok !== true && isEndpointAiToolPolicyCheckId(check.id))
    .map((check) => cleanCheckId(check.id).slice('ai_tool_'.length))
    .filter(Boolean);
}

module.exports = {
  endpointAiToolAttentionIds,
  failedInstallCheckIds,
  isEndpointAiToolPolicyCheckId,
};
