'use strict';

const AI_TOOL_RESERVED_CHECKS = new Set(['ai_tool_inventory', 'ai_tool_inventory_runtime']);
const AI_TOOL_POLICY_CHECK_RE = /^ai_tool_[a-z][a-z0-9_]{0,39}$/;
const MCP_SERVER_RESERVED_CHECKS = new Set(['mcp_inventory', 'mcp_inventory_runtime']);
const MCP_SERVER_POLICY_CHECK_RE = /^mcp_server_[a-z][a-z0-9_]{0,39}$/;

function cleanCheckId(value) {
  return String(value || '').trim();
}

function isEndpointAiToolPolicyCheckId(value) {
  const id = cleanCheckId(value);
  return AI_TOOL_POLICY_CHECK_RE.test(id) && !AI_TOOL_RESERVED_CHECKS.has(id);
}

function isEndpointMcpServerPolicyCheckId(value) {
  const id = cleanCheckId(value);
  return MCP_SERVER_POLICY_CHECK_RE.test(id) && !MCP_SERVER_RESERVED_CHECKS.has(id);
}

// Inventory attention checks (unapproved AI tools or MCP servers) surface as
// posture attention, NOT sensor-health failures — installing an agent that sees
// an unapproved MCP server must not turn the fleet row red or fire an alert.
function isInventoryAttentionCheckId(value) {
  return isEndpointAiToolPolicyCheckId(value) || isEndpointMcpServerPolicyCheckId(value);
}

function failedInstallCheckIds(checks = []) {
  return (Array.isArray(checks) ? checks : [])
    .filter((check) => check && check.ok !== true && !isInventoryAttentionCheckId(check.id))
    .map((check) => cleanCheckId(check.id))
    .filter(Boolean);
}

function endpointAiToolAttentionIds(checks = []) {
  return (Array.isArray(checks) ? checks : [])
    .filter((check) => check && check.ok !== true && isEndpointAiToolPolicyCheckId(check.id))
    .map((check) => cleanCheckId(check.id).slice('ai_tool_'.length))
    .filter(Boolean);
}

function endpointMcpServerAttentionIds(checks = []) {
  return (Array.isArray(checks) ? checks : [])
    .filter((check) => check && check.ok !== true && isEndpointMcpServerPolicyCheckId(check.id))
    .map((check) => cleanCheckId(check.id).slice('mcp_server_'.length))
    .filter(Boolean);
}

module.exports = {
  endpointAiToolAttentionIds,
  endpointMcpServerAttentionIds,
  failedInstallCheckIds,
  isEndpointAiToolPolicyCheckId,
  isEndpointMcpServerPolicyCheckId,
};
