'use strict';
/**
 * Metadata-only MCP/SaaS connector registry.
 *
 * The registry distinguishes shipped connector runtime from profile templates.
 * It is intentionally credential-free so install checks, posture, and package
 * manifests can prove coverage breadth without exposing tokens or document IDs.
 */
const fs = require('fs');
const path = require('path');

const MAX_TEXT = 120;

const CONNECTOR_PROFILES = Object.freeze([
  {
    id: 'microsoft365',
    label: 'Microsoft 365 Graph',
    stage: 'shipped',
    category: 'document_repository',
    runtimePath: 'sensors/mcp-guard/connectors/microsoft365.js',
    operations: ['driveItem.getContent', 'sites.page.get', 'sites.listItem.get'],
    tokenAliases: ['M365_GRAPH_ACCESS_TOKEN', 'MICROSOFT_GRAPH_ACCESS_TOKEN'],
    tenantAliases: ['M365_TENANT_ID', 'AZURE_TENANT_ID'],
    scopeAliases: ['M365_GRAPH_SCOPES', 'MICROSOFT_GRAPH_SCOPES'],
    defaultScopes: ['Files.Read', 'Sites.Selected'],
    detail: 'Text-readable OneDrive and SharePoint driveItem, site page, and list item content via the shared MCP guard.',
  },
  {
    id: 'google_drive',
    label: 'Google Drive',
    stage: 'shipped',
    category: 'document_repository',
    runtimePath: 'sensors/mcp-guard/connectors/google-drive.js',
    operations: ['files.export', 'files.get'],
    tokenAliases: ['GOOGLE_DRIVE_ACCESS_TOKEN', 'GOOGLE_WORKSPACE_ACCESS_TOKEN'],
    tenantAliases: ['GOOGLE_WORKSPACE_CUSTOMER_ID', 'GOOGLE_WORKSPACE_DOMAIN'],
    scopeAliases: ['GOOGLE_DRIVE_SCOPES'],
    defaultScopes: ['https://www.googleapis.com/auth/drive.readonly'],
    tenantRequired: false,
    detail: 'Read-only Google Drive blob downloads and Google Workspace document export through the shared MCP guard.',
  },
  {
    id: 'slack',
    label: 'Slack',
    stage: 'shipped',
    category: 'collaboration',
    runtimePath: 'sensors/mcp-guard/connectors/slack.js',
    operations: ['conversations.history', 'files.info'],
    tokenAliases: ['SLACK_BOT_TOKEN', 'SLACK_CONNECTOR_TOKEN'],
    tenantAliases: ['SLACK_TEAM_ID', 'SLACK_ENTERPRISE_ID'],
    scopeAliases: ['SLACK_SCOPES'],
    defaultScopes: ['channels:history', 'groups:history', 'files:read'],
    tenantRequired: false,
    detail: 'Read-only Slack conversation history and text-readable private file content guarded before model use.',
  },
  {
    id: 'teams',
    label: 'Microsoft Teams',
    stage: 'shipped',
    category: 'collaboration',
    runtimePath: 'sensors/mcp-guard/connectors/teams.js',
    operations: ['chats.messages', 'channels.messages'],
    tokenAliases: ['TEAMS_GRAPH_ACCESS_TOKEN', 'M365_GRAPH_ACCESS_TOKEN'],
    tenantAliases: ['TEAMS_TENANT_ID', 'M365_TENANT_ID', 'AZURE_TENANT_ID'],
    scopeAliases: ['TEAMS_GRAPH_SCOPES'],
    defaultScopes: ['ChannelMessage.Read.Group', 'ChatMessage.Read.Chat'],
    tenantRequired: false,
    detail: 'Read-only Teams channel and chat messages through Microsoft Graph and the shared MCP guard.',
  },
  {
    id: 'jira_confluence',
    label: 'Jira And Confluence',
    stage: 'shipped',
    category: 'knowledge_base',
    runtimePath: 'sensors/mcp-guard/connectors/atlassian.js',
    operations: ['issue.get', 'page.get'],
    tokenAliases: ['ATLASSIAN_ACCESS_TOKEN', 'ATLASSIAN_API_TOKEN', 'JIRA_API_TOKEN', 'CONFLUENCE_API_TOKEN'],
    tenantAliases: ['ATLASSIAN_SITE_URL'],
    scopeAliases: ['ATLASSIAN_SCOPES'],
    defaultScopes: ['read:jira-work', 'read:page:confluence'],
    detail: 'Read-only Jira issue and Confluence page content guarded before agent summarization.',
  },
  {
    id: 'database_readonly',
    label: 'Database Read-Only',
    stage: 'shipped',
    category: 'database',
    runtimePath: 'sensors/mcp-guard/connectors/database-readonly.js',
    operations: ['query.readonly', 'schema.readonly'],
    tokenAliases: ['MCP_DATABASE_DSN', 'DATABASE_READONLY_DSN'],
    tenantAliases: ['MCP_DATABASE_LABEL'],
    scopeAliases: ['MCP_DATABASE_SCOPES'],
    defaultScopes: ['readonly'],
    tenantRequired: false,
    detail: 'Read-only SQLite query and schema tools that redact rows before model use.',
  },
]);

function cleanText(value, fallback = '', max = MAX_TEXT) {
  const text = String(value == null ? fallback : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return (text || fallback).slice(0, max);
}

function configured(value) {
  return value != null && String(value).trim() !== '';
}

function firstConfigured(config = {}, aliases = []) {
  for (const alias of aliases || []) {
    if (configured(config[alias])) return { alias, value: String(config[alias]) };
  }
  return { alias: '', value: '' };
}

function splitScopes(value) {
  return String(value || '').split(/[,\s]+/).map((scope) => cleanText(scope, '', 48)).filter(Boolean);
}

function existsRuntime(repoRoot, relPath) {
  return configured(relPath) && fs.existsSync(path.join(repoRoot, relPath));
}

function profileStatus(profile, opts = {}) {
  const repoRoot = path.resolve(opts.repoRoot || path.join(__dirname, '..', '..'));
  const config = opts.envConfig || {};
  const token = firstConfigured(config, profile.tokenAliases);
  const tenant = firstConfigured(config, profile.tenantAliases);
  const rawScopes = firstConfigured(config, profile.scopeAliases).value;
  const scopes = splitScopes(rawScopes);
  const effectiveScopes = scopes.length ? scopes : (profile.defaultScopes || []);
  const runtimePresent = profile.stage === 'shipped'
    ? existsRuntime(repoRoot, profile.runtimePath)
    : false;
  const credentialsSeen = configured(token.value) || configured(tenant.value) || scopes.length > 0;
  const tenantRequired = profile.tenantRequired === true
    || (profile.tenantRequired !== false && Array.isArray(profile.tenantAliases) && profile.tenantAliases.length > 0);
  const configuredOk = configured(token.value) && (!tenantRequired || configured(tenant.value));
  const status = profile.stage === 'shipped'
    ? (runtimePresent ? (configuredOk ? 'configured' : 'runtime_present') : 'runtime_missing')
    : (credentialsSeen ? 'template_credentials_seen' : 'profile_template');

  return {
    id: cleanText(profile.id, 'unknown', 80),
    label: cleanText(profile.label, 'Connector', 80),
    stage: profile.stage === 'shipped' ? 'shipped' : 'template',
    category: cleanText(profile.category, 'connector', 80),
    status,
    runtimePresent,
    configured: configuredOk,
    credentialsSeen,
    operations: (profile.operations || []).map((item) => cleanText(item, '', 80)).filter(Boolean).slice(0, 6),
    scopeCount: effectiveScopes.length,
    defaultScopeCount: (profile.defaultScopes || []).length,
    detail: cleanText(profile.detail, 'metadata-only connector profile', 180),
  };
}

function connectorRegistryStatus(opts = {}) {
  const profiles = CONNECTOR_PROFILES.map((profile) => profileStatus(profile, opts));
  const shipped = profiles.filter((profile) => profile.stage === 'shipped');
  const templates = profiles.filter((profile) => profile.stage === 'template');
  const configuredProfiles = profiles.filter((profile) => profile.configured || profile.credentialsSeen);
  const runtimeMissing = shipped.filter((profile) => !profile.runtimePresent);
  return {
    summary: {
      profiles: profiles.length,
      shipped: shipped.length,
      shippedRuntimePresent: shipped.filter((profile) => profile.runtimePresent).length,
      profileTemplates: templates.length,
      configuredProfiles: configuredProfiles.length,
      runtimeMissing: runtimeMissing.length,
      nextConnector: templates[0] ? templates[0].id : 'none',
      privacy: 'metadata only; tokens and document IDs excluded',
    },
    profiles,
  };
}

function check(id, ok, detail) {
  return {
    id: cleanText(id, 'mcp_connector_registry', 80).replace(/[^A-Za-z0-9_.:-]/g, '_'),
    ok: ok === true,
    detail: cleanText(detail, ok ? 'ok' : 'attention', 160),
  };
}

function connectorRegistryChecks(status = connectorRegistryStatus()) {
  const summary = status.summary || {};
  const profiles = Array.isArray(status.profiles) ? status.profiles : [];
  const checks = [
    check(
      'mcp_connector_registry',
      Number(summary.shippedRuntimePresent || 0) >= 1 && Number(summary.profiles || 0) >= 4,
      `shipped:${Number(summary.shippedRuntimePresent || 0)}/${Number(summary.shipped || 0)} profiles:${Number(summary.profiles || 0)} next:${cleanText(summary.nextConnector, 'google_drive', 40)}`,
    ),
  ];
  for (const profile of profiles.slice(0, 10)) {
    const ok = profile.stage === 'shipped' ? profile.runtimePresent === true : true;
    checks.push(check(
      `mcp_connector_profile_${profile.id}`,
      ok,
      `stage:${profile.stage} status:${profile.status} scopes:${Number(profile.scopeCount || 0)}`,
    ));
  }
  return checks;
}

module.exports = {
  CONNECTOR_PROFILES,
  connectorRegistryChecks,
  connectorRegistryStatus,
  profileStatus,
};
