'use strict';
/**
 * Sanitized approval-workflow notifications.
 *
 * Notification payloads are intentionally smaller than SIEM alerts because they
 * may land in broader operational channels. They contain routing context and
 * detector labels, never prompt bodies, token vaults, release tokens, raw
 * finding values, or decision notes.
 */
require('./env').loadEnv();
const { safeSensor } = require('./sensor-metadata');
const routing = require('./routing');
const smtp = require('./smtp');
const { outboundHttpsUrl } = require('./url-policy');

const MAX_LABELS = 20;
const MAX_REASONS = 8;
const DEFAULT_LINEAR_API_URL = 'https://api.linear.app/graphql';
// Bound outbound notifier requests so a hung webhook/ticket endpoint cannot
// stall an approval action that awaits notification delivery.
const OUTBOUND_TIMEOUT_MS = (() => {
  const n = Number(process.env.REDACTWALL_NOTIFIER_TIMEOUT_MS || process.env.APPROVAL_NOTIFIER_TIMEOUT_MS);
  return Number.isFinite(n) && n > 0 ? n : 8000;
})();
function outboundSignal() {
  return typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(OUTBOUND_TIMEOUT_MS) : undefined;
}

function envValue(env, ...names) {
  for (const name of names) {
    const value = env && env[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function trimmed(value, limit = 2048) {
  const text = String(value || '').trim();
  return text ? text.slice(0, limit) : '';
}

function csv(value, limit = 20) {
  return trimmed(value, 4096)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .slice(0, limit);
}

function jiraIssueUrl(baseUrl) {
  const normalized = outboundHttpsUrl(baseUrl);
  if (!normalized) return '';
  const url = new URL(normalized);
  url.pathname = url.pathname.replace(/\/+$/, '') + '/rest/api/3/issue';
  url.search = '';
  url.hash = '';
  return url.toString();
}

function linearApiUrl(value) {
  const raw = trimmed(value);
  if (!raw) return DEFAULT_LINEAR_API_URL;
  return outboundHttpsUrl(raw);
}

function parseBool(value, fallback = false) {
  if (typeof value !== 'string' || !value.trim()) return fallback;
  return /^(1|true|yes|on)$/i.test(value.trim());
}

function parsePort(value, fallback) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : fallback;
}

function configuredJiraChannel(env) {
  const url = jiraIssueUrl(envValue(env, 'REDACTWALL_APPROVAL_JIRA_BASE_URL', 'APPROVAL_JIRA_BASE_URL'));
  const email = envValue(env, 'REDACTWALL_APPROVAL_JIRA_EMAIL', 'APPROVAL_JIRA_EMAIL');
  const token = envValue(env, 'REDACTWALL_APPROVAL_JIRA_API_TOKEN', 'APPROVAL_JIRA_API_TOKEN');
  const projectKey = envValue(env, 'REDACTWALL_APPROVAL_JIRA_PROJECT_KEY', 'APPROVAL_JIRA_PROJECT_KEY');
  if (!url || !email || !token || !projectKey) return null;
  return {
    type: 'jira',
    name: 'jira',
    url,
    email,
    token,
    projectKey,
    issueType: envValue(env, 'REDACTWALL_APPROVAL_JIRA_ISSUE_TYPE', 'APPROVAL_JIRA_ISSUE_TYPE') || 'Task',
  };
}

function configuredLinearChannel(env) {
  const token = envValue(env, 'REDACTWALL_APPROVAL_LINEAR_API_KEY', 'APPROVAL_LINEAR_API_KEY');
  const teamId = envValue(env, 'REDACTWALL_APPROVAL_LINEAR_TEAM_ID', 'APPROVAL_LINEAR_TEAM_ID');
  const url = linearApiUrl(envValue(env, 'REDACTWALL_APPROVAL_LINEAR_API_URL', 'APPROVAL_LINEAR_API_URL'));
  if (!token || !teamId || !url) return null;
  return {
    type: 'linear',
    name: 'linear',
    url,
    token,
    teamId,
    stateId: envValue(env, 'REDACTWALL_APPROVAL_LINEAR_STATE_ID', 'APPROVAL_LINEAR_STATE_ID'),
    projectId: envValue(env, 'REDACTWALL_APPROVAL_LINEAR_PROJECT_ID', 'APPROVAL_LINEAR_PROJECT_ID'),
    labelIds: csv(envValue(env, 'REDACTWALL_APPROVAL_LINEAR_LABEL_IDS', 'APPROVAL_LINEAR_LABEL_IDS')),
  };
}

function configuredChannels(env = process.env, opts = {}) {
  if (Array.isArray(opts.channels)) return opts.channels.map(normalizeConfiguredChannel).filter(Boolean);
  const channels = [];
  const webhookUrl = outboundHttpsUrl(envValue(env, 'REDACTWALL_APPROVAL_NOTIFY_WEBHOOK_URL', 'APPROVAL_NOTIFY_WEBHOOK_URL'));
  if (webhookUrl) {
    channels.push({
      type: 'webhook',
      name: 'webhook',
      url: webhookUrl,
      token: envValue(env, 'REDACTWALL_APPROVAL_NOTIFY_WEBHOOK_TOKEN', 'APPROVAL_NOTIFY_WEBHOOK_TOKEN'),
    });
  }
  const slackUrl = outboundHttpsUrl(envValue(env, 'REDACTWALL_APPROVAL_SLACK_WEBHOOK_URL', 'APPROVAL_SLACK_WEBHOOK_URL'));
  if (slackUrl) channels.push({ type: 'slack', name: 'slack', url: slackUrl });
  const teamsUrl = outboundHttpsUrl(envValue(env, 'REDACTWALL_APPROVAL_TEAMS_WEBHOOK_URL', 'APPROVAL_TEAMS_WEBHOOK_URL'));
  if (teamsUrl) channels.push({ type: 'teams', name: 'teams', url: teamsUrl });
  const ticketUrl = outboundHttpsUrl(envValue(env, 'REDACTWALL_APPROVAL_TICKET_WEBHOOK_URL', 'APPROVAL_TICKET_WEBHOOK_URL'));
  if (ticketUrl) {
    channels.push({
      type: 'ticket',
      name: 'ticket',
      url: ticketUrl,
      token: envValue(env, 'REDACTWALL_APPROVAL_TICKET_WEBHOOK_TOKEN', 'APPROVAL_TICKET_WEBHOOK_TOKEN'),
      system: envValue(env, 'REDACTWALL_APPROVAL_TICKET_SYSTEM', 'APPROVAL_TICKET_SYSTEM'),
      project: envValue(env, 'REDACTWALL_APPROVAL_TICKET_PROJECT', 'APPROVAL_TICKET_PROJECT'),
      issueType: envValue(env, 'REDACTWALL_APPROVAL_TICKET_ISSUE_TYPE', 'APPROVAL_TICKET_ISSUE_TYPE'),
    });
  }
  const jira = configuredJiraChannel(env);
  if (jira) channels.push(jira);
  const linear = configuredLinearChannel(env);
  if (linear) channels.push(linear);
  const smtpHost = envValue(env, 'REDACTWALL_APPROVAL_SMTP_HOST', 'APPROVAL_SMTP_HOST');
  const smtpFrom = envValue(env, 'REDACTWALL_APPROVAL_SMTP_FROM', 'APPROVAL_SMTP_FROM');
  const smtpTo = smtp.parseRecipients(envValue(env, 'REDACTWALL_APPROVAL_SMTP_TO', 'APPROVAL_SMTP_TO'));
  if (smtpHost && smtp.extractEmailAddress(smtpFrom) && smtpTo.length) {
    const secure = parseBool(envValue(env, 'REDACTWALL_APPROVAL_SMTP_SECURE', 'APPROVAL_SMTP_SECURE'), false);
    channels.push({
      type: 'smtp',
      name: 'smtp',
      host: smtpHost,
      port: parsePort(envValue(env, 'REDACTWALL_APPROVAL_SMTP_PORT', 'APPROVAL_SMTP_PORT'), secure ? 465 : 587),
      from: smtpFrom,
      to: smtpTo,
      username: envValue(env, 'REDACTWALL_APPROVAL_SMTP_USERNAME', 'APPROVAL_SMTP_USERNAME'),
      password: envValue(env, 'REDACTWALL_APPROVAL_SMTP_PASSWORD', 'APPROVAL_SMTP_PASSWORD'),
      secure,
      requireTls: !parseBool(envValue(env, 'REDACTWALL_APPROVAL_SMTP_ALLOW_INSECURE', 'APPROVAL_SMTP_ALLOW_INSECURE'), false),
      timeoutMs: parsePort(envValue(env, 'REDACTWALL_APPROVAL_SMTP_TIMEOUT_MS', 'APPROVAL_SMTP_TIMEOUT_MS'), 10000),
    });
  }
  return channels;
}

function normalizeConfiguredChannel(channel) {
  if (!channel || !channel.type) return null;
  if (channel.type === 'smtp') return channel;
  const url = outboundHttpsUrl(channel.url);
  return url ? { ...channel, url } : null;
}

function safeReasons(reasons = []) {
  return (Array.isArray(reasons) ? reasons : [])
    .filter((reason) => typeof reason === 'string' && reason.trim())
    .slice(0, MAX_REASONS)
    .map((reason) => reason.trim().slice(0, 160));
}

function safeFindingLabels(query = {}) {
  return routing.labelsFor(query).sort().slice(0, MAX_LABELS);
}

function notificationTitle(action) {
  if (action === 'APPROVAL_ESCALATED') return 'RedactWall approval escalated';
  return 'RedactWall approval routed';
}

function sanitizedApprovalNotification(query = {}, opts = {}) {
  const workflow = routing.publicWorkflow(query);
  const action = opts.action || 'APPROVAL_ROUTED';
  return {
    schemaVersion: 1,
    eventType: 'redactwall.approval_workflow',
    action,
    title: notificationTitle(action),
    queryId: query.id || null,
    createdAt: query.createdAt || null,
    status: query.status || null,
    user: query.user || 'unknown',
    orgId: query.orgId || null,
    source: query.source || 'unknown',
    channel: query.channel || 'unknown',
    sensor: safeSensor(query.sensor),
    destination: query.destination || 'unknown',
    riskScore: Number(query.riskScore) || 0,
    maxSeverity: Number(query.maxSeverity) || 0,
    maxSeverityLabel: query.maxSeverityLabel || 'none',
    labels: safeFindingLabels(query),
    reasons: safeReasons(query.reasons),
    workflow,
  };
}

function shouldNotifyApproval(query) {
  if (!query || !routing.routeableStatus(query.status)) return false;
  const workflow = routing.publicWorkflow(query);
  return !!(workflow.assignedGroup || workflow.assignedRole || workflow.slaDueAt);
}

function oneLine(payload) {
  const owner = [payload.workflow.assignedGroup, payload.workflow.assignedRole].filter(Boolean).join('/');
  const labels = payload.labels.length ? payload.labels.join(', ') : 'no detector labels';
  return `${payload.title}: ${owner || 'unassigned'} for ${payload.queryId || 'unknown'} at ${payload.destination || 'unknown'} (${labels})`;
}

function slackPayload(payload) {
  const fields = [
    { type: 'mrkdwn', text: `*Owner*\n${payload.workflow.assignedGroup || 'unassigned'} / ${payload.workflow.assignedRole || 'unassigned'}` },
    { type: 'mrkdwn', text: `*SLA*\n${payload.workflow.slaDueAt || 'none'}` },
    { type: 'mrkdwn', text: `*Destination*\n${payload.destination}` },
    { type: 'mrkdwn', text: `*Risk*\n${payload.maxSeverityLabel} (${payload.riskScore})` },
  ];
  return {
    text: oneLine(payload),
    blocks: [
      { type: 'header', text: { type: 'plain_text', text: payload.title } },
      { type: 'section', fields },
      { type: 'context', elements: [{ type: 'mrkdwn', text: `Query ${payload.queryId || 'unknown'} - ${payload.labels.join(', ') || 'no labels'}` }] },
    ],
  };
}

function teamsPayload(payload) {
  return {
    '@type': 'MessageCard',
    '@context': 'https://schema.org/extensions',
    summary: payload.title,
    themeColor: payload.action === 'APPROVAL_ESCALATED' ? 'C2410C' : '2563EB',
    title: payload.title,
    sections: [{
      activityTitle: `Query ${payload.queryId || 'unknown'}`,
      facts: [
        { name: 'Owner', value: `${payload.workflow.assignedGroup || 'unassigned'} / ${payload.workflow.assignedRole || 'unassigned'}` },
        { name: 'SLA', value: payload.workflow.slaDueAt || 'none' },
        { name: 'Destination', value: payload.destination },
        { name: 'Risk', value: `${payload.maxSeverityLabel} (${payload.riskScore})` },
        { name: 'Labels', value: payload.labels.join(', ') || 'none' },
      ],
      markdown: true,
    }],
  };
}

function boundedText(value, limit = 80) {
  const text = String(value || '').trim();
  return text ? text.slice(0, limit) : null;
}

function priorityForTicket(payload) {
  if (payload.action === 'APPROVAL_ESCALATED') return 'high';
  if (payload.maxSeverity >= 4 || payload.riskScore >= 75) return 'critical';
  if (payload.maxSeverity >= 3 || payload.riskScore >= 50) return 'high';
  return 'normal';
}

function ticketQuery(payload) {
  return {
    id: payload.queryId,
    createdAt: payload.createdAt,
    status: payload.status,
    user: payload.user,
    orgId: payload.orgId,
    source: payload.source,
    channel: payload.channel,
    sensor: payload.sensor,
    destination: payload.destination,
    riskScore: payload.riskScore,
    maxSeverity: payload.maxSeverity,
    maxSeverityLabel: payload.maxSeverityLabel,
    labels: payload.labels,
    reasons: payload.reasons,
  };
}

function ticketPayload(channel, payload) {
  return {
    schemaVersion: 1,
    eventType: 'redactwall.approval_ticket',
    action: payload.action,
    title: payload.title,
    summary: oneLine(payload),
    dedupeKey: `redactwall:${payload.queryId || 'unknown'}:${payload.action}`,
    priority: priorityForTicket(payload),
    ticket: {
      system: boundedText(channel.system) || 'generic',
      project: boundedText(channel.project),
      issueType: boundedText(channel.issueType) || 'Security Review',
    },
    query: ticketQuery(payload),
    workflow: payload.workflow,
  };
}

function issueSummary(payload) {
  const owner = [payload.workflow.assignedGroup, payload.workflow.assignedRole].filter(Boolean).join('/');
  const destination = payload.destination || 'unknown';
  const label = payload.labels[0] || payload.maxSeverityLabel || 'review';
  return boundedText(`RedactWall ${payload.action === 'APPROVAL_ESCALATED' ? 'escalation' : 'approval'}: ${label} at ${destination}${owner ? ' for ' + owner : ''}`, 240);
}

function issueDescription(payload) {
  return [
    payload.title,
    `Query: ${payload.queryId || 'unknown'}`,
    `Action: ${payload.action || 'unknown'}`,
    `Owner: ${payload.workflow.assignedGroup || 'unassigned'} / ${payload.workflow.assignedRole || 'unassigned'}`,
    `SLA: ${payload.workflow.slaDueAt || 'none'}`,
    `Destination: ${payload.destination || 'unknown'}`,
    `Source: ${payload.source || 'unknown'} / ${payload.channel || 'unknown'}`,
    `User: ${payload.user || 'unknown'}`,
    `Org: ${payload.orgId || 'unknown'}`,
    `Risk: ${payload.maxSeverityLabel || 'none'} (${payload.riskScore || 0})`,
    `Labels: ${payload.labels.join(', ') || 'none'}`,
    `Reasons: ${payload.reasons.join('; ') || 'none'}`,
    '',
    'This issue was generated from sanitized RedactWall workflow metadata only. It intentionally omits prompt bodies, redacted previews, raw findings, token vaults, release tokens, decision notes, and uploaded file bytes.',
  ].join('\n').slice(0, 8000);
}

function issueLabel(value) {
  const label = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
  return label || null;
}

function issueLabels(payload) {
  return ['redactwall', 'approval', priorityForTicket(payload), ...payload.labels]
    .map(issueLabel)
    .filter(Boolean)
    .slice(0, 12);
}

function jiraAdf(text) {
  const content = String(text || '')
    .split('\n')
    .map((line) => line.trim())
    .map((line) => ({
      type: 'paragraph',
      content: line ? [{ type: 'text', text: line }] : [],
    }));
  return { type: 'doc', version: 1, content };
}

function jiraIssuePayload(channel, payload) {
  return {
    fields: {
      project: { key: boundedText(channel.projectKey, 80) },
      issuetype: { name: boundedText(channel.issueType, 80) || 'Task' },
      summary: issueSummary(payload),
      description: jiraAdf(issueDescription(payload)),
      labels: issueLabels(payload),
    },
  };
}

function linearIssuePayload(channel, payload) {
  const input = {
    teamId: boundedText(channel.teamId, 80),
    title: issueSummary(payload),
    description: issueDescription(payload),
  };
  if (channel.stateId) input.stateId = boundedText(channel.stateId, 80);
  if (channel.projectId) input.projectId = boundedText(channel.projectId, 80);
  if (Array.isArray(channel.labelIds) && channel.labelIds.length) {
    input.labelIds = channel.labelIds.map((id) => boundedText(id, 80)).filter(Boolean).slice(0, 20);
  }
  return {
    query: 'mutation RedactWallIssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url title } } }',
    variables: { input },
  };
}

function bodyForChannel(channel, payload) {
  if (channel.type === 'slack') return slackPayload(payload);
  if (channel.type === 'teams') return teamsPayload(payload);
  if (channel.type === 'ticket') return ticketPayload(channel, payload);
  if (channel.type === 'jira') return jiraIssuePayload(channel, payload);
  if (channel.type === 'linear') return linearIssuePayload(channel, payload);
  return payload;
}

function smtpPayload(payload) {
  return { ...payload, summary: payload.summary || oneLine(payload) };
}

function smtpMessageForPayload(channel, payload, now = new Date()) {
  return smtp.messageForPayload(channel, smtpPayload(payload), now);
}

function headersForChannel(channel) {
  const headers = { 'Content-Type': 'application/json' };
  if ((channel.type === 'webhook' || channel.type === 'ticket') && channel.token) headers.Authorization = 'Bearer ' + channel.token;
  if (channel.type === 'jira') {
    headers.Accept = 'application/json';
    headers.Authorization = 'Basic ' + Buffer.from(`${channel.email}:${channel.token}`, 'utf8').toString('base64');
  }
  if (channel.type === 'linear') {
    headers.Accept = 'application/json';
    headers.Authorization = channel.token;
  }
  return headers;
}

async function linearResponseResult(res) {
  if (!res || !res.ok || typeof res.json !== 'function') return { reason: null, issue: null };
  try {
    const data = await res.json();
    if (data && ((Array.isArray(data.errors) && data.errors.length) || data.data?.issueCreate?.success === false)) {
      return { reason: 'graphql_error', issue: null };
    }
    const issue = data && data.data && data.data.issueCreate && data.data.issueCreate.issue;
    return {
      reason: null,
      issue: issue && typeof issue === 'object'
        ? {
          id: boundedText(issue.id, 120),
          identifier: boundedText(issue.identifier, 120),
          url: boundedText(issue.url, 2048),
          title: boundedText(issue.title, 240),
        }
        : null,
    };
  } catch {
    return { reason: 'invalid_graphql_response', issue: null };
  }
}

async function postJson(channel, payload, opts = {}) {
  const fetchImpl = opts.fetch || fetch;
  const res = await fetchImpl(channel.url, {
    method: 'POST',
    headers: headersForChannel(channel),
    body: JSON.stringify(bodyForChannel(channel, payload)),
    signal: outboundSignal(),
  });
  const linearResult = channel.type === 'linear' ? await linearResponseResult(res) : { reason: null, issue: null };
  if (linearResult.reason) return { channel: channel.name || channel.type, sent: false, reason: linearResult.reason };
  if (channel.type === 'linear' && res && res.ok) {
    const issue = linearResult.issue || {};
    return {
      channel: channel.name || channel.type,
      sent: true,
      status: res.status,
      externalId: issue.identifier || issue.id || null,
      url: issue.url || null,
    };
  }
  if (channel.type === 'jira' && res && res.ok) {
    const issue = typeof res.json === 'function' ? await res.json().catch(() => ({})) : {};
    return {
      channel: channel.name || channel.type,
      sent: true,
      status: res.status,
      externalId: (issue && (issue.key || issue.id)) || null,
    };
  }
  return res && res.ok
    ? { channel: channel.name || channel.type, sent: true, status: res.status }
    : { channel: channel.name || channel.type, sent: false, reason: 'http_' + (res && res.status) };
}

function deliveryStatus(result) {
  if (!result || result.reason === 'disabled') return 'not_configured';
  if (!Array.isArray(result.results) || !result.results.length) return 'not_configured';
  const sent = result.results.filter((item) => item.sent).length;
  if (sent === result.results.length) return 'sent';
  if (sent > 0) return 'partial';
  return 'failed';
}

async function emitApprovalNotification(query, opts = {}) {
  if (!shouldNotifyApproval(query)) return { sent: false, reason: 'not_routeable', channels: [], results: [] };
  const channels = configuredChannels(opts.env || process.env, opts);
  if (!channels.length) return { sent: false, reason: 'disabled', channels: [], results: [] };
  const payload = sanitizedApprovalNotification(query, opts);
  const results = [];
  for (const channel of channels) {
    try {
      results.push(channel.type === 'smtp'
        ? await smtp.send(channel, smtpPayload(payload), opts)
        : await postJson(channel, payload, opts));
    } catch {
      results.push({ channel: channel.name || channel.type, sent: false, reason: 'error' });
    }
  }
  const sent = results.some((item) => item.sent);
  return {
    sent,
    status: deliveryStatus({ results }),
    channels: results.map((item) => item.channel).filter(Boolean),
    results,
  };
}

module.exports = {
  configuredChannels,
  deliveryStatus,
  headersForChannel,
  emitApprovalNotification,
  jiraIssuePayload,
  linearApiUrl,
  linearIssuePayload,
  linearResponseResult,
  sanitizedApprovalNotification,
  shouldNotifyApproval,
  smtpMessageForPayload,
  ticketPayload,
};
