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

const MAX_LABELS = 20;
const MAX_REASONS = 8;

function envValue(env, ...names) {
  for (const name of names) {
    const value = env && env[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function parseBool(value, fallback = false) {
  if (typeof value !== 'string' || !value.trim()) return fallback;
  return /^(1|true|yes|on)$/i.test(value.trim());
}

function parsePort(value, fallback) {
  const port = Number(value);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : fallback;
}

function configuredChannels(env = process.env, opts = {}) {
  if (Array.isArray(opts.channels)) return opts.channels.filter((c) => c && c.type && (c.url || c.type === 'smtp'));
  const channels = [];
  const webhookUrl = envValue(env, 'PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_URL', 'APPROVAL_NOTIFY_WEBHOOK_URL');
  if (webhookUrl) {
    channels.push({
      type: 'webhook',
      name: 'webhook',
      url: webhookUrl,
      token: envValue(env, 'PROMPTWALL_APPROVAL_NOTIFY_WEBHOOK_TOKEN', 'APPROVAL_NOTIFY_WEBHOOK_TOKEN'),
    });
  }
  const slackUrl = envValue(env, 'PROMPTWALL_APPROVAL_SLACK_WEBHOOK_URL', 'APPROVAL_SLACK_WEBHOOK_URL');
  if (slackUrl) channels.push({ type: 'slack', name: 'slack', url: slackUrl });
  const teamsUrl = envValue(env, 'PROMPTWALL_APPROVAL_TEAMS_WEBHOOK_URL', 'APPROVAL_TEAMS_WEBHOOK_URL');
  if (teamsUrl) channels.push({ type: 'teams', name: 'teams', url: teamsUrl });
  const ticketUrl = envValue(env, 'PROMPTWALL_APPROVAL_TICKET_WEBHOOK_URL', 'APPROVAL_TICKET_WEBHOOK_URL');
  if (ticketUrl) {
    channels.push({
      type: 'ticket',
      name: 'ticket',
      url: ticketUrl,
      token: envValue(env, 'PROMPTWALL_APPROVAL_TICKET_WEBHOOK_TOKEN', 'APPROVAL_TICKET_WEBHOOK_TOKEN'),
      system: envValue(env, 'PROMPTWALL_APPROVAL_TICKET_SYSTEM', 'APPROVAL_TICKET_SYSTEM'),
      project: envValue(env, 'PROMPTWALL_APPROVAL_TICKET_PROJECT', 'APPROVAL_TICKET_PROJECT'),
      issueType: envValue(env, 'PROMPTWALL_APPROVAL_TICKET_ISSUE_TYPE', 'APPROVAL_TICKET_ISSUE_TYPE'),
    });
  }
  const smtpHost = envValue(env, 'PROMPTWALL_APPROVAL_SMTP_HOST', 'APPROVAL_SMTP_HOST');
  const smtpFrom = envValue(env, 'PROMPTWALL_APPROVAL_SMTP_FROM', 'APPROVAL_SMTP_FROM');
  const smtpTo = smtp.parseRecipients(envValue(env, 'PROMPTWALL_APPROVAL_SMTP_TO', 'APPROVAL_SMTP_TO'));
  if (smtpHost && smtp.extractEmailAddress(smtpFrom) && smtpTo.length) {
    const secure = parseBool(envValue(env, 'PROMPTWALL_APPROVAL_SMTP_SECURE', 'APPROVAL_SMTP_SECURE'), false);
    channels.push({
      type: 'smtp',
      name: 'smtp',
      host: smtpHost,
      port: parsePort(envValue(env, 'PROMPTWALL_APPROVAL_SMTP_PORT', 'APPROVAL_SMTP_PORT'), secure ? 465 : 587),
      from: smtpFrom,
      to: smtpTo,
      username: envValue(env, 'PROMPTWALL_APPROVAL_SMTP_USERNAME', 'APPROVAL_SMTP_USERNAME'),
      password: envValue(env, 'PROMPTWALL_APPROVAL_SMTP_PASSWORD', 'APPROVAL_SMTP_PASSWORD'),
      secure,
      requireTls: !parseBool(envValue(env, 'PROMPTWALL_APPROVAL_SMTP_ALLOW_INSECURE', 'APPROVAL_SMTP_ALLOW_INSECURE'), false),
      timeoutMs: parsePort(envValue(env, 'PROMPTWALL_APPROVAL_SMTP_TIMEOUT_MS', 'APPROVAL_SMTP_TIMEOUT_MS'), 10000),
    });
  }
  return channels;
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
  if (action === 'APPROVAL_ESCALATED') return 'PromptWall approval escalated';
  return 'PromptWall approval routed';
}

function sanitizedApprovalNotification(query = {}, opts = {}) {
  const workflow = routing.publicWorkflow(query);
  const action = opts.action || 'APPROVAL_ROUTED';
  return {
    schemaVersion: 1,
    eventType: 'promptwall.approval_workflow',
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
    eventType: 'promptwall.approval_ticket',
    action: payload.action,
    title: payload.title,
    summary: oneLine(payload),
    dedupeKey: `promptwall:${payload.queryId || 'unknown'}:${payload.action}`,
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

function bodyForChannel(channel, payload) {
  if (channel.type === 'slack') return slackPayload(payload);
  if (channel.type === 'teams') return teamsPayload(payload);
  if (channel.type === 'ticket') return ticketPayload(channel, payload);
  return payload;
}

function smtpPayload(payload) {
  return { ...payload, summary: payload.summary || oneLine(payload) };
}

function smtpMessageForPayload(channel, payload, now = new Date()) {
  return smtp.messageForPayload(channel, smtpPayload(payload), now);
}

async function postJson(channel, payload, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if ((channel.type === 'webhook' || channel.type === 'ticket') && channel.token) headers.Authorization = 'Bearer ' + channel.token;
  const fetchImpl = opts.fetch || fetch;
  const res = await fetchImpl(channel.url, {
    method: 'POST',
    headers,
    body: JSON.stringify(bodyForChannel(channel, payload)),
  });
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
  emitApprovalNotification,
  sanitizedApprovalNotification,
  shouldNotifyApproval,
  smtpMessageForPayload,
  ticketPayload,
};
