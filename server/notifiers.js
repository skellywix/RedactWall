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

const MAX_LABELS = 20;
const MAX_REASONS = 8;

function envValue(env, ...names) {
  for (const name of names) {
    const value = env && env[name];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function configuredChannels(env = process.env, opts = {}) {
  if (Array.isArray(opts.channels)) return opts.channels.filter((c) => c && c.url && c.type);
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

function bodyForChannel(channel, payload) {
  if (channel.type === 'slack') return slackPayload(payload);
  if (channel.type === 'teams') return teamsPayload(payload);
  return payload;
}

async function postJson(channel, payload, opts = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (channel.type === 'webhook' && channel.token) headers.Authorization = 'Bearer ' + channel.token;
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
      results.push(await postJson(channel, payload, opts));
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
};
