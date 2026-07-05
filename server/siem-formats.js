'use strict';
/**
 * Outbound event envelope adapters for SIEM/SOAR destinations.
 *
 * Each adapter turns a sanitized, prompt-free RedactWall security event into the
 * exact request shape a target platform expects (endpoint suffix, auth header,
 * payload envelope). Pure functions — no I/O — so they are fully unit-testable.
 * The delivery engine (server/subscriptions.js) calls buildRequest and sends it.
 *
 * Event contract is `redactwall.security_event` schemaVersion 2: the schema-1
 * sanitized alert plus a stable `id` (dedupe key) and `schemaVersion: 2`.
 */
const EVENT_SCHEMA_VERSION = 2;

function toEvent(alert) {
  return { ...alert, schemaVersion: EVENT_SCHEMA_VERSION, id: dedupeKey(alert) };
}

function dedupeKey(alert) {
  return [alert.queryId || 'noid', alert.action || alert.status || 'event'].join(':');
}

function epochSeconds(iso) {
  const t = Date.parse(iso || '');
  return Number.isFinite(t) ? Math.floor(t / 1000) : Math.floor(Date.now() / 1000);
}

function summaryLine(e) {
  const detectors = (e.findings || []).map((f) => f.type).join(',') || (e.categories || []).join(',') || 'none';
  return `RedactWall ${e.action || e.status} user=${e.user} dest=${e.destination} risk=${e.riskScore} sev=${e.maxSeverityLabel} detectors=${detectors}`;
}

// Splunk HTTP Event Collector — Authorization: Splunk <token>, {event, sourcetype, time}.
function splunkHec(event, dest) {
  return {
    url: joinUrl(dest.url, '/services/collector/event'),
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Splunk ' + (dest.token || '') },
    body: JSON.stringify({ event, sourcetype: 'redactwall:security_event', source: 'redactwall', time: epochSeconds(event.createdAt) }),
  };
}

// Datadog Logs Intake — DD-API-KEY header, array of log objects.
function datadog(event, dest) {
  return {
    url: dest.url || 'https://http-intake.logs.datadoghq.com/api/v2/logs',
    method: 'POST',
    headers: { 'content-type': 'application/json', 'dd-api-key': dest.token || '' },
    body: JSON.stringify([{ message: JSON.stringify(event), ddsource: 'redactwall', service: 'redactwall', status: statusLevel(event), ddtags: `env:prod,action:${event.action || event.status}`, timestamp: Date.parse(event.createdAt) || Date.now() }]),
  };
}

// Microsoft Sentinel Logs Ingestion (DCR) — bearer token, JSON array with TimeGenerated.
// The Entra client-credentials token is supplied out of band as dest.token.
function sentinel(event, dest) {
  return {
    url: dest.url,
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + (dest.token || '') },
    body: JSON.stringify([{ TimeGenerated: event.createdAt || new Date().toISOString(), ...event }]),
  };
}

// Google Chronicle / SecOps unstructured logs — bearer, {customer_id, log_type, entries[]}.
function chronicle(event, dest) {
  return {
    url: dest.url || 'https://malachiteingestion-pa.googleapis.com/v2/unstructuredlogentries:batchCreate',
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + (dest.token || '') },
    body: JSON.stringify({ customer_id: dest.customerId || '', log_type: dest.logType || 'REDACTWALL', entries: [{ log_text: JSON.stringify(event), ts_rfc3339: event.createdAt || new Date().toISOString() }] }),
  };
}

// IBM QRadar — LEEF 2.0 line delivered over HTTP to a collector.
function qradarLeef(event, dest) {
  const attrs = [
    'usrName=' + event.user, 'cat=' + (event.action || event.status), 'sev=' + (event.maxSeverity || 0),
    'dst=' + event.destination, 'src=' + (event.source || 'unknown'), 'risk=' + (event.riskScore || 0),
    'queryId=' + event.queryId, 'devTime=' + (event.createdAt || new Date().toISOString()),
  ].join('\t');
  const leef = `LEEF:2.0|RedactWall|ControlPlane|1.0|${event.action || event.status}|\t|${attrs}`;
  return { url: dest.url, method: 'POST', headers: { 'content-type': 'text/plain' }, body: leef };
}

// Slack incoming webhook — Block Kit message.
function slack(event, dest) {
  const text = ':shield: ' + summaryLine(event);
  return {
    url: dest.url,
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text, blocks: [
      { type: 'section', text: { type: 'mrkdwn', text: '*RedactWall security event*\n' + summaryLine(event) } },
      { type: 'section', fields: [
        { type: 'mrkdwn', text: `*Action:*\n${event.action || event.status}` },
        { type: 'mrkdwn', text: `*Risk:*\n${event.riskScore} (${event.maxSeverityLabel})` },
        { type: 'mrkdwn', text: `*User:*\n${event.user}` },
        { type: 'mrkdwn', text: `*Destination:*\n${event.destination}` },
      ] },
    ] }),
  };
}

// Microsoft Teams — Power Automate Workflow adaptive card.
function teams(event, dest) {
  return {
    url: dest.url,
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ type: 'message', attachments: [{ contentType: 'application/vnd.microsoft.card.adaptive', content: {
      $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4',
      body: [
        { type: 'TextBlock', size: 'Medium', weight: 'Bolder', text: 'RedactWall security event' },
        { type: 'TextBlock', wrap: true, text: summaryLine(event) },
        { type: 'FactSet', facts: [
          { title: 'Action', value: String(event.action || event.status) },
          { title: 'Risk', value: `${event.riskScore} (${event.maxSeverityLabel})` },
          { title: 'User', value: String(event.user) },
          { title: 'Destination', value: String(event.destination) },
        ] },
      ],
    } }] }),
  };
}

// Generic HTTPS webhook — the canonical v2 envelope, optional bearer.
function webhook(event, dest) {
  const headers = { 'content-type': 'application/json' };
  if (dest.token) headers.authorization = 'Bearer ' + dest.token;
  return { url: dest.url, method: 'POST', headers, body: JSON.stringify(event) };
}

// OpenTelemetry OTLP/HTTP (JSON) logs. Maps a sanitized event to a LogRecord.
// int64 fields (timeUnixNano, intValue) MUST be JSON strings per the proto3
// JSON mapping, or strict collectors reject the payload. Attributes use the
// redactwall.* namespace (not the still-evolving gen_ai.*) and carry only
// label-shaped metadata — never masked values or reasons.
function otlpAttr(key, value) {
  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? { key, value: { intValue: String(value) } }
      : { key, value: { doubleValue: value } };
  }
  if (typeof value === 'boolean') return { key, value: { boolValue: value } };
  return { key, value: { stringValue: String(value == null ? '' : value) } };
}

function otlpSeverity(event) {
  const s = event.maxSeverity || 0;
  if (s >= 4) return { number: 21, text: 'FATAL' };
  if (s >= 3) return { number: 17, text: 'ERROR' };
  if (s >= 2) return { number: 13, text: 'WARN' };
  return { number: 9, text: 'INFO' };
}

function otlp(event, dest) {
  const sev = otlpSeverity(event);
  const ts = String((Date.parse(event.createdAt || '') || Date.now()) * 1e6);
  const record = {
    timeUnixNano: ts,
    severityNumber: sev.number,
    severityText: sev.text,
    body: { stringValue: summaryLine(event) },
    attributes: [
      otlpAttr('redactwall.event_type', 'security_event'),
      otlpAttr('redactwall.action', event.action || event.status || ''),
      otlpAttr('redactwall.query_id', event.queryId || ''),
      otlpAttr('redactwall.schema_version', event.schemaVersion || 2),
      otlpAttr('enduser.id', event.user || ''),
      otlpAttr('redactwall.destination', event.destination || ''),
      otlpAttr('redactwall.source', event.source || ''),
      otlpAttr('redactwall.channel', event.channel || ''),
      otlpAttr('redactwall.risk_score', event.riskScore || 0),
      otlpAttr('redactwall.max_severity', event.maxSeverity || 0),
      otlpAttr('redactwall.finding_types', (event.findings || []).map((f) => f.type).join(',')),
    ],
  };
  const headers = { 'content-type': 'application/json' };
  if (dest.token) headers.authorization = 'Bearer ' + dest.token;
  return {
    url: joinUrl(dest.url, '/v1/logs'),
    method: 'POST',
    headers,
    body: JSON.stringify({
      resourceLogs: [{
        resource: { attributes: [otlpAttr('service.name', dest.serviceName || 'redactwall')] },
        scopeLogs: [{ scope: { name: 'redactwall.subscriptions' }, logRecords: [record] }],
      }],
    }),
  };
}

const ADAPTERS = { splunk_hec: splunkHec, datadog, sentinel, chronicle, qradar: qradarLeef, slack, teams, otlp, webhook };

function statusLevel(event) {
  const s = event.maxSeverity || 0;
  return s >= 4 ? 'critical' : s >= 3 ? 'error' : s >= 2 ? 'warning' : 'info';
}

function joinUrl(base, suffix) {
  const b = String(base || '').replace(/\/+$/, '');
  return b.endsWith(suffix) ? b : b + suffix;
}

function supportedTypes() {
  return Object.keys(ADAPTERS);
}

// Build the outbound request for a destination from a sanitized alert.
function buildRequest(alert, dest) {
  const adapter = ADAPTERS[dest.type] || webhook;
  return adapter(toEvent(alert), dest);
}

module.exports = { buildRequest, toEvent, dedupeKey, summaryLine, supportedTypes, EVENT_SCHEMA_VERSION, ADAPTERS };
