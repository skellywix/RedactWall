'use strict';

const { safeSensor } = require('./sensor-metadata');
const aiCatalog = require('./ai-app-catalog');
const {
  failedInstallCheckIds,
  isEndpointAiToolPolicyCheckId,
} = require('./install-checks');

const SENSOR_LABELS = {
  browser_extension: 'Browser extension',
  endpoint_agent: 'Endpoint agent',
  mcp_guard: 'MCP guard',
  api: 'API gateway',
  proxy: 'Network proxy',
};

const DEFAULT_REQUIRED_SENSORS = ['browser_extension', 'endpoint_agent', 'mcp_guard'];
const SENSOR_ID_RE = /^[a-z][a-z0-9_:-]{0,79}$/;
const FLEET_LIMIT = 150;
const ENDPOINT_AI_TOOL_LIMIT = 100;
const AI_TOOL_LABELS = {
  chatgpt_desktop: 'ChatGPT Desktop',
  claude_desktop: 'Claude Desktop',
  claude_code: 'Claude Code',
  cursor: 'Cursor',
  windsurf: 'Windsurf',
  gemini_cli: 'Gemini CLI',
  codex_cli: 'Codex CLI',
};
const BLOCKED_STATUSES = new Set([
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'action_blocked',
  'injection_blocked',
  'file_blocked_unscanned',
  'ocr_required',
  'response_flagged',
  'response_blocked',
]);
const REDACTED_STATUSES = new Set(['redacted', 'response_redacted']);

function normalizeDestination(destination) {
  const raw = String(destination || 'unknown').trim().toLowerCase();
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

function destinationPolicyState(destination, policy = {}) {
  if (destinationMatches(destination, policy.allowedDestinations || [])) return 'allowed';
  if (destinationMatches(destination, policy.blockedDestinations || [])) return 'blocked';
  if (destinationMatches(destination, policy.blockedFileUploadDestinations || [])) return 'file_upload_blocked';
  if (destinationMatches(destination, policy.governedDestinations || [])) return 'governed';
  return 'review';
}

function configuredDestinations(policy = {}) {
  const rows = [];
  for (const [field, state] of [
    ['governedDestinations', 'governed'],
    ['allowedDestinations', 'allowed'],
    ['blockedDestinations', 'blocked'],
    ['blockedFileUploadDestinations', 'file_upload_blocked'],
  ]) {
    for (const destination of policy[field] || []) rows.push({ destination: normalizeDestination(destination), policyState: state });
  }
  return rows;
}

function emptyAggregate(destination, policyState = 'review') {
  return {
    destination,
    policyState,
    events: 0,
    blocked: 0,
    redacted: 0,
    shadow: 0,
    users: new Set(),
    lastSeen: null,
  };
}

function bumpAggregate(bucket, q) {
  bucket.events += 1;
  if (BLOCKED_STATUSES.has(q.status)) bucket.blocked += 1;
  if (REDACTED_STATUSES.has(q.status)) bucket.redacted += 1;
  if (isShadowAiEvent(q)) bucket.shadow += 1;
  if (q.user) bucket.users.add(q.user);
  if (!bucket.lastSeen || String(q.createdAt || '') > bucket.lastSeen) bucket.lastSeen = q.createdAt || null;
}

function publicAggregate(bucket, extra = {}) {
  const out = {
    destination: bucket.destination,
    policyState: bucket.policyState || 'review',
    events: bucket.events,
    blocked: bucket.blocked,
    redacted: bucket.redacted,
    shadow: bucket.shadow,
    users: bucket.users.size,
    lastSeen: bucket.lastSeen,
    ...extra,
  };
  const risk = aiCatalog.riskAttributes(bucket.destination);
  if (risk) out.risk = risk;
  return out;
}

function isDesktopCollectorEvent(q) {
  const note = String(q.decisionNote || q.note || '');
  return q.source === 'endpoint_agent'
    && q.channel === 'file_upload'
    && /native handoff/i.test(note);
}

function isShadowAiEvent(q) {
  return q && (q.status === 'shadow_ai' || (q.status === 'destination_blocked' && q.channel === 'shadow_ai'));
}

function cleanSensorMetadata(sensor) {
  return safeSensor(sensor) || {};
}

function safeFleetText(value, fallback = 'unknown') {
  const text = String(value || '').trim();
  return (text || fallback).slice(0, 160);
}

function cleanInstallChecks(checks) {
  return (Array.isArray(checks) ? checks : []).slice(0, 40).map((check) => {
    if (!check || typeof check !== 'object') return null;
    const id = normalizeSensorId(check.id);
    if (!id) return null;
    const detail = typeof check.detail === 'string' && check.detail.trim()
      ? check.detail.trim().slice(0, 160)
      : null;
    return {
      id,
      ok: check.ok === true,
      ...(detail ? { detail } : {}),
    };
  }).filter(Boolean);
}

function labelForAiTool(id) {
  if (AI_TOOL_LABELS[id]) return AI_TOOL_LABELS[id];
  return String(id || 'unknown')
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
    .slice(0, 80) || 'Unknown AI tool';
}

function detectedToolCount(check) {
  const match = String((check && check.detail) || '').match(/^detected:(\d+)$/);
  return match ? Number(match[1]) : null;
}

function aiToolInventoryForChecks(checks = []) {
  const inventoryCheck = checks.find((check) => check.id === 'ai_tool_inventory');
  const tools = [];
  for (const check of checks) {
    if (!check || !isEndpointAiToolPolicyCheckId(check.id)) continue;
    const id = String(check.id).slice('ai_tool_'.length);
    const approved = check.ok === true;
    tools.push({
      id,
      label: labelForAiTool(id),
      approved,
      state: approved ? 'approved' : 'unapproved',
      detail: String(check.detail || (approved ? 'detected' : 'unapproved detected')).slice(0, 160),
    });
  }
  if (!inventoryCheck && !tools.length) return null;
  tools.sort((a, b) => Number(a.approved) - Number(b.approved) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  const detected = detectedToolCount(inventoryCheck);
  const unapproved = tools.filter((tool) => !tool.approved).length;
  return {
    detected: detected == null ? tools.length : detected,
    reported: tools.length,
    unapproved,
    truncated: detected != null && detected > tools.length,
    state: unapproved ? 'attention' : 'covered',
    tools,
  };
}

function installHealthFor(q) {
  const checks = cleanInstallChecks(q && q.installChecks);
  if (!checks.length) return null;
  const failedChecks = failedInstallCheckIds(checks);
  const health = {
    at: (q && q.createdAt) || null,
    state: failedChecks.length ? 'attention' : 'covered',
    failedChecks,
    checks,
  };
  const aiToolInventory = aiToolInventoryForChecks(checks);
  if (aiToolInventory) health.aiToolInventory = aiToolInventory;
  return health;
}

function bumpInstallHealth(sensor, q) {
  const health = installHealthFor(q);
  if (!health) return;
  if (!sensor._installHealth || String(health.at || '') >= String(sensor._installHealth.at || '')) {
    sensor._installHealth = health;
  }
}

function normalizeSensorId(value) {
  const id = String(value || '').trim().toLowerCase();
  return SENSOR_ID_RE.test(id) ? id : null;
}

function requiredSensorSources(policy = {}) {
  const source = Array.isArray(policy.requiredSensors) ? policy.requiredSensors : DEFAULT_REQUIRED_SENSORS;
  const out = [];
  const seen = new Set();
  for (const item of source) {
    const id = normalizeSensorId(item);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out.length ? out : DEFAULT_REQUIRED_SENSORS.slice();
}

function desiredSensorVersions(policy = {}) {
  const source = policy.desiredSensorVersions && typeof policy.desiredSensorVersions === 'object'
    ? policy.desiredSensorVersions
    : {};
  const out = {};
  for (const [rawKey, rawValue] of Object.entries(source)) {
    const key = normalizeSensorId(rawKey);
    const version = String(rawValue || '').trim();
    if (!key || !version || version.length > 80) continue;
    out[key] = version;
  }
  return out;
}

function bumpVersion(sensor, q) {
  const meta = cleanSensorMetadata(q.sensor);
  const version = meta.version || meta.packageVersion || null;
  if (version) {
    const bucket = sensor._versions.get(version) || { version, events: 0, lastSeen: null };
    bucket.events += 1;
    if (!bucket.lastSeen || String(q.createdAt || '') > bucket.lastSeen) bucket.lastSeen = q.createdAt || null;
    sensor._versions.set(version, bucket);
  }
  if (meta.platform) sensor._platforms.add(meta.platform);
}

function finalizeSensor(sensor, opts = {}) {
  const versions = [...(sensor._versions || new Map()).values()]
    .sort((a, b) => String(b.lastSeen || '').localeCompare(String(a.lastSeen || '')) || b.events - a.events || a.version.localeCompare(b.version));
  const platforms = [...(sensor._platforms || new Set())].sort();
  const latestVersion = versions[0] ? versions[0].version : null;
  const desiredVersion = opts.desiredVersion || null;
  const versionHealth = sensor.events === 0 ? 'missing'
    : versions.length === 0 ? 'unknown'
    : desiredVersion && latestVersion !== desiredVersion ? 'outdated'
    : versions.length === 1 ? 'current'
    : 'mixed';
  return {
    source: sensor.source,
    label: sensor.label,
    required: opts.required === true,
    events: sensor.events,
    lastSeen: sensor.lastSeen,
    latestVersion,
    desiredVersion,
    versionHealth,
    versions,
    platforms,
    installHealth: sensor._installHealth || null,
  };
}

function fleetKey(source, user, orgId) {
  return [source || 'api', user || 'unknown', orgId || ''].join('\u0000');
}

function stateRank(state) {
  return { attention: 0, missing: 1, outdated: 2, unknown: 3, covered: 4 }[state] ?? 5;
}

function emptyFleetRow({ source, user, orgId, label }) {
  return {
    source,
    label: label || SENSOR_LABELS[source] || source,
    user: safeFleetText(user),
    orgId: orgId ? safeFleetText(orgId, '') : null,
    events: 0,
    lastSeen: null,
    _versions: new Map(),
    _platforms: new Set(),
    _installHealth: null,
  };
}

function bumpFleetRow(row, q) {
  row.events += 1;
  if (!row.lastSeen || String(q.createdAt || '') > row.lastSeen) row.lastSeen = q.createdAt || null;
  const meta = cleanSensorMetadata(q.sensor);
  const version = meta.version || meta.packageVersion || null;
  if (version) {
    const bucket = row._versions.get(version) || { version, events: 0, lastSeen: null };
    bucket.events += 1;
    if (!bucket.lastSeen || String(q.createdAt || '') > bucket.lastSeen) bucket.lastSeen = q.createdAt || null;
    row._versions.set(version, bucket);
  }
  if (meta.platform) row._platforms.add(meta.platform);
  const health = installHealthFor(q);
  if (health && (!row._installHealth || String(health.at || '') >= String(row._installHealth.at || ''))) {
    row._installHealth = health;
  }
}

function finalizeFleetRow(row, opts = {}) {
  const versions = [...(row._versions || new Map()).values()]
    .sort((a, b) => String(b.lastSeen || '').localeCompare(String(a.lastSeen || '')) || b.events - a.events || a.version.localeCompare(b.version));
  const latestVersion = versions[0] ? versions[0].version : null;
  const desiredVersion = opts.desiredVersion || null;
  const installHealth = row._installHealth || null;
  const versionHealth = row.events === 0 ? 'missing'
    : versions.length === 0 ? 'unknown'
    : desiredVersion && latestVersion !== desiredVersion ? 'outdated'
    : versions.length === 1 ? 'current'
    : 'mixed';
  const state = row.events === 0 ? 'missing'
    : installHealth && installHealth.state === 'attention' ? 'attention'
    : versionHealth === 'outdated' || versionHealth === 'mixed' ? 'outdated'
    : opts.required === true && !installHealth ? 'unknown'
    : versionHealth === 'unknown' ? 'unknown'
    : 'covered';
  return {
    source: row.source,
    label: row.label,
    user: row.user,
    orgId: row.orgId,
    required: opts.required === true,
    state,
    events: row.events,
    lastSeen: row.lastSeen,
    latestVersion,
    desiredVersion,
    versionHealth,
    platforms: [...(row._platforms || new Set())].sort(),
    installHealth,
  };
}

function endpointAiToolRows(rows) {
  const out = [];
  for (const row of rows || []) {
    if (!row || row.source !== 'endpoint_agent') continue;
    const inventory = row.installHealth && row.installHealth.aiToolInventory;
    if (!inventory || !Array.isArray(inventory.tools)) continue;
    for (const tool of inventory.tools) {
      out.push({
        id: tool.id,
        label: tool.label,
        approved: tool.approved === true,
        state: tool.state,
        detail: tool.detail,
        user: row.user || 'unknown',
        orgId: row.orgId || null,
        lastSeen: (row.installHealth && row.installHealth.at) || row.lastSeen || null,
        platforms: Array.isArray(row.platforms) ? row.platforms.slice(0, 5) : [],
      });
    }
  }
  return out
    .sort((a, b) => Number(a.approved) - Number(b.approved)
      || String(a.user || '').localeCompare(String(b.user || ''))
      || String(a.label || '').localeCompare(String(b.label || '')))
    .slice(0, ENDPOINT_AI_TOOL_LIMIT);
}

function summarize(rows, pol) {
  const policy = pol || {};
  const configured = configuredDestinations(policy);
  const governed = new Map();
  const ungoverned = new Map();
  const shadow = new Map();
  const sensorCounts = new Map();
  const fleetRows = new Map();
  const fleetUsers = new Map();
  const requiredSources = requiredSensorSources(policy);
  const desiredVersions = desiredSensorVersions(policy);
  const desktopCollector = {
    events: 0,
    lastSeen: null,
    destinations: new Set(),
  };
  const statuses = {};

  for (const item of configured) {
    if (!item.destination || item.destination === 'unknown' || governed.has(item.destination)) continue;
    governed.set(item.destination, emptyAggregate(item.destination, destinationPolicyState(item.destination, policy)));
  }

  for (const q of rows || []) {
    const destination = normalizeDestination(q.destination);
    const policyState = destinationPolicyState(destination, policy);
    const source = q.source || 'api';
    const user = safeFleetText(q.user);
    const orgId = q.orgId ? safeFleetText(q.orgId, '') : null;
    const userKey = [user, orgId || ''].join('\u0000');
    if (user !== 'unknown') fleetUsers.set(userKey, { user, orgId });
    const sensor = sensorCounts.get(source) || { source, label: SENSOR_LABELS[source] || source, events: 0, lastSeen: null, _versions: new Map(), _platforms: new Set() };
    sensor.events += 1;
    if (!sensor.lastSeen || String(q.createdAt || '') > sensor.lastSeen) sensor.lastSeen = q.createdAt || null;
    bumpVersion(sensor, q);
    bumpInstallHealth(sensor, q);
    sensorCounts.set(source, sensor);
    const fk = fleetKey(source, user, orgId);
    const fleetRow = fleetRows.get(fk) || emptyFleetRow({ source, user, orgId, label: SENSOR_LABELS[source] || source });
    bumpFleetRow(fleetRow, q);
    fleetRows.set(fk, fleetRow);
    statuses[q.status || 'unknown'] = (statuses[q.status || 'unknown'] || 0) + 1;

    if (isDesktopCollectorEvent(q)) {
      desktopCollector.events += 1;
      desktopCollector.destinations.add(destination);
      if (!desktopCollector.lastSeen || String(q.createdAt || '') > desktopCollector.lastSeen) {
        desktopCollector.lastSeen = q.createdAt || null;
      }
    }

    const isGoverned = policyState !== 'review';
    const bucketMap = isGoverned ? governed : ungoverned;
    if (!bucketMap.has(destination)) bucketMap.set(destination, emptyAggregate(destination, policyState));
    bumpAggregate(bucketMap.get(destination), q);

    if (isShadowAiEvent(q)) {
      if (!shadow.has(destination)) shadow.set(destination, emptyAggregate(destination, policyState));
      bumpAggregate(shadow.get(destination), q);
    }
  }

  const requiredSensors = requiredSources.map((source) => {
    const seen = sensorCounts.get(source);
    return seen || { source, label: SENSOR_LABELS[source] || source, events: 0, lastSeen: null, _versions: new Map(), _platforms: new Set() };
  });
  const additionalSensors = [...sensorCounts.values()].filter((s) => !requiredSources.includes(s.source));
  const sensors = [...requiredSensors, ...additionalSensors]
    .map((sensor) => finalizeSensor(sensor, {
      required: requiredSources.includes(sensor.source),
      desiredVersion: desiredVersions[sensor.source] || null,
    }))
    .sort((a, b) => Number(b.required) - Number(a.required) || b.events - a.events || a.label.localeCompare(b.label));
  const activeRequired = requiredSensors.filter((s) => s.events > 0).length;
  for (const who of fleetUsers.values()) {
    for (const source of requiredSources) {
      const fk = fleetKey(source, who.user, who.orgId);
      if (!fleetRows.has(fk)) {
        fleetRows.set(fk, emptyFleetRow({ source, user: who.user, orgId: who.orgId, label: SENSOR_LABELS[source] || source }));
      }
    }
  }
  const allFleet = [...fleetRows.values()]
    .map((row) => finalizeFleetRow(row, {
      required: requiredSources.includes(row.source),
      desiredVersion: desiredVersions[row.source] || null,
    }));
  const fleet = allFleet
    .filter((row) => requiredSources.includes(row.source))
    .sort((a, b) => stateRank(a.state) - stateRank(b.state)
      || String(a.user || '').localeCompare(String(b.user || ''))
      || String(a.source || '').localeCompare(String(b.source || '')))
    .slice(0, FLEET_LIMIT);
  const endpointAiTools = endpointAiToolRows(allFleet);
  const endpointInventories = allFleet
    .filter((row) => row.source === 'endpoint_agent' && row.installHealth && row.installHealth.aiToolInventory)
    .map((row) => row.installHealth.aiToolInventory);
  const endpointAiInventoryReports = endpointInventories.length;
  const endpointAiToolDetections = endpointInventories.reduce((sum, inventory) => sum + (Number(inventory.detected) || 0), 0);
  const endpointAiToolUnapproved = endpointInventories.reduce((sum, inventory) => sum + (Number(inventory.unapproved) || 0), 0);
  const fleetAttention = fleet.filter((row) => ['attention', 'missing', 'outdated', 'unknown'].includes(row.state)).length;
  const fleetCovered = fleet.filter((row) => row.state === 'covered').length;
  const activeSensorVersionGaps = sensors.filter((s) => s.events > 0 && s.versionHealth !== 'current').length;
  const activeSensorHealthWarnings = sensors.filter((s) => s.events > 0 && s.installHealth && s.installHealth.state === 'attention').length;
  const governedActive = [...governed.values()].filter((g) => g.events > 0).length;
  const governedTotal = governed.size || 0;
  const shadowEvents = [...shadow.values()].reduce((sum, bucket) => sum + bucket.shadow, 0);
  const unresolvedShadowDestinations = [...shadow.values()].filter((bucket) => (bucket.policyState || 'review') === 'review').length;
  const score = Math.round(
    (activeRequired / requiredSensors.length) * 45
    + (governedTotal ? (governedActive / governedTotal) * 25 : 0)
    + (governedTotal ? 10 : 0)
    + (unresolvedShadowDestinations ? 0 : 20),
  );

  return {
    generatedAt: new Date().toISOString(),
    score: Math.max(0, Math.min(100, score)),
    totals: {
      events: (rows || []).length,
      governedDestinations: governedTotal,
      governedActive,
      shadowEvents,
      unresolvedShadowDestinations,
      blocked: Object.entries(statuses)
        .filter(([status]) => BLOCKED_STATUSES.has(status))
        .reduce((sum, [, count]) => sum + count, 0),
      requiredSensors: requiredSensors.length,
      activeRequiredSensors: activeRequired,
      activeSensorVersionGaps,
      activeSensorHealthWarnings,
      endpointAiInventoryReports,
      endpointAiToolDetections,
      endpointAiToolUnapproved,
      fleetRows: fleet.length,
      fleetCovered,
      fleetAttention,
    },
    sensors,
    fleet,
    endpointAiTools,
    governedDestinations: [...governed.values()]
      .map((bucket) => publicAggregate(bucket, { governed: true }))
      .sort((a, b) => b.events - a.events || a.destination.localeCompare(b.destination)),
    ungovernedDestinations: [...ungoverned.values()]
      .map((bucket) => publicAggregate(bucket, { governed: false }))
      .sort((a, b) => b.events - a.events || a.destination.localeCompare(b.destination))
      .slice(0, 12),
    shadowDestinations: [...shadow.values()]
      .map((bucket) => publicAggregate(bucket, { governed: (bucket.policyState || 'review') !== 'review' }))
      .sort((a, b) => Number(a.governed) - Number(b.governed) || b.shadow - a.shadow || a.destination.localeCompare(b.destination))
      .slice(0, 12),
    desktopCollector: {
      events: desktopCollector.events,
      lastSeen: desktopCollector.lastSeen,
      destinations: [...desktopCollector.destinations].sort(),
    },
    posture: [
      ...sensors.filter((sensor) => sensor.required).map((sensor) => ({
        id: sensor.source,
        label: sensor.label,
        state: sensor.events && sensor.versionHealth === 'current'
          && !(sensor.installHealth && sensor.installHealth.state === 'attention') ? 'covered' : 'attention',
        detail: sensor.events
          ? `${sensor.events} events${sensor.desiredVersion ? ` / desired v${sensor.desiredVersion}` : ''}` +
            `${sensor.installHealth && sensor.installHealth.failedChecks.length ? ` / ${sensor.installHealth.failedChecks.length} failed checks` : ''}`
          : 'required, no events',
      })),
      {
        id: 'desktop_collector',
        label: 'Desktop collector',
        state: desktopCollector.events ? 'covered' : 'attention',
        detail: desktopCollector.events ? `${desktopCollector.events} protected uploads` : 'no protected uploads',
      },
      {
        id: 'mcp_guard',
        label: 'MCP guard',
        state: (sensorCounts.get('mcp_guard') || {}).events ? 'covered' : 'attention',
        detail: `${(sensorCounts.get('mcp_guard') || {}).events || 0} events`,
      },
      {
        id: 'shadow_ai',
        label: 'Shadow AI',
        state: unresolvedShadowDestinations ? 'attention' : 'covered',
        detail: `${unresolvedShadowDestinations} pending reviews / ${shadowEvents} sightings`,
      },
      {
        id: 'sensor_versions',
        label: 'Sensor versions',
        state: activeSensorVersionGaps ? 'attention' : 'covered',
        detail: activeSensorVersionGaps ? `${activeSensorVersionGaps} version gaps` : 'reported',
      },
      {
        id: 'sensor_health',
        label: 'Sensor install health',
        state: activeSensorHealthWarnings ? 'attention' : 'covered',
        detail: activeSensorHealthWarnings ? `${activeSensorHealthWarnings} install warnings` : 'checks passing',
      },
      {
        id: 'endpoint_ai_tools',
        label: 'Endpoint AI tools',
        state: endpointAiToolUnapproved ? 'attention' : (endpointAiInventoryReports ? 'covered' : 'attention'),
        detail: endpointAiInventoryReports
          ? `${endpointAiToolDetections} detected tools / ${endpointAiToolUnapproved} unapproved`
          : 'no endpoint inventory heartbeat',
      },
      {
        id: 'governed_destinations',
        label: 'Governed AI list',
        state: governedTotal ? 'covered' : 'attention',
        detail: `${governedTotal} destinations`,
      },
    ],
  };
}

module.exports = { summarize, normalizeDestination, isDesktopCollectorEvent, isShadowAiEvent };
