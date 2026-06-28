'use strict';

const { safeSensor } = require('./sensor-metadata');

const SENSOR_LABELS = {
  browser_extension: 'Browser extension',
  endpoint_agent: 'Endpoint agent',
  mcp_guard: 'MCP guard',
  api: 'API gateway',
  proxy: 'Network proxy',
};

const REQUIRED_SENSORS = ['browser_extension', 'endpoint_agent', 'mcp_guard'];
const BLOCKED_STATUSES = new Set([
  'pending',
  'pending_justification',
  'denied',
  'blocked_by_user',
  'destination_blocked',
  'file_upload_blocked',
  'injection_blocked',
  'file_blocked_unscanned',
  'response_flagged',
]);

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

function emptyAggregate(destination) {
  return {
    destination,
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
  if (q.status === 'redacted') bucket.redacted += 1;
  if (q.status === 'shadow_ai') bucket.shadow += 1;
  if (q.user) bucket.users.add(q.user);
  if (!bucket.lastSeen || String(q.createdAt || '') > bucket.lastSeen) bucket.lastSeen = q.createdAt || null;
}

function publicAggregate(bucket, extra = {}) {
  return {
    destination: bucket.destination,
    events: bucket.events,
    blocked: bucket.blocked,
    redacted: bucket.redacted,
    shadow: bucket.shadow,
    users: bucket.users.size,
    lastSeen: bucket.lastSeen,
    ...extra,
  };
}

function cleanSensorMetadata(sensor) {
  return safeSensor(sensor) || {};
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

function finalizeSensor(sensor) {
  const versions = [...(sensor._versions || new Map()).values()]
    .sort((a, b) => String(b.lastSeen || '').localeCompare(String(a.lastSeen || '')) || b.events - a.events || a.version.localeCompare(b.version));
  const platforms = [...(sensor._platforms || new Set())].sort();
  const versionHealth = sensor.events === 0 ? 'missing'
    : versions.length === 0 ? 'unknown'
    : versions.length === 1 ? 'current'
    : 'mixed';
  return {
    source: sensor.source,
    label: sensor.label,
    events: sensor.events,
    lastSeen: sensor.lastSeen,
    latestVersion: versions[0] ? versions[0].version : null,
    versionHealth,
    versions,
    platforms,
  };
}

function summarize(rows, pol) {
  const policy = pol || {};
  const governedSet = new Set((policy.governedDestinations || []).map(normalizeDestination));
  const governed = new Map();
  const ungoverned = new Map();
  const shadow = new Map();
  const sensorCounts = new Map();
  const statuses = {};

  for (const destination of governedSet) governed.set(destination, emptyAggregate(destination));

  for (const q of rows || []) {
    const destination = normalizeDestination(q.destination);
    const source = q.source || 'api';
    const sensor = sensorCounts.get(source) || { source, label: SENSOR_LABELS[source] || source, events: 0, lastSeen: null, _versions: new Map(), _platforms: new Set() };
    sensor.events += 1;
    if (!sensor.lastSeen || String(q.createdAt || '') > sensor.lastSeen) sensor.lastSeen = q.createdAt || null;
    bumpVersion(sensor, q);
    sensorCounts.set(source, sensor);
    statuses[q.status || 'unknown'] = (statuses[q.status || 'unknown'] || 0) + 1;

    const isGoverned = governedSet.has(destination);
    const bucketMap = isGoverned ? governed : ungoverned;
    if (!bucketMap.has(destination)) bucketMap.set(destination, emptyAggregate(destination));
    bumpAggregate(bucketMap.get(destination), q);

    if (q.status === 'shadow_ai') {
      if (!shadow.has(destination)) shadow.set(destination, emptyAggregate(destination));
      bumpAggregate(shadow.get(destination), q);
    }
  }

  const requiredSensors = REQUIRED_SENSORS.map((source) => {
    const seen = sensorCounts.get(source);
    return seen || { source, label: SENSOR_LABELS[source] || source, events: 0, lastSeen: null, _versions: new Map(), _platforms: new Set() };
  });
  const additionalSensors = [...sensorCounts.values()].filter((s) => !REQUIRED_SENSORS.includes(s.source));
  const sensors = [...requiredSensors, ...additionalSensors]
    .map(finalizeSensor)
    .sort((a, b) => b.events - a.events || a.label.localeCompare(b.label));
  const activeRequired = requiredSensors.filter((s) => s.events > 0).length;
  const activeSensorVersionGaps = sensors.filter((s) => s.events > 0 && s.versionHealth !== 'current').length;
  const governedActive = [...governed.values()].filter((g) => g.events > 0).length;
  const governedTotal = governed.size || 0;
  const shadowEvents = statuses.shadow_ai || 0;
  const score = Math.round(
    (activeRequired / REQUIRED_SENSORS.length) * 45
    + (governedTotal ? (governedActive / governedTotal) * 25 : 0)
    + (governedTotal ? 10 : 0)
    + (shadowEvents ? 0 : 20),
  );

  return {
    generatedAt: new Date().toISOString(),
    score: Math.max(0, Math.min(100, score)),
    totals: {
      events: (rows || []).length,
      governedDestinations: governedTotal,
      governedActive,
      shadowEvents,
      blocked: Object.entries(statuses)
        .filter(([status]) => BLOCKED_STATUSES.has(status))
        .reduce((sum, [, count]) => sum + count, 0),
    },
    sensors,
    governedDestinations: [...governed.values()]
      .map((bucket) => publicAggregate(bucket, { governed: true }))
      .sort((a, b) => b.events - a.events || a.destination.localeCompare(b.destination)),
    ungovernedDestinations: [...ungoverned.values()]
      .map((bucket) => publicAggregate(bucket, { governed: false }))
      .sort((a, b) => b.events - a.events || a.destination.localeCompare(b.destination))
      .slice(0, 12),
    shadowDestinations: [...shadow.values()]
      .map((bucket) => publicAggregate(bucket, { governed: governedSet.has(bucket.destination) }))
      .sort((a, b) => b.shadow - a.shadow || a.destination.localeCompare(b.destination))
      .slice(0, 12),
    posture: [
      {
        id: 'browser_extension',
        label: 'Browser extension',
        state: (sensorCounts.get('browser_extension') || {}).events ? 'covered' : 'attention',
        detail: `${(sensorCounts.get('browser_extension') || {}).events || 0} events`,
      },
      {
        id: 'endpoint_agent',
        label: 'Endpoint agent',
        state: (sensorCounts.get('endpoint_agent') || {}).events ? 'covered' : 'attention',
        detail: `${(sensorCounts.get('endpoint_agent') || {}).events || 0} events`,
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
        state: shadowEvents ? 'attention' : 'covered',
        detail: `${shadowEvents} sightings`,
      },
      {
        id: 'sensor_versions',
        label: 'Sensor versions',
        state: activeSensorVersionGaps ? 'attention' : 'covered',
        detail: activeSensorVersionGaps ? `${activeSensorVersionGaps} version gaps` : 'reported',
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

module.exports = { summarize, normalizeDestination };
