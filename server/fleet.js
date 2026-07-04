'use strict';
/**
 * Cross-sensor presence registry. Every gate call and heartbeat refreshes an
 * in-memory map of user -> { sensor -> last seen }, bootstrapped lazily from
 * the query store on first use. Two jobs:
 *   1. companionsFor(user): tell a sensor about its peers on the same identity
 *      (returned in the heartbeat response), so the browser extension can say
 *      "the endpoint agent is missing on this device" and vice versa.
 *   2. summary(): the console's per-user fleet matrix with coverage gaps.
 */

const TRACKED = ['browser_extension', 'endpoint_agent', 'mcp_guard'];
const STALE_MS = 48 * 3600 * 1000;

let db = null;
let presence = null; // Map<user, { [source]: { lastSeen, version, platform } }>

function init(database) {
  db = database;
  presence = null;
}

function ensure() {
  if (presence) return presence;
  presence = new Map();
  if (db) {
    for (const row of db.listQueries({ limit: 5000 })) record(row);
  }
  return presence;
}

function record(row) {
  if (!row || !TRACKED.includes(row.source)) return;
  const user = String(row.user || '').trim().toLowerCase();
  if (!user || user === 'unknown') return;
  const ts = Date.parse(row.createdAt || '') || Date.now();
  const bySensor = presence.get(user) || {};
  const cur = bySensor[row.source];
  if (cur && ts <= cur.lastSeen) return;
  bySensor[row.source] = {
    lastSeen: ts,
    version: (row.sensor && row.sensor.version) || (cur && cur.version) || null,
    platform: (row.sensor && row.sensor.platform) || (cur && cur.platform) || null,
  };
  presence.set(user, bySensor);
}

function recordPresence(row) {
  ensure();
  record(row);
}

function sensorState(entry, now) {
  if (!entry) return 'missing';
  return now - entry.lastSeen > STALE_MS ? 'stale' : 'active';
}

// What one sensor should know about its peers on the same identity.
function companionsFor(user, { exclude } = {}) {
  const bySensor = ensure().get(String(user || '').trim().toLowerCase()) || {};
  const now = Date.now();
  const out = {};
  for (const s of TRACKED) {
    if (s === exclude) continue;
    out[s] = sensorState(bySensor[s], now);
  }
  return out;
}

function userSummary(user, bySensor, now) {
  const sensors = {};
  for (const s of TRACKED) {
    const entry = bySensor[s];
    sensors[s] = {
      state: sensorState(entry, now),
      lastSeen: entry ? new Date(entry.lastSeen).toISOString() : null,
      version: entry ? entry.version : null,
      platform: entry ? entry.platform : null,
    };
  }
  // A user covered in the browser but not on the desktop (or vice versa) is a
  // real blind spot. MCP guard is workload-level, so only flag it once it has
  // reported before and gone silent.
  const gaps = [];
  if (sensors.browser_extension.state === 'active' && sensors.endpoint_agent.state !== 'active') {
    gaps.push({ sensor: 'endpoint_agent', state: sensors.endpoint_agent.state, reportedBy: 'browser_extension' });
  }
  if (sensors.endpoint_agent.state === 'active' && sensors.browser_extension.state !== 'active') {
    gaps.push({ sensor: 'browser_extension', state: sensors.browser_extension.state, reportedBy: 'endpoint_agent' });
  }
  if (sensors.mcp_guard.state === 'stale') {
    gaps.push({ sensor: 'mcp_guard', state: 'stale', reportedBy: 'control_plane' });
  }
  return { user, sensors, gaps };
}

function summary({ now = Date.now() } = {}) {
  const users = [...ensure().entries()]
    .map(([user, bySensor]) => userSummary(user, bySensor, now))
    .sort((a, b) => (b.gaps.length - a.gaps.length) || a.user.localeCompare(b.user));
  return {
    trackedSensors: TRACKED,
    staleAfterHours: STALE_MS / 3600000,
    users,
    gapCount: users.reduce((sum, u) => sum + u.gaps.length, 0),
  };
}

module.exports = { init, recordPresence, companionsFor, summary, TRACKED, STALE_MS };
