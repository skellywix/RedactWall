'use strict';

function safeTextField(value, max = 80) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.slice(0, max) : null;
}

function safeSensor(sensor) {
  if (!sensor || typeof sensor !== 'object') return null;
  const safe = {
    name: safeTextField(sensor.name),
    version: safeTextField(sensor.version),
    packageVersion: safeTextField(sensor.packageVersion),
    platform: safeTextField(sensor.platform),
  };
  const compact = Object.fromEntries(Object.entries(safe).filter(([, value]) => value));
  return Object.keys(compact).length ? compact : null;
}

function safeSensorVersionGap(gap) {
  if (!gap || typeof gap !== 'object') return null;
  const versions = Array.isArray(gap.versions) ? gap.versions.slice(0, 8).map((item) => ({
    version: safeTextField(item && item.version),
    events: Number.isFinite(Number(item && item.events)) ? Math.max(0, Math.floor(Number(item.events))) : 0,
    lastSeen: safeTextField(item && item.lastSeen, 64),
  })).filter((item) => item.version) : [];
  const platforms = Array.isArray(gap.platforms)
    ? gap.platforms.map((platform) => safeTextField(platform)).filter(Boolean).slice(0, 8)
    : [];
  const safe = {
    source: safeTextField(gap.source),
    label: safeTextField(gap.label),
    versionHealth: safeTextField(gap.versionHealth),
    latestVersion: safeTextField(gap.latestVersion),
    versions,
    platforms,
  };
  const compact = Object.fromEntries(Object.entries(safe).filter(([, value]) => (
    Array.isArray(value) ? value.length : value
  )));
  return Object.keys(compact).length ? compact : null;
}

module.exports = { safeSensor, safeSensorVersionGap, safeTextField };
