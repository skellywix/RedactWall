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

module.exports = { safeSensor, safeTextField };
