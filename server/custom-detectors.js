'use strict';
/**
 * Customer detector-pack loader.
 *
 * The config file is data only. The shared detection engine validates regex
 * shape, bounds repetition, blocks built-in ID overrides, and returns a
 * browser-safe public config that sensors can enforce locally.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');
const detector = require('../detection-engine/detect');

const CONFIG_PATH = process.env.SENTINEL_CUSTOM_DETECTORS_PATH
  || process.env.PROMPTWALL_CUSTOM_DETECTORS_PATH
  || path.join(__dirname, '..', 'config', 'custom-detectors.json');

function loadRaw() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      if (Array.isArray(parsed)) return { detectors: parsed };
      if (parsed && typeof parsed === 'object') return parsed;
    }
  } catch (e) { /* default empty pack */ }
  return { detectors: [] };
}

function loadCustomDetectors() {
  return detector.publicCustomDetectorConfig(loadRaw());
}

function listDetectorIds() {
  return loadCustomDetectors().map((item) => item.id);
}

module.exports = {
  CONFIG_PATH,
  loadRaw,
  loadCustomDetectors,
  listDetectorIds,
};
