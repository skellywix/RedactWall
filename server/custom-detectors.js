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

const CONFIG_ENV_PATH = process.env.REDACTWALL_CUSTOM_DETECTORS_PATH || process.env.PROMPTWALL_CUSTOM_DETECTORS_PATH || process.env.SENTINEL_CUSTOM_DETECTORS_PATH;
const CONFIG_PATH = CONFIG_ENV_PATH
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
  return defaultLoader.loadCustomDetectors();
}

function enabledDetectorCount(items) {
  return items.reduce((count, item) => (
    item && typeof item === 'object' && !Array.isArray(item) && item.enabled === false
      ? count
      : count + 1
  ), 0);
}

function createLoader(configPath, configuredByEnv = false, fsImpl = fs) {
  let cached = null;
  let lastGood = [];
  let loadedGood = false;

  function failedState(sig, error) {
    return { sig, ok: false, configured: true, error, detectors: lastGood };
  }

  function loadState() {
    let stat;
    try {
      stat = fsImpl.statSync(configPath);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') {
        cached = failedState('stat-error', 'detector pack could not be inspected');
        return cached;
      }
      const sig = 'missing';
      if (cached && cached.sig === sig) return cached;
      if (loadedGood) cached = failedState(sig, 'detector pack disappeared after a successful load');
      else if (configuredByEnv) cached = failedState(sig, 'configured detector pack is missing');
      else cached = { sig, ok: true, configured: false, error: null, detectors: [] };
      return cached;
    }
    const sig = `${stat.mtimeMs}:${stat.ctimeMs}:${stat.size}`;
    if (cached && cached.sig === sig) return cached;

    let contents;
    try {
      contents = fsImpl.readFileSync(configPath, 'utf8');
    } catch {
      return failedState(sig, 'detector pack could not be read');
    }

    let parsed;
    try {
      parsed = JSON.parse(contents);
    } catch {
      cached = failedState(sig, 'detector pack is not valid JSON');
      return cached;
    }
    const raw = Array.isArray(parsed) ? { detectors: parsed } : parsed;
    if (!raw || typeof raw !== 'object' || !Array.isArray(raw.detectors)) {
      cached = failedState(sig, 'detector pack must contain a detectors array');
      return cached;
    }

    try {
      const detectors = detector.publicCustomDetectorConfig(raw);
      if (detectors.length !== enabledDetectorCount(raw.detectors)) {
        cached = failedState(sig, 'detector pack has an invalid, duplicate, or excess enabled detector');
        return cached;
      }
      lastGood = detectors;
      loadedGood = true;
      cached = { sig, ok: true, configured: true, error: null, detectors };
    } catch {
      cached = failedState(sig, 'detector pack could not be validated');
    }
    return cached;
  }

  function status() {
    const state = loadState();
    return {
      ok: state.ok,
      configured: state.configured,
      detectors: state.detectors.length,
      error: state.error,
      usingLastKnownGood: !state.ok && state.detectors.length > 0,
    };
  }

  return {
    loadCustomDetectors: () => loadState().detectors,
    status,
  };
}

const defaultLoader = createLoader(CONFIG_PATH, !!CONFIG_ENV_PATH);

function status() { return defaultLoader.status(); }

function listDetectorIds() {
  return loadCustomDetectors().map((item) => item.id);
}

module.exports = {
  CONFIG_PATH,
  createLoader,
  loadRaw,
  loadCustomDetectors,
  listDetectorIds,
  status,
};
