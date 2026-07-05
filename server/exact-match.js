'use strict';
/**
 * Exact Data Match (EDM) watchlist loader.
 *
 * The config file holds ONLY salted one-way fingerprints of known-sensitive
 * values plus the salt — never the plaintext values. `scripts/edm-fingerprint.js`
 * turns a plaintext list into this file locally; the plaintext is discarded.
 * Detection hashes candidate spans with the same salt and checks set membership,
 * so an org can flag its own member IDs / account numbers / employee names
 * without the values (or a reversible index) ever reaching a sensor.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');
const detector = require('../detection-engine/detect');

const CONFIG_PATH = process.env.REDACTWALL_EXACT_MATCH_PATH || process.env.PROMPTWALL_EXACT_MATCH_PATH || process.env.SENTINEL_EXACT_MATCH_PATH
  || path.join(__dirname, '..', 'config', 'exact-match.json');

function loadRaw() {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      const parsed = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    }
  } catch (e) { /* default: no watchlist */ }
  return { salt: '', fingerprints: [] };
}

// Engine-ready config for analyze(text, { exactMatch }). Returns null when no
// usable watchlist is configured so the hot path skips EDM entirely.
function exactMatchConfig() {
  const normalized = detector.normalizeExactMatchConfig(loadRaw());
  return normalized.enabled ? loadRaw() : null;
}

// Bounded, plaintext-free summary for the console and evidence packs.
function publicSummary() {
  const normalized = detector.normalizeExactMatchConfig(loadRaw());
  return {
    enabled: normalized.enabled,
    fingerprints: normalized.set.size,
    minLength: normalized.minLen,
    maxWords: normalized.maxWords,
    severity: normalized.severity,
  };
}

module.exports = {
  CONFIG_PATH,
  loadRaw,
  exactMatchConfig,
  publicSummary,
};
