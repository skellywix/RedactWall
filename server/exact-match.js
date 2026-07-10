'use strict';
/**
 * Exact Data Match (EDM) watchlist loader.
 *
 * The config file holds ONLY salted SHA-256 fingerprints of high-entropy,
 * randomly generated identifiers plus the public salt — never plaintext values.
 * `scripts/edm-fingerprint.js`
 * turns a plaintext list into this file locally; the plaintext is discarded.
 * Detection hashes candidate spans with the same salt and checks set membership.
 * Managed sensors receive only this fingerprint pack through the authenticated,
 * signed policy surface so they can enforce EDM before egress; plaintext source
 * values never leave the control plane or fingerprinting workstation.
 */
require('./env').loadEnv();
const fs = require('fs');
const path = require('path');
const detector = require('../detection-engine/detect');

const CONFIG_ENV_PATH = process.env.REDACTWALL_EXACT_MATCH_PATH || process.env.PROMPTWALL_EXACT_MATCH_PATH || process.env.SENTINEL_EXACT_MATCH_PATH;
const CONFIG_PATH = CONFIG_ENV_PATH || path.join(__dirname, '..', 'config', 'exact-match.json');
const PROFILE = detector.EDM_PROFILE;
const DISABLED_RAW = Object.freeze({
  formatVersion: PROFILE.formatVersion,
  algorithm: PROFILE.algorithm,
  valuePolicy: PROFILE.valuePolicy,
  enabled: false,
  salt: '',
  minLen: PROFILE.minLen,
  maxWords: PROFILE.maxWords,
  fingerprints: [],
});
const DISABLED_NORMALIZED = detector.normalizeExactMatchConfig(DISABLED_RAW);

function nominallyEnabled(raw) {
  return raw.enabled === true
    || (raw.enabled !== false && Array.isArray(raw.fingerprints) && raw.fingerprints.length > 0);
}

function validationError(raw) {
  if (!nominallyEnabled(raw)) return null;
  if (raw.formatVersion !== PROFILE.formatVersion || raw.algorithm !== PROFILE.algorithm
      || raw.valuePolicy !== PROFILE.valuePolicy) {
    return 'enabled exact-match pack requires the version 2 SHA-256 high-entropy profile';
  }
  if (typeof raw.salt !== 'string'
      || !new RegExp(`^[A-Za-z0-9_-]{${PROFILE.saltMinLength},128}$`).test(raw.salt)) {
    return `enabled exact-match pack requires an ASCII salt of at least ${PROFILE.saltMinLength} characters`;
  }
  if (!Number.isInteger(raw.minLen) || raw.minLen < PROFILE.minLen || raw.minLen > 128) {
    return `enabled exact-match pack minLen must be between ${PROFILE.minLen} and 128`;
  }
  if (raw.maxWords !== PROFILE.maxWords) {
    return `enabled exact-match pack maxWords must be ${PROFILE.maxWords}`;
  }
  if (!Array.isArray(raw.fingerprints) || raw.fingerprints.length === 0) {
    return 'enabled exact-match pack requires at least one fingerprint';
  }
  if (raw.fingerprints.some((value) => typeof value !== 'string')) {
    return 'exact-match fingerprints must all be strings';
  }
  const normalized = raw.fingerprints.map((value) => String(value || '').trim().toLowerCase());
  if (normalized.some((value) => !/^[0-9a-f]{64}$/.test(value))) {
    return 'exact-match fingerprints must all be 64-character SHA-256 hex digests';
  }
  if (new Set(normalized).size !== normalized.length) {
    return 'exact-match fingerprints must be unique';
  }
  return null;
}

// Returning the SAME raw object across calls is load-bearing: analyze()'s EDM
// cache is keyed by object identity. Failed reloads retain that exact LKG object
// while readiness stays red, so coverage never disappears silently.
function createLoader(configPath, configuredByEnv = false, fsImpl = fs) {
  let cached = null;
  let lastGood = null;

  function effectiveState(state) {
    if (lastGood) return { ...state, ...lastGood, usingLastKnownGood: true };
    return {
      ...state,
      raw: DISABLED_RAW,
      normalized: DISABLED_NORMALIZED,
      config: null,
      usingLastKnownGood: false,
    };
  }

  function failedState(sig, error) {
    return effectiveState({ sig, ok: false, configured: true, error });
  }

  function loadState() {
    let stat;
    try {
      stat = fsImpl.statSync(configPath);
    } catch (error) {
      if (!error || error.code !== 'ENOENT') {
        cached = failedState('stat-error', 'exact-match pack could not be inspected');
        return cached;
      }
      const sig = 'missing';
      if (cached && cached.sig === sig) return cached;
      if (lastGood) cached = failedState(sig, 'exact-match pack disappeared after a successful load');
      else if (configuredByEnv) cached = failedState(sig, 'configured exact-match pack is missing');
      else cached = {
        sig,
        ok: true,
        configured: false,
        error: null,
        raw: DISABLED_RAW,
        normalized: DISABLED_NORMALIZED,
        config: null,
        usingLastKnownGood: false,
      };
      return cached;
    }

    const sig = `${stat.mtimeMs}:${stat.ctimeMs}:${stat.size}`;
    if (cached && cached.sig === sig) return cached;

    let contents;
    try {
      contents = fsImpl.readFileSync(configPath, 'utf8');
    } catch (error) {
      return failedState(sig, 'exact-match pack could not be read');
    }

    let raw;
    try {
      raw = JSON.parse(contents);
    } catch (error) {
      cached = failedState(sig, 'exact-match pack is not valid JSON');
      return cached;
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      cached = failedState(sig, 'exact-match pack must be a JSON object');
      return cached;
    }

    const invalid = validationError(raw);
    if (invalid) {
      cached = failedState(sig, invalid);
      return cached;
    }
    const normalized = detector.normalizeExactMatchConfig(raw);
    if (nominallyEnabled(raw) && (!normalized.enabled || normalized.set.size !== raw.fingerprints.length)) {
      cached = failedState(sig, 'exact-match pack could not be normalized without dropping fingerprints');
      return cached;
    }

    lastGood = {
      raw,
      normalized,
      config: normalized.enabled ? raw : null,
    };
    cached = {
      sig,
      ok: true,
      configured: true,
      error: null,
      ...lastGood,
      usingLastKnownGood: false,
    };
    return cached;
  }

  function status() {
    const state = loadState();
    return {
      ok: state.ok,
      configured: state.configured,
      enabled: state.normalized.enabled,
      fingerprints: state.normalized.set.size,
      error: state.error,
      usingLastKnownGood: state.usingLastKnownGood,
    };
  }

  return {
    exactMatchConfig: () => loadState().config,
    loadRaw: () => loadState().raw,
    normalized: () => loadState().normalized,
    status,
  };
}

const defaultLoader = createLoader(CONFIG_PATH, !!CONFIG_ENV_PATH);

function loadRaw() { return defaultLoader.loadRaw(); }

// Engine-ready config for analyze(text, { exactMatch }). Returns null when no
// usable watchlist is configured so the hot path skips EDM entirely.
function exactMatchConfig() { return defaultLoader.exactMatchConfig(); }

function status() { return defaultLoader.status(); }

// Bounded, plaintext-free summary for the console and evidence packs.
function publicSummary() {
  const normalized = defaultLoader.normalized();
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
  createLoader,
  loadRaw,
  exactMatchConfig,
  publicSummary,
  status,
};
