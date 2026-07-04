'use strict';
/**
 * Named endpoint file-flow watcher profiles.
 *
 * Profiles let a pilot map multiple local app/drop/staging directories to
 * explicit AI destinations while keeping all file reads inside the endpoint
 * agent. Public summaries expose only profile ids and counts, never paths.
 */
const path = require('path');
const { withEnvAliases } = require('../../server/env');

const MAX_FILE_FLOW_PROFILES = 8;
const PROFILE_ID_RE = /^[a-z][a-z0-9_]{0,39}$/;

function cleanText(value, fallback, max) {
  const text = String(value || '').replace(/[\r\n\t]/g, ' ').trim();
  return (text || fallback).slice(0, max);
}

function normalizeProfileId(value, index = 0) {
  const id = String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');
  if (PROFILE_ID_RE.test(id)) return id;
  return `profile_${Math.max(1, index + 1)}`;
}

function configuredProfilesValue(env = process.env) {
  const resolved = withEnvAliases(env);
  return resolved.ENDPOINT_AGENT_FILE_FLOW_PROFILES
    || resolved.PROMPTWALL_ENDPOINT_AGENT_FILE_FLOW_PROFILES
    || '';
}

function parseProfilesJson(raw) {
  const text = String(raw || '').trim();
  if (!text) return [];
  const parsed = JSON.parse(text);
  if (Array.isArray(parsed)) return parsed;
  if (parsed && Array.isArray(parsed.profiles)) return parsed.profiles;
  throw new Error('endpoint file-flow profiles must be a JSON array');
}

function normalizeFileFlowProfiles(input = []) {
  const src = Array.isArray(input) ? input : parseProfilesJson(input);
  const profiles = [];
  for (const [index, item] of src.entries()) {
    if (!item || typeof item !== 'object' || item.enabled === false) continue;
    const rawDir = cleanText(item.dir || item.path || item.watchDir, '', 1024);
    if (!rawDir) throw new Error('endpoint file-flow profile directory is required');
    profiles.push({
      id: normalizeProfileId(item.id || item.name || item.destination, index),
      dir: path.resolve(rawDir),
      destination: cleanText(item.destination || item.app || item.name, 'Desktop AI', 80),
      user: cleanText(item.user, '', 160),
    });
    if (profiles.length >= MAX_FILE_FLOW_PROFILES) break;
  }
  return profiles;
}

function fileFlowProfilesFromEnv(env = process.env) {
  return normalizeFileFlowProfiles(parseProfilesJson(configuredProfilesValue(env)));
}

function publicProfileChecks(profiles = [], dirExists = () => false) {
  const normalized = normalizeFileFlowProfiles(profiles);
  const checks = [{
    id: 'endpoint_file_flow_profiles',
    ok: true,
    detail: normalized.length ? `configured:${normalized.length}` : 'disabled',
  }];
  for (const profile of normalized) {
    const ok = dirExists(profile.dir) === true;
    checks.push({
      id: `endpoint_file_flow_profile_${profile.id}`,
      ok,
      detail: ok ? 'configured directory' : 'missing directory',
    });
  }
  return checks;
}

module.exports = {
  MAX_FILE_FLOW_PROFILES,
  normalizeFileFlowProfiles,
  fileFlowProfilesFromEnv,
  publicProfileChecks,
  normalizeProfileId,
  parseProfilesJson,
};
