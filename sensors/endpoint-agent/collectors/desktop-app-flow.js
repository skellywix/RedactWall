'use strict';
/**
 * Per-app guarded drop folders for desktop AI apps.
 *
 * For each detected desktop AI tool the collector provisions a guarded
 * folder (one per app) and exposes it as a file-flow profile, so anything a
 * user stages for that app is scanned, blocked, or redacted locally before
 * it can be handed to the app. Public summaries expose tool ids and counts
 * only — never local paths, file names, or file content.
 */
const fs = require('fs');
const path = require('path');
const { withEnvAliases } = require('../../../server/env');
const aiToolInventory = require('./ai-tool-inventory');
const fileFlowProfiles = require('../file-flow-profiles');

const APP_FLOW_TOOL_IDS = ['chatgpt_desktop', 'claude_desktop', 'copilot', 'cursor', 'windsurf'];
const MAX_APP_FLOW_PROFILES = APP_FLOW_TOOL_IDS.length;

function envValue(env, key) {
  const resolved = withEnvAliases(env || process.env);
  return resolved[key] || resolved[`PROMPTWALL_${key}`] || '';
}

function flagEnabled(value) {
  return ['1', 'true', 'yes', 'on'].includes(String(value || '').trim().toLowerCase());
}

function appFlowSettings(env = process.env, watchDir = '') {
  const baseDir = String(envValue(env, 'ENDPOINT_AGENT_APP_FLOW_DIR') || '').trim();
  const enabled = flagEnabled(envValue(env, 'ENDPOINT_AGENT_APP_FLOW')) || Boolean(baseDir);
  return {
    enabled,
    // Resolve the operator-supplied dir so guarded folders are always absolute
    // (on Windows a POSIX-style path would otherwise stay drive-relative).
    baseDir: baseDir ? path.resolve(baseDir) : (watchDir ? path.join(watchDir, 'AI Apps') : ''),
  };
}

function flowTools(opts = {}) {
  const tools = Array.isArray(opts.tools) ? opts.tools : aiToolInventory.KNOWN_AI_TOOLS;
  return tools.filter((tool) => APP_FLOW_TOOL_IDS.includes(tool && tool.id));
}

function detectedFlowTools(opts = {}) {
  if (Array.isArray(opts.detected)) {
    return flowTools(opts).filter((tool) => opts.detected.includes(tool.id));
  }
  return flowTools(opts).filter((tool) => aiToolInventory.collectAiToolInventorySync({
    env: opts.env,
    platform: opts.platform,
    processNames: opts.processNames || [],
    tools: [tool],
  }).detected.length > 0);
}

function ensureProfileDir(dir, deps = {}) {
  const mkdir = deps.mkdirSync || fs.mkdirSync;
  try {
    mkdir(dir, { recursive: true });
    return true;
  } catch {
    return false;
  }
}

function desktopAppFlowProfiles(opts = {}) {
  const settings = opts.settings || appFlowSettings(opts.env, opts.watchDir);
  if (!settings.enabled || !settings.baseDir) return [];
  const profiles = [];
  for (const tool of detectedFlowTools(opts).slice(0, MAX_APP_FLOW_PROFILES)) {
    const dir = path.join(settings.baseDir, tool.label);
    if (opts.ensureDirs !== false && !ensureProfileDir(dir, opts)) continue;
    profiles.push({ id: `app_flow_${tool.id}`, dir, destination: tool.label });
  }
  return fileFlowProfiles.normalizeFileFlowProfiles(profiles);
}

function publicAppFlowChecks(profiles = [], dirExists = () => false) {
  const checks = [{
    id: 'endpoint_app_flow',
    ok: true,
    detail: profiles.length ? `guarded apps:${profiles.length}` : 'disabled',
  }];
  for (const profile of profiles) {
    const ok = dirExists(profile.dir) === true;
    checks.push({
      id: `endpoint_${profile.id}`,
      ok,
      detail: ok ? 'guarded folder ready' : 'guarded folder missing',
    });
  }
  return checks;
}

module.exports = {
  APP_FLOW_TOOL_IDS,
  MAX_APP_FLOW_PROFILES,
  appFlowSettings,
  desktopAppFlowProfiles,
  detectedFlowTools,
  publicAppFlowChecks,
};
