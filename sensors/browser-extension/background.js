/* PromptWall background service worker.
 * - Holds the server URL + ingest key, and the org policy (cached).
 * - Resolves the END-USER IDENTITY from MDM-injected managed storage (so the
 *   audit log can answer "did employee X paste member data?" — REVIEW #8).
 * - Relays sensor events from content scripts to the control plane.
 * - Discovers "shadow AI": use of AI tools the policy does not govern.
 * Detection itself happens locally in the content script.
 */
try { importScripts('lib/adapters.js'); } catch (e) { /* PSAdapters used only for shadow-AI */ }

const DEFAULTS = {
  serverUrl: 'http://localhost:4000',
  ingestKey: '',
  requestTimeoutMs: 10000,
  enabled: true,
  policy: { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25, governedDestinations: [], allowedDestinations: [], blockedDestinations: [], blockedFileUploadDestinations: [], blockUnapprovedAiDestinations: true, alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'] },
};
const MANAGED_KEYS = ['user', 'email', 'orgId', 'serverUrl', 'ingestKey'];
const IDENTITY_KEYS = ['user', 'email', 'orgId'];
const INSTALL_HEARTBEAT_DESTINATION = 'browser-install';

async function cfg() {
  const c = await chrome.storage.local.get(Object.keys(DEFAULTS));
  return { ...DEFAULTS, ...c };
}

async function managedConfig() {
  try { return (await chrome.storage.managed.get(MANAGED_KEYS)) || {}; } catch (e) { return {}; }
}

function resolveIdentity(managed = {}, local = {}) {
  const user = managed.email || managed.user || local.email || local.user || 'unattributed@unmanaged';
  const orgId = managed.orgId || local.orgId || null;
  return { user, orgId, managed: !!(managed.email || managed.user) };
}

// Identity precedence: MDM-managed (enterprise force-install) > local override >
// an explicit "unmanaged" marker (so unattributed events are visible as a gap,
// never silently mislabeled as a real person).
async function identity() {
  const [managed, local] = await Promise.all([managedConfig(), chrome.storage.local.get(IDENTITY_KEYS)]);
  return resolveIdentity(managed, local);
}

async function serverCfg() {
  const [managed, c] = await Promise.all([managedConfig(), cfg()]);
  return { serverUrl: managed.serverUrl || c.serverUrl, ingestKey: managed.ingestKey || c.ingestKey, enabled: c.enabled, requestTimeoutMs: c.requestTimeoutMs };
}

function requestTimeoutMs(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return DEFAULTS.requestTimeoutMs;
  return Math.max(50, Math.min(60000, Math.floor(n)));
}

function failClosed(reason) {
  return { decision: 'block', status: 'control_plane_unavailable', reason };
}

function scanUnavailable(reason) {
  return { decision: 'block', status: 'scan_unavailable', supported: true, inspected: false, reason };
}

function missingServerConfigReason(c) {
  if (!c.serverUrl) return 'missing_server_url';
  if (!c.ingestKey) return 'missing_ingest_key';
  return null;
}

function validServerOrigin(value) {
  try {
    const url = new URL(String(value || ''));
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return `${url.protocol}//${url.host}`;
  } catch (e) {
    return null;
  }
}

function sensorMetadata() {
  const manifest = (chrome.runtime && chrome.runtime.getManifest) ? chrome.runtime.getManifest() : {};
  return {
    name: 'browser_extension',
    version: manifest.version || 'unknown',
    platform: 'chrome_mv3',
  };
}

function installCheck(id, ok, detail) {
  return {
    id,
    ok: ok === true,
    detail: String(detail || (ok ? 'ok' : 'attention')).slice(0, 160),
  };
}

function manifestInfo() {
  return (chrome.runtime && chrome.runtime.getManifest) ? chrome.runtime.getManifest() : {};
}

function hasContentScriptCoverage(manifest = manifestInfo()) {
  return (manifest.content_scripts || []).some((script) => (
    Array.isArray(script.matches)
    && script.matches.length > 0
    && Array.isArray(script.js)
    && script.js.includes('lib/detect.js')
    && script.js.includes('content.js')
  ));
}

function buildInstallChecks({ config = DEFAULTS, server = {}, identity: who = {}, managed = {}, manifest = manifestInfo() } = {}) {
  const origin = validServerOrigin(server.serverUrl);
  const hasManagedServer = !!(managed.serverUrl && managed.ingestKey);
  const hasManagedIdentity = !!(managed.email || managed.user);
  const hasManagedTenant = !!managed.orgId;
  return [
    installCheck('extension_manifest', manifest.manifest_version === 3 && !!manifest.version, `mv${manifest.manifest_version || 'unknown'} v${manifest.version || 'unknown'}`),
    installCheck('background_worker', !!(manifest.background && manifest.background.service_worker), 'service worker configured'),
    installCheck('content_script_coverage', hasContentScriptCoverage(manifest), 'content scripts cover AI hosts'),
    installCheck('protection_enabled', config.enabled !== false, config.enabled === false ? 'disabled locally' : 'enabled'),
    installCheck('server_url', !!origin, origin || 'missing or invalid'),
    installCheck('ingest_key', !!(server.ingestKey && String(server.ingestKey).length >= 16), 'configured'),
    installCheck('managed_config', hasManagedServer, hasManagedServer ? 'managed server config present' : 'local or missing server config'),
    installCheck('managed_identity', who.managed === true && hasManagedIdentity, who.managed === true ? 'managed identity present' : 'unmanaged identity'),
    installCheck('org_id', !!(who.orgId && hasManagedTenant), who.orgId ? 'configured' : 'missing'),
    installCheck('policy_cache', !!(config.policy && typeof config.policy === 'object'), 'policy available'),
  ];
}

function buildHeartbeatBody(checks, who, opts = {}) {
  return {
    user: (who && who.user) || 'unattributed@unmanaged',
    orgId: (who && who.orgId) || null,
    source: 'browser_extension',
    destination: opts.destination || INSTALL_HEARTBEAT_DESTINATION,
    sensor: sensorMetadata(),
    checks: (checks || []).map((item) => ({
      id: item.id,
      ok: item.ok === true,
      detail: item.detail,
    })),
  };
}

async function fetchJsonWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs(timeoutMs));
  try {
    const r = await fetch(url, { ...(options || {}), signal: controller.signal });
    const body = await r.json().catch(() => null);
    if (!r.ok) return { ok: false, reason: 'http_' + r.status, body };
    if (!body || typeof body !== 'object') return { ok: false, reason: 'invalid_json', body };
    return { ok: true, body };
  } catch (e) {
    return { ok: false, reason: e && e.name === 'AbortError' ? 'timeout' : 'unreachable' };
  } finally {
    clearTimeout(timer);
  }
}

async function reportInstallHealth() {
  const [config, managed, localIdentity] = await Promise.all([
    cfg(),
    managedConfig(),
    chrome.storage.local.get(IDENTITY_KEYS),
  ]);
  const who = resolveIdentity(managed, localIdentity);
  const server = {
    serverUrl: managed.serverUrl || config.serverUrl,
    ingestKey: managed.ingestKey || config.ingestKey,
    enabled: config.enabled,
    requestTimeoutMs: config.requestTimeoutMs,
  };
  const checks = buildInstallChecks({ config, server, identity: who, managed });
  if (!server.enabled) return { ok: false, reason: 'disabled', checks };
  const missing = missingServerConfigReason(server);
  if (missing) return { ok: false, reason: missing, checks };
  if (!validServerOrigin(server.serverUrl)) return { ok: false, reason: 'invalid_server_url', checks };
  return fetchJsonWithTimeout(String(server.serverUrl).replace(/\/+$/, '') + '/api/v1/heartbeat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': server.ingestKey },
    body: JSON.stringify(buildHeartbeatBody(checks, who)),
  }, server.requestTimeoutMs);
}

async function refreshPolicy() {
  const c = await serverCfg();
  if (!c.enabled) return;
  if (missingServerConfigReason(c)) return;
  try {
    const r = await fetchJsonWithTimeout(c.serverUrl + '/api/v1/policy', { headers: { 'x-api-key': c.ingestKey } }, c.requestTimeoutMs);
    if (r.ok) {
      const p = r.body;
      await chrome.storage.local.set({ policy: { ...DEFAULTS.policy, ...p } });
    }
  } catch (e) { /* offline → keep cached/default policy (fail-safe to block) */ }
}

async function refreshPolicyAndHealth() {
  await refreshPolicy();
  await reportInstallHealth();
}

function runAsync(fn) {
  try { Promise.resolve(fn()).catch(() => {}); } catch (e) {}
}

chrome.runtime.onInstalled.addListener(() => runAsync(refreshPolicyAndHealth));
chrome.runtime.onStartup.addListener(() => runAsync(refreshPolicyAndHealth));
chrome.alarms?.create('refreshPolicy', { periodInMinutes: 15 });
chrome.alarms?.create('installHeartbeat', { periodInMinutes: 60 });
chrome.alarms?.onAlarm.addListener((a) => {
  if (a.name === 'refreshPolicy') runAsync(refreshPolicy);
  if (a.name === 'installHeartbeat') runAsync(reportInstallHealth);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getConfig') {
    Promise.all([cfg(), identity()]).then(([c, who]) => sendResponse({ policy: c.policy, enabled: c.enabled, user: who.user, orgId: who.orgId }));
    return true;
  }
  if (msg.type === 'report') {
    Promise.all([serverCfg(), identity()]).then(async ([c, who]) => {
      if (!c.enabled) {
        sendResponse && sendResponse(null);
        return;
      }
      const missing = missingServerConfigReason(c);
      if (missing) {
        sendResponse && sendResponse(failClosed(missing));
        return;
      }
      try {
        const r = await fetchJsonWithTimeout(c.serverUrl + '/api/v1/gate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': c.ingestKey },
          body: JSON.stringify({
            prompt: msg.payload.prompt,
            user: who.user,
            orgId: who.orgId,
            destination: msg.payload.destination,
            channel: msg.payload.channel,
            source: msg.payload.source,
            sensor: sensorMetadata(),
            clientCategories: msg.payload.clientCategories || msg.payload.categories,
            clientFindings: msg.payload.clientFindings,
            clientEntityCounts: msg.payload.clientEntityCounts,
            clientRiskScore: msg.payload.clientRiskScore,
            clientMaxSeverity: msg.payload.clientMaxSeverity,
            clientMaxSeverityLabel: msg.payload.clientMaxSeverityLabel,
            clientPreRedacted: msg.payload.clientPreRedacted,
            clientOutcome: msg.payload.outcome,
            note: msg.payload.note,
          }),
        }, c.requestTimeoutMs);
        sendResponse && sendResponse(r.ok ? r.body : failClosed('gate_' + r.reason));
      } catch (e) { sendResponse && sendResponse(failClosed('gate_unreachable')); }
    });
    return true;
  }
  if (msg.type === 'scanFile') {
    Promise.all([serverCfg(), identity()]).then(async ([c, who]) => {
      if (!c.enabled) {
        sendResponse && sendResponse(null);
        return;
      }
      const missing = missingServerConfigReason(c);
      if (missing) {
        sendResponse && sendResponse(scanUnavailable(missing));
        return;
      }
      try {
        const r = await fetchJsonWithTimeout(c.serverUrl + '/api/v1/scan-file', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': c.ingestKey },
          body: JSON.stringify({
            filename: msg.payload.filename,
            contentBase64: msg.payload.contentBase64,
            user: who.user,
            orgId: who.orgId,
            destination: msg.payload.destination,
            channel: msg.payload.channel,
            source: msg.payload.source,
            sensor: sensorMetadata(),
          }),
        }, c.requestTimeoutMs);
        sendResponse && sendResponse(r.ok ? r.body : scanUnavailable('scan_file_' + r.reason));
      } catch (e) { sendResponse && sendResponse(scanUnavailable('scan_file_unreachable')); }
    });
    return true;
  }
});

// ---- Shadow-AI discovery -----------------------------------------------------
// Flag visits to AI tools that policy does NOT govern (so an examiner sees the
// unmonitored paths, not just the guarded ones). Throttled to once/host/12h.
const seenShadow = {};
chrome.tabs?.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== 'complete' || !tab || !tab.url || !self.PSAdapters) return;
  let host; try { host = new URL(tab.url).hostname; } catch (e) { return; }
  const c = await cfg();
  const governed = [
    ...((c.policy && c.policy.governedDestinations) || []),
    ...((c.policy && c.policy.allowedDestinations) || []),
    ...((c.policy && c.policy.blockedDestinations) || []),
    ...((c.policy && c.policy.blockedFileUploadDestinations) || []),
  ];
  if (!self.PSAdapters.isAiHost(host) || self.PSAdapters.isGoverned(host, governed)) return;
  const now = Date.now();
  if (seenShadow[host] && now - seenShadow[host] < 12 * 3600 * 1000) return;
  seenShadow[host] = now;
  const [sc, who] = await Promise.all([serverCfg(), identity()]);
  if (!sc.enabled) return;
  if (missingServerConfigReason(sc)) return;
  try {
    const blockUnapproved = !c.policy || c.policy.blockUnapprovedAiDestinations !== false;
    await fetchJsonWithTimeout(sc.serverUrl + '/api/v1/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': sc.ingestKey },
      body: JSON.stringify({
        prompt: (blockUnapproved ? '[unapproved AI blocked] ' : '[shadow-AI] visit to ungoverned AI tool: ') + host,
        user: who.user,
        orgId: who.orgId,
        destination: host,
        channel: 'shadow_ai',
        source: 'browser_extension',
        sensor: sensorMetadata(),
        clientOutcome: blockUnapproved ? 'destination_blocked' : 'shadow_ai',
        note: blockUnapproved ? 'blocked locally: unapproved AI destination' : 'ungoverned AI tool',
      }),
    }, sc.requestTimeoutMs);
  } catch (e) {}
});
