/* RedactWall background service worker.
 * - Holds the server URL + ingest key, and the org policy (cached).
 * - Resolves the END-USER IDENTITY from MDM-injected managed storage (so the
 *   audit log can answer "did employee X paste member data?" — REVIEW #8).
 * - Relays sensor events from content scripts to the control plane.
 * - Discovers "shadow AI": use of AI tools the policy does not govern.
 * Detection itself happens locally in the content script.
 */
try { importScripts('lib/browser-api.js'); } catch (e) { /* optional browser namespace bridge */ }
try { importScripts('lib/adapters.js'); } catch (e) { /* optional shared host catalog */ }

const DEFAULTS = {
  serverUrl: 'http://localhost:4000',
  ingestKey: '',
  requestTimeoutMs: 10000,
  enabled: true,
  policy: { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25, governedDestinations: [], allowedDestinations: [], blockedDestinations: [], blockedFileUploadDestinations: [], blockedBrowserActions: [], blockUnapprovedAiDestinations: true, alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN'] },
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

function missingServerConfigReason(c) {
  if (!c.serverUrl) return 'missing_server_url';
  if (!c.ingestKey) return 'missing_ingest_key';
  return null;
}

function validServerOrigin(value) {
  try {
    const url = new URL(String(value || ''));
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    if (url.username || url.password) return null;
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
    platform: browserPlatform(manifest),
  };
}

function browserPlatform(manifest = manifestInfo()) {
  if (manifest.browser_specific_settings && manifest.browser_specific_settings.gecko) return 'firefox_mv3';
  const ua = (typeof navigator !== 'undefined' && navigator.userAgent) ? navigator.userAgent : '';
  if (/\bEdg\//.test(ua)) return 'edge_mv3';
  return 'chrome_mv3';
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
  const background = manifest.background || {};
  const hasBackground = !!(background.service_worker || (Array.isArray(background.scripts) && background.scripts.length));
  return [
    installCheck('extension_manifest', manifest.manifest_version === 3 && !!manifest.version, `mv${manifest.manifest_version || 'unknown'} v${manifest.version || 'unknown'}`),
    installCheck('background_worker', hasBackground, background.service_worker ? 'service worker configured' : 'background script configured'),
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
  const result = await fetchJsonWithTimeout(String(server.serverUrl).replace(/\/+$/, '') + '/api/v1/heartbeat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': server.ingestKey },
    body: JSON.stringify(buildHeartbeatBody(checks, who)),
  }, server.requestTimeoutMs);
  // The control plane answers with the state of this user's OTHER sensors, so
  // the extension can surface a missing/stale endpoint agent (and vice versa).
  if (result.ok && result.body && result.body.companions) {
    await chrome.storage.local.set({ fleetCompanions: { at: Date.now(), companions: result.body.companions } });
  }
  return result;
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

function normalizeDestinationHost(value) {
  const raw = String(value || '').trim().toLowerCase();
  if (!raw) return '';
  try {
    const url = raw.includes('://') ? new URL(raw) : new URL('https://' + raw);
    if ((url.protocol === 'blob:' || url.protocol === 'filesystem:') && url.pathname) {
      return normalizeDestinationHost(url.pathname);
    }
    return (url.hostname || '').replace(/^www\./, '');
  } catch (e) {
    return raw.replace(/^www\./, '').split(/[/?#]/)[0];
  }
}

function hostMatchesDestination(host, patterns) {
  const normalizedHost = normalizeDestinationHost(host);
  const destinations = Array.isArray(patterns) ? patterns : [];
  const A = self.PSAdapters;
  if (A && A.isGoverned && A.isGoverned(normalizedHost, destinations)) return true;
  return destinations.some((pattern) => {
    const target = normalizeDestinationHost(pattern);
    if (!normalizedHost || !target) return false;
    if (target === '*') return true;
    if (target.startsWith('*.')) {
      const base = target.slice(2);
      return normalizedHost === base || normalizedHost.endsWith('.' + base);
    }
    if (target.startsWith('*')) {
      const base = target.slice(1).replace(/^\./, '');
      return normalizedHost === base || normalizedHost.endsWith('.' + base);
    }
    return normalizedHost === target || normalizedHost.endsWith('.' + target);
  });
}

function browserActionBlockRule(action, destination, pol = {}) {
  const normalizedAction = String(action || '').trim().toLowerCase();
  for (const rule of (pol.blockedBrowserActions || [])) {
    if (!rule || rule.enabled === false) continue;
    if (String(rule.action || '').trim().toLowerCase() !== normalizedAction) continue;
    if (hostMatchesDestination(destination, rule.destinations || [])) return rule;
  }
  return null;
}

function downloadHostCandidates(item = {}) {
  const out = [];
  const seen = new Set();
  for (const field of ['referrer', 'finalUrl', 'url']) {
    const host = normalizeDestinationHost(item[field]);
    if (!host || seen.has(host)) continue;
    seen.add(host);
    out.push(host);
  }
  return out;
}

function downloadDestinationForPolicy(item = {}, pol = {}) {
  for (const host of downloadHostCandidates(item)) {
    if (browserActionBlockRule('download', host, pol)) return host;
  }
  return null;
}

function cancelDownload(id) {
  return new Promise((resolve) => {
    try {
      if (!chrome.downloads || !chrome.downloads.cancel || id == null) {
        resolve(false);
        return;
      }
      chrome.downloads.cancel(id, () => {
        resolve(!(chrome.runtime && chrome.runtime.lastError));
      });
    } catch (e) {
      resolve(false);
    }
  });
}

async function reportBlockedDownload(destination, rule) {
  const [sc, who] = await Promise.all([serverCfg(), identity()]);
  if (!sc.enabled) return { ok: false, reason: 'disabled' };
  const missing = missingServerConfigReason(sc);
  if (missing) return { ok: false, reason: missing };
  const host = normalizeDestinationHost(destination) || 'unknown';
  const reason = (rule && rule.reason) || 'download blocked by policy';
  return fetchJsonWithTimeout(sc.serverUrl + '/api/v1/gate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': sc.ingestKey },
    body: JSON.stringify({
      prompt: '[browser action blocked] download ' + host,
      user: who.user,
      orgId: who.orgId,
      destination: host,
      channel: 'download',
      source: 'browser_extension',
      sensor: sensorMetadata(),
      clientOutcome: 'action_blocked',
      note: reason,
    }),
  }, sc.requestTimeoutMs);
}

async function handleDownloadCreated(item = {}) {
  const c = await cfg();
  if (!c.enabled) return { ok: false, reason: 'disabled' };
  const destination = downloadDestinationForPolicy(item, c.policy || {});
  if (!destination) return { ok: false, reason: 'not_configured' };
  const rule = browserActionBlockRule('download', destination, c.policy || {});
  await cancelDownload(item.id);
  return reportBlockedDownload(destination, rule);
}

// ---- Local file-intent handoff -----------------------------------------------
// When the content script blocks an upload it cannot inspect locally, hand the
// file's NAME and SIZE (never bytes) to the endpoint agent's native messaging
// host so the real file gets scanned on the device. Strictly best-effort: a
// missing host, missing permission, or slow reply never affects enforcement -
// the upload is already blocked before this runs.
const FILE_INTENT_HOST = 'com.redactwall.file_intent';

function boundedFileIntent(payload = {}) {
  const fileName = String(payload.fileName || '').slice(0, 255);
  const sizeBytes = Math.floor(Number(payload.sizeBytes));
  if (!fileName || !Number.isFinite(sizeBytes) || sizeBytes <= 0) return null;
  return { fileName, sizeBytes };
}

async function relayFileIntent(payload, senderUrl) {
  if (!chrome.runtime || typeof chrome.runtime.sendNativeMessage !== 'function') {
    return { ok: false, reason: 'unsupported' };
  }
  const c = await cfg();
  if (!c.enabled) return { ok: false, reason: 'disabled' };
  const bounded = boundedFileIntent(payload);
  if (!bounded) return { ok: false, reason: 'invalid_intent' };
  const who = await identity();
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(FILE_INTENT_HOST, {
        type: 'upload_intent',
        ...bounded,
        destination: normalizeDestinationHost(senderUrl) || 'unknown',
        user: who.user,
      }, (reply) => {
        void (chrome.runtime && chrome.runtime.lastError); // host not installed -> silent
        resolve({ ok: true, reply: reply || null });
      });
    } catch (e) {
      resolve({ ok: false, reason: 'native_error' });
    }
  });
}

chrome.runtime.onInstalled.addListener(() => runAsync(refreshPolicyAndHealth));
chrome.runtime.onStartup.addListener(() => runAsync(refreshPolicyAndHealth));
chrome.downloads?.onCreated?.addListener((item) => runAsync(() => handleDownloadCreated(item)));
chrome.alarms?.create('refreshPolicy', { periodInMinutes: 15 });
chrome.alarms?.create('installHeartbeat', { periodInMinutes: 60 });
chrome.alarms?.onAlarm.addListener((a) => {
  if (a.name === 'refreshPolicy') runAsync(refreshPolicy);
  if (a.name === 'installHeartbeat') runAsync(reportInstallHealth);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'fileIntent') {
    runAsync(() => relayFileIntent(msg.payload || {}, sender && sender.url));
    sendResponse && sendResponse({ queued: true });
    return false;
  }
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
            clientAccount: msg.payload.clientAccount,
            clientOutcome: msg.payload.outcome,
            note: msg.payload.note,
          }),
        }, c.requestTimeoutMs);
        sendResponse && sendResponse(r.ok ? r.body : failClosed('gate_' + r.reason));
      } catch (e) { sendResponse && sendResponse(failClosed('gate_unreachable')); }
    });
    return true;
  }
});

// ---- Shadow-AI discovery -----------------------------------------------------
// Flag visits to AI tools that policy does NOT govern (so an examiner sees the
// unmonitored paths, not just the guarded ones). Throttled to once/host/12h.
const SHADOW_TTL_MS = 12 * 3600 * 1000;
const SHADOW_SEEN_KEY = 'shadowSeen';

// The throttle map must survive MV3 service-worker suspension (~30s idle), or
// every wake re-reports the same host. chrome.storage.session persists for the
// browser session across worker restarts; fall back to local where it is absent.
function shadowThrottleStore() {
  return (chrome.storage && chrome.storage.session) || chrome.storage.local;
}

async function shadowSeenRecently(host, now) {
  const store = shadowThrottleStore();
  const seen = (await store.get(SHADOW_SEEN_KEY))[SHADOW_SEEN_KEY] || {};
  if (seen[host] && now - seen[host] < SHADOW_TTL_MS) return true;
  seen[host] = now;
  for (const h of Object.keys(seen)) {
    if (now - seen[h] >= SHADOW_TTL_MS) delete seen[h];
  }
  await store.set({ [SHADOW_SEEN_KEY]: seen });
  return false;
}

chrome.tabs?.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== 'complete' || !tab || !tab.url || !self.PSAdapters) return;
  let host; try { host = new URL(tab.url).hostname; } catch (e) { return; }
  const c = await cfg();
  const governed = [
    ...((c.policy && c.policy.governedDestinations) || []),
    ...((c.policy && c.policy.allowedDestinations) || []),
    ...((c.policy && c.policy.blockedDestinations) || []),
    ...((c.policy && c.policy.blockedFileUploadDestinations) || []),
    ...((c.policy && c.policy.blockedBrowserActions) || []).flatMap((rule) => (rule && rule.destinations) || []),
  ];
  if (!self.PSAdapters.isAiHost(host) || self.PSAdapters.isGoverned(host, governed)) return;
  const now = Date.now();
  if (await shadowSeenRecently(host, now)) return;
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
