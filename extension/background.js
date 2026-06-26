/* PromptSentinel background service worker.
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
  ingestKey: 'dev-ingest-key',
  enabled: true,
  policy: { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25, governedDestinations: [], alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'SECRET_KEY', 'PRIVATE_KEY'] },
};

async function cfg() {
  const c = await chrome.storage.local.get(Object.keys(DEFAULTS));
  return { ...DEFAULTS, ...c };
}

// Identity precedence: MDM-managed (enterprise force-install) > local override >
// an explicit "unmanaged" marker (so unattributed events are visible as a gap,
// never silently mislabeled as a real person).
async function identity() {
  let managed = {};
  try { managed = (await chrome.storage.managed.get(['user', 'email', 'orgId'])) || {}; } catch (e) {}
  const local = await chrome.storage.local.get(['user', 'email', 'orgId']);
  const user = managed.email || managed.user || local.email || local.user || 'unattributed@unmanaged';
  const orgId = managed.orgId || local.orgId || null;
  return { user, orgId, managed: !!(managed.email || managed.user) };
}

async function serverCfg() {
  let managed = {};
  try { managed = (await chrome.storage.managed.get(['serverUrl', 'ingestKey'])) || {}; } catch (e) {}
  const c = await cfg();
  return { serverUrl: managed.serverUrl || c.serverUrl, ingestKey: managed.ingestKey || c.ingestKey, enabled: c.enabled };
}

async function refreshPolicy() {
  const c = await serverCfg();
  if (!c.enabled) return;
  try {
    const r = await fetch(c.serverUrl + '/api/v1/policy', { headers: { 'x-api-key': c.ingestKey } });
    if (r.ok) {
      const p = await r.json();
      await chrome.storage.local.set({ policy: { ...DEFAULTS.policy, ...p } });
    }
  } catch (e) { /* offline → keep cached/default policy (fail-safe to block) */ }
}

chrome.runtime.onInstalled.addListener(refreshPolicy);
chrome.runtime.onStartup.addListener(refreshPolicy);
chrome.alarms?.create('refreshPolicy', { periodInMinutes: 15 });
chrome.alarms?.onAlarm.addListener((a) => { if (a.name === 'refreshPolicy') refreshPolicy(); });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'getConfig') {
    Promise.all([cfg(), identity()]).then(([c, who]) => sendResponse({ policy: c.policy, enabled: c.enabled, user: who.user, orgId: who.orgId }));
    return true;
  }
  if (msg.type === 'report') {
    Promise.all([serverCfg(), identity()]).then(async ([c, who]) => {
      if (!c.enabled) return;
      try {
        const r = await fetch(c.serverUrl + '/api/v1/gate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-api-key': c.ingestKey },
          body: JSON.stringify({
            prompt: msg.payload.prompt,
            user: who.user,
            orgId: who.orgId,
            destination: msg.payload.destination,
            channel: msg.payload.channel,
            source: msg.payload.source,
            clientCategories: msg.payload.categories,
            clientFindings: msg.payload.clientFindings,
            clientEntityCounts: msg.payload.clientEntityCounts,
            clientRiskScore: msg.payload.clientRiskScore,
            clientMaxSeverity: msg.payload.clientMaxSeverity,
            clientMaxSeverityLabel: msg.payload.clientMaxSeverityLabel,
            clientPreRedacted: msg.payload.clientPreRedacted,
            clientOutcome: msg.payload.outcome,
            note: msg.payload.note,
          }),
        });
        const j = await r.json().catch(() => ({}));
        sendResponse && sendResponse(j);
      } catch (e) { /* swallow; UX already enforced locally */ }
    });
    return true;
  }
  if (msg.type === 'scanFile') {
    Promise.all([serverCfg(), identity()]).then(async ([c, who]) => {
      if (!c.enabled) return;
      try {
        const r = await fetch(c.serverUrl + '/api/v1/scan-file', {
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
          }),
        });
        sendResponse && sendResponse(await r.json().catch(() => ({})));
      } catch (e) { sendResponse && sendResponse(null); }
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
  const governed = (c.policy && c.policy.governedDestinations) || [];
  if (!self.PSAdapters.isAiHost(host) || self.PSAdapters.isGoverned(host, governed)) return;
  const now = Date.now();
  if (seenShadow[host] && now - seenShadow[host] < 12 * 3600 * 1000) return;
  seenShadow[host] = now;
  const [sc, who] = await Promise.all([serverCfg(), identity()]);
  if (!sc.enabled) return;
  try {
    await fetch(sc.serverUrl + '/api/v1/gate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': sc.ingestKey },
      body: JSON.stringify({ prompt: '[shadow-AI] visit to ungoverned AI tool: ' + host, user: who.user, orgId: who.orgId, destination: host, channel: 'shadow_ai', source: 'browser_extension', clientOutcome: 'shadow_ai' }),
    });
  } catch (e) {}
});
