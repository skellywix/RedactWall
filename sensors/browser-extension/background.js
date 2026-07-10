
try { importScripts('lib/browser-api.js'); } catch (e) {  }
try { importScripts('lib/adapters.js'); } catch (e) {  }
try { importScripts('lib/policy-bundle.js'); } catch (e) {  }
try { importScripts('lib/destination-coverage.js'); } catch (e) {  }

const DEFAULTS = {
  serverUrl: 'http://localhost:4000',
  ingestKey: '',
  policyPublicKey: '',
  requestTimeoutMs: 10000,
  enabled: true,
  policyBundle: null,
  policy: { enforcementMode: 'block', blockMinSeverity: 2, blockRiskScore: 25, governedDestinations: [], allowedDestinations: [], blockedDestinations: [], blockedFileUploadDestinations: [], blockedBrowserActions: [], blockUnapprovedAiDestinations: true, alwaysBlock: ['US_SSN', 'CREDIT_CARD', 'BANK_ACCOUNT', 'ROUTING_NUMBER', 'IBAN', 'US_PASSPORT', 'US_ITIN', 'US_NPI', 'MEMBER_ID', 'LOAN_NUMBER', 'MEDICAL_RECORD_NUMBER', 'HEALTH_INSURANCE_ID', 'UK_NINO', 'UK_NHS_NUMBER', 'CANADA_SIN', 'AUSTRALIA_TFN', 'INDIA_AADHAAR', 'SECRET_KEY', 'PRIVATE_KEY', 'CANARY_TOKEN', 'EXACT_MATCH'] },
};
const MANAGED_KEYS = ['user', 'email', 'orgId', 'serverUrl', 'ingestKey', 'policyPublicKey', 'enabled'];
const IDENTITY_KEYS = ['user', 'email', 'orgId'];
const INSTALL_HEARTBEAT_DESTINATION = 'browser-install';
const MAX_CONTROL_PLANE_RESPONSE_BYTES = 512 * 1024;

function mandatoryAlwaysBlock(value) {
  const configured = Array.isArray(value) ? value : [];
  return [...new Set([...DEFAULTS.policy.alwaysBlock, ...configured]
    .filter((type) => typeof type === 'string' && type.trim())
    .map((type) => type.trim().toUpperCase()))];
}

function normalizeSensorPolicy(value = {}) {
  return { ...DEFAULTS.policy, ...(value || {}), alwaysBlock: mandatoryAlwaysBlock(value && value.alwaysBlock) };
}

async function cfg() {
  const [c, managed] = await Promise.all([
    chrome.storage.local.get(Object.keys(DEFAULTS)),
    managedConfig(),
  ]);
  const enabled = resolveEnabled(managed, c.enabled);
  const policyPublicKey = configuredPolicyPublicKey(managed, c);
  const trusted = await trustedCachedPolicy(c.policyBundle, policyPublicKey);
  return {
    ...DEFAULTS,
    ...c,
    enabled: enabled.value,
    enabledLocked: enabled.locked,
    policy: normalizeSensorPolicy(trusted.ok ? trusted.bundle.policy : DEFAULTS.policy),
    policyTrusted: trusted.ok,
    policyExpiresAt: trusted.ok ? trusted.bundle.expiresAt : null,
    policyPublicKey,
  };
}

async function trustedCachedPolicy(bundle, publicKey, options) {
  const verifier = self.RedactWallPolicyTrust;
  if (!verifier || typeof verifier.verifyBundle !== 'function') return { ok: false, reason: 'verifier_unavailable' };
  const result = await verifier.verifyBundle(bundle, publicKey, options);
  return result.ok ? { ok: true, bundle } : result;
}

function policySequence(previous, next) {
  if (!previous) return { ok: true };
  const priorIssued = Date.parse(previous.issuedAt);
  const nextIssued = Date.parse(next.issuedAt);
  if (priorIssued > nextIssued) return { ok: false, reason: 'rollback_detected' };
  if (priorIssued === nextIssued && previous.signature !== next.signature) {
    return { ok: false, reason: 'policy_sequence_conflict' };
  }
  return { ok: true };
}

async function managedConfig() {
  try { return (await chrome.storage.managed.get(MANAGED_KEYS)) || {}; } catch (e) { return {}; }
}

function hasManagedConfiguration(managed = {}) {
  return MANAGED_KEYS.some((key) => Object.prototype.hasOwnProperty.call(managed, key)
    && managed[key] !== undefined && managed[key] !== null && managed[key] !== '');
}

function resolveEnabled(managed = {}, localEnabled = DEFAULTS.enabled) {
  const locked = hasManagedConfiguration(managed);
  if (typeof managed.enabled === 'boolean') return { value: managed.enabled, locked: true };
  if (locked) return { value: true, locked: true };
  return { value: localEnabled !== false, locked: false };
}

function resolveIdentity(managed = {}, local = {}) {
  const user = managed.email || managed.user || local.email || local.user || 'unattributed@unmanaged';
  const orgId = managed.orgId || local.orgId || null;
  return { user, orgId, managed: !!(managed.email || managed.user) };
}
async function identity() {
  const [managed, local] = await Promise.all([managedConfig(), chrome.storage.local.get(IDENTITY_KEYS)]);
  return resolveIdentity(managed, local);
}

async function serverCfg() {
  const [managed, c] = await Promise.all([managedConfig(), cfg()]);
  return {
    serverUrl: managed.serverUrl || c.serverUrl,
    ingestKey: managed.ingestKey || c.ingestKey,
    enabled: c.enabled,
    enabledLocked: c.enabledLocked,
    requestTimeoutMs: c.requestTimeoutMs,
    policyPublicKey: c.policyPublicKey || '',
  };
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

  // Remote planes require HTTPS.
  if (!validServerOrigin(c.serverUrl)) return 'invalid_server_url';
  return null;
}

function isLoopbackHost(host) {
  const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  // Reject loopback lookalikes.
  if (/^[a-z0-9-]+\.localhost$/.test(h)) return true;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const o = m.slice(1).map(Number);
    if (o.every((n) => n <= 255) && o[0] === 127) return true;
  }
  return false;
}
function validServerOrigin(value) {
  try {
    const url = new URL(String(value || ''));
    if (url.username || url.password) return null;
    if (url.protocol === 'https:') return `${url.protocol}//${url.host}`;
    if (url.protocol === 'http:' && isLoopbackHost(url.hostname)) return `${url.protocol}//${url.host}`;
    return null;
  } catch (e) {
    return null;
  }
}

function configuredPolicyPublicKey(managed = {}, local = {}) {
  const managedPin = String(managed.policyPublicKey || '').trim();
  if (managedPin) return managedPin;
  const localPin = String(local.policyPublicKey || '').trim();
  if (!localPin) return '';
  const origin = validServerOrigin(local.serverUrl);
  if (!origin) return '';
  try { return isLoopbackHost(new URL(origin).hostname) ? localPin : ''; } catch (_) { return ''; }
}

function serverPermissionPattern(value) {
  const origin = validServerOrigin(value);
  return origin ? origin + '/*' : null;
}

async function hasServerPermission(value) {
  const pattern = serverPermissionPattern(value);
  if (!pattern || !chrome.permissions || !chrome.permissions.contains) return false;
  try { return (await chrome.permissions.contains({ origins: [pattern] })) === true; } catch (_) { return false; }
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

function destinationCoverageApi() {
  const api = self.RedactWallDestinationCoverage;
  if (!api || typeof api.buildCoverageModel !== 'function') throw new Error('destination_coverage_unavailable');
  return api;
}

function dynamicScriptDefinition(matches, manifest = manifestInfo()) {
  const template = (manifest.content_scripts || []).find((script) => (
    Array.isArray(script.js) && script.js.includes('lib/detect.js') && script.js.includes('content.js')
  ));
  if (!template) throw new Error('content_script_template_unavailable');
  return {
    id: destinationCoverageApi().DYNAMIC_SCRIPT_ID,
    matches: [...matches].sort(),
    js: [...template.js],
    css: [...(template.css || [])],
    allFrames: false,
    runAt: template.run_at || 'document_idle',
    persistAcrossSessions: true,
  };
}

async function replaceDestinationBlocks(items) {
  const coverage = destinationCoverageApi();
  const dnr = chrome.declarativeNetRequest;
  if (!dnr || !dnr.getDynamicRules || !dnr.updateDynamicRules) throw new Error('destination_blocking_unavailable');
  const current = await dnr.getDynamicRules();
  const removeRuleIds = (current || []).filter(coverage.ownsBlockingRule).map((rule) => rule.id);
  await dnr.updateDynamicRules({ removeRuleIds, addRules: coverage.blockingRules(items) });
}

async function setDynamicDestinationScript(origins) {
  const scripting = chrome.scripting;
  if (!scripting || !scripting.getRegisteredContentScripts) throw new Error('dynamic_scripting_unavailable');
  const coverage = destinationCoverageApi();
  const scripts = await scripting.getRegisteredContentScripts();
  const present = (scripts || []).some((script) => script.id === coverage.DYNAMIC_SCRIPT_ID);
  if (!origins.length) {
    if (present) await scripting.unregisterContentScripts({ ids: [coverage.DYNAMIC_SCRIPT_ID] });
    return;
  }
  const definition = dynamicScriptDefinition(origins);
  if (present) await scripting.updateContentScripts([definition]);
  else await scripting.registerContentScripts([definition]);
}

async function registeredDestinationOrigins() {
  const scripting = chrome.scripting;
  if (!scripting || !scripting.getRegisteredContentScripts) throw new Error('dynamic_scripting_unavailable');
  const scripts = await scripting.getRegisteredContentScripts();
  const coverage = destinationCoverageApi();
  const current = (scripts || []).find((script) => script.id === coverage.DYNAMIC_SCRIPT_ID);
  return new Set(Array.isArray(current && current.matches) ? current.matches : []);
}

async function grantedDestinationItems(items) {
  const granted = [];
  const missing = [];
  for (const item of items) {
    let allowed = false;
    try { allowed = await chrome.permissions.contains({ origins: [item.origin] }); } catch (_) {}
    (allowed ? granted : missing).push(item);
  }
  return { granted, missing };
}

async function ejectUncoveredTabs(items) {
  if (!items.length) return 0;
  const coverage = destinationCoverageApi();
  if (!chrome.tabs || !chrome.tabs.query || !chrome.tabs.update || !chrome.runtime.getURL) {
    throw new Error('tab_ejection_unavailable');
  }
  const tabs = await chrome.tabs.query({});
  const blockedPage = chrome.runtime.getURL('coverage-required.html');
  const affected = (tabs || []).filter((tab) => items.some((item) => coverage.tabMatchesItem(tab.url, item)));
  for (const tab of affected) await chrome.tabs.update(tab.id, { url: blockedPage });
  return affected.length;
}

function destinationCoverageState(model, missing, blocked, reason = null) {
  return {
    ready: missing.length === 0 && model.unsupported.length === 0 && !reason,
    reason,
    requiredOrigins: model.dynamic.map((item) => item.origin),
    missingOrigins: missing.map((item) => item.origin),
    blockedOrigins: blocked.map((item) => item.origin || item.host || item.type),
    unsupported: model.unsupported.map((item) => item.host || item.type),
    staticHosts: model.staticHosts,
  };
}

async function saveDestinationCoverageState(state) {
  await chrome.storage.local.set({ destinationCoverage: state });
  return state;
}

let destinationCoverageMutation = Promise.resolve();

function serializeDestinationCoverage(mutate) {
  const run = destinationCoverageMutation.then(mutate, mutate);
  destinationCoverageMutation = run.catch(() => {});
  return run;
}

function conservativeCoverageItems(policies) {
  const coverage = destinationCoverageApi();
  const values = policies.flatMap((policy) => coverage.policyDestinationValues(policy || {}));
  const model = coverage.buildCoverageModel({ governedDestinations: values }, manifestInfo());
  return [...model.dynamic, ...model.unsupported];
}

async function uncoveredCoverageItems(items) {
  const dynamic = items.filter((item) => item && item.origin);
  const registered = await registeredDestinationOrigins();
  const permissions = await grantedDestinationItems(dynamic);
  const granted = new Set(permissions.granted.map((item) => item.origin));
  return items.filter((item) => !item.origin || !registered.has(item.origin) || !granted.has(item.origin));
}

async function syncDestinationCoverageLocked(policy = DEFAULTS.policy) {
  const model = destinationCoverageApi().buildCoverageModel(policy, manifestInfo());
  const allBlockable = [...model.dynamic, ...model.unsupported];
  await replaceDestinationBlocks(allBlockable);
  const permissions = await grantedDestinationItems(model.dynamic);
  try {
    const previousOrigins = await registeredDestinationOrigins();
    await ejectUncoveredTabs(permissions.granted.filter((item) => !previousOrigins.has(item.origin)));
    await setDynamicDestinationScript(permissions.granted.map((item) => item.origin));
  } catch (_) {
    await ejectUncoveredTabs(allBlockable);
    return saveDestinationCoverageState(destinationCoverageState(model, model.dynamic, allBlockable, 'registration_failed'));
  }
  const finalBlocks = [...permissions.missing, ...model.unsupported];
  try {
    await replaceDestinationBlocks(finalBlocks);
  } catch (_) {
    await ejectUncoveredTabs(allBlockable);
    return saveDestinationCoverageState(destinationCoverageState(model, model.dynamic, allBlockable, 'block_finalization_failed'));
  }
  await ejectUncoveredTabs(finalBlocks);
  return saveDestinationCoverageState(destinationCoverageState(model, permissions.missing, finalBlocks));
}

function syncDestinationCoverage(policy = DEFAULTS.policy) {
  return serializeDestinationCoverage(() => syncDestinationCoverageLocked(policy));
}

function syncCurrentDestinationCoverage() {
  return serializeDestinationCoverage(async () => {
    const current = await cfg();
    return syncDestinationCoverageLocked(current.policy || DEFAULTS.policy);
  });
}

function buildInstallChecks({ config = DEFAULTS, server = {}, identity: who = {}, managed = {}, manifest = manifestInfo(), serverAccess = false, destinationCoverage = { ready: true } } = {}) {
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
    installCheck(
      'custom_destination_coverage',
      destinationCoverage.ready === true,
      destinationCoverage.ready
        ? 'configured browser destinations protected'
        : `${(destinationCoverage.missingOrigins || []).length} permission grants pending; ${(destinationCoverage.unsupported || []).length} require proxy enforcement`,
    ),
    installCheck('protection_enabled', config.enabled !== false, config.enabled === false ? 'disabled locally' : 'enabled'),
    installCheck('server_url', !!origin, origin || 'missing or invalid'),
    installCheck('server_host_permission', serverAccess, serverAccess ? 'granted' : 'grant exact control-plane origin'),
    installCheck('ingest_key', !!(server.ingestKey && String(server.ingestKey).length >= 16), 'configured'),
    installCheck(
      'policy_public_key_pin',
      !!(managed.policyPublicKey || config.policyPublicKey),
      managed.policyPublicKey ? 'managed Ed25519 pin present'
        : config.policyPublicKey ? 'loopback development Ed25519 pin present' : 'missing managed Ed25519 pin',
    ),
    installCheck('managed_config', hasManagedServer, hasManagedServer ? 'managed server config present' : 'local or missing server config'),
    installCheck('managed_identity', who.managed === true && hasManagedIdentity, who.managed === true ? 'managed identity present' : 'unmanaged identity'),
    installCheck('org_id', !!(who.orgId && hasManagedTenant), who.orgId ? 'configured' : 'missing'),
    installCheck('policy_cache', config.policyTrusted === true, config.policyTrusted ? 'verified signed policy available' : 'no fresh verified signed policy'),
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

function responseReadError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

async function readBoundedJsonResponse(response, signal, maxBytes = MAX_CONTROL_PLANE_RESPONSE_BYTES) {
  const declared = String((response.headers && response.headers.get('content-length')) || '').trim();
  if (/^\d+$/.test(declared) && Number(declared) > maxBytes) {
    if (response.body && typeof response.body.cancel === 'function') await response.body.cancel().catch(() => {});
    throw responseReadError('response_too_large', 'control-plane response is too large');
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    throw responseReadError('invalid_json', 'control-plane response is not streamable');
  }
  const reader = response.body.getReader();
  let abortHandler;
  const aborted = new Promise((resolve, reject) => {
    abortHandler = () => {
      Promise.resolve(reader.cancel()).catch(() => {});
      const error = new Error('control-plane response timed out');
      error.name = 'AbortError';
      reject(error);
    };
    if (signal.aborted) abortHandler();
    else signal.addEventListener('abort', abortHandler, { once: true });
  });
  const consume = (async () => {
    const chunks = [];
    let total = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value || []);
      total += chunk.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw responseReadError('response_too_large', 'control-plane response is too large');
      }
      chunks.push(chunk);
    }
    const joined = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      const text = new TextDecoder().decode(joined);
      return text ? JSON.parse(text) : null;
    } catch (_) {
      throw responseReadError('invalid_json', 'control-plane response is not valid JSON');
    }
  })();
  try {
    return await Promise.race([consume, aborted]);
  } finally {
    signal.removeEventListener('abort', abortHandler);
    try { reader.releaseLock(); } catch (_) {  }
  }
}

async function fetchJsonWithTimeout(url, options, timeoutMs) {
  if (!(await hasServerPermission(url))) return { ok: false, reason: 'missing_host_permission' };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs(timeoutMs));
  try {
    const r = await fetch(url, { ...(options || {}), signal: controller.signal, redirect: 'error' });
    let body;
    try {
      body = await readBoundedJsonResponse(r, controller.signal);
    } catch (error) {
      if (error && error.name === 'AbortError') throw error;
      return { ok: false, reason: (error && error.code) || 'invalid_json' };
    }
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
  const missing = missingServerConfigReason(server);
  const serverAccess = !missing && await hasServerPermission(server.serverUrl);
  let destinationCoverage;
  try { destinationCoverage = await syncCurrentDestinationCoverage(); }
  catch (_) { destinationCoverage = { ready: false, reason: 'coverage_sync_failed', missingOrigins: [], unsupported: ['runtime'] }; }
  const checks = buildInstallChecks({ config, server, identity: who, managed, serverAccess, destinationCoverage });
  if (!server.enabled) return { ok: false, reason: 'disabled', checks };
  if (missing) return { ok: false, reason: missing, checks };
  if (!serverAccess) return { ok: false, reason: 'missing_host_permission', checks };
  const result = await fetchJsonWithTimeout(String(server.serverUrl).replace(/\/+$/, '') + '/api/v1/heartbeat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': server.ingestKey },
    body: JSON.stringify(buildHeartbeatBody(checks, who)),
  }, server.requestTimeoutMs);
  if (result.ok && result.body && result.body.companions) {
    await chrome.storage.local.set({ fleetCompanions: { at: Date.now(), companions: result.body.companions } });
  }
  return result;
}

function policyPublicationFailure() {
  const error = new Error('verified browser policy publication could not be confirmed');
  error.code = 'policy_publication_failed';
  return error;
}

function publishPolicyWithCoverage(bundle, publicKey) {
  return serializeDestinationCoverage(async () => {
    const cached = (await chrome.storage.local.get(['policyBundle'])).policyBundle;
    let previousPolicy = DEFAULTS.policy;
    if (cached !== undefined && cached !== null) {
      const highWater = await trustedCachedPolicy(cached, publicKey, { allowExpired: true });
      if (!highWater.ok || !policySequence(highWater.bundle, bundle).ok) return null;
      previousPolicy = normalizeSensorPolicy(highWater.bundle.policy);
    }
    const nextPolicy = normalizeSensorPolicy(bundle.policy);
    const conservative = conservativeCoverageItems([previousPolicy, nextPolicy]);
    await replaceDestinationBlocks(conservative);
    await ejectUncoveredTabs(await uncoveredCoverageItems(conservative));
    await chrome.storage.local.set({ policyBundle: bundle, policy: nextPolicy, policyExpiresAt: bundle.expiresAt });
    const published = (await chrome.storage.local.get(['policyBundle'])).policyBundle;
    const accepted = await trustedCachedPolicy(published, publicKey);
    if (!accepted.ok || published.signature !== bundle.signature) throw policyPublicationFailure();
    return syncDestinationCoverageLocked(nextPolicy);
  });
}

async function refreshPolicy() {
  const c = await serverCfg();
  if (!c.enabled) return;
  if (missingServerConfigReason(c) || !c.policyPublicKey) return;
  try {
    const r = await fetchJsonWithTimeout(c.serverUrl + '/api/v1/policy/bundle', { headers: { 'x-api-key': c.ingestKey } }, c.requestTimeoutMs);
    if (r.ok) {
      const verified = await trustedCachedPolicy(r.body, c.policyPublicKey);
      if (!verified.ok) return;
      await publishPolicyWithCoverage(r.body, c.policyPublicKey);
    }
  } catch (e) { /* offline → keep cached/default policy (fail-safe to block) */ }
}

async function refreshPolicyAndHealth() {
  await refreshPolicy();
  await reportInstallHealth();
}

async function pollApprovalStatus(id, releaseToken) {
  const queryId = String(id || '').trim();
  const token = String(releaseToken || '').trim();
  if (!queryId || queryId.length > 200 || !token || token.length > 512) return failClosed('invalid_approval_request');
  const c = await serverCfg();
  if (!c.enabled) return failClosed('disabled');
  const missing = missingServerConfigReason(c);
  if (missing) return failClosed(missing);
  const result = await fetchJsonWithTimeout(
    c.serverUrl + '/api/v1/status/' + encodeURIComponent(queryId),
    { headers: { 'x-api-key': c.ingestKey, 'x-release-token': token } },
    c.requestTimeoutMs,
  );
  return result.ok ? result.body : failClosed('status_' + result.reason);
}

async function resolveJustification(id, releaseToken, outcome, note) {
  const queryId = String(id || '').trim();
  const token = String(releaseToken || '').trim();
  const resolution = String(outcome || '');
  const reason = String(note || '');
  const validOutcome = resolution === 'justified' || resolution === 'blocked_by_user';
  const validReason = resolution !== 'justified' || reason.trim().length >= 4;
  if (!queryId || queryId.length > 200 || !token || token.length > 512
      || !validOutcome || !validReason || reason.length > 2000) {
    return failClosed('invalid_justification_request');
  }
  const c = await serverCfg();
  if (!c.enabled) return failClosed('disabled');
  const missing = missingServerConfigReason(c);
  if (missing) return failClosed(missing);
  const result = await fetchJsonWithTimeout(
    c.serverUrl + '/api/v1/justify/' + encodeURIComponent(queryId),
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': c.ingestKey, 'x-release-token': token },
      body: JSON.stringify({ outcome: resolution, note: reason }),
    },
    c.requestTimeoutMs,
  );
  return result.ok ? result.body : failClosed('justify_' + result.reason);
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
  if (!c.policyTrusted) {
    await cancelDownload(item.id);
    return { ok: false, reason: 'policy_unavailable' };
  }
  const destination = downloadDestinationForPolicy(item, c.policy || {});
  if (!destination) return { ok: false, reason: 'not_configured' };
  const rule = browserActionBlockRule('download', destination, c.policy || {});
  await cancelDownload(item.id);
  return reportBlockedDownload(destination, rule);
}

const REHYDRATION_PAGE = 'rehydrate.html';
const REHYDRATION_TTL_MS = 2 * 60 * 1000;
const MAX_REHYDRATION_SESSIONS = 100;
const REHYDRATION_TOKEN_RE = /^\[\[[A-Z][A-Z0-9_]*_\d+\]\]$/;
const rehydrationSessions = new Map();

function trustedContentSender(sender, claimedSite, expectedTabId = null) {
  if (!sender || sender.id !== chrome.runtime.id || sender.frameId !== 0 || typeof sender.url !== 'string') return false;
  if (!sender.tab || !Number.isInteger(sender.tab.id)) return false;
  if (expectedTabId !== null && sender.tab.id !== expectedTabId) return false;
  try {
    const source = new URL(sender.url);
    return source.protocol === 'https:'
      && normalizeDestinationHost(source.hostname) === normalizeDestinationHost(claimedSite);
  } catch (_) {
    return false;
  }
}

function trustedRehydrationPageSender(sender, expectedChannel) {
  if (!sender || sender.id !== chrome.runtime.id || typeof sender.url !== 'string') return false;
  try {
    const actual = new URL(sender.url);
    const expected = new URL(chrome.runtime.getURL(REHYDRATION_PAGE));
    const expectedHash = expectedChannel ? '#channel=' + encodeURIComponent(expectedChannel) : '';
    return actual.protocol === expected.protocol
      && actual.host === expected.host
      && actual.pathname === expected.pathname
      && !actual.search
      && (!actual.hash || actual.hash === expectedHash);
  } catch (_) {
    return false;
  }
}

function boundedRehydrationEntries(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) return null;
  const entries = [];
  const seen = new Set();
  const encoder = new TextEncoder();
  let totalBytes = 0;
  for (const item of value) {
    if (!item || typeof item.token !== 'string' || !REHYDRATION_TOKEN_RE.test(item.token)) return null;
    if (typeof item.value !== 'string' || !item.value || item.value.length > 8192 || seen.has(item.token)) return null;
    totalBytes += encoder.encode(item.token).byteLength + encoder.encode(item.value).byteLength;
    if (totalBytes > 64 * 1024) return null;
    seen.add(item.token);
    entries.push({ token: item.token, value: item.value });
  }
  return entries;
}

function newRehydrationChannel() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function removeRehydrationSession(channel) {
  const session = rehydrationSessions.get(channel);
  if (!session) return false;
  rehydrationSessions.delete(channel);
  for (const entry of session.entries) { entry.token = ''; entry.value = ''; }
  session.entries.length = 0;
  return true;
}

function cleanupExpiredRehydrations(now = Date.now()) {
  for (const [channel, session] of rehydrationSessions) {
    if (session.expiresAt <= now) removeRehydrationSession(channel);
  }
}

function storeRehydrationSession(msg, sender) {
  cleanupExpiredRehydrations();
  const site = normalizeDestinationHost(msg && msg.site);
  if (!site || !trustedContentSender(sender, site)) return { ok: false, reason: 'invalid_source' };
  const entries = boundedRehydrationEntries(msg && msg.entries);
  if (!entries) return { ok: false, reason: 'invalid_entries' };
  for (const [existingChannel, session] of rehydrationSessions) {
    if (session.sourceTabId === sender.tab.id) removeRehydrationSession(existingChannel);
  }
  if (rehydrationSessions.size >= MAX_REHYDRATION_SESSIONS) {
    for (const entry of entries) { entry.token = ''; entry.value = ''; }
    entries.length = 0;
    return { ok: false, reason: 'capacity' };
  }
  let channel;
  do { channel = newRehydrationChannel(); } while (rehydrationSessions.has(channel));
  const expiresAt = Date.now() + REHYDRATION_TTL_MS;
  rehydrationSessions.set(channel, {
    site, entries, expiresAt, sourceTabId: sender.tab.id, tabId: null, opening: false,
  });
  return { ok: true, channel, expiresAt };
}

async function openRehydrationSession(msg, sender) {
  cleanupExpiredRehydrations();
  const channel = String((msg && msg.channel) || '');
  const session = rehydrationSessions.get(channel);
  if (!session || !trustedContentSender(sender, msg && msg.site, session.sourceTabId)
      || session.site !== normalizeDestinationHost(msg && msg.site)) {
    return { ok: false, reason: 'invalid_channel' };
  }
  if (session.tabId !== null || session.opening) return { ok: false, reason: 'already_open' };
  session.opening = true;
  try {
    const tab = await chrome.tabs.create({
      active: true,
      url: chrome.runtime.getURL(REHYDRATION_PAGE) + '#channel=' + encodeURIComponent(channel),
    });
    if (!tab || !Number.isInteger(tab.id)) return { ok: false, reason: 'open_failed' };
    if (rehydrationSessions.get(channel) !== session) {
      runAsync(() => chrome.tabs.remove(tab.id));
      return { ok: false, reason: 'invalid_channel' };
    }
    session.tabId = tab.id;
    return { ok: true };
  } catch (_) {
    return { ok: false, reason: 'open_failed' };
  } finally {
    if (rehydrationSessions.get(channel) === session) session.opening = false;
  }
}

function revealRehydrationSession(msg, sender) {
  cleanupExpiredRehydrations();
  const channel = String((msg && msg.channel) || '');
  const session = rehydrationSessions.get(channel);
  if (!session || !trustedRehydrationPageSender(sender, channel) || !sender.tab || sender.tab.id !== session.tabId) {
    return { ok: false, reason: 'invalid_channel' };
  }
  const entries = session.entries.map((entry) => ({ token: entry.token, value: entry.value }));
  removeRehydrationSession(channel);
  return { ok: true, entries };
}

function discardRehydrationSession(msg, sender) {
  cleanupExpiredRehydrations();
  const channel = String((msg && msg.channel) || '');
  const contentSender = trustedContentSender(sender, msg && msg.site);
  const pageSender = trustedRehydrationPageSender(sender, channel) && sender.tab && Number.isInteger(sender.tab.id);
  if (!contentSender && !pageSender) return { ok: false, reason: 'invalid_source' };
  const session = rehydrationSessions.get(channel);
  if (!session) return { ok: true };
  const contentOwner = contentSender && sender.tab.id === session.sourceTabId
    && session.site === normalizeDestinationHost(msg && msg.site);
  const pageOwner = pageSender && sender.tab.id === session.tabId;
  if (!contentOwner && !pageOwner) return { ok: false, reason: 'invalid_channel' };
  removeRehydrationSession(channel);
  return { ok: true };
}

function discardRehydrationForTab(tabId) {
  for (const [channel, session] of rehydrationSessions) {
    if (session.tabId === tabId || session.sourceTabId === tabId) removeRehydrationSession(channel);
  }
}

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
chrome.tabs?.onRemoved?.addListener((tabId) => discardRehydrationForTab(tabId));
chrome.permissions?.onAdded?.addListener(() => runAsync(syncCurrentDestinationCoverage));
chrome.permissions?.onRemoved?.addListener(() => runAsync(syncCurrentDestinationCoverage));
chrome.storage?.onChanged?.addListener((changes, areaName) => {
  if (areaName === 'local' && (changes.policyBundle || changes.policy)) runAsync(syncCurrentDestinationCoverage);
});
chrome.alarms?.create('refreshPolicy', { periodInMinutes: 15 });
chrome.alarms?.create('installHeartbeat', { periodInMinutes: 60 });
chrome.alarms?.create('rehydrationCleanup', { periodInMinutes: 1 });
chrome.alarms?.onAlarm.addListener((a) => {
  if (a.name === 'refreshPolicy') runAsync(refreshPolicy);
  if (a.name === 'installHeartbeat') runAsync(reportInstallHealth);
  if (a.name === 'rehydrationCleanup') cleanupExpiredRehydrations();
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'rehydrationStore') {
    sendResponse && sendResponse(storeRehydrationSession(msg, sender));
    return false;
  }
  if (msg.type === 'rehydrationOpen') {
    openRehydrationSession(msg, sender)
      .then((result) => sendResponse && sendResponse(result))
      .catch(() => sendResponse && sendResponse({ ok: false, reason: 'open_failed' }));
    return true;
  }
  if (msg.type === 'rehydrationReveal') {
    sendResponse && sendResponse(revealRehydrationSession(msg, sender));
    return false;
  }
  if (msg.type === 'rehydrationDiscard') {
    sendResponse && sendResponse(discardRehydrationSession(msg, sender));
    return false;
  }
  if (msg.type === 'fileIntent') {
    runAsync(() => relayFileIntent(msg.payload || {}, sender && sender.url));
    sendResponse && sendResponse({ queued: true });
    return false;
  }
  if (msg.type === 'getConfig') {
    Promise.all([cfg(), identity()]).then(([c, who]) => sendResponse({
      policy: c.policy,
      policyTrusted: c.policyTrusted,
      policyExpiresAt: c.policyExpiresAt,
      enabled: c.enabled,
      enabledLocked: c.enabledLocked,
      user: who.user,
      orgId: who.orgId,
    }));
    return true;
  }
  if (msg.type === 'getDestinationCoverage' || msg.type === 'syncDestinationCoverage') {
    syncCurrentDestinationCoverage()
      .then((result) => sendResponse && sendResponse(result))
      .catch(() => sendResponse && sendResponse({ ready: false, reason: 'coverage_sync_failed', missingOrigins: [], unsupported: ['runtime'] }));
    return true;
  }
  if (msg.type === 'approvalStatus') {
    pollApprovalStatus(msg.id, msg.releaseToken)
      .then((result) => sendResponse && sendResponse(result))
      .catch(() => sendResponse && sendResponse(failClosed('status_unreachable')));
    return true;
  }
  if (msg.type === 'resolveJustification') {
    resolveJustification(msg.id, msg.releaseToken, msg.outcome, msg.note)
      .then((result) => sendResponse && sendResponse(result))
      .catch(() => sendResponse && sendResponse(failClosed('justify_unreachable')));
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

// Persist throttled shadow-AI sightings across MV3 worker restarts.
const SHADOW_TTL_MS = 12 * 3600 * 1000;
const SHADOW_SEEN_KEY = 'shadowSeen';

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
    ...((c.policy && c.policy.blockedBrowserActions) || []).flatMap((rule) => (
      rule && rule.enabled !== false && String(rule.action || '').trim() ? (rule.destinations || []) : []
    )),
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
