const DEF = { serverUrl: 'http://localhost:4000', enabled: true, policy: { enforcementMode: 'block' } };
const SENSOR_NAMES = { endpoint_agent: 'Endpoint agent', mcp_guard: 'MCP guard', browser_extension: 'Browser extension' };
const Ext = window.PWBrowserApi || {};
Promise.all([
  Ext.storageGet('local', ['serverUrl', 'enabled', 'policy', 'fleetCompanions']),
  Ext.storageGet('managed', ['serverUrl', 'orgId', 'email', 'user', 'enabled']),
]).then(([local, managed]) => {
  const cfg = { ...DEF, ...(local || {}) };
  const managedLocked = hasManagedConfiguration(managed);
  const enabled = typeof (managed && managed.enabled) === 'boolean'
    ? managed.enabled
    : managedLocked || cfg.enabled !== false;
  const serverUrl = (managed && managed.serverUrl) || cfg.serverUrl;
  const toggle = document.getElementById('toggle');
  toggle.checked = enabled;
  toggle.disabled = managedLocked;
  if (managedLocked) toggle.title = 'Protection is managed by your organization';
  paint(enabled);
  document.getElementById('mode').textContent = (cfg.policy && cfg.policy.enforcementMode) || 'block';
  document.getElementById('dash').href = serverUrl + '/app/';
  paintFleet(cfg.fleetCompanions);
  paintServerAccess(serverUrl);
  paintDestinationCoverage();
  toggle.addEventListener('change', () => {
    if (managedLocked) return;
    window.PWBrowserApi.storageSet('local', { enabled: toggle.checked });
    paint(toggle.checked);
  });
});

function hasManagedConfiguration(managed) {
  const value = managed || {};
  return ['serverUrl', 'orgId', 'email', 'user', 'enabled'].some((key) => (
    Object.prototype.hasOwnProperty.call(value, key)
      && value[key] !== undefined && value[key] !== null && value[key] !== ''
  ));
}

function secureServerPattern(value) {
  try {
    const url = new URL(String(value || ''));
    return url.protocol === 'https:' && !url.username && !url.password ? url.origin + '/*' : null;
  } catch (_) { return null; }
}

async function paintServerAccess(serverUrl) {
  const pattern = secureServerPattern(serverUrl);
  const permissions = Ext.api && Ext.api.permissions;
  if (!pattern || !permissions) return;
  const panel = document.getElementById('serverAccess');
  const status = document.getElementById('serverAccessText');
  const button = document.getElementById('grantServerAccess');
  let granted = false;
  try { granted = await permissions.contains({ origins: [pattern] }); } catch (_) {}
  panel.hidden = granted === true;
  if (granted) return;
  status.textContent = 'Allow access to ' + new URL(serverUrl).host + '. Protection remains fail-closed until granted.';
  button.onclick = () => {
    button.disabled = true;
    Promise.resolve(permissions.request({ origins: [pattern] })).then((allowed) => {
      panel.hidden = allowed === true;
      status.textContent = allowed ? 'Access granted.' : 'Permission required; protection remains fail-closed.';
      button.disabled = false;
    }).catch(() => { status.textContent = 'Permission request failed; protection remains fail-closed.'; button.disabled = false; });
  };
}

function destinationLabel(pattern) {
  return String(pattern || '').replace(/^https:\/\/\*?\.?/, '').replace(/\/\*$/, '');
}

function renderDestinationCoverage(state) {
  const panel = document.getElementById('destinationAccess');
  const status = document.getElementById('destinationAccessText');
  const button = document.getElementById('grantDestinationAccess');
  const missing = Array.isArray(state && state.missingOrigins) ? state.missingOrigins : [];
  const unsupported = Array.isArray(state && state.unsupported) ? state.unsupported : [];
  panel.hidden = !!(state && state.ready);
  if (state && state.ready) return;
  if (!state) {
    status.textContent = 'Coverage could not be verified. Configured custom sites remain blocked.';
    button.hidden = true;
    return;
  }
  const preview = missing.slice(0, 3).map(destinationLabel).join(', ');
  const pending = missing.length ? `${missing.length} exact site grant${missing.length === 1 ? '' : 's'} pending${preview ? ': ' + preview : ''}.` : '';
  const proxy = unsupported.length ? ' A gateway or proxy is required for broad wildcard policy.' : '';
  status.textContent = `${pending}${proxy} Sites without active coverage remain blocked.`.trim();
  button.hidden = missing.length === 0;
  button.textContent = missing.length > 20 ? 'Allow next 20 sites' : 'Allow exact sites';
  button.onclick = () => requestDestinationAccess(missing.slice(0, 20));
}

function requestDestinationAccess(origins) {
  const permissions = Ext.api && Ext.api.permissions;
  const button = document.getElementById('grantDestinationAccess');
  const status = document.getElementById('destinationAccessText');
  if (!permissions || !origins.length) return;
  button.disabled = true;
  Promise.resolve(permissions.request({ origins })).then(async (allowed) => {
    if (!allowed) {
      status.textContent = 'Site permission is required. Uncovered destinations remain blocked.';
      button.disabled = false;
      return;
    }
    const next = await Ext.sendMessage({ type: 'syncDestinationCoverage' });
    button.disabled = false;
    renderDestinationCoverage(next);
  }).catch(() => {
    status.textContent = 'Permission request failed. Uncovered destinations remain blocked.';
    button.disabled = false;
  });
}

async function paintDestinationCoverage() {
  if (typeof Ext.sendMessage !== 'function') return;
  renderDestinationCoverage(await Ext.sendMessage({ type: 'getDestinationCoverage' }));
}
// The heartbeat response tells this extension whether the user's other
// sensors are reporting; a missing endpoint agent is a coverage gap the
// console already knows about, and the user should see it here too.
function paintFleet(fleet) {
  const companions = fleet && fleet.companions;
  if (!companions) return;
  const lines = Object.keys(SENSOR_NAMES)
    .filter((key) => key in companions)
    .map((key) => {
      const state = companions[key];
      const label = state === 'active' ? 'reporting' : state === 'stale' ? 'gone quiet (coverage gap)' : 'not installed (coverage gap)';
      return SENSOR_NAMES[key] + ': ' + label;
    });
  if (!lines.length) return;
  document.getElementById('fleet').hidden = false;
  document.getElementById('fleetLines').textContent = lines.join(' · ');
}
function paint(on) {
  document.getElementById('dot').className = 'dot ' + (on ? 'on' : 'off');
  document.getElementById('state').textContent = on ? 'Protecting this browser' : 'Paused';
}
