const DEF = { serverUrl: 'http://localhost:4000', enabled: true, policy: { enforcementMode: 'block' } };
const SENSOR_NAMES = { endpoint_agent: 'Endpoint agent', mcp_guard: 'MCP guard', browser_extension: 'Browser extension' };
(window.PWBrowserApi || {}).storageGet('local', ['serverUrl', 'enabled', 'policy', 'fleetCompanions']).then((c) => {
  const cfg = { ...DEF, ...c };
  const toggle = document.getElementById('toggle');
  toggle.checked = cfg.enabled !== false;
  paint(cfg.enabled !== false);
  document.getElementById('mode').textContent = (cfg.policy && cfg.policy.enforcementMode) || 'block';
  document.getElementById('dash').href = cfg.serverUrl + '/index.html';
  paintFleet(cfg.fleetCompanions);
  toggle.addEventListener('change', () => {
    window.PWBrowserApi.storageSet('local', { enabled: toggle.checked });
    paint(toggle.checked);
  });
});
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
