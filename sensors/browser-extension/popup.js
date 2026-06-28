const DEF = { serverUrl: 'http://localhost:4000', enabled: true, policy: { enforcementMode: 'block' } };
(window.PWBrowserApi || {}).storageGet('local', ['serverUrl', 'enabled', 'policy']).then((c) => {
  const cfg = { ...DEF, ...c };
  const toggle = document.getElementById('toggle');
  toggle.checked = cfg.enabled !== false;
  paint(cfg.enabled !== false);
  document.getElementById('mode').textContent = (cfg.policy && cfg.policy.enforcementMode) || 'block';
  document.getElementById('dash').href = cfg.serverUrl + '/index.html';
  toggle.addEventListener('change', () => {
    window.PWBrowserApi.storageSet('local', { enabled: toggle.checked });
    paint(toggle.checked);
  });
});
function paint(on) {
  document.getElementById('dot').className = 'dot ' + (on ? 'on' : 'off');
  document.getElementById('state').textContent = on ? 'Protecting this browser' : 'Paused';
}
