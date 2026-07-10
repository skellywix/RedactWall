(function () {
  'use strict';

  const Ext = globalThis.PWBrowserApi;
  const TOKEN_RE = /^\[\[[A-Z][A-Z0-9_]*_\d+\]\]$/;
  const CHANNEL_RE = /^[a-f0-9]{32}$/;
  const DISPLAY_TTL_MS = 30 * 1000;
  const params = new URLSearchParams(location.hash.slice(1));
  const channel = params.get('channel') || '';
  history.replaceState(null, '', location.pathname);

  const revealButton = document.getElementById('reveal');
  const copyButton = document.getElementById('copy');
  const closeButton = document.getElementById('close');
  const valuesElement = document.getElementById('values');
  const statusElement = document.getElementById('status');
  let revealed = [];
  let clearTimer = null;
  let discarded = false;

  function validEntries(value) {
    if (!Array.isArray(value) || value.length < 1 || value.length > 100) return null;
    const seen = new Set();
    const entries = [];
    const encoder = new TextEncoder();
    let total = 0;
    for (const item of value) {
      if (!item || typeof item.token !== 'string' || !TOKEN_RE.test(item.token) || seen.has(item.token)) return null;
      if (typeof item.value !== 'string' || !item.value || item.value.length > 8192) return null;
      total += encoder.encode(item.token).byteLength + encoder.encode(item.value).byteLength;
      if (total > 64 * 1024) return null;
      seen.add(item.token);
      entries.push({ token: item.token, value: item.value });
    }
    return entries;
  }

  function clearSensitive(message) {
    if (clearTimer !== null) clearTimeout(clearTimer);
    clearTimer = null;
    for (const entry of revealed) { entry.token = ''; entry.value = ''; }
    revealed = [];
    valuesElement.replaceChildren();
    valuesElement.hidden = true;
    copyButton.disabled = true;
    if (message) statusElement.textContent = message;
  }

  function renderEntries(entries) {
    const fragment = document.createDocumentFragment();
    for (const entry of entries) {
      const row = document.createElement('div');
      const token = document.createElement('code');
      const value = document.createElement('output');
      row.className = 'value';
      token.textContent = entry.token;
      value.textContent = entry.value;
      row.append(token, value);
      fragment.appendChild(row);
    }
    valuesElement.replaceChildren(fragment);
    valuesElement.hidden = false;
  }

  async function revealOnce(event) {
    if (!event.isTrusted || !CHANNEL_RE.test(channel) || !Ext) return;
    revealButton.disabled = true;
    statusElement.textContent = 'Retrieving values from extension memory...';
    const response = await Ext.sendMessage({ type: 'rehydrationReveal', channel });
    const entries = response && response.ok === true ? validEntries(response.entries) : null;
    if (!entries) {
      statusElement.textContent = 'These values expired, were already revealed, or came from another tab.';
      return;
    }
    revealed = entries;
    renderEntries(entries);
    copyButton.disabled = false;
    statusElement.textContent = 'Values are visible for up to 30 seconds.';
    clearTimer = setTimeout(() => clearSensitive('Values hidden after 30 seconds.'), DISPLAY_TTL_MS);
  }

  async function copyAndHide(event) {
    if (!event.isTrusted || !revealed.length || !navigator.clipboard) return;
    const text = revealed.map((entry) => entry.token + ': ' + entry.value).join('\n');
    try {
      await navigator.clipboard.writeText(text);
      clearSensitive('Copied by your explicit request. Values are hidden again.');
    } catch (_) {
      statusElement.textContent = 'Clipboard access failed. Values remain visible briefly.';
    }
  }

  function discardChannel() {
    if (discarded || !CHANNEL_RE.test(channel) || !Ext) return;
    discarded = true;
    void Ext.sendMessage({ type: 'rehydrationDiscard', channel });
  }

  function discardAndClose() {
    clearSensitive('Values discarded.');
    discardChannel();
    window.close();
  }

  revealButton.addEventListener('click', revealOnce);
  copyButton.addEventListener('click', copyAndHide);
  closeButton.addEventListener('click', discardAndClose);
  window.addEventListener('pagehide', () => {
    clearSensitive();
    discardChannel();
  });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) return;
    clearSensitive('Values discarded when this tab left the foreground.');
    revealButton.disabled = true;
    discardChannel();
  });

  if (!CHANNEL_RE.test(channel) || !Ext) {
    revealButton.disabled = true;
    statusElement.textContent = 'This reveal link is invalid or expired.';
  }
})();
