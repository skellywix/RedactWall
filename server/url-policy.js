'use strict';

function outboundHttpsUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:') return '';
    if (url.username || url.password) return '';
    url.hash = '';
    return url.toString();
  } catch {
    return '';
  }
}

module.exports = { outboundHttpsUrl };
