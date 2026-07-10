'use strict';

function publicOrigin(value, { production = false } = {}) {
  const configured = String(value || '').trim();
  if (!configured || configured.length > 2048) return '';
  try {
    const url = new URL(configured);
    if (!['http:', 'https:'].includes(url.protocol)) return '';
    if (production && url.protocol !== 'https:') return '';
    if (url.username || url.password || url.search || url.hash) return '';
    return url.origin;
  } catch {
    return '';
  }
}

module.exports = { publicOrigin };
