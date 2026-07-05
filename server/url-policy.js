'use strict';

// Block IP-literal hosts that are never a legitimate outbound webhook target and
// are classic SSRF pivots: loopback, link-local (incl. the cloud metadata
// endpoint 169.254.169.254), and the unspecified address. RFC1918 private ranges
// (10/8, 172.16/12, 192.168/16) are intentionally allowed because this is a
// self-hosted product whose SIEM/webhook often lives on an internal network.
function isBlockedIpv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const o = m.slice(1).map(Number);
  if (o.some((n) => n > 255)) return true; // malformed octet — reject
  if (o[0] === 127) return true;           // 127.0.0.0/8 loopback
  if (o[0] === 0) return true;             // 0.0.0.0/8 unspecified/this-host
  if (o[0] === 169 && o[1] === 254) return true; // 169.254.0.0/16 link-local (metadata)
  return false;
}

function isBlockedIpv6(host) {
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  const zone = h.indexOf('%');
  if (zone !== -1) h = h.slice(0, zone);
  if (h === '::1' || h === '::' || h === '0:0:0:0:0:0:0:1' || h === '0:0:0:0:0:0:0:0') return true;
  if (/^fe[89ab][0-9a-f]:/.test(h)) return true; // fe80::/10 link-local
  // IPv4-mapped form embedding a blocked v4 address, in dotted (::ffff:127.0.0.1)
  // or URL-normalized hex (::ffff:7f00:1) notation.
  const dotted = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h);
  if (dotted && isBlockedIpv4(dotted[1])) return true;
  const hex = /::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    const v4 = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
    if (isBlockedIpv4(v4)) return true;
  }
  return false;
}

function isBlockedHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host.includes(':') || (host.startsWith('[') && host.endsWith(']'))) return isBlockedIpv6(host);
  return isBlockedIpv4(host);
}

function outboundHttpsUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const url = new URL(raw);
    if (url.protocol !== 'https:') return '';
    if (url.username || url.password) return '';
    if (isBlockedHost(url.hostname)) return '';
    url.hash = '';
    return url.toString();
  } catch {
    return '';
  }
}

module.exports = { outboundHttpsUrl, isBlockedHost };
