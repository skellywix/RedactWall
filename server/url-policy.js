'use strict';

// Block IP-literal hosts that are never a legitimate outbound webhook target and
// are classic SSRF pivots: loopback, link-local (incl. the cloud metadata
// endpoint 169.254.169.254), and the unspecified address. RFC1918 private ranges
// (10/8, 172.16/12, 192.168/16) are intentionally allowed because this is a
// self-hosted product whose SIEM/webhook often lives on an internal network.
// Parse an IPv4 literal in ANY inet_aton form the resolver accepts — dotted
// quad, but also decimal (2130706433), octal (0177.0.0.1), hex (0x7f000001),
// and short forms (127.1) — to a 32-bit value, or null if it isn't an IPv4
// literal. A plain denylist over dotted-quad text let all the other encodings
// of 127.0.0.1 / 169.254.169.254 through (SSRF bypass, review finding R1).
function parseIpv4Loose(host) {
  const parts = String(host).split('.');
  if (!parts.length || parts.length > 4) return null;
  const nums = [];
  for (const p of parts) {
    if (p === '') return null;
    let n;
    if (/^0x[0-9a-f]+$/i.test(p)) n = parseInt(p, 16);
    else if (/^0[0-7]*$/.test(p)) n = parseInt(p, 8);
    else if (/^[1-9][0-9]*$/.test(p)) n = parseInt(p, 10);
    else return null;
    if (!Number.isInteger(n) || n < 0) return null;
    nums.push(n);
  }
  const last = nums.length - 1;
  for (let i = 0; i < last; i++) if (nums[i] > 255) return null; // leading bytes are octets
  if (nums[last] >= Math.pow(256, 4 - last)) return null;        // trailing value fits remaining bytes
  let value = nums[last];
  for (let i = 0; i < last; i++) value += nums[i] * Math.pow(256, 3 - i);
  return value >>> 0;
}

function isBlockedIpv4(host) {
  const v = parseIpv4Loose(host);
  if (v === null) return false;
  const b0 = (v >>> 24) & 0xff;
  const b1 = (v >>> 16) & 0xff;
  if (b0 === 127) return true;              // 127.0.0.0/8 loopback
  if (b0 === 0) return true;                // 0.0.0.0/8 unspecified/this-host
  if (b0 === 169 && b1 === 254) return true; // 169.254.0.0/16 link-local (metadata)
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

function outboundHttpsUrlWithoutParameters(value) {
  const raw = String(value || '').trim();
  try {
    const url = new URL(raw);
    if (url.search || url.hash) return '';
  } catch { return ''; }
  return outboundHttpsUrl(raw);
}

module.exports = { outboundHttpsUrl, outboundHttpsUrlWithoutParameters, isBlockedHost };
