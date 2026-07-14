'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');

const BOOT_DOMAIN = 'redactwall.connected-fallback.boot.v1';
let cachedBootId = null;

function systemBootClock() {
  if (!cachedBootId) cachedBootId = bootId(readBootMarker());
  const nowMs = Math.round(os.uptime() * 1000);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw unavailable();
  return { bootId: cachedBootId, nowMs };
}

function readBootMarker() {
  try {
    if (process.platform === 'linux') {
      const value = fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim().toLowerCase();
      if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value)) {
        throw unavailable();
      }
      return value;
    }
    if (process.platform === 'win32') {
      const value = execFileSync('powershell.exe', [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("O")',
      ], {
        encoding: 'utf8',
        timeout: 5_000,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      const parsed = Date.parse(value);
      if (!value || !Number.isFinite(parsed)) throw unavailable();
      return new Date(parsed).toISOString();
    }
    if (process.platform === 'darwin') {
      const value = execFileSync('/usr/sbin/sysctl', ['-n', 'kern.boottime'], {
        encoding: 'utf8', timeout: 5_000, stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      const match = value.match(/sec\s*=\s*(\d+),\s*usec\s*=\s*(\d+)/);
      if (!match || !Number.isSafeInteger(Number(match[1]))
          || !Number.isSafeInteger(Number(match[2]))) throw unavailable();
      return `${match[1]}.${match[2].padStart(6, '0')}`;
    }
  } catch (error) {
    if (error && error.code === 'MONOTONIC_BOOT_ID_UNAVAILABLE') throw error;
    throw unavailable();
  }
  throw unavailable();
}

function bootId(marker) {
  if (typeof marker !== 'string' || !marker) throw unavailable();
  return crypto.createHash('sha256')
    .update(`${BOOT_DOMAIN}\0${process.platform}\0${marker}`, 'utf8')
    .digest('hex').slice(0, 32);
}

function unavailable() {
  const error = new Error('operating-system boot identity is unavailable');
  error.code = 'MONOTONIC_BOOT_ID_UNAVAILABLE';
  return error;
}

module.exports = { systemBootClock };
