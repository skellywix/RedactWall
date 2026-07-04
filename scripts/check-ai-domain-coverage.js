'use strict';
/**
 * Fails when the reviewed AI destination watchlist is not represented by the
 * canonical adapter host list. If CLOUDFLARE_API_TOKEN is set, the script also
 * checks Cloudflare Radar Internet Services rankings through serviceDomainMap.
 */
const fs = require('fs');
const path = require('path');
const adapters = require('../detection-engine/adapters');

const ROOT = path.join(__dirname, '..');
const DEFAULT_WATCHLIST = path.join(ROOT, 'config', 'ai-domain-watchlist.json');
const DEFAULT_MANIFEST = path.join(ROOT, 'sensors', 'browser-extension', 'manifest.json');
const RADAR_TOP_URL = 'https://api.cloudflare.com/client/v4/radar/ranking/internet_services/top';

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function normalizeDomain(value) {
  return adapters.normalizeHost(value);
}

function uniqueDomains(values = []) {
  const out = [];
  const seen = new Set();
  for (const value of values || []) {
    const domain = normalizeDomain(value);
    if (!domain || domain === 'unknown' || seen.has(domain)) continue;
    seen.add(domain);
    out.push(domain);
  }
  return out;
}

function serviceDomains(service, serviceDomainMap = {}) {
  if (!service) return [];
  if (serviceDomainMap[service]) return serviceDomainMap[service];
  const normalized = String(service).trim().toLowerCase();
  const match = Object.entries(serviceDomainMap).find(([name]) => name.trim().toLowerCase() === normalized);
  return match ? match[1] : [];
}

function collectCandidateDomains(watchlist, radarServices = []) {
  const domains = uniqueDomains(watchlist.candidateDomains || []);
  const seen = new Set(domains);
  const unknownServices = [];
  for (const service of radarServices || []) {
    const mapped = uniqueDomains(serviceDomains(service, watchlist.serviceDomainMap || {}));
    if (!mapped.length) {
      unknownServices.push(String(service));
      continue;
    }
    for (const domain of mapped) {
      if (!seen.has(domain)) {
        seen.add(domain);
        domains.push(domain);
      }
    }
  }
  return { domains, unknownServices };
}

function hostCovered(domain, hostList = adapters.AI_HOSTS) {
  return (hostList || []).some((host) => adapters.hostMatches(domain, host));
}

function manifestPatternHost(pattern) {
  return normalizeDomain(String(pattern || '')
    .replace(/^https?:\/\//i, '')
    .replace(/^www\./i, '')
    .replace(/^\*\./, '')
    .replace(/\/\*$/, ''));
}

function manifestHosts(manifest = {}) {
  const matches = [
    ...(manifest.host_permissions || []),
    ...((manifest.content_scripts || []).flatMap((script) => script.matches || [])),
  ];
  return uniqueDomains(matches.map(manifestPatternHost));
}

function manifestCovered(domain, manifest = {}) {
  const hosts = manifestHosts(manifest);
  return hosts.some((host) => adapters.hostMatches(domain, host));
}

function checkCoverage({ watchlist, adapterHosts = adapters.AI_HOSTS, radarServices = [], manifest = null }) {
  const { domains, unknownServices } = collectCandidateDomains(watchlist, radarServices);
  const missingDomains = domains.filter((domain) => !hostCovered(domain, adapterHosts)).sort();
  const missingManifestDomains = manifest
    ? (adapterHosts || []).filter((domain) => !manifestCovered(domain, manifest)).sort()
    : [];
  return {
    checkedDomains: domains.sort(),
    missingDomains,
    missingManifestDomains,
    unknownServices: [...new Set(unknownServices)].sort(),
  };
}

async function fetchRadarServices({
  token = process.env.CLOUDFLARE_API_TOKEN,
  serviceCategory = process.env.AI_DOMAIN_RADAR_SERVICE_CATEGORY || 'Generative AI',
  limit = Number(process.env.AI_DOMAIN_RADAR_LIMIT || 100),
  fetchImpl = globalThis.fetch,
} = {}) {
  if (!token) return { skipped: true, services: [] };
  if (typeof fetchImpl !== 'function') throw new Error('fetch unavailable for Cloudflare Radar check');
  const url = new URL(RADAR_TOP_URL);
  url.searchParams.set('format', 'JSON');
  url.searchParams.set('limit', String(Math.max(1, Math.min(200, Math.floor(limit) || 100))));
  if (serviceCategory) url.searchParams.set('serviceCategory', serviceCategory);
  const res = await fetchImpl(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const body = await res.json().catch(() => null);
  if (!res.ok || !body || body.success === false) {
    const message = body && Array.isArray(body.errors) && body.errors[0] && body.errors[0].message
      ? body.errors[0].message
      : `HTTP ${res.status}`;
    throw new Error(`Cloudflare Radar check failed: ${message}`);
  }
  const top = body.result && Array.isArray(body.result.top_0) ? body.result.top_0 : [];
  return { skipped: false, services: top.map((row) => row.service).filter(Boolean) };
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  const read = deps.readJson || readJson;
  const fetchRadar = deps.fetchRadarServices || fetchRadarServices;
  const check = deps.checkCoverage || checkCoverage;
  const watchlistPath = argv.includes('--watchlist')
    ? path.resolve(argv[argv.indexOf('--watchlist') + 1])
    : DEFAULT_WATCHLIST;
  const watchlist = read(watchlistPath);
  let radar = { skipped: true, services: [] };
  try {
    radar = await fetchRadar();
  } catch (err) {
    io.error(err.message);
    setExitCode(1);
    return null;
  }
  const manifest = read(deps.manifestPath || DEFAULT_MANIFEST);
  const result = check({ watchlist, radarServices: radar.services, manifest });
  let failed = false;
  io.log(`AI domain coverage check: ${result.checkedDomains.length} domains`);
  if (radar.skipped) io.log('Cloudflare Radar skipped: set CLOUDFLARE_API_TOKEN to include weekly popularity data.');
  if (result.unknownServices.length) {
    io.error('Cloudflare Radar services need mapping:');
    for (const service of result.unknownServices) io.error('  - ' + service);
    failed = true;
  }
  if (result.missingDomains.length) {
    io.error('AI domains missing from detection-engine/adapters.js AI_HOSTS:');
    for (const domain of result.missingDomains) io.error('  - ' + domain);
    failed = true;
  }
  if (result.missingManifestDomains.length) {
    io.error('AI adapter hosts missing from browser extension manifest coverage:');
    for (const domain of result.missingManifestDomains) io.error('  - ' + domain);
    failed = true;
  }
  if (failed) setExitCode(1);
  else io.log('AI domain coverage current.');
  return result;
}

if (require.main === module) main();

module.exports = {
  RADAR_TOP_URL,
  collectCandidateDomains,
  checkCoverage,
  fetchRadarServices,
  hostCovered,
  main,
  manifestCovered,
  manifestHosts,
  normalizeDomain,
  readJson,
  serviceDomains,
};
