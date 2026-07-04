'use strict';
require('../server/env').loadEnv();
/**
 * Imports sanitized AI-app sightings from proxy, firewall, SSE, or CASB exports.
 * The script strips URL paths locally and sends only host-level observations to
 * /api/v1/discovery. It never forwards raw log rows.
 */
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_SENTINEL_URL = process.env.SENTINEL_URL || process.env.PROMPTWALL_URL || 'http://localhost:4000';
const DEFAULT_SOURCE = 'proxy';
const DEFAULT_VENDOR = 'generic';
const API_BATCH_SIZE = 100;
const DESTINATION_RE = /^[A-Za-z0-9.*:-]+$/;
const SAFE_POLICY_TEXT_RE = /^[A-Za-z0-9 ._@:+/-]+$/;
const SENSOR_ID_RE = /^[a-z][a-z0-9_:-]{0,79}$/;
const SENSITIVE_ROUTING_CODE = /(?:\d{3}[-_:.]?\d{2}[-_:.]?\d{4}|\d{12,19})/;

const FIELD_ALIASES = {
  destination: [
    'destination', 'host', 'hostname', 'domain', 'fqdn', 'url', 'request_url', 'requesturl',
    'requestUrl', 'dest_host', 'dst_host', 'server_host', 'app_host', 'application_host',
    'cloud_app', 'app', 'application', 'service', 'internet_service',
  ],
  user: [
    'user', 'username', 'user_name', 'userPrincipalName', 'user_principal_name', 'principal',
    'actor', 'src_user', 'source_user', 'email', 'login',
  ],
  orgId: ['orgId', 'org_id', 'tenant', 'tenant_id', 'customer', 'customer_id'],
  events: [
    'events', 'count', 'hits', 'requests', 'request_count', 'requestCount', 'sessions',
    'num_events', 'event_count', 'occurrences',
  ],
  firstSeen: ['firstSeen', 'first_seen', 'first_time', 'start_time', 'start', 'earliest', 'created_at'],
  lastSeen: ['lastSeen', 'last_seen', 'last_time', 'end_time', 'end', 'latest', 'timestamp', 'time', 'event_time'],
  category: ['category', 'app_category', 'application_category', 'type', 'ai_category'],
  confidence: ['confidence', 'score', 'risk_score', 'confidence_score'],
};

const APP_NAME_HOSTS = {
  chatgpt: 'chatgpt.com',
  'openai chatgpt': 'chatgpt.com',
  claude: 'claude.ai',
  'anthropic claude': 'claude.ai',
  copilot: 'copilot.microsoft.com',
  'microsoft copilot': 'copilot.microsoft.com',
  gemini: 'gemini.google.com',
  'google gemini': 'gemini.google.com',
  perplexity: 'perplexity.ai',
  notebooklm: 'notebooklm.google.com',
  'notebook lm': 'notebooklm.google.com',
  poe: 'poe.com',
  cursor: 'cursor.com',
  replit: 'replit.com',
  'github copilot': 'github.com',
};

const CATEGORY_MAP = {
  chatbot: 'chatbot',
  chat: 'chatbot',
  llm: 'llm',
  model: 'llm',
  agent: 'agent',
  mcp: 'agent',
  coding: 'coding',
  code: 'coding',
  developer: 'coding',
  image: 'image',
  audio: 'audio',
};

function printHelp(io = console) {
  io.log([
    'Usage: npm run discovery:import -- --input export.csv --vendor zscaler --dry-run',
    '',
    'Options:',
    '  --input, -i <file>       CSV or JSON export to read',
    '  --vendor <name>          zscaler, netskope, purview, firewall, or generic',
    '  --source <id>            Sensor source id to record, default proxy',
    '  --sentinel-url <url>     PromptWall base URL, default SENTINEL_URL or http://localhost:4000',
    '  --api-key <key>          Ingest key; prefer INGEST_API_KEY or PROMPTWALL_INGEST_API_KEY env',
    '  --user <identity>        Import actor, default discovery-import',
    '  --org-id <id>            Optional tenant id',
    '  --dry-run                Build sanitized batches without posting',
    '  --format <csv|json>      Override file format detection',
    '  --limit <n>              Max input rows to read, default 5000',
    '  --json                   Print machine-readable summary',
  ].join('\n'));
}

function readOption(argv, long, short = null) {
  const longIndex = argv.indexOf(long);
  if (longIndex >= 0) return argv[longIndex + 1];
  if (short) {
    const shortIndex = argv.indexOf(short);
    if (shortIndex >= 0) return argv[shortIndex + 1];
  }
  return undefined;
}

function parseArgs(argv = process.argv.slice(2)) {
  const help = argv.includes('--help') || argv.includes('-h');
  return {
    help,
    input: readOption(argv, '--input', '-i') || '',
    vendor: safeText((readOption(argv, '--vendor') || DEFAULT_VENDOR).trim().toLowerCase(), DEFAULT_VENDOR, 80),
    source: safeSensorId(readOption(argv, '--source') || DEFAULT_SOURCE),
    sentinelUrl: readOption(argv, '--sentinel-url') || DEFAULT_SENTINEL_URL,
    apiKey: readOption(argv, '--api-key') || process.env.INGEST_API_KEY || process.env.PROMPTWALL_INGEST_API_KEY || '',
    user: safeText(readOption(argv, '--user') || 'discovery-import', 'discovery-import', 128),
    orgId: safeText(readOption(argv, '--org-id') || '', '', 128),
    dryRun: argv.includes('--dry-run'),
    format: (readOption(argv, '--format') || '').trim().toLowerCase(),
    limit: boundedInt(readOption(argv, '--limit'), 5000, 1, 50000),
    json: argv.includes('--json'),
  };
}

function boundedInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(n)));
}

function safeSensorId(value) {
  const text = String(value || '').trim().toLowerCase();
  return SENSOR_ID_RE.test(text) ? text : DEFAULT_SOURCE;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = '';
  let inQuotes = false;
  for (let i = 0; i < String(text || '').length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];
    if (ch === '"' && inQuotes && next === '"') {
      cell += '"';
      i += 1;
    } else if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      row.push(cell);
      cell = '';
    } else if ((ch === '\n' || ch === '\r') && !inQuotes) {
      if (ch === '\r' && next === '\n') i += 1;
      row.push(cell);
      if (row.some((value) => String(value).trim() !== '')) rows.push(row);
      row = [];
      cell = '';
    } else {
      cell += ch;
    }
  }
  row.push(cell);
  if (row.some((value) => String(value).trim() !== '')) rows.push(row);
  if (!rows.length) return [];
  const headers = rows[0].map((value) => String(value || '').trim());
  return rows.slice(1).map((values) => {
    const out = {};
    headers.forEach((header, index) => {
      if (!header) return;
      out[header] = values[index] == null ? '' : String(values[index]).trim();
    });
    return out;
  });
}

function parseJsonRecords(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (_) {
    const rows = String(text || '')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line));
    return rows;
  }
  if (Array.isArray(parsed)) return parsed;
  for (const key of ['records', 'rows', 'events', 'data', 'results', 'items']) {
    if (Array.isArray(parsed && parsed[key])) return parsed[key];
  }
  if (parsed && typeof parsed === 'object') return [parsed];
  return [];
}

function detectFormat(file, override = '') {
  if (override === 'csv' || override === 'json') return override;
  const ext = path.extname(String(file || '')).toLowerCase();
  return ext === '.json' || ext === '.jsonl' ? 'json' : 'csv';
}

function parseInput(text, opts = {}) {
  const format = opts.format || detectFormat(opts.input || '', '');
  if (format === 'json') return parseJsonRecords(text);
  return parseCsv(text);
}

function canonicalKey(key) {
  return String(key || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

function valueFor(record = {}, aliases = []) {
  if (!record || typeof record !== 'object') return '';
  const normalized = new Map();
  for (const [key, value] of Object.entries(record)) normalized.set(canonicalKey(key), value);
  for (const alias of aliases) {
    const value = normalized.get(canonicalKey(alias));
    if (value !== undefined && value !== null && String(value).trim() !== '') return value;
  }
  return '';
}

function safeText(value, fallback = '', max = 128) {
  const text = String(value || '').replace(/[\u0000-\u001F]/g, ' ').trim();
  if (!text) return fallback;
  if (SENSITIVE_ROUTING_CODE.test(text) || !SAFE_POLICY_TEXT_RE.test(text)) return fallback;
  return text.slice(0, max);
}

function knownAppHost(value) {
  const normalized = String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  return APP_NAME_HOSTS[normalized] || '';
}

function normalizeDestination(value) {
  const raw = String(value || '').trim();
  if (!raw || SENSITIVE_ROUTING_CODE.test(raw)) return '';
  const mapped = knownAppHost(raw);
  if (mapped) return mapped;
  const compact = raw.replace(/\s+/g, '-').toLowerCase();
  let host = '';
  try {
    const url = compact.includes('://') ? new URL(compact) : new URL('https://' + compact);
    host = url.hostname;
  } catch (_) {
    host = compact.split(/[/?#]/)[0];
  }
  host = String(host || '').replace(/^www\./, '').replace(/:\d+$/, '');
  if (!host || host === 'unknown') return '';
  if (!DESTINATION_RE.test(host) || SENSITIVE_ROUTING_CODE.test(host)) return '';
  if (!host.includes('.') && !host.startsWith('*.')) return '';
  return host.slice(0, 253);
}

function normalizeCategory(value) {
  const key = String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  return CATEGORY_MAP[key] || 'unknown';
}

function normalizeTimestamp(value) {
  const text = String(value || '').trim();
  if (!text || SENSITIVE_ROUTING_CODE.test(text)) return null;
  const parsed = new Date(text);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function normalizeConfidence(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return undefined;
  if (n > 1 && n <= 100) return Math.round(n) / 100;
  return Math.max(0, Math.min(1, n));
}

function compareIso(a, b, direction) {
  if (!a) return b || null;
  if (!b) return a;
  return direction === 'max'
    ? (String(a) >= String(b) ? a : b)
    : (String(a) <= String(b) ? a : b);
}

function sightingFromRecord(record, opts = {}) {
  const destination = normalizeDestination(valueFor(record, FIELD_ALIASES.destination));
  if (!destination) return null;
  const user = safeText(valueFor(record, FIELD_ALIASES.user), opts.user || 'discovery-import', 128);
  const orgId = safeText(valueFor(record, FIELD_ALIASES.orgId), opts.orgId || '', 128);
  const events = boundedInt(valueFor(record, FIELD_ALIASES.events), 1, 1, 100000);
  const firstSeen = normalizeTimestamp(valueFor(record, FIELD_ALIASES.firstSeen));
  const lastSeen = normalizeTimestamp(valueFor(record, FIELD_ALIASES.lastSeen));
  const category = normalizeCategory(valueFor(record, FIELD_ALIASES.category));
  const confidence = normalizeConfidence(valueFor(record, FIELD_ALIASES.confidence));
  return {
    destination,
    user,
    ...(orgId ? { orgId } : {}),
    events,
    ...(firstSeen ? { firstSeen } : {}),
    ...(lastSeen ? { lastSeen } : {}),
    category,
    ...(confidence !== undefined ? { confidence } : {}),
  };
}

function aggregateSightings(records = [], opts = {}) {
  const buckets = new Map();
  const stats = { inputRows: 0, acceptedRows: 0, skippedRows: 0 };
  for (const record of records) {
    stats.inputRows += 1;
    const sighting = sightingFromRecord(record, opts);
    if (!sighting) {
      stats.skippedRows += 1;
      continue;
    }
    stats.acceptedRows += 1;
    const key = [sighting.destination, sighting.user, sighting.orgId || '', sighting.category].join('\u0000');
    const current = buckets.get(key) || { ...sighting, events: 0 };
    current.events += sighting.events;
    current.firstSeen = compareIso(current.firstSeen, sighting.firstSeen, 'min');
    current.lastSeen = compareIso(current.lastSeen, sighting.lastSeen, 'max');
    if (sighting.confidence !== undefined) current.confidence = Math.max(Number(current.confidence || 0), sighting.confidence);
    buckets.set(key, current);
  }
  return { sightings: [...buckets.values()].sort((a, b) => b.events - a.events || a.destination.localeCompare(b.destination)), stats };
}

function buildBatches(records = [], opts = {}) {
  const limited = records.slice(0, opts.limit || 5000);
  const { sightings, stats } = aggregateSightings(limited, opts);
  const batches = [];
  for (let i = 0; i < sightings.length; i += API_BATCH_SIZE) {
    batches.push({
      source: safeSensorId(opts.source || DEFAULT_SOURCE),
      vendor: safeText(opts.vendor || DEFAULT_VENDOR, DEFAULT_VENDOR, 80),
      user: safeText(opts.user || 'discovery-import', 'discovery-import', 128),
      ...(safeText(opts.orgId || '', '', 128) ? { orgId: safeText(opts.orgId || '', '', 128) } : {}),
      sensor: { name: 'ai_discovery_importer', version: '0.1.0', platform: 'node_cli' },
      sightings: sightings.slice(i, i + API_BATCH_SIZE),
    });
  }
  return { batches, stats: { ...stats, acceptedSightings: sightings.length, batches: batches.length } };
}

async function postBatch(batch, opts = {}) {
  const base = String(opts.sentinelUrl || DEFAULT_SENTINEL_URL).replace(/\/+$/, '');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw new Error('fetch unavailable');
  if (!opts.apiKey) throw new Error('INGEST_API_KEY is required unless --dry-run is used');
  const res = await fetchImpl(`${base}/api/v1/discovery`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': opts.apiKey,
    },
    body: JSON.stringify(batch),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`discovery import failed: HTTP ${res.status}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

function summaryForBatches(batches = [], stats = {}) {
  const observations = batches.reduce((sum, batch) => sum + batch.sightings.reduce((inner, item) => inner + item.events, 0), 0);
  const destinations = [...new Set(batches.flatMap((batch) => batch.sightings.map((item) => item.destination)))].sort();
  return {
    status: 'ready',
    batches: batches.length,
    sightings: batches.reduce((sum, batch) => sum + batch.sightings.length, 0),
    observations,
    destinations: destinations.slice(0, 25),
    truncatedDestinations: destinations.length > 25,
    stats,
    privacy: 'host-only destinations; prompt bodies and URL paths omitted',
  };
}

async function main(argv = process.argv.slice(2), deps = {}) {
  const opts = parseArgs(argv);
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  if (opts.help) {
    printHelp(io);
    return { status: 'help' };
  }
  if (!opts.input) {
    io.error('Missing --input');
    printHelp(io);
    setExitCode(2);
    return { status: 'error', error: 'missing input' };
  }
  const readFile = deps.readFile || fs.readFileSync;
  const file = path.resolve(opts.input);
  const text = readFile(file, 'utf8');
  const records = parseInput(text, { input: file, format: opts.format || detectFormat(file) });
  const { batches, stats } = buildBatches(records, opts);
  const summary = summaryForBatches(batches, stats);
  if (opts.dryRun) {
    if (opts.json) io.log(JSON.stringify(summary, null, 2));
    else {
      io.log(`Discovery dry run: ${summary.sightings} sightings / ${summary.observations} observations / ${summary.batches} batches`);
      io.log(`Destinations: ${summary.destinations.join(', ') || 'none'}`);
      io.log(summary.privacy);
    }
    return summary;
  }
  const responses = [];
  try {
    for (const batch of batches) responses.push(await postBatch(batch, { ...opts, fetchImpl: deps.fetchImpl }));
  } catch (err) {
    io.error(err.message);
    setExitCode(1);
    return { status: 'error', error: err.message };
  }
  const posted = {
    ...summary,
    status: 'posted',
    responses: responses.map((body) => ({
      imported: body.imported,
      observations: body.observations,
      status: body.status,
    })),
  };
  if (opts.json) io.log(JSON.stringify(posted, null, 2));
  else io.log(`Discovery import posted: ${posted.sightings} sightings / ${posted.observations} observations`);
  return posted;
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}

module.exports = {
  API_BATCH_SIZE,
  FIELD_ALIASES,
  parseArgs,
  parseCsv,
  parseJsonRecords,
  parseInput,
  normalizeDestination,
  sightingFromRecord,
  aggregateSightings,
  buildBatches,
  postBatch,
  summaryForBatches,
  main,
};
