'use strict';
/**
 * Build an Exact Data Match (EDM) watchlist WITHOUT persisting any plaintext.
 *
 * Reads known-sensitive values (one per line) from a local file or stdin,
 * fingerprints each with a per-org salt using the SAME one-way hash the
 * detection engine uses, and writes only { salt, fingerprints } to
 * config/exact-match.json. The plaintext is never written anywhere.
 *
 *   node scripts/edm-fingerprint.js --in secret-values.txt
 *   printf 'ACME-MEMBER-77413\nJane Q Public\n' | node scripts/edm-fingerprint.js
 *   node scripts/edm-fingerprint.js --in members.csv --column "Member Number"
 *
 * Flags:
 *   --in <file>     Read values from a file instead of stdin.
 *   --column <c>    Treat the input as CSV and fingerprint one column: a header
 *                   name (skips the header row) or a 1-based index (all rows).
 *                   Runs locally; only salted one-way hashes are ever written.
 *   --out <file>    Output path (default config/exact-match.json).
 *   --salt <value>  Reuse an existing salt (default: generate a fresh one and
 *                   reuse the salt already in --out if present, so appends work).
 *   --severity <n>  1-4 severity for a match (default 4).
 *   --min-len <n>   Minimum candidate length to fingerprint (default 6).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const detector = require('../detection-engine/detect');

function arg(name, fallback) {
  const i = process.argv.indexOf('--' + name);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

function readInput() {
  const inFile = arg('in', null);
  if (inFile) return fs.readFileSync(inFile, 'utf8');
  try { return fs.readFileSync(0, 'utf8'); } catch (e) { return ''; }
}

// Minimal CSV field parser: handles quoted fields, escaped ("") quotes, and
// commas inside quotes. Assumes rows are newline-separated (no embedded
// newlines in fields) — the shape of a core-banking roster export.
function parseCsvLine(line) {
  const out = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') { field += '"'; i++; } else inQuotes = false;
      } else field += ch;
    } else if (ch === '"') inQuotes = true;
    else if (ch === ',') { out.push(field); field = ''; } else field += ch;
  }
  out.push(field);
  return out;
}

// Extract one column of values from CSV text. `column` is a header name
// (case-insensitive; the header row is skipped) or a 1-based index (all rows).
function valuesFromCsv(text, column) {
  const lines = String(text || '').split(/\r?\n/).filter((l) => l.length);
  if (!lines.length) return [];
  let idx;
  let dataStart;
  if (/^\d+$/.test(String(column))) {
    idx = Number(column) - 1;
    dataStart = 0;
  } else {
    const header = parseCsvLine(lines[0]).map((h) => h.trim().toLowerCase());
    idx = header.indexOf(String(column).trim().toLowerCase());
    if (idx === -1) {
      throw new Error(`--column "${column}" not found in CSV header: ${parseCsvLine(lines[0]).join(', ')}`);
    }
    dataStart = 1;
  }
  const out = [];
  for (let r = dataStart; r < lines.length; r++) {
    const v = (parseCsvLine(lines[r])[idx] || '').trim();
    if (v) out.push(v);
  }
  return out;
}

function main() {
  const outPath = arg('out', path.join(__dirname, '..', 'config', 'exact-match.json'));
  let existing = { salt: '', fingerprints: [] };
  try { if (fs.existsSync(outPath)) existing = JSON.parse(fs.readFileSync(outPath, 'utf8')) || existing; } catch (e) { /* start fresh */ }

  const salt = arg('salt', existing.salt) || crypto.randomBytes(24).toString('hex');
  const minLen = Math.max(4, Number(arg('min-len', 6)) || 6);
  const severity = Math.max(1, Math.min(4, Number(arg('severity', 4)) || 4));

  const priorFingerprints = Array.isArray(existing.fingerprints) ? existing.fingerprints : [];
  // Merging is only sound when the salt matches: fingerprints hashed under a
  // different salt can never match at detection time, so silently carrying them
  // forward under the new salt would leave dead, unmatchable entries.
  if (existing.salt && existing.salt !== salt && priorFingerprints.length) {
    throw new Error(
      `--salt differs from the salt already in ${outPath}; its ${priorFingerprints.length} existing ` +
      'fingerprints were hashed with the previous salt and would become unmatchable. Re-fingerprint the ' +
      'full value list into a fresh --out, or omit --salt to reuse the existing one.'
    );
  }

  const column = arg('column', null);
  const raw = readInput();
  const values = column
    ? valuesFromCsv(raw, column)
    : raw.split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
  const set = new Set(priorFingerprints);
  let added = 0;
  for (const value of values) {
    if (value.replace(/\s+/g, '').length < minLen) continue;
    const fp = detector.edmFingerprint(value, salt);
    if (fp && !set.has(fp)) { set.add(fp); added++; }
    // Also fingerprint the digits-only form so "900-123-456" matches "900123456".
    const digits = value.replace(/\D/g, '');
    if (digits.length >= minLen) { const dfp = detector.edmFingerprint(digits, salt); if (dfp && !set.has(dfp)) { set.add(dfp); added++; } }
  }

  const out = { salt, minLen, severity, enabled: set.size > 0, fingerprints: Array.from(set) };
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n');
  process.stdout.write(`EDM watchlist written to ${outPath}\n  values read: ${values.length}\n  fingerprints added: ${added}\n  total fingerprints: ${set.size}\n  (plaintext discarded; only salted one-way hashes are stored)\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (e) {
    process.stderr.write(`${e && e.message ? e.message : e}\n`);
    process.exit(1);
  }
}

module.exports = { parseCsvLine, valuesFromCsv };
