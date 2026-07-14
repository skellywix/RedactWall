'use strict';
/**
 * Build an Exact Data Match (EDM) watchlist WITHOUT persisting any plaintext.
 *
 * Reads high-entropy random identifiers (one per line) from a local file or
 * stdin, fingerprints each with the same salted SHA-256 profile the detector
 * uses, and writes only the versioned fingerprint pack. The script never
 * creates a plaintext copy.
 *
 *   node scripts/edm-fingerprint.js --in secret-values.txt
 *   printf '550e8400-e29b-41d4-a716-446655440000\n' | node scripts/edm-fingerprint.js
 *   node scripts/edm-fingerprint.js --in random-identifiers.csv --column "Random Identifier"
 *
 * Flags:
 *   --in <file>     Read values from a file instead of stdin.
 *   --column <c>    Treat the input as CSV and fingerprint one column: a header
 *                   name (skips the header row) or a 1-based index (all rows).
 *                   Runs locally; only salted one-way hashes are ever written.
 *   --allow-sparse  With --column: skip rows whose selected cell is empty or
 *                   missing instead of failing; the skipped count is reported.
 *   --out <file>    Output path (default config/exact-match.json).
 *   --salt <value>  Reuse an existing salt (default: generate a fresh one and
 *                   reuse the salt already in --out if present, so appends work).
 *   --severity <n>  1-4 severity for a match (default 4).
 *   --min-len <n>   Minimum candidate length to fingerprint (default 20).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const detector = require('../detection-engine/detect');
const privatePaths = require('../server/private-path');
const fileMutationLock = require('../server/file-mutation-lock');

const PROFILE = detector.EDM_PROFILE;

function committedCleanupWarning(warning) {
  const retained = warning && warning.retainedPath ? `; retained=${warning.retainedPath}` : '';
  process.stderr.write(`[warn] committed EDM pack needs cleanup (${warning.code})${retained}\n`);
}

function arg(name, fallback, argv = process.argv.slice(2)) {
  const i = argv.indexOf('--' + name);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : fallback;
}

function readInput(argv) {
  const inFile = arg('in', null, argv);
  if (inFile) return fs.readFileSync(inFile, 'utf8');
  try { return fs.readFileSync(0, 'utf8'); } catch (e) { return ''; }
}

function compatibleProfile(value) {
  return value && value.formatVersion === PROFILE.formatVersion
    && value.algorithm === PROFILE.algorithm && value.valuePolicy === PROFILE.valuePolicy;
}

// Minimal CSV field parser: handles quoted fields, escaped ("") quotes, and
// commas inside quotes. Fail-closed on structure it cannot represent: a quote
// opening mid-field or a line ending inside an open quote (which is what an
// embedded newline in a quoted field looks like after splitting) throws, so a
// malformed roster can never silently shift or drop the fingerprinted column.
// Error messages carry structure only — never cell contents.
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
    } else if (ch === '"') {
      if (field.length) throw new Error('quote opened mid-field');
      inQuotes = true;
    } else if (ch === ',') { out.push(field); field = ''; } else field += ch;
  }
  if (inQuotes) throw new Error('quote not closed before end of line (embedded newlines in fields are not supported)');
  out.push(field);
  return out;
}

// Resolve `column` (header name, case-insensitive, or 1-based index) against
// the header row. Ambiguous duplicate header matches and unknown names throw
// with structural detail only (column counts, never header cell contents).
function selectCsvColumn(headerCells, column) {
  if (/^\d+$/.test(String(column))) {
    const idx = Number(column) - 1;
    if (!Number.isSafeInteger(idx) || idx < 0) throw new Error('--column index must be a positive integer');
    return { idx, dataStart: 0 };
  }
  const wanted = String(column).trim().toLowerCase();
  const matches = [];
  headerCells.forEach((h, i) => { if (h.trim().toLowerCase() === wanted) matches.push(i); });
  if (!matches.length) {
    throw new Error(`--column "${column}" not found in CSV header (${headerCells.length} column${headerCells.length === 1 ? '' : 's'})`);
  }
  if (matches.length > 1) {
    throw new Error(`--column "${column}" matches ${matches.length} CSV header columns; use a 1-based index instead`);
  }
  return { idx: matches[0], dataStart: 1 };
}

// Extract one column of values from CSV text as { values, skipped }, where
// values carry their physical 1-based source line and skipped lists rows whose
// selected cell is empty/missing. Callers fail closed on skipped rows unless
// sparse input was explicitly allowed.
function valuesFromCsv(text, column, options = {}) {
  const rows = [];
  String(text || '').split(/\r?\n/).forEach((raw, index) => {
    if (!raw.length) return;
    let cells;
    try { cells = parseCsvLine(raw); }
    catch (e) { throw new Error(`CSV row ${index + 1}: ${e.message}; no output was written`); }
    rows.push({ line: index + 1, cells });
  });
  if (!rows.length) return { values: [], skipped: [] };
  const { idx, dataStart } = selectCsvColumn(rows[0].cells, column);
  const values = [];
  const skipped = [];
  for (let r = dataStart; r < rows.length; r++) {
    const value = (rows[r].cells[idx] || '').trim();
    if (value) values.push({ value, line: rows[r].line });
    else skipped.push(rows[r].line);
  }
  if (skipped.length && !options.allowSparse) {
    const shown = skipped.slice(0, 12).join(', ');
    throw new Error(
      `${skipped.length} CSV row(s) have an empty or missing selected column; fix the export or pass ` +
      `--allow-sparse to skip them (line${skipped.length === 1 ? '' : 's'} ${shown}${skipped.length > 12 ? ', ...' : ''}); no output was written`
    );
  }
  return { values, skipped };
}

function readExisting(outPath) {
  if (!fs.existsSync(outPath)) return { salt: '', fingerprints: [] };
  let existing;
  try { existing = JSON.parse(fs.readFileSync(outPath, 'utf8')); }
  catch { throw new Error('existing EDM pack is unreadable or invalid JSON; no output was written'); }
  if (!existing || typeof existing !== 'object' || Array.isArray(existing)) {
    throw new Error('existing EDM pack must be a JSON object; no output was written');
  }
  return existing;
}

function selectedSalt(argv, existing) {
  const explicit = arg('salt', null, argv);
  if (explicit) return explicit;
  if (compatibleProfile(existing)
      && new RegExp(`^[A-Za-z0-9_-]{${PROFILE.saltMinLength},128}$`).test(String(existing.salt || ''))) {
    return existing.salt;
  }
  return crypto.randomBytes(24).toString('hex');
}

function selectedMinLength(argv, existing) {
  const raw = arg('min-len', compatibleProfile(existing) ? existing.minLen : PROFILE.minLen, argv);
  const value = Number(raw);
  if (!Number.isInteger(value) || value < PROFILE.minLen || value > 128) {
    throw new Error(`--min-len must be an integer between ${PROFILE.minLen} and 128`);
  }
  return value;
}

function inputValues(contents) {
  return String(contents).split(/\r?\n/).map((value, index) => ({
    value: value.trim(),
    line: index + 1,
  })).filter((entry) => entry.value);
}

function validateValues(values, minLen) {
  const invalid = values.filter((entry) => (
    entry.value.length < minLen || !detector.edmValueEligibility(entry.value).ok
  ));
  if (!invalid.length) return;
  const lines = invalid.slice(0, 12).map((entry) => entry.line).join(', ');
  throw new Error(
    `${invalid.length} EDM input value(s) violate ${PROFILE.valuePolicy}; no output was written ` +
    `(line${invalid.length === 1 ? '' : 's'} ${lines}${invalid.length > 12 ? ', ...' : ''})`
  );
}

function writePrivatePack(outPath, output) {
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const temp = path.join(path.dirname(outPath), `.${path.basename(outPath)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  let fd;
  let publicationStarted = false;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    privatePaths.securePrivatePath(temp, { fresh: true, label: 'EDM fingerprint pack staging file' });
    fs.writeFileSync(fd, output, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    publicationStarted = true;
    privatePaths.publishFileDurably(temp, outPath, {
      cleanupComponent: 'edm-pack-publication',
      onCommittedCleanupWarning: committedCleanupWarning,
    });
    privatePaths.assertPrivatePath(outPath, { label: 'EDM fingerprint pack' });
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* preserve original error */ }
    if (!publicationStarted) try { fs.unlinkSync(temp); } catch { /* staging cleanup only */ }
  }
}

function buildPack(argv, contents, existing) {
  const priorFingerprints = Array.isArray(existing.fingerprints) ? existing.fingerprints : [];
  if (priorFingerprints.length && !compatibleProfile(existing)) {
    throw new Error('existing EDM fingerprints use an unsafe legacy profile; rebuild from the complete high-entropy source list into a fresh output');
  }

  const salt = selectedSalt(argv, existing);
  if (!new RegExp(`^[A-Za-z0-9_-]{${PROFILE.saltMinLength},128}$`).test(salt)) {
    throw new Error(`--salt must contain ${PROFILE.saltMinLength}-128 ASCII letters, digits, underscores, or hyphens`);
  }
  const minLen = selectedMinLength(argv, existing);
  const severity = Math.max(1, Math.min(4, Number(arg('severity', 4, argv)) || 4));

  // Merging is only sound when the salt matches: fingerprints hashed under a
  // different salt can never match at detection time, so silently carrying them
  // forward under the new salt would leave dead, unmatchable entries.
  if (existing.salt && existing.salt !== salt && priorFingerprints.length) {
    throw new Error(
      `--salt differs from the existing pack salt; its ${priorFingerprints.length} existing ` +
      'fingerprints were hashed with the previous salt and would become unmatchable. Re-fingerprint the ' +
      'full value list into a fresh --out, or omit --salt to reuse the existing one.'
    );
  }

  // A CSV --column projects one input column into the same {value, line}
  // shape line-oriented input uses (with true source line numbers), so
  // eligibility validation and duplicate dedup stay identical. Extraction is
  // fail-closed: structural CSV problems and empty selected cells throw
  // unless --allow-sparse is passed.
  const input = packInputValues(argv, contents);
  const values = input.values;
  validateValues(values, minLen);
  const set = new Set(priorFingerprints);
  let added = 0;
  for (const entry of values) {
    const fp = detector.edmFingerprint(entry.value, salt);
    if (fp && !set.has(fp)) { set.add(fp); added++; }
    const digits = entry.value.replace(/\D/g, '');
    if (digits !== entry.value && digits.length >= minLen && detector.edmValueEligibility(digits).ok) {
      const dfp = detector.edmFingerprint(digits, salt);
      if (dfp && !set.has(dfp)) { set.add(dfp); added++; }
    }
  }

  return {
    pack: {
      formatVersion: PROFILE.formatVersion,
      algorithm: PROFILE.algorithm,
      valuePolicy: PROFILE.valuePolicy,
      salt,
      minLen,
      maxWords: PROFILE.maxWords,
      severity,
      enabled: set.size > 0,
      fingerprints: Array.from(set),
    },
    values: values.length,
    skippedRows: input.skippedRows,
    added,
  };
}

// Select the pack's input values: one CSV column when --column is given
// (fail-closed — a column that yields nothing is an error, not an empty pack),
// otherwise one value per line.
function packInputValues(argv, contents) {
  const column = arg('column', null, argv);
  if (!column) return { values: inputValues(contents), skippedRows: 0 };
  const extracted = valuesFromCsv(contents, column, { allowSparse: argv.includes('--allow-sparse') });
  if (!extracted.values.length) {
    throw new Error(`--column "${column}" produced no eligible values; no output was written`);
  }
  return { values: extracted.values, skippedRows: extracted.skipped.length };
}

function main(argv = process.argv.slice(2), io = process) {
  const outPath = path.resolve(arg('out', path.join(__dirname, '..', 'config', 'exact-match.json'), argv));
  const contents = readInput(argv);
  return fileMutationLock.withFileMutationLockSync(outPath, () => {
    const result = buildPack(argv, contents, readExisting(outPath));
    writePrivatePack(outPath, JSON.stringify(result.pack, null, 2) + '\n');
    const skipped = result.skippedRows ? `  rows skipped (empty selected column): ${result.skippedRows}\n` : '';
    io.stdout.write(`EDM watchlist written to ${outPath}\n  eligible values read: ${result.values}\n${skipped}  fingerprints added: ${result.added}\n  total fingerprints: ${result.pack.fingerprints.length}\n  (plaintext was not copied; only salted SHA-256 fingerprints are stored)\n`);
    return result;
  }, {
    cleanupComponent: 'edm-pack-lock',
    onCommittedCleanupWarning: committedCleanupWarning,
  });
}

if (require.main === module) {
  try { main(); }
  catch (e) {
    process.stderr.write(`${e && e.message ? e.message : e}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  buildPack,
  compatibleProfile,
  inputValues,
  main,
  parseCsvLine,
  selectCsvColumn,
  validateValues,
  valuesFromCsv,
};
