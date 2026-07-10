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
 *
 * Flags:
 *   --in <file>     Read values from a file instead of stdin.
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
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    privatePaths.securePrivatePath(temp, { fresh: true, label: 'EDM fingerprint pack staging file' });
    fs.writeFileSync(fd, output, 'utf8');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    privatePaths.publishFileDurably(temp, outPath);
    privatePaths.assertPrivatePath(outPath, { label: 'EDM fingerprint pack' });
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* preserve original error */ }
    try { fs.unlinkSync(temp); } catch { /* renamed or best-effort cleanup */ }
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

  const values = inputValues(contents);
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
    added,
  };
}

function main(argv = process.argv.slice(2), io = process) {
  const outPath = path.resolve(arg('out', path.join(__dirname, '..', 'config', 'exact-match.json'), argv));
  const contents = readInput(argv);
  return fileMutationLock.withFileMutationLockSync(outPath, () => {
    const result = buildPack(argv, contents, readExisting(outPath));
    writePrivatePack(outPath, JSON.stringify(result.pack, null, 2) + '\n');
    io.stdout.write(`EDM watchlist written to ${outPath}\n  eligible values read: ${result.values}\n  fingerprints added: ${result.added}\n  total fingerprints: ${result.pack.fingerprints.length}\n  (plaintext was not copied; only salted SHA-256 fingerprints are stored)\n`);
    return result;
  });
}

if (require.main === module) {
  try { main(); }
  catch (e) {
    process.stderr.write(`${e && e.message ? e.message : e}\n`);
    process.exitCode = 1;
  }
}

module.exports = { buildPack, compatibleProfile, inputValues, main, validateValues };
