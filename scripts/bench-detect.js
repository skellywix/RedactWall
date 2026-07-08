'use strict';
/**
 * Detection latency / throughput benchmark for the shared engine.
 *
 *   node scripts/bench-detect.js            # human-readable percentile report
 *   node scripts/bench-detect.js --json     # machine-readable metrics
 *   node scripts/bench-detect.js --ci       # exit 1 if any BUDGET is exceeded
 *
 * Why this exists: RedactWall runs analyze() ON-DEVICE, in-process, with no
 * network hop — unlike a cloud DLP whose "p99" includes a round-trip and a
 * customer rate limit. This measures the real cost of a scan so we can publish
 * an honest number (docs/product/DETECTION_BENCHMARKS.md) and catch order-of-magnitude
 * regressions (e.g. catastrophic regex backtracking) in CI. require()-able so
 * test/bench-latency.test.js can hold the same budgets.
 *
 * Timing is process.hrtime.bigint() around a single analyze() call, after a
 * warmup, over deterministic synthetic workloads. No raw prompt text is ever
 * printed — only workload name, byte size, iteration count, and timings.
 */
const path = require('path');
const D = require(path.join(__dirname, '..', 'detection-engine', 'detect'));

const FIXTURE = path.join(__dirname, '..', 'test', 'fixtures', 'semantic-eval.json');

// CI budgets — p95 ceilings with ~10-20x headroom over measured dev-machine
// numbers so shared runners never flake, while still tripping on a real
// blow-up. Gate on p95 (p99 is GC-noisy at small N); p99 is reported, not gated.
const BUDGETS = {
  'benign-short': { p95Ms: 10, minScansPerSec: 100 },
  'pii-short': { p95Ms: 10 },
  'paste-10kb': { p95Ms: 100 },
  'file-100kb': { p95Ms: 1000 },
};

// Deterministic synthetic workloads. Benign prose repeated to a target length,
// with synthetic PII appended per test/README.md conventions. No unseeded
// randomness — the same run produces the same strings every time.
const BENIGN_SENTENCE = 'The branch reviewed member onboarding steps and updated the quarterly service checklist. ';
const SYNTH_PII = ' Member SSN 123-45-6789, card 4111 1111 1111 1111, email jane.doe@example.com.';

function repeatTo(len) {
  let s = '';
  while (s.length < len) s += BENIGN_SENTENCE;
  return s.slice(0, len);
}

function buildWorkloads(deps = {}) {
  const readFile = deps.readFile || ((p) => require('fs').readFileSync(p, 'utf8'));
  let corpusText = '';
  try {
    const fixture = JSON.parse(readFile(FIXTURE));
    corpusText = [...fixture.semantic, ...fixture.structured].map((e) => e.text).join('\n');
  } catch (_) { corpusText = repeatTo(20000); }
  return {
    'benign-short': repeatTo(200),
    'pii-short': repeatTo(140) + SYNTH_PII,
    'paste-10kb': repeatTo(10 * 1024),
    'file-100kb': repeatTo(100 * 1024),
    'eval-corpus': corpusText,
  };
}

const DEFAULT_ITERS = {
  'benign-short': 2000, 'pii-short': 2000, 'paste-10kb': 1000, 'file-100kb': 200, 'eval-corpus': 200,
};

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

function runBench(opts = {}) {
  const scale = opts.quick ? 0.1 : (opts.iterations || 1);
  const workloads = buildWorkloads(opts);
  const results = {};
  for (const name of Object.keys(workloads)) {
    const text = workloads[name];
    const iters = Math.max(20, Math.round(DEFAULT_ITERS[name] * scale));
    // Warmup so V8 JIT has settled before we measure.
    for (let i = 0; i < 20; i++) D.analyze(text);
    const times = new Array(iters);
    for (let i = 0; i < iters; i++) {
      const t0 = process.hrtime.bigint();
      D.analyze(text);
      times[i] = Number(process.hrtime.bigint() - t0) / 1e6; // ms
    }
    times.sort((a, b) => a - b);
    const sum = times.reduce((a, b) => a + b, 0);
    results[name] = {
      bytes: Buffer.byteLength(text),
      iterations: iters,
      p50: round3(percentile(times, 50)),
      p95: round3(percentile(times, 95)),
      p99: round3(percentile(times, 99)),
      mean: round3(sum / iters),
      scansPerSec: Math.round(iters / (sum / 1000)),
    };
  }
  return results;
}

function round3(n) { return Math.round(n * 1000) / 1000; }

function failures(results) {
  const out = [];
  for (const name of Object.keys(BUDGETS)) {
    const r = results[name];
    if (!r) { out.push(`${name}: no result`); continue; }
    const b = BUDGETS[name];
    if (b.p95Ms != null && r.p95 > b.p95Ms) out.push(`${name} p95 ${r.p95}ms > ${b.p95Ms}ms budget`);
    if (b.minScansPerSec != null && r.scansPerSec < b.minScansPerSec) {
      out.push(`${name} throughput ${r.scansPerSec}/s < ${b.minScansPerSec}/s budget`);
    }
  }
  return out;
}

function report(results) {
  const L = ['DETECTION LATENCY (in-process analyze(), on-device, no network)'];
  L.push('  workload         bytes    iters     p50      p95      p99     mean   scans/s');
  for (const name of Object.keys(results)) {
    const r = results[name];
    L.push('  ' + name.padEnd(15) +
      String(r.bytes).padStart(7) + String(r.iterations).padStart(9) +
      (r.p50 + 'ms').padStart(9) + (r.p95 + 'ms').padStart(9) + (r.p99 + 'ms').padStart(9) +
      (r.mean + 'ms').padStart(9) + String(r.scansPerSec).padStart(10));
  }
  return L.join('\n');
}

function main(argv = process.argv.slice(2), deps = {}) {
  const io = deps.console || console;
  const setExitCode = deps.setExitCode || ((code) => { process.exitCode = code; });
  const results = (deps.runBench || runBench)(argv.includes('--quick') ? { quick: true } : {});
  const f = failures(results);
  if (argv.includes('--json')) {
    io.log(JSON.stringify({ results, budgets: BUDGETS }, null, 2));
  } else {
    io.log(report(results));
    io.log('\n' + (f.length ? 'BUDGETS EXCEEDED:\n  - ' + f.join('\n  - ') : 'All latency budgets met.'));
  }
  if (argv.includes('--ci') && f.length) setExitCode(1);
  return { results, failures: f };
}

if (require.main === module) main();

module.exports = { runBench, failures, report, main, buildWorkloads, BUDGETS };
