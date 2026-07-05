# Detection Benchmarks

Reference latency, throughput, and accuracy for PromptWall's shared detection
engine (`detection-engine/detect.js`). Reproduce locally with `npm run bench`
and `npm run eval`.

## How to read these numbers (important caveat)

These are **in-process, on-device** measurements: the cost of a single
`analyze()` call on the machine doing the scanning, with **no network hop**.
That is the real cost PromptWall pays per keystroke, paste, or file scan,
because detection runs locally in the browser extension, the endpoint agent,
the MCP guard, and the gateway — prompt text never leaves the institution to
be classified.

A cloud DLP publishes a different kind of number. Nightfall's prompt-sanitization
sample repo advertises **≤100 ms p99** and **≥1000 rps** — but those figures
describe a round-trip to their AWS service, and the customer-facing API is rate
limited to **5 rps (free) / 10 rps (enterprise)**. So the comparison is
apples-to-oranges: our number excludes a network the cloud number includes, and
we have no per-scan rate limit because there is no shared service to protect.
The honest takeaway is only this: even our **100 KB worst case** (a large pasted
document) finishes well under the 100 ms figure, and a typical short prompt is
sub-millisecond.

## Latency and throughput

Reference run: Node v22.22.2, Linux x64, single core, 2026-07-05. Percentiles
in milliseconds per `analyze()` call, after a 20-iteration JIT warmup. Numbers
are machine-dependent — re-run `npm run bench` on your own hardware.

| Workload | Bytes | p50 (ms) | p95 (ms) | p99 (ms) | Scans/sec |
|----------|------:|---------:|---------:|---------:|----------:|
| `benign-short` | 200 | 0.271 | 0.425 | 0.475 | 3,432 |
| `pii-short` | 218 | 0.317 | 0.479 | 0.593 | 2,974 |
| `paste-10kb` | 10,240 | 5.663 | 6.314 | 7.450 | 174 |
| `file-100kb` | 102,400 | 55.905 | 58.222 | 59.714 | 18 |
| `eval-corpus` | 41,749 | 22.944 | 24.206 | 24.833 | 43 |

`benign-short` is the per-keystroke hot path (no findings). `pii-short` is a
short prompt carrying an SSN and a card. `paste-10kb` and `file-100kb` model
large pastes and endpoint file scans. `eval-corpus` replays the entire held-out
corpus for a realistic mixed-content throughput number.

## Accuracy

Measured over the held-out labeled corpus (`test/fixtures/semantic-eval.json`,
**587 cases**: 271 semantic positives, 128 benign hard-negatives, 136 structured
positives, 52 adversarial bait). Run `npm run eval` for the full per-category
breakdown.

CI floors enforced by `scripts/eval-detect.js --ci`, `test/eval.test.js`, and
`suite/detector/eval-floors.suite.js`:

| Floor | Value |
|-------|------:|
| Semantic precision (per category) | ≥ 0.95 |
| Semantic recall (per category) | ≥ 0.80 |
| Structured recall (tested PII types) | ≥ 0.95 |
| Benign false positives | 0 |
| Adversarial bait false positives | 0 |

The zero-false-positive floors are the hard gate: a DLP control that cries wolf
on benign business prompts gets switched off.

## CI enforcement

- **Latency budgets** (`scripts/bench-detect.js` `BUDGETS`, gated on **p95** —
  p99 is GC-noisy at small N): `benign-short`/`pii-short` p95 ≤ 10 ms,
  `paste-10kb` p95 ≤ 100 ms, `file-100kb` p95 ≤ 1000 ms, short-prompt throughput
  ≥ 100 scans/sec. Held at ~10–20× headroom over the reference numbers so shared
  runners never flake, while still tripping on a real blow-up (e.g. catastrophic
  regex backtracking). Enforced by `test/bench-latency.test.js` (auto-run under
  `npm test`) and `suite/detector/latency-budget.suite.js`.
- **Accuracy floors** as above.

## Reproduce

```bash
npm run bench            # human-readable percentile report
npm run bench -- --json  # machine-readable metrics
npm run bench -- --ci    # exit 1 if any latency budget is exceeded
npm run eval             # precision / recall / F1 with the accuracy floors
```
