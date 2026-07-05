# Vendored tesseract language data

`eng.traineddata.gz` is the tesseract English LSTM model (the compact
integer-quantized `best_int` build), vendored here so the endpoint agent's
bundled WASM OCR fallback runs fully offline. Model paths are hard-pinned to
this directory in `sensors/endpoint-agent/ocr-wasm.js`; the agent never fetches
model weights from a network.

- Engine: [`tesseract.js`](https://github.com/naptha/tesseract.js) — Apache-2.0.
- Language data: tesseract `eng` traineddata, distributed via the
  `@tesseract.js-data/eng` package — Apache-2.0.

To refresh the model, replace this file with a newer `eng.traineddata.gz` from
that package and re-run `npm run package:endpoint-agent`.
