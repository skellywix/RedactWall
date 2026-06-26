# CLAUDE.md

## Review Standards

- Keep functions under about 30 lines. Extract helpers when a function starts doing multiple jobs.
- Do not duplicate logic more than twice. Detector boilerplate belongs in `shared/detect.js`, not per sensor.
- Match the surrounding module's patterns before adding new abstractions.
- Avoid N+1 work over the `better-sqlite3` layer.
- Keep the hot detection path allocation-light because it runs on every keystroke and paste.
- Remove dead code and unused imports or exports.
- Use names that communicate intent.
- Put detector changes in `shared/detect.js`, then run `npm run sync-engine`. Never hand-edit `extension/lib/detect.js`.
- Do not log or throw raw prompt text, PII, or secrets.
- Keep the `shared/` public API stable because all sensors depend on it.
