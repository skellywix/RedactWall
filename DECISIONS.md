# PromptSentinel Production Loop Decisions

- 2026-06-26: Use one verified pass per commit. Each pass must leave `npm test`, `npm run sync-check`, and audit integrity green.
- 2026-06-26: Compete on simple regulated deployment and examiner-grade evidence, not breadth-first connector count.
- 2026-06-26: Eccentric ideas are welcome only when they make the product easier to trust, operate, or demo.
- 2026-06-26: Admin unsafe actions require a session-bound CSRF header. Sensor ingest routes stay outside this middleware because they use ingest-key auth, not browser cookies.
