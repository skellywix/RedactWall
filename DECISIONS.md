# PromptSentinel Production Loop Decisions

- 2026-06-26: Use one verified pass per commit. Each pass must leave `npm test`, `npm run sync-check`, and audit integrity green.
- 2026-06-26: Compete on simple regulated deployment and examiner-grade evidence, not breadth-first connector count.
- 2026-06-26: Eccentric ideas are welcome only when they make the product easier to trust, operate, or demo.
- 2026-06-26: Admin unsafe actions require a session-bound CSRF header. Sensor ingest routes stay outside this middleware because they use ingest-key auth, not browser cookies.
- 2026-06-26: Use a conservative CSP that allows current inline dashboard assets but still locks framing, base URI, form target, connect sources, MIME sniffing, referrers, and browser feature access.
- 2026-06-26: SIEM/webhook alerts are best-effort and sanitized. Webhook failures must never block a user's request or leak raw prompt content into logs.
- 2026-06-26: Evidence exports use hashes for prompt bodies and audit details. Even redacted prompt text can contain sensitive category-only context, so exports omit bodies entirely.
- 2026-06-26: Canary tokens use explicit `PS-CANARY-...` or `PROMPTSENTINEL-CANARY-...` formats with enough suffix entropy to avoid flagging ordinary discussion of canaries.
- 2026-06-26: Managed Chrome deployment examples are treated as secret-bearing config because managed storage carries the ingest key. Source examples must keep placeholders only.
