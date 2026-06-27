# PromptSentinel Production Readiness Plan

## Goal

Move PromptSentinel from working proof of loop to a credible production baseline for regulated AI usage demos and pilots.

## Production Baseline Criteria

- Security admin console has standard web-app hardening: session stability, brute-force lockout, CSRF protection, safe cookies, security headers, and no raw PII in logs or errors.
- Sensors enforce policy consistently across browser prompts, browser file uploads, endpoint files, MCP tool output, and API/proxy calls.
- Detection quality is measured by `npm run eval`, not guessed. `alwaysBlock` types do not regress.
- Runtime evidence is examiner-friendly: tamper-evident audit, event export, policy history, approval history, reveal logging, and reproducible integrity checks.
- Deployment is demo-ready and pilot-ready: repeatable install, Docker path, health checks, stable secrets, reset procedure, and clear operator docs.
- Integration runway is visible: SIEM/webhook, managed browser deployment, endpoint service path, and MCP guard packaging.

## External Offering Comparison Snapshot

PromptSentinel should not try to out-platform Strac, Nightfall, Cyberhaven, or Lakera immediately. The wedge is a simpler install for smaller regulated shops, with examiner-grade proof and local-first prompt protection.

Observed market bar:

- Strac-style products emphasize broad AI DLP coverage across browser, endpoint, SaaS, MCP, and AI agent paths.
- Nightfall-style products emphasize many detectors, cloud DLP operations, browser coverage, and enterprise workflow integrations.
- Cyberhaven-style products emphasize data lineage, shadow AI discovery, and visibility into where sensitive data travels.
- Lakera-style products emphasize prompt injection, agent security, and LLM-facing runtime controls.

PromptSentinel differentiators to build toward:

- Local-first, examiner-friendly evidence in an afternoon install.
- One policy, three sensors, one shared detection engine.
- Tamper-evident audit as a first-class product object.
- Eccentric but useful controls: honeytoken/canary prompt detection, "safe-to-send" receipts, examiner export packs, shadow-AI risk postcards, and policy fire drills.

## Required Evidence Commands

Run at the end of every successful pass:

```bash
npm run hooks:install
npm run review:ci
node -e "console.log(JSON.stringify(require('./src/db').verifyAuditChain()))"
```

When detector behavior changes:

```bash
npm run eval
npm run simulate -- http://localhost:4000
```

When admin-console behavior changes:

```bash
npm run test:browser
```

When `shared/detect.js` changes:

```bash
npm run sync-engine
npm run sync-check
```

## Constraints

- Do not weaken `alwaysBlock` entities.
- Do not log or persist raw prompt text except encrypted held items covered by policy.
- Do not hand-edit `extension/lib/detect.js`; sync from `shared/detect.js`.
- Keep browser, endpoint, MCP, and server behavior aligned.
- Use synthetic sensitive data only.
- Commit every successful pass separately.
- Keep the commit-and-push process aligned: `pre-commit` must pass review checks before commit; post-commit push must only run after the same checks pass.

## Iteration Themes

1. Admin console hardening.
2. Sensor enforcement parity.
3. Audit/export/compliance evidence.
4. Managed deployment and pilot operations.
5. Integrations and alerting.
6. Detection quality and false-positive discipline.
7. Eccentric differentiators that fit the wedge.
