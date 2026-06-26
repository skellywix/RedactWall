# PromptSentinel Stack Review

Reviewed: 26 June 2026

## Decision Summary

PromptSentinel should optimize for a regulated pilot that installs quickly, proves control effectiveness, and avoids unnecessary moving parts. The right stack is not the most fashionable one. It is the one that keeps browser, endpoint, MCP, and server behavior easy to verify.

## Changes Made

- Upgraded backend runtime framework from Express 4 to Express 5.
- Added Helmet for production security headers instead of maintaining all browser security headers by hand.
- Moved admin dashboard and login JavaScript from inline HTML into external static files:
  - `public/dashboard.js`
  - `public/login.js`
- Tightened CSP so `script-src` no longer needs `unsafe-inline`.
- Added static tests that prevent inline scripts and mojibake from creeping back into the admin frontend.
- Added Zod request-body validation for sensor and admin APIs, with sanitized field-only validation errors.

## Current Stack Verdict

| Area | Current Choice | Verdict | Rationale |
| --- | --- | --- | --- |
| Backend HTTP server | Node.js plus Express 5 | Keep | Express is still a strong fit for a small, auditable API server. Express 5 gives the current major version without a broad rewrite. |
| Request validation | Zod | Keep | Zod fits the current CommonJS app with compact runtime schemas, no separate schema build step, and enough structure to fail closed on bad sensor/admin bodies. |
| Security headers | Helmet plus custom `Permissions-Policy` | Keep | Helmet is purpose-built for Express security headers. The app keeps one custom header Helmet does not own directly. |
| Frontend dashboard | Static HTML, CSS, and vanilla JS | Keep for now | The dashboard is a small authenticated operations console. React, Next, or Vite would add a build chain before the UI needs it. External JS plus strict CSP solves the immediate security issue. |
| Browser extension | Chrome Manifest V3 plus vanilla JS | Keep | Extension and content-script code benefits from being dependency-light and easy to audit. |
| Database | SQLite through `better-sqlite3` | Keep for demo and pilot | SQLite fits the local-first, install-in-an-afternoon wedge. Move to Postgres only when multi-tenant hosted operation becomes real. |
| Tests | Node built-in test runner | Keep | The repo is CommonJS, API-heavy, and already has broad Node test coverage. No need to add Jest or Vitest yet. |
| File processing | `pdf-parse`, `adm-zip`, local processors | Keep with caution | Good enough for synthetic demos and small pilots now that corrupt, unreadable, and timed-out supported files fail closed. Production should still move parsing into a constrained worker and possibly add OCR later. |
| Packaging | Docker plus local Node install | Keep | This supports both developer demos and controlled pilot deployment. |

## Why Not React, Next.js, or Vite Right Now

The admin console is not a marketing site, a public app, or a complex client state machine. It is a logged-in security operations surface with a small number of views. A React/Vite migration would add dependency, build, and CSP concerns without improving the product's highest-risk surfaces today.

The better frontend improvement was to remove inline scripts and enforce `script-src 'self'`. That directly reduces XSS risk while preserving the no-build demo path.

Revisit Vite plus React when at least two of these become true:

- The dashboard needs reusable component state across many screens.
- The policy editor becomes complex enough to need typed client models.
- The app needs visual regression coverage and a build artifact anyway.
- The product team plans a hosted SaaS console separate from the local pilot console.

## Why Not Fastify Right Now

Fastify is a strong framework, especially for schema-first APIs and high-throughput services. PromptSentinel's current backend bottlenecks are not router performance. They are detection quality, evidence integrity, extension behavior, deployment safety, and file processing. Migrating from Express to Fastify would touch every route and test for limited immediate gain.

The better backend improvement was Express 5 plus Helmet, with real HTTP integration tests already in place.

Revisit Fastify when:

- API schemas become first-class product contracts.
- Request validation needs shared JSON Schema or OpenAPI artifacts for outside integrators.
- The service becomes multi-tenant and high-throughput enough for router performance to matter.

## Next Stack Improvements

1. Add Playwright browser checks for the admin console.
   The current static tests prove script placement and headers. Browser tests would prove login, policy save, evidence export, and queue actions render correctly.

2. Add TypeScript only when shared contracts become painful.
   The repo is currently small enough that CommonJS plus tests is fine. TypeScript becomes worth it when the extension, server, endpoint agent, and MCP guard share larger typed payloads.

3. Plan Postgres for hosted multi-tenant control plane.
   SQLite remains correct for local demos and pilots. Hosted SaaS needs tenant isolation, backups, migrations, and operational monitoring.

4. Move file parsing into a constrained worker process.
   Current guardrails add file limits, parser timeouts, and fail-closed behavior. A production hosted service should still isolate Office and PDF parsing from the main web process.

## Works Cited

Express. "Moving to Express 5." *Express*, OpenJS Foundation, https://expressjs.com/en/guide/migrating-5.html. Accessed 26 June 2026.

Helmet. "Helmet." *Helmet*, https://helmetjs.github.io/. Accessed 26 June 2026.

Node.js. "Test Runner." *Node.js Documentation*, OpenJS Foundation, https://nodejs.org/api/test.html. Accessed 26 June 2026.

OWASP Foundation. "Content Security Policy Cheat Sheet." *OWASP Cheat Sheet Series*, https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html. Accessed 26 June 2026.

SQLite. "Appropriate Uses For SQLite." *SQLite*, https://www.sqlite.org/whentouse.html. Accessed 26 June 2026.

Google. "Manifest V3." *Chrome for Developers*, https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3. Accessed 26 June 2026.

Vite. "Why Vite." *Vite*, https://vite.dev/guide/why.html. Accessed 26 June 2026.

Zod. "Intro." *Zod*, https://zod.dev/. Accessed 26 June 2026.
