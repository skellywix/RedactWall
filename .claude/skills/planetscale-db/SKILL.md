---
name: planetscale-db
description: Index-aware schema design and git-style DB branching for serverless MySQL/Postgres via the pscale CLI. Directly relevant to PromptWall's roadmap item of moving off single-node SQLite to a "real database". Use when designing the production data layer for audit, queries, and approvals. Wraps the external PlanetScale skill.
---

# PlanetScale Database Skills

Teaches the agent to design schemas that scale and to treat schema changes as reviewable, branchable, reversible code — the discipline PromptWall needs as it graduates from `better-sqlite3`.

## Install (run it yourself)
```
brew install planetscale/tap/pscale
pscale auth login    # you authenticate; I won't enter credentials
npx skills add planetscale/agent-skill
```

## PromptWall context (the roadmap "real database")
Today state lives in `data/sentinel.db` (SQLite via `better-sqlite3`), with the tamper-evident, hash-chained audit table central to the compliance story. When migrating:
- **Preserve the hash-chain semantics** (`prevHash`, canonical entry hash, contentHash binding) exactly — the audit log's tamper-evidence is the product's examiner-facing promise. Verify `verifyAuditChain()`-equivalent logic post-migration.
- **Index the real query patterns:** audit by `queryId`/`ts`/`actor`; approval queue by status; detections by type/time for the dashboard. Add composite indexes for the dashboard's "top categories over time".
- **Branch per change:** `pscale branch create promptwall <feature>`, design, `pscale deploy-request create` — every schema change is reviewed like a PR.
- **Select only needed columns** (no `SELECT *`) on hot dashboard/audit paths.

## Rules
- A schema migration is a `goal-contract-loop` task: end state = tables + indexes created on a branch; evidence = deploy request + the existing `test/db.test.js` (ported) green; constraint = audit tamper-evidence preserved.
- Never migrate audit data in a way that breaks chain continuity; plan a verified cutover.
