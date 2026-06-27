---
name: dependency-upkeep-loop
description: Scheduled dependency hygiene loop. Audits for vulnerabilities, proposes safe version bumps, runs the full gate, and auto-merges only low-risk green updates while routing majors/risky ones to a human. Invoke with /dependency-upkeep-loop or schedule weekly with /loop.
---

# Dependency Upkeep Loop

Keeps the small dependency surface (`express`, `better-sqlite3`, `pdf-parse`, `adm-zip`, `cookie-parser`) current without surprise breakage. For a product an examiner trusts, a known-vulnerable dep is a finding.

## When to run
- Weekly: `/loop "Run the dependency-upkeep-loop skill" --schedule "0 9 * * 1"`.

## Loop
1. **Audit:** `npm audit` and `npm outdated`. Record findings in `STATUS.md`.
2. **Classify each update:**
   - *Low-risk* (patch/minor, no breaking notes): proceed.
   - *Risky* (major, native module like `better-sqlite3`, or anything touching `pdf-parse`/`adm-zip` which parse untrusted uploads): route to a human — these are attack surface.
3. **For low-risk, one package per branch:** `git worktree add ../ps-bump-<pkg> -b chore/bump-<pkg>`, bump, `npm ci`.
4. **Full gate:** `npm test` && `npm run sync-check` && `docker build -t promptsentinel:dep .`.
5. **Auto-merge low-risk on green** (maturity level 4): `gh pr create --fill && gh pr merge --auto --squash`. Risky ones get a PR with a written risk note and NO auto-merge.

## Stop condition (contract)
- Evidence: `npm audit` clean or remaining items triaged in `STATUS.md`; each merged bump has a green gate run.
- Constraints: never auto-merge a major or a parser/native dep; never bump and refactor in the same PR.

## Security note
`pdf-parse` and `adm-zip` process untrusted user uploads via `server/processors.js`. Treat their CVEs as priority and pair upgrades with a `bug-repro-fix-loop` regression test using a crafted sample.
