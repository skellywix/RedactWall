# PromptWall Competitive Alignment

## Goal

PromptWall should win the first regulated pilots by being easier to deploy,
easier to verify, and easier to explain to an examiner than broad enterprise
DLP platforms. The product should not chase every connector first. It should
prove that prompt, file, and agent traffic headed to AI tools is governed by one
policy, one local detection engine, and one tamper-evident evidence trail.

## Current Market Bar

- Strac points the market toward broad AI DLP coverage across tools such as
  ChatGPT and other employee AI usage paths. PromptWall should match the buyer
  expectation that sensitive data is stopped before it reaches a model, but keep
  the install smaller and more explainable.
- Prompt Security pushes visibility into employee GenAI usage, risk, and policy
  enforcement. PromptWall should make coverage posture and shadow-AI sightings
  obvious in the admin console, with no raw prompt bodies in the visibility
  layer.
- Harmonic-style AI governance products make inline employee coaching part of
  the value proposition, not an afterthought. PromptWall should keep guidance
  short, category-specific, and visible at the exact moment a user is about to
  leak data.
- Nightfall-style AI DLP raises the detection breadth bar with broad sensitive
  data coverage across AI apps, browsers, endpoints, and file uploads. PromptWall
  should not chase every detector immediately, but every blocked event should
  teach the user the safe substitute to use next time.
- OWASP's LLM risk work reinforces that prompt injection and sensitive
  information disclosure are first-class product risks, not edge cases.
  PromptWall should keep local prompt-injection defenses, response scanning,
  MCP redaction, and approval release checks in the core acceptance gate.

## Product Direction

Keep:

- Local-first browser, endpoint, and MCP sensors.
- One shared detection engine synced into the browser extension.
- Warn, justify, redact, block, approval release, and audited admin step-up.
- Shadow-AI discovery and coverage posture as control metadata only.
- Customer-silo AWS deployment until shared multi-tenant storage is deliberately
  redesigned.

Build next:

- Native desktop collector feeding the existing metadata-only endpoint handoff.
- Browser coverage tests that prove governed destinations receive active
  content-script protection when that is technically possible.
- App and action policy controls beyond destination and file-upload blocking,
  especially response-scanning controls.
- Data lineage views that answer which user, sensor, destination, category, and
  decision were involved without retaining sensitive content.
- Backup-status evidence inside the examiner export pack, including last backup
  verification and restore-drill evidence without prompt bodies.

## This Pass

- Rebrand the visible project from PromptSentinel to PromptWall.
- Keep compatibility-sensitive runtime contracts stable where breaking them
  would damage existing installs or retained evidence.
- Add active Poe browser protection because Poe was already a governed
  destination in policy and adapters.
- Add blocked destination policy controls across browser, endpoint, gate, file,
  and response paths, with `destination_blocked` evidence that does not retain
  prompt or file content.
- Add per-destination file-upload blocking so customers can allow chat while
  forbidding document uploads to selected tools, with `file_upload_blocked`
  evidence that does not retain uploaded bytes, extracted text, or sensitive
  filenames.
- Add inline employee coaching to the browser block/warn/justify banner so the
  user gets a concrete safe alternative for SSNs, credentials, confidential
  business context, source code, contracts, canary tokens, and other sensitive
  categories before anything leaves the page.
- Preserve legacy canary token compatibility while adding the PromptWall canary
  prefix.
- Add tested `PROMPTWALL_*` runtime aliases so new PromptWall deployments can
  use the renamed prefix without breaking existing `SENTINEL_*` installs.
- Expand the sanitized examiner evidence export with coverage posture, sensor
  versions, parsed policy history, and prompt/file lineage summaries by user,
  destination, sensor, category, channel, and decision.

## Acceptance Evidence

Run before accepting a completed pass:

```powershell
npm run sync-check
npm test
npm run eval
node -e "console.log(JSON.stringify(require('./server/db').verifyAuditChain()))"
```

When browser behavior changes, also run:

```powershell
npm run test:browser
npm run package:extension -- <temp-output-dir>
```

For examiner export changes, also run:

```powershell
npm test -- test/evidence.test.js test/policy-history.test.js
```

## Works Cited

OWASP Foundation. "OWASP Top 10 for Large Language Model Applications."
*OWASP GenAI Security Project*, OWASP Foundation, https://genai.owasp.org/llm-top-10/.
Accessed 27 June 2026.

Prompt Security. "Prompt Security." *Prompt Security*, Prompt Security,
https://www.prompt.security/. Accessed 27 June 2026.

Harmonic Security. "Harmonic Security | AI Governance & Control Platform."
*Harmonic Security*, Harmonic Security, https://www.harmonic.security/.
Accessed 28 June 2026.

Nightfall AI. "Nightfall: AI Data Security & Data Loss Prevention Platform."
*Nightfall AI*, Nightfall AI, https://www.nightfall.ai/.
Accessed 28 June 2026.

Strac. "ChatGPT DLP." *Strac*, Strac,
https://www.strac.io/integration/chatgpt-dlp. Accessed 27 June 2026.
