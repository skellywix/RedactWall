---
name: agent-self-validation
description: Make the agent prove its change works end-to-end before it hands back — not just green unit tests (tests pass while the product is still broken, constantly). Keep "how to exercise the app" in AGENTS.md, force real E2E evidence (run the app, screenshots, simulation output), and attach it to the PR. Invoke with /agent-self-validation or bake it into every implementation.
---

# Agent Self-Validation (E2E evidence)

Frontier models lean on unit tests because of how they're trained — but unit-green, product-broken is one of the most common failure modes. Before a change comes back, the agent must demonstrate the feature actually works.

## Two requirements
1. **The repo tells the agent how to exercise the app.** Keep explicit steps in `AGENTS.md` so any fresh agent can validate end-to-end without you explaining it each time.
2. **Force E2E evidence.** The change isn't done until the agent has produced artifacts proving it works in the real product, attached as a **Testing** section on the PR.

## PromptWall E2E evidence menu (pick what the change touches)
- **Detection change:** `npm run simulate` over the sample corpus — show before/after verdicts for the relevant prompts (use **synthetic** PII only). For `alwaysBlock` types, prove they still block.
- **Browser sensor:** load the unpacked `sensors/browser-extension/` in a test Chrome profile, paste a synthetic SSN into a chat box, screenshot the block modal AND confirm no request left the page (see `browser-use`).
- **Policy/enforcement:** flip `config/policy.json` mode, show warn vs require-justification vs redact vs block behaving correctly; in redact mode confirm only tokens leave.
- **Audit/DB:** `node -e "require('./server/db').verifyAuditChain()"` → `ok:true`; show a tampered-row case returning `ok:false`.
- **Server endpoints:** exercise the approval-queue flow (block → hold → approve → release) and capture the audit entries.

## Output
A short, reproducible **Testing** section: the commands run, their output, and screenshots where UI is involved. This is the evidence the `no-mistakes-review` pipeline demands and what lets you merge without reading every line.
