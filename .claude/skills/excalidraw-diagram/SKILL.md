---
name: excalidraw-diagram
description: Generate production-quality Excalidraw architecture/sequence diagrams from natural language, with a render-and-self-check loop so the output isn't broken. For PromptWall, use it to draw three-sensors-one-brain, the block→approve flow, and the audit hash-chain. Wraps the external excalidraw-diagram skill.
---

# Excalidraw Diagram Generator

Diagrams that argue, not just display — visual structure maps to conceptual structure, with a Playwright render → self-review → fix pass so you get a diagram you can publish.

## Install (run it yourself)
`npx skills add https://github.com/coleam00/excalidraw-diagram-skill --skill excalidraw-diagram`

## PromptWall diagrams worth keeping in the repo
- **Three sensors, one brain:** browser extension + endpoint agent + MCP guard all calling the shared `detection-engine/detect.js` engine, reporting to the control plane (policy, approval queue, audit, dashboard). Mirror the ASCII diagram in `README.md` as a real figure.
- **Enforcement flow:** prompt → detect → policy `evaluate()` → warn / justify / redact / block → (if block) held in approval queue → admin approve/deny → release. A decision/sequence diagram.
- **Audit hash-chain:** how each entry's hash covers the canonical entry + `prevHash` + evidence `contentHash` — the tamper-evidence story, drawn for examiners.
- **Redact mode:** tokenize on device → tokens leave → AI replies → de-tokenize locally (zero raw PII off-device).

## Why for this project
A regulator/board won't read `server/`. The architecture and audit diagrams are the artifacts that explain the compliance design and survive longer than any conversation. The self-validation loop means you ship a clean figure, not a first draft.

## Rules
- Use the skill's `references/color-palette.md` and align with `frontend-design` severity colors.
- Diagrams use synthetic/illustrative data only.
- Commit diagrams next to the docs they support (`README.md`, `docs/`).
