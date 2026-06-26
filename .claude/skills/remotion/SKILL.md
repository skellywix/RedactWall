---
name: remotion
description: Create videos programmatically in React (no timeline editor). For PromptSentinel, use it for product demos and release clips — e.g. a 30s "watch it block an SSN paste" walkthrough, or an animated explainer of three-sensors-one-brain. Wraps the external Remotion agent skill.
---

# Remotion

Video as code: components + `useCurrentFrame()` animation, rendered to MP4. Removes the "video needs a separate team" excuse for demos and launch assets.

## Install (run it yourself — I don't run installers)
`npx skills add remotion/agent-skills` — then preview in Remotion Studio and render to MP4.

## PromptSentinel uses
- **The money demo:** 30s screen-capture-style clip — user pastes a synthetic SSN into ChatGPT, the block modal fires, the admin approves from the dashboard, the audit entry appears. This is the product's whole loop in one video.
- **Release notes:** short clips per shipped feature (new detector, redact mode).
- **Explainer:** animated "three sensors, one engine" diagram for the site/sales deck.

## Workflow
1. Describe the scene in a prompt; Remotion generates the React components.
2. Preview in Studio, adjust timing.
3. Render to MP4 for the README header / sales page / docs.

## Rules
- Synthetic data only in any on-screen prompt — never show real member PII.
- Keep brand/severity colors consistent with `frontend-design` (block=red, etc.).
- Demos are marketing assets, not tests — don't let a polished video stand in for `npm run simulate` evidence.
