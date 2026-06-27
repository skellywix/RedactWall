---
name: frontend-design
description: Produce distinctive, production-grade UI instead of generic "AI-generated" defaults (Inter + purple gradient + grid cards). Apply when building or restyling any PromptSentinel user-facing surface — the admin dashboard, approval queue, login. Self-contained; optionally pair with the official Anthropic frontend-design skill.
---

# Frontend Design

Escapes "distributional convergence" — the statistical-center look every model defaults to. Decide a design system BEFORE writing markup.

## Optional upstream skill
Official Anthropic skill (277k+ installs): `npx skills add anthropics/claude-code --skill frontend-design`. This file works on its own; the upstream skill adds more depth. (Run the install yourself — I don't run installers.)

## Before any code, commit to a system
1. **Point of view:** PromptSentinel is a compliance/security tool for credit-union security admins. Aim for "calm, trustworthy, dense-but-legible control panel" — not playful SaaS. Think audit console, not landing page.
2. **Type:** one distinctive but sober typeface pairing; real type scale; tabular numerals for the audit log and risk scores.
3. **Color:** a restrained palette with deliberate semantic colors — severity (block=red, justify=amber, warn=yellow, allow=green) must be consistent everywhere and colorblind-safe. No decorative gradients.
4. **Motion:** purposeful only (a row settling into the approval queue, a verdict badge). Nothing bouncy.

## PromptSentinel surfaces to apply it to
- **Dashboard** (`server/public/index.html`): detections over time, top PII categories, top destinations, pending approvals — information-dense, scannable.
- **Approval queue:** the admin's core job. Each held prompt: redacted preview, detected types as severity chips, requester + justification, one-click approve/deny with reason.
- **Login** (`server/public/login.html`): minimal, reassuring, no marketing.

## Rules
- Severity color + iconography is a design SYSTEM, defined once, reused. An examiner-facing tool must read consistently.
- Never show raw detected PII in the UI — show redacted/tokenized values with a gated reveal (matches the server's redact-first posture).
- Accessibility is non-negotiable: contrast, focus states, keyboard nav for the queue.

## Output
A short design rationale (the four choices above) + the implementation. State the system so the next session reuses it instead of re-converging on the default.
