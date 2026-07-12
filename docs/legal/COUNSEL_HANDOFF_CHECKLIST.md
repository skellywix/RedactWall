# Counsel Handoff Checklist — DPA / BAA / GLBA Flow-Down

> The templates in this folder (`DPA_TEMPLATE_SAMPLE.md`, `BAA_TEMPLATE_SAMPLE.md`,
> `GLBA_FLOWDOWN_SAMPLE.md`) are **SAMPLE, non-binding drafts**. They become
> binding only after your legal counsel reviews, completes, and executes them.
> This checklist is what to hand counsel. It is **not legal advice**.

## Before sending to counsel
- [ ] Fill every `[bracketed]` term (party legal names, state, notice windows,
      retention periods, governing law).
- [ ] Confirm which agreements actually apply: a **BAA** is needed only if
      RedactWall will handle PHI on behalf of a HIPAA covered entity — many
      credit-union deployments do **not** need one.
- [ ] Attach the current **Security Trust Package** (`npm run security:package`)
      so counsel can map contract clauses to the per-control assurance levels and
      the NCUA due-diligence responses.

## What counsel should confirm
- [ ] **Roles & data flow** — that the DPA correctly reflects RedactWall as
      processor and the credit union as controller, and that on-device detection
      means member NPI is **not** transmitted to the processor for scanning.
- [ ] **Sub-processors** — that the "no default sub-processors" statement matches
      the actual deployment; list any that apply in the schedule.
- [ ] **Breach / incident notice windows** — that the processor's notice window
      (sample: 48h) leaves the credit union able to meet its **72-hour** NCUA
      reporting duty (12 CFR 748.1(c)), and that the GLBA/FTC 30-day path is
      covered where applicable.
- [ ] **Safeguards mapping** — that the security-measures clauses match what the
      product enforces (AES-256-GCM at rest, MFA, step-up, hash-chained audit).
- [ ] **Return / deletion** on termination, audit rights, and order of precedence.
- [ ] **Governing law**, indemnity, liability caps, and insurance requirements —
      none of which the samples opine on.

## After execution
- [ ] Record the executed-agreement reference in the credit union's vendor file.
- [ ] Note the DPA/BAA execution in the AI use-case inventory / vendor-oversight
      record so the examiner pack's `vendor_service_provider_oversight` control
      has a pointer.

## What RedactWall does NOT provide
RedactWall does not provide legal advice, does not draft jurisdiction-specific
terms, and does not warrant that these samples are sufficient for any particular
transaction. Engage qualified counsel.
