# Data Processing Addendum (DPA) — SAMPLE

> **SAMPLE — NON-BINDING.** This template is provided for procurement
> convenience only. It is **not legal advice** and does **not** create any
> obligation. Review and execute only after review by your own legal counsel.
> RedactWall (the "Processor") and the credit union (the "Controller") should
> tailor every bracketed term.

## 1. Parties and roles
- **Controller:** [Credit Union legal name], a federally insured credit union.
- **Processor:** [RedactWall entity].
- The Processor processes Controller data solely to provide the RedactWall
  inline DLP service and only on the Controller's documented instructions.

## 2. Nature and purpose of processing
- **Purpose:** on-device detection of sensitive data in AI prompts, policy
  enforcement, approval workflow, and tamper-evident audit evidence.
- **Data minimization:** detection runs on the Controller's endpoints/control
  plane; only masked findings, hashes, and bounded metadata are retained.
  Raw prompt bodies, secrets, and token vaults are excluded from exports.

## 3. Categories of data and data subjects
- **Data subjects:** members, employees, and third parties whose data may be
  entered into AI tools.
- **Categories:** member NPI (as flagged: SSN, member/account/loan/routing
  numbers, card numbers, DOB, TIN), credentials/secrets, and business content.

## 4. Sub-processors
- The Processor uses **no default sub-processors** for the local-first
  deployment. Any sub-processor is disclosed in Schedule A and governed by
  terms no less protective than this DPA; the Controller is notified before a
  sub-processor is added and may object.

## 5. Security measures (GLBA 12 CFR 748 Appendix A)
- AES-256-GCM encryption of retained approval data; TOTP MFA for administrators;
  HMAC-signed sessions and CSRF protection; SHA-256 hash-chained, tamper-evident
  audit log; least-privilege console roles including a read-only Auditor role.

## 6. Incident notification
- The Processor notifies the Controller without undue delay and no later than
  **[48] hours** after becoming aware of a personal-data breach affecting
  Controller data, to support the Controller's **72-hour** NCUA reporting duty
  (12 CFR 748.1(c)).

## 7. Data subject requests, audits, return/deletion
- The Processor assists the Controller with data-subject requests, makes
  available information needed to demonstrate compliance, and returns or deletes
  Controller data on termination per Schedule A.

## 8. Term and governing law
- This DPA runs coterminous with the underlying agreement. Governing law:
  [state]. Order of precedence: this DPA controls over conflicting terms as to
  data protection.

_Schedules: A (sub-processors, return/deletion), B (security measures)._
