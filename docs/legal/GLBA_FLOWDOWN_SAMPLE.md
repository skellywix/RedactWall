# GLBA Service-Provider Flow-Down Clauses — SAMPLE

> **SAMPLE — NON-BINDING.** Provided for procurement convenience only. This is
> **not legal advice** and creates no obligation. Review and execute only with
> your legal counsel. These clauses are intended to be inserted into a master
> services agreement between a credit union and RedactWall.

Under the Gramm-Leach-Bliley Act and the NCUA Guidelines for Safeguarding
Member Information (12 CFR Part 748, Appendix A), a credit union must require
its service providers to protect member information. The following flow-down
clauses map RedactWall's controls to those obligations.

## 1. Safeguarding member information
The Provider shall implement and maintain administrative, technical, and
physical safeguards designed to protect the security, confidentiality, and
integrity of member nonpublic personal information (NPI), consistent with 12 CFR
748 Appendix A. Detection is performed on the Credit Union's endpoints/control
plane and NPI is not transmitted to the Provider for scanning.

## 2. Access controls
The Provider shall enforce least-privilege access, multi-factor authentication
for administrative access, and step-up authentication for reveal or release of
retained sensitive data.

## 3. Encryption
The Provider shall encrypt retained sensitive data at rest (AES-256-GCM) and
require HTTPS/TLS for any optional network features; no member NPI leaves the
Credit Union's environment for scanning.

## 4. Monitoring and audit
The Provider shall maintain a tamper-evident, hash-chained audit log of
enforcement decisions, verifiable by the Credit Union, and shall provide
examiner-ready evidence exports that exclude prompt bodies and raw findings.

## 5. Incident response and reporting
The Provider shall notify the Credit Union without undue delay upon becoming
aware of a security incident affecting Credit Union data, in time to support the
Credit Union's **72-hour** reporting obligation under 12 CFR 748.1(c). The Credit
Union remains responsible for filing with the NCUA.

## 6. Testing of controls
The Provider shall support the Credit Union's obligation to **regularly test key
controls** (Appendix A) by providing verification tooling (audit-chain
verification, backup/restore drills, and published detection benchmarks).

## 7. Subcontractors / sub-processors
The Provider shall not engage a sub-processor with access to Credit Union data
without prior disclosure and shall bind any such sub-processor to protections no
less strict than these clauses. The local-first deployment uses no default
sub-processors.

## 8. Oversight and right to audit
The Provider shall make available control documentation (Security Trust Package,
SBOM, and this due-diligence response) to support the Credit Union's ongoing
third-party oversight under NCUA 07-CU-13 and 01-CU-20.
