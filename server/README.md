# Server

The server is the RedactWall control plane: policy, ingest, approval workflow,
dashboard, evidence, and the tamper-evident audit log.

## Main Entry Points

| File | Purpose |
|------|---------|
| `app.js` | Express app, API routes, dashboard routes, SSE, heartbeat ingest |
| `policy.js` | Policy loading, normalization, destination controls, scanner config |
| `detector.js` | Server wrapper around the shared detection engine |
| `processors.js` | File extraction registry for uploads and endpoint evidence |
| `db.js` | SQLite store, query rows, audit log, retention purge, SCIM tables |
| `auth.js` | Console auth, roles, sessions, MFA, step-up checks |
| `coverage.js` | Fleet coverage, install-health posture, endpoint AI tool posture |
| `evidence.js` | Sanitized examiner evidence pack builder |

## Supporting Areas

| File or folder | Purpose |
|----------------|---------|
| `public/` | Static dashboard and login UI |
| `routing.js` | Approval ownership, SLA metadata, workflow helpers |
| `workflow.js` | Approval escalation and workflow state updates |
| `tenant.js` | SaaS tenant and managed-user enforcement |
| `scim.js`, `oidc.js` | Provisioning and SSO |
| `install-checks.js` | Shared install-check classification helpers |
| `notifiers.js`, `alerts.js` | Sanitized webhook, SIEM, and ticket notifications |

## Safety Rules

- Do not log or export raw prompt text, file text, OCR output, clipboard text,
  token vaults, ingest keys, handoff secrets, or release tokens.
- Audit entries should carry bounded metadata and hashes, not sensitive bodies.
- After changes to `db.js`, `crypto.js`, or audit behavior, verify:

```bash
node -e "console.log(require('./server/db').verifyAuditChain())"
```

- Keep admin write routes behind auth and CSRF checks.
- Keep sensor ingest routes behind the ingest key and validation schemas.
