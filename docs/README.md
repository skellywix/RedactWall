# PromptWall Documentation

Use this index when you know the job but not the file name.

## Start Here

| Job | Document |
|-----|----------|
| Install or operate PromptWall | `DEPLOYMENT.md` |
| Run a production pilot handoff | `TECHNICIAN_DEPLOYMENT_GUIDE.md` |
| Deploy the customer-silo AWS shape | `AWS_SAAS_DEPLOYMENT.md` |
| Run a sales or customer demo | `../DEMO_INSTALL_GUIDE.md` |
| Present the client-facing story | `SALES_DEMO_GUIDE.md` |
| Prepare a demo machine | `DEMO_TECHNICIAN_SETUP.md` |

## Deployment And Sensors

| Topic | Document |
|-------|----------|
| Managed browser extension rollout | `MANAGED_EXTENSION_DEPLOYMENT.md` |
| Browser extension release checklist | `EXTENSION_RELEASE_CHECKLIST.md` |
| Endpoint agent, MCP guard, Docker, secrets, health checks | `DEPLOYMENT.md` |
| Evidence pack schedule automation | `EVIDENCE_PACK_TASK.md` |
| Daily docs sync automation | `DOCUMENTATION_SYNC_TASK.md` |

## Identity, Policy, And Workflow

| Topic | Document |
|-------|----------|
| SCIM provisioning and OIDC login | `SCIM_PROVISIONING.md` |
| Entra and Okta setup | `IDENTITY_IDP_SETUP.md` |
| Scoped policy and time-bound exceptions | `POLICY_SCOPES.md` |
| Approval ownership, notifications, and SLA escalation | `APPROVAL_ROUTING.md` |

## MCP And Connectors

| Topic | Document |
|-------|----------|
| MCP connector SDK rules | `MCP_CONNECTOR_SDK.md` |
| Microsoft 365 connector | `MCP_MICROSOFT365_CONNECTOR.md` |

## Product And Evidence

| Topic | Document |
|-------|----------|
| Competitive positioning and product direction | `COMPETITIVE_ALIGNMENT.md` |
| Examiner evidence, backup, restore, retention | `DEPLOYMENT.md` |

## Generated Docs

`../DEMO_INSTALL_GUIDE.md`, `SALES_DEMO_GUIDE.md`, and
`DEMO_TECHNICIAN_SETUP.md` include generated current-state sections. Refresh
them with:

```bash
npm run docs:demo-guide
```

Check for drift with:

```bash
npm run docs:demo-guide:check
```
