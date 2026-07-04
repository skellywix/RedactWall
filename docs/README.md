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
| Monitor-only AI chat proxy lab | `AI_CHAT_DLP_PROXY_LAB.md` |
| Enforced AI LLM Gateway, shared limiter, and HA compose | `AI_LLM_GATEWAY.md` |
| Endpoint agent, MCP guard, Docker, secrets, health checks | `DEPLOYMENT.md` |
| Evidence pack schedule automation | `EVIDENCE_PACK_TASK.md` |
| Security trust package export | `SECURITY_TRUST_PACKAGE.md` |
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
| Google Drive connector | `MCP_GOOGLE_DRIVE_CONNECTOR.md` |
| Slack connector | `MCP_SLACK_CONNECTOR.md` |
| Microsoft Teams connector | `MCP_TEAMS_CONNECTOR.md` |
| Atlassian Jira and Confluence connector | `MCP_ATLASSIAN_CONNECTOR.md` |
| Database read-only connector | `MCP_DATABASE_READONLY_CONNECTOR.md` |

## Product And Evidence

| Topic | Document |
|-------|----------|
| Competitive positioning and product direction | `COMPETITIVE_ALIGNMENT.md` |
| Vendor-risk security trust package | `SECURITY_TRUST_PACKAGE.md` |
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
