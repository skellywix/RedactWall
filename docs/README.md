# RedactWall Documentation

Use this index when you know the job but not the file name. Files are
organized by topic: `deployment/`, `demo/`, `identity/`, `connectors/`,
`reference/`, `security/`, `product/`, and `process/`.

## Start Here

| Job | Document |
|-----|----------|
| Move the SaaS to production end to end | `deployment/PRODUCTION_LAUNCH_GUIDE.md` |
| Install or operate RedactWall | `deployment/DEPLOYMENT.md` |
| Run a production pilot handoff | `deployment/TECHNICIAN_DEPLOYMENT_GUIDE.md` |
| Deploy the customer-silo AWS shape | `deployment/AWS_SAAS_DEPLOYMENT.md` |
| Run a sales or customer demo | `../DEMO_INSTALL_GUIDE.md` |
| Present the client-facing story | `demo/SALES_DEMO_GUIDE.md` |
| Prepare a demo machine | `demo/DEMO_TECHNICIAN_SETUP.md` |

## Deployment (`deployment/`)

| Topic | Document |
|-------|----------|
| Production launch sequence (AWS, domain, TLS, all portals) | `deployment/PRODUCTION_LAUNCH_GUIDE.md` |
| Endpoint agent, MCP guard, Docker, secrets, health checks | `deployment/DEPLOYMENT.md` |
| Customer-silo AWS stack (CloudFormation) | `deployment/AWS_SAAS_DEPLOYMENT.md` |
| Install-day production readiness runbook | `deployment/TECHNICIAN_DEPLOYMENT_GUIDE.md` |
| License signing keypair, issuing, rotation | `deployment/LICENSE_KEY_SETUP.md` |
| Managed Postgres control plane (shared-plane migration) | `deployment/MANAGED_POSTGRES.md` |
| Managed browser extension rollout | `deployment/MANAGED_EXTENSION_DEPLOYMENT.md` |
| Browser extension release checklist | `deployment/EXTENSION_RELEASE_CHECKLIST.md` |
| Enforced AI LLM Gateway, shared limiter, and single-host redundant compose | `deployment/AI_LLM_GATEWAY.md` |
| AI Gateway overview (OpenAI-compatible reverse proxy) | `deployment/AI_GATEWAY.md` |
| Squid ICAP network backstop | `deployment/ICAP_NETWORK_BACKSTOP.md` |
| Monitor-only AI chat proxy lab | `deployment/AI_CHAT_DLP_PROXY_LAB.md` |
| Agent hooks for Claude Code (prompts, shell, MCP tool calls) | `deployment/AGENT_HOOKS.md` |
| Evidence pack schedule automation | `deployment/EVIDENCE_PACK_TASK.md` |

## Demo (`demo/`)

| Topic | Document |
|-------|----------|
| Sales and client-facing demo script | `demo/SALES_DEMO_GUIDE.md` |
| Demo machine setup and reset | `demo/DEMO_TECHNICIAN_SETUP.md` |
| Demo install hub (generated, repo root) | `../DEMO_INSTALL_GUIDE.md` |

## Identity, Policy, And Workflow (`identity/`)

| Topic | Document |
|-------|----------|
| SCIM provisioning and OIDC login | `identity/SCIM_PROVISIONING.md` |
| Entra and Okta setup | `identity/IDENTITY_IDP_SETUP.md` |
| Console access roles and titles | `identity/ACCESS_ROLES.md` |
| Scoped policy and time-bound exceptions | `identity/POLICY_SCOPES.md` |
| Approval ownership, notifications, and SLA escalation | `identity/APPROVAL_ROUTING.md` |
| Email and digest notifications | `identity/NOTIFICATIONS.md` |

## API Reference (`reference/`)

| Topic | Document |
|-------|----------|
| Developer REST API (`/api/v1`) reference + OpenAPI spec | `reference/API_REFERENCE.md` |

## MCP And Connectors (`connectors/`)

| Topic | Document |
|-------|----------|
| MCP connector SDK rules | `connectors/MCP_CONNECTOR_SDK.md` |
| Microsoft 365 connector | `connectors/MCP_MICROSOFT365_CONNECTOR.md` |
| Google Drive connector | `connectors/MCP_GOOGLE_DRIVE_CONNECTOR.md` |
| Slack connector | `connectors/MCP_SLACK_CONNECTOR.md` |
| Microsoft Teams connector | `connectors/MCP_TEAMS_CONNECTOR.md` |
| Atlassian Jira and Confluence connector | `connectors/MCP_ATLASSIAN_CONNECTOR.md` |
| Database read-only connector | `connectors/MCP_DATABASE_READONLY_CONNECTOR.md` |

## Security And Compliance (`security/`)

| Topic | Document |
|-------|----------|
| Architecture, crypto inventory, threat model | `security/SECURITY_WHITEPAPER.md` |
| Security incident response runbook | `security/INCIDENT_RESPONSE.md` |
| Vendor-risk security trust package | `security/SECURITY_TRUST_PACKAGE.md` |
| NCUA Readiness Center and examiner pack | `security/NCUA_READINESS.md` |
| Codebase hardening review (July 2026) | `security/SECURITY_REVIEW_2026-07.md` |
| Vulnerability disclosure policy | `../SECURITY.md` |

## Product And Evidence (`product/`)

| Topic | Document |
|-------|----------|
| Product roadmap | `../ROADMAP.md` |
| Texas FCU product map and tab positioning | `product/TEXAS_FCU_PRODUCT_MAP.md` |
| Competitive positioning and product direction | `product/COMPETITIVE_ALIGNMENT.md` |
| Feature benchmark vs. market leaders | `product/COMPETITIVE_BENCHMARK_2026.md` |
| Sales battlecard vs. Nightfall AI (internal) | `product/BATTLECARD_NIGHTFALL.md` |
| Detection latency and accuracy benchmarks | `product/DETECTION_BENCHMARKS.md` |

## Engineering And Commercial Processes (`process/`)

| Topic | Document |
|-------|----------|
| Versioning, release train, artifacts, SBOM | `process/RELEASE_PROCESS.md` |
| Test tiers, gates, flaky policy, coverage | `process/TESTING_STRATEGY.md` |
| Documentation types, style, lifecycle | `process/DOCUMENTATION_STANDARDS.md` |
| License files, seats, expiry, pricing shape | `process/CUSTOMER_LICENSING.md` |
| Connected (vendor-managed) mode: heartbeat, kill-switch, seats | `process/CONNECTED_DEPLOYMENT.md` |
| Support severities, response targets, versions | `process/SUPPORT_POLICY.md` |
| Release history | `../CHANGELOG.md` |

## Generated Docs

`../DEMO_INSTALL_GUIDE.md`, `demo/SALES_DEMO_GUIDE.md`, and
`demo/DEMO_TECHNICIAN_SETUP.md` include generated current-state sections.
Refresh them with:

```bash
npm run docs:demo-guide
```

Check for drift with:

```bash
npm run docs:demo-guide:check
```
