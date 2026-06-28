# Microsoft 365 MCP Connector

PromptWall ships a first-party Microsoft 365 Graph connector for MCP runtimes.
It fetches text-readable OneDrive or SharePoint driveItem content through
Microsoft Graph, then calls `sanitizeDriveItemContent()` before returning a tool
result to the model.

This connector is intentionally narrow. It protects text-readable file content
first. Office document conversion, PDF parsing, site search, and folder walking
should be added as separate capabilities after pilot needs are clear.

## Runtime Inputs

Required:

- `driveId`
- `itemId`
- Microsoft Graph access token supplied as `accessToken`,
  `M365_GRAPH_ACCESS_TOKEN`, or `MICROSOFT_GRAPH_ACCESS_TOKEN`

Optional:

- `M365_TENANT_ID` or `AZURE_TENANT_ID` for connector health evidence
- `M365_GRAPH_SCOPES` or `MICROSOFT_GRAPH_SCOPES` for connector health evidence
- `maxBytes` to reduce the default 512 KB text download limit

## Usage

```js
const {
  createDriveItemContentTool,
  microsoft365ConnectorHealth,
} = require('./sensors/mcp-guard/connectors/microsoft365');

const fetchMicrosoft365File = createDriveItemContentTool({
  accessToken: process.env.M365_GRAPH_ACCESS_TOKEN,
  agent: 'claude-desktop',
  guardOptions: {
    server: process.env.SENTINEL_URL,
    key: process.env.INGEST_API_KEY,
  },
});

const result = await fetchMicrosoft365File({
  driveId: 'drive-item-container-id',
  itemId: 'drive-item-id',
});

const health = microsoft365ConnectorHealth({
  tenantId: process.env.M365_TENANT_ID,
  scopes: ['Files.Read'],
}, true, 'OAuth probe ok');
```

`result` is safe to return to the MCP client. If PromptWall detects sensitive
content, the result contains a single redacted text block. The control plane
receives sanitized evidence only: redacted text, masked findings, categories,
risk metadata, destination label, and sensor version.

## Permission Guidance

For delegated pilots, prefer the least privileged `Files.Read` scope when the
agent only needs files the signed-in user can access. Use `Files.Read.All` only
when the customer has approved broader file read access. For app-only
production designs, prefer moving toward `Sites.Selected` plus explicit site
grants when the pilot scope allows it.

Do not place Graph access tokens, refresh tokens, client secrets, or tenant
secrets in source code, package artifacts, screenshots, logs, or heartbeat
details.

`npm run mcp:check` reports optional Microsoft 365 connector health when these
environment values are present. It records token presence, tenant presence, and
scope count only. It does not print or post the Graph access token.

## Limits

- The connector rejects unsupported binary content types by default.
- The connector rejects content larger than the configured byte limit before
  returning it to the model.
- The connector does not include `driveId` or `itemId` in the returned
  `structuredContent`; connector IDs can encode sensitive business context.
- The connector does not parse Office, PDF, image, or scanned content yet.

## Works Cited

Microsoft. "Get DriveItem Content." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0.
Accessed 28 June 2026.

Microsoft. "Microsoft Graph Permissions Reference." *Microsoft Learn*,
Microsoft, https://learn.microsoft.com/en-us/graph/permissions-reference.
Accessed 28 June 2026.
