# MCP Connector SDK

PromptWall's MCP connector SDK is the required boundary for connector tool
results. It keeps `sensors/mcp-guard/guard.js` as the detection and redaction
boundary, then returns a model-safe MCP result shape to the caller.

Use it for any connector that fetches customer content from Microsoft 365,
SharePoint, OneDrive, Google Drive, Slack, Teams, Jira, databases, or internal
knowledge stores. The first shipped connector is
`sensors/mcp-guard/connectors/microsoft365.js`.

## Required Pattern

```js
const { sanitizeToolResult, wrapConnectorTool } = require('./sensors/mcp-guard/sdk');

async function fetchFile(args) {
  return {
    content: [{ type: 'text', text: await readConnectorText(args.fileId) }],
    structuredContent: { fileId: args.fileId },
  };
}

const guardedFetchFile = wrapConnectorTool(fetchFile, {
  agent: 'claude-desktop',
  connector: 'microsoft365',
  tool: 'driveItem.getContent',
});
```

`wrapConnectorTool()` calls `sanitizeToolResult()` before returning the tool
result to the model. If the shared engine finds sensitive content, the returned
MCP result is replaced with a single safe text content block. Raw connector
output is not sent to the control plane. The control plane receives only the
redacted text, masked findings, categories, risk metadata, destination label,
and sensor version.

For custom control flow, call `sanitizeToolResult()` directly:

```js
const safe = await sanitizeToolResult(rawToolResult, {
  agent: 'cursor-agent',
  connector: 'google-drive',
  tool: 'files.export',
});

return safe.result;
```

## Connector Health

Connector runtimes should report health with bounded check objects:

```js
const { connectorHealthCheck } = require('./sensors/mcp-guard/sdk');

const check = connectorHealthCheck({
  id: 'Microsoft 365 Graph',
  tenantId: process.env.AZURE_TENANT_ID,
  scopes: ['Files.Read.All', 'Sites.Read.All'],
}, true, 'OAuth probe ok');
```

Send those check objects through the existing sanitized sensor heartbeat path.
Do not include access tokens, refresh tokens, document IDs that encode customer
data, raw document text, or connector request bodies in health details.

## Connector Rules

- Call `sanitizeToolResult()` on every tool response before the model sees it.
- Keep OAuth tokens, refresh tokens, tenant secrets, and connector credentials
  outside source code and package artifacts.
- Include connector name, operation name, tenant ID, and scope count in health
  evidence when possible.
- Do not log raw tool output, raw prompt text, connector request bodies, or file
  bytes.
- Keep first-party connectors thin. Fetch content, pass it through the SDK, and
  let the shared detection engine and policy decide what is safe.

## Shipped Connector

PromptWall now includes a Microsoft 365 Graph driveItem content connector for
text-readable OneDrive and SharePoint files. It fetches the file body, applies
`sanitizeDriveItemContent()`, and returns only the sanitized MCP result. See
`docs/MCP_MICROSOFT365_CONNECTOR.md`.

Google Drive should follow only when a pilot needs it.

## Works Cited

Microsoft. "Get DriveItem Content." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0.
Accessed 28 June 2026.

Microsoft. "Microsoft Graph Permissions Reference." *Microsoft Learn*,
Microsoft, https://learn.microsoft.com/en-us/graph/permissions-reference.
Accessed 28 June 2026.
