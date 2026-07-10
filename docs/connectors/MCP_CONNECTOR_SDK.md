# MCP Connector SDK

RedactWall's MCP connector SDK is the required boundary for connector tool
results. It keeps `sensors/mcp-guard/guard.js` as the detection and redaction
boundary, then returns a model-safe MCP result shape to the caller.

Use it for any connector that fetches customer content from Microsoft 365,
SharePoint, OneDrive, Google Drive, Slack, Teams, Jira, Confluence, databases,
or internal knowledge stores. Shipped connectors live under
`sensors/mcp-guard/connectors/`.

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

`wrapConnectorTool()` checks request policy before calling `fetchFile()`, then
calls `sanitizeToolResult()` before returning the tool result to the model.
Blocked, approval-required, and non-allowlisted tools therefore cannot perform
the upstream read or side effect. If the shared engine finds sensitive content,
the returned MCP result is replaced with a single safe text content block. Raw
connector output is not sent to the control plane. The control plane receives
only label-safe policy evidence or redacted findings, categories, risk metadata,
destination label, and sensor version.

The SDK scans the complete serialized MCP envelope, including mixed text,
`resource_link`, `structuredContent`, and vendor-specific fields. Opaque binary
content and results that throw during inspection fail closed with a generic
text block; exception text and raw result fields are never forwarded or logged.

For custom control flow, use `executeConnectorTool()` so request policy is
enforced before the handler runs:

```js
const { executeConnectorTool } = require('./sensors/mcp-guard/sdk');

const safe = await executeConnectorTool(fetchFile, args, {
  agent: 'cursor-agent',
  connector: 'google-drive',
  tool: 'files.export',
}, guardOptions);

return safe.result;
```

`sanitizeToolResult()` is an output-only boundary. Call it directly only when
the host has already enforced `guardToolRequest()` before executing the tool.
Fetching or mutating first and then calling `sanitizeToolResult()` is unsafe
because a policy-blocked action has already happened.

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

## Connector Registry

RedactWall ships a metadata-only connector registry at
`sensors/mcp-guard/connector-registry.js`. It records which connector profiles
are shipped runtime versus profile templates:

- **Shipped** means connector code is included in the MCP guard package. Today
  that is Microsoft 365 Graph file content, Google Drive file content, Slack
  conversation/file content, Microsoft Teams message content, Jira/Confluence
  knowledge-base content, and read-only SQLite database query/schema results.
- **Template** means the connector profile, least-privilege scope shape, and
  install-health evidence contract are defined, but connector runtime code is
  not yet shipped. The current catalog has no template-only profiles.
- `npm run mcp:check -- --emit-heartbeat` sends only bounded registry checks
  such as `mcp_connector_registry` and `mcp_connector_profile_google_drive`.
  The checks include stage, status, and scope counts, not tokens, tenant
  secrets, document IDs, request bodies, or raw tool output.

The Agentic MCP dashboard and `/api/posture` use this registry to separate
source-code profile breadth from deployed install proof. A buyer should see
`installProof: true` only after a real MCP guard heartbeat reports the registry
checks.

## Connector Rules

- Use `wrapConnectorTool()` or `executeConnectorTool()` so policy is checked
  before execution and every response is sanitized before the model sees it.
- Never fetch, query, or mutate first and rely on output sanitization as tool
  policy enforcement.
- Keep OAuth tokens, refresh tokens, tenant secrets, and connector credentials
  outside source code and package artifacts.
- Include connector name, operation name, tenant ID, and scope count in health
  evidence when possible.
- Do not log raw tool output, raw prompt text, connector request bodies, or file
  bytes.
- Keep first-party connectors thin. Fetch content, pass it through the SDK, and
  let the shared detection engine and policy decide what is safe.

## Shipped Connectors

RedactWall now includes six first-party connector runtimes:

- Microsoft 365 Graph driveItem content for text-readable OneDrive and
  SharePoint files. It preflights request policy, fetches the file body, applies
  `sanitizeDriveItemContent()`, and returns only the sanitized MCP result. See
  `docs/connectors/MCP_MICROSOFT365_CONNECTOR.md`.
- Google Drive file content for Drive blob files and Google Workspace document
  exports. It applies `sanitizeDriveFileContent()` and returns only the
  sanitized MCP result. See `docs/connectors/MCP_GOOGLE_DRIVE_CONNECTOR.md`.
- Slack conversation history and text-readable private file content. It applies
  `sanitizeConversationHistory()` or `sanitizeSlackFileContent()` and returns
  only the sanitized MCP result. See `docs/connectors/MCP_SLACK_CONNECTOR.md`.
- Microsoft Teams channel and chat messages through Microsoft Graph. It applies
  `sanitizeTeamsChannelMessages()` or `sanitizeTeamsChatMessages()` and returns
  only the sanitized MCP result. See `docs/connectors/MCP_TEAMS_CONNECTOR.md`.
- Atlassian Jira issues and Confluence pages through the Jira Cloud and
  Confluence Cloud REST APIs. It applies `sanitizeJiraIssue()` or
  `sanitizeConfluencePage()` and returns only the sanitized MCP result. See
  `docs/connectors/MCP_ATLASSIAN_CONNECTOR.md`.
- Read-only SQLite query and schema inspection for bounded pilot databases. It
  allows only single-statement `SELECT` or `WITH` queries, opens the database in
  read-only mode, applies `sanitizeDatabaseRows()` or `sanitizeDatabaseSchema()`,
  and returns only the sanitized MCP result. See
  `docs/connectors/MCP_DATABASE_READONLY_CONNECTOR.md`.

## Works Cited

Microsoft. "Get DriveItem Content." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0.
Accessed 28 June 2026.

Microsoft. "Microsoft Graph Permissions Reference." *Microsoft Learn*,
Microsoft, https://learn.microsoft.com/en-us/graph/permissions-reference.
Accessed 28 June 2026.

Google. "Download and export files." *Google for Developers*,
https://developers.google.com/workspace/drive/api/guides/manage-downloads.
Accessed 4 July 2026.

Slack. "conversations.history method." *Slack Developer Docs*,
https://docs.slack.dev/reference/methods/conversations.history/.
Accessed 4 July 2026.

Slack. "files.info method." *Slack Developer Docs*,
https://docs.slack.dev/reference/methods/files.info/.
Accessed 4 July 2026.

Microsoft. "List channel messages." *Microsoft Learn*,
https://learn.microsoft.com/en-us/graph/api/channel-list-messages?view=graph-rest-1.0.
Accessed 4 July 2026.

Microsoft. "List messages in a chat." *Microsoft Learn*,
https://learn.microsoft.com/en-us/graph/api/chat-list-messages?view=graph-rest-1.0.
Accessed 4 July 2026.

Atlassian. "Get issue." *Jira Cloud Platform REST API*,
https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/.
Accessed 4 July 2026.

Atlassian. "Get page by id." *Confluence Cloud REST API v2*,
https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/.
Accessed 4 July 2026.

SQLite. "URI Filenames In SQLite." *SQLite Documentation*,
https://sqlite.org/uri.html. Accessed 4 July 2026.

WiseLibs. "better-sqlite3 API." *GitHub*,
https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md.
Accessed 4 July 2026.
