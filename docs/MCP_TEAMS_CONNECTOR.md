# Microsoft Teams MCP Connector

PromptWall ships a first-party Microsoft Teams connector for MCP runtimes. It
reads bounded Teams channel or chat messages through Microsoft Graph, converts
message bodies to plain text, then calls `sanitizeTeamsChannelMessages()` or
`sanitizeTeamsChatMessages()` before returning a tool result to the model.

This connector is intentionally narrow. It protects read-only channel and chat
message content first. Replies, hosted content, files, exports across all users,
meeting transcripts, and rich attachment parsing should be added only after a
pilot needs those paths.

## Runtime Inputs

Channel messages required:

- `teamId`
- `channelId`
- Graph access token supplied as `accessToken`, `TEAMS_GRAPH_ACCESS_TOKEN`,
  `M365_GRAPH_ACCESS_TOKEN`, or `MICROSOFT_GRAPH_ACCESS_TOKEN`

Chat messages required:

- `chatId`
- Graph access token supplied as `accessToken`, `TEAMS_GRAPH_ACCESS_TOKEN`,
  `M365_GRAPH_ACCESS_TOKEN`, or `MICROSOFT_GRAPH_ACCESS_TOKEN`

Optional:

- `top` or `limit` up to the Microsoft Graph `$top` maximum of 50
- `orderby` and `filter` for supported chat-message date windows
- `TEAMS_TENANT_ID`, `M365_TENANT_ID`, or `AZURE_TENANT_ID` for connector
  health evidence
- `TEAMS_GRAPH_SCOPES` for connector health evidence
- `maxBytes` to reduce the default 512 KB message text limit

## Usage

```js
const {
  createTeamsChannelMessagesTool,
  createTeamsChatMessagesTool,
  teamsConnectorHealth,
} = require('./sensors/mcp-guard/connectors/teams');

const fetchChannelMessages = createTeamsChannelMessagesTool({
  accessToken: process.env.TEAMS_GRAPH_ACCESS_TOKEN,
  agent: 'claude-desktop',
  guardOptions: {
    server: process.env.SENTINEL_URL,
    key: process.env.INGEST_API_KEY,
  },
});

const channelMessages = await fetchChannelMessages({
  teamId: 'opaque-team-id',
  channelId: 'opaque-channel-id',
  top: 20,
});

const fetchChatMessages = createTeamsChatMessagesTool({
  accessToken: process.env.TEAMS_GRAPH_ACCESS_TOKEN,
  agent: 'claude-desktop',
  guardOptions: {
    server: process.env.SENTINEL_URL,
    key: process.env.INGEST_API_KEY,
  },
});

const chatMessages = await fetchChatMessages({
  chatId: 'opaque-chat-id',
  top: 20,
});

const health = teamsConnectorHealth({
  tenantId: process.env.TEAMS_TENANT_ID,
  scopes: ['ChannelMessage.Read.Group', 'ChatMessage.Read.Chat'],
}, true, 'OAuth probe ok');
```

`channelMessages` and `chatMessages` are safe to return to the MCP client. If
PromptWall detects sensitive content, the result contains a single redacted text
block. The control plane receives sanitized evidence only: redacted text, masked
findings, categories, risk metadata, destination label, and sensor version.

## Microsoft Graph Behavior

The connector follows the official Microsoft Graph Teams messaging split:

- Channel messages use `GET /teams/{team-id}/channels/{channel-id}/messages`.
- Chat messages use `GET /chats/{chat-id}/messages`.
- The connector sends `Authorization: Bearer {token}` and never includes a
  request body.

The returned `structuredContent` contains connector, operation, content type,
byte count, message count, and pagination flag only. It does not include team
IDs, channel IDs, chat IDs, message IDs, user IDs, Graph next links, access
tokens, or raw message text outside the sanitized MCP result.

## Permission Guidance

For delegated pilots, prefer the least privileged scope that matches the
approved conversation type. Microsoft Graph documents resource-specific
application permissions such as `ChannelMessage.Read.Group` and
`ChatMessage.Read.Chat`, and broader alternatives such as
`ChannelMessage.Read.All` or `Chat.Read.All` only when the customer approves the
access boundary.

Do not place Graph access tokens, refresh tokens, tenant secrets, team IDs,
channel IDs, chat IDs, message IDs, hosted-content URLs, or message text in
source code, package artifacts, screenshots, logs, or heartbeat details.

`npm run mcp:check` reports optional Teams connector health when these
environment values are present. It records token presence, optional tenant
presence, and scope count only. It does not print or post the Graph token.

## Limits

- The connector rejects unsupported path-shaped IDs before building Graph URLs.
- The connector caps `$top` at 50 messages per request.
- The connector rejects message text larger than the configured byte limit
  before returning it to the model.
- HTML message bodies are converted to plain text before scanning.
- The connector does not fetch replies, hosted content, SharePoint-backed files,
  meeting transcripts, or tenant-wide export APIs yet.

## Works Cited

Microsoft. "List channel messages." *Microsoft Learn*,
https://learn.microsoft.com/en-us/graph/api/channel-list-messages?view=graph-rest-1.0.
Accessed 4 July 2026.

Microsoft. "List messages in a chat." *Microsoft Learn*,
https://learn.microsoft.com/en-us/graph/api/chat-list-messages?view=graph-rest-1.0.
Accessed 4 July 2026.

Microsoft. "Working with Microsoft Teams messaging APIs in Microsoft Graph."
*Microsoft Learn*, https://learn.microsoft.com/en-us/graph/teams-messaging-overview.
Accessed 4 July 2026.
