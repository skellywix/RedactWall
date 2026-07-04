# Slack MCP Connector

PromptWall ships a first-party Slack connector for MCP runtimes. It fetches
bounded Slack conversation history or text-readable private Slack file content,
then calls `sanitizeConversationHistory()` or `sanitizeSlackFileContent()`
before returning a tool result to the model.

This connector is intentionally narrow. It protects read-only message and file
content first. Channel search, thread traversal, admin exports, Slack Connect
tenant mapping, and rich attachment parsing should be added only after a pilot
needs those paths.

## Runtime Inputs

Conversation history required:

- `channel` or `channelId`
- Slack bot token supplied as `accessToken`, `SLACK_BOT_TOKEN`, or
  `SLACK_CONNECTOR_TOKEN`

File content required:

- `file` or `fileId`
- Slack bot token supplied as `accessToken`, `SLACK_BOT_TOKEN`, or
  `SLACK_CONNECTOR_TOKEN`

Optional:

- `limit`, `cursor`, `oldest`, `latest`, and `inclusive` for
  `conversations.history`
- `SLACK_TEAM_ID` or `SLACK_ENTERPRISE_ID` for connector health evidence
- `SLACK_SCOPES` for connector health evidence
- `maxBytes` to reduce the default 512 KB text download limit

## Usage

```js
const {
  createSlackConversationHistoryTool,
  createSlackFileContentTool,
  slackConnectorHealth,
} = require('./sensors/mcp-guard/connectors/slack');

const fetchSlackHistory = createSlackConversationHistoryTool({
  accessToken: process.env.SLACK_BOT_TOKEN,
  agent: 'claude-desktop',
  guardOptions: {
    server: process.env.SENTINEL_URL,
    key: process.env.INGEST_API_KEY,
  },
});

const history = await fetchSlackHistory({
  channel: 'opaque-slack-channel-id',
  limit: 15,
});

const fetchSlackFile = createSlackFileContentTool({
  accessToken: process.env.SLACK_BOT_TOKEN,
  agent: 'claude-desktop',
  guardOptions: {
    server: process.env.SENTINEL_URL,
    key: process.env.INGEST_API_KEY,
  },
});

const file = await fetchSlackFile({
  fileId: 'opaque-slack-file-id',
});

const health = slackConnectorHealth({
  teamId: process.env.SLACK_TEAM_ID,
  scopes: ['channels:history', 'groups:history', 'files:read'],
}, true, 'OAuth probe ok');
```

`history` and `file` are safe to return to the MCP client. If PromptWall
detects sensitive content, the result contains a single redacted text block.
The control plane receives sanitized evidence only: redacted text, masked
findings, categories, risk metadata, destination label, and sensor version.

## Slack API Behavior

The connector follows the official Slack Web API split:

- `conversations.history` returns message events for a channel, private
  channel, DM, or group DM when the token has the matching history scope.
- `files.info` returns file metadata. The connector then downloads
  `url_private_download` or `url_private` with the same bearer token.

The returned `structuredContent` contains connector, operation, content type,
byte count, message count, pagination flag, MIME type, and transfer mode only.
It does not include Slack channel IDs, file IDs, message timestamps, private
URLs, access tokens, or raw file text outside the sanitized MCP result.

## Permission Guidance

For delegated pilots, prefer the narrowest Slack scopes that match the allowed
conversation types. Public channels need `channels:history`; private channels
need `groups:history`; file reads need `files:read`. Add DM or MPIM scopes only
after the customer approves that access boundary.

Slack's current Web API documentation notes stricter rate limits for some
externally distributed non-Marketplace apps. Keep connector callers conservative:
default history fetches to 15 messages, use cursors, and avoid broad polling.

Do not place Slack bot tokens, refresh tokens, signing secrets, workspace IDs,
channel IDs, file IDs, private file URLs, or message text in source code,
package artifacts, screenshots, logs, or heartbeat details.

`npm run mcp:check` reports optional Slack connector health when these
environment values are present. It records token presence, optional tenant
presence, and scope count only. It does not print or post the Slack token.

## Limits

- The connector rejects unsupported binary content types by default.
- The connector rejects content larger than the configured byte limit before
  returning it to the model.
- Private file downloads are allowed only from Slack-controlled file hosts, and
  redirects are disabled for the file fetch.
- The connector removes Slack user, channel, and broadcast mention IDs from
  message text before sanitization.
- The connector does not parse images, PDFs, threads, reactions, or rich
  attachments yet.

## Works Cited

Slack. "conversations.history method." *Slack Developer Docs*,
https://docs.slack.dev/reference/methods/conversations.history/.
Accessed 4 July 2026.

Slack. "files.info method." *Slack Developer Docs*,
https://docs.slack.dev/reference/methods/files.info/.
Accessed 4 July 2026.

Slack. "File object." *Slack Developer Docs*,
https://docs.slack.dev/reference/objects/file-object/.
Accessed 4 July 2026.
