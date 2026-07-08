# MCP Atlassian Connector

The Atlassian connector gives MCP agents guarded, read-only access to Jira
issues and Confluence pages. RedactWall fetches bounded content from Atlassian,
runs it through the shared MCP guard, and returns only the sanitized MCP result
to the model.

## What It Covers

- Jira Cloud issue reads through `GET /rest/api/3/issue/{issueIdOrKey}`.
- Confluence Cloud page reads through `GET /wiki/api/v2/pages/{id}`.
- Jira summary, description, and comments.
- Confluence storage, view, and Atlas document body formats.
- MCP health and registry proof without issue ids, page ids, tokens, request
  bodies, or raw connector output.

## Environment

Set these values in the MCP guard environment:

| Variable | Purpose |
| --- | --- |
| `ATLASSIAN_SITE_URL` | Atlassian Cloud site URL, for example `https://example.atlassian.net`. |
| `ATLASSIAN_ACCESS_TOKEN` or `ATLASSIAN_API_TOKEN` | OAuth bearer token or API token. |
| `ATLASSIAN_EMAIL` | Optional. When set with an API token, the connector uses Basic auth. |
| `ATLASSIAN_SCOPES` | Optional scope evidence override. Defaults to `read:jira-work read:page:confluence`. |

Compatibility aliases are also accepted: `JIRA_BASE_URL`,
`CONFLUENCE_BASE_URL`, `JIRA_API_TOKEN`, `CONFLUENCE_API_TOKEN`, `JIRA_EMAIL`,
`CONFLUENCE_EMAIL`, `JIRA_SCOPES`, and `CONFLUENCE_SCOPES`.

## Runtime

Use the connector helpers from
`sensors/mcp-guard/connectors/atlassian.js`:

```js
const {
  createJiraIssueTool,
  createConfluencePageTool,
} = require('./sensors/mcp-guard/connectors/atlassian');

const jiraIssue = createJiraIssueTool({ agent: 'claude-desktop' });
const confluencePage = createConfluencePageTool({ agent: 'claude-desktop' });
```

The Jira tool accepts `issueIdOrKey` and optional `fields`. The Confluence tool
accepts `pageId` and optional `bodyFormat`, one of `storage`,
`atlas_doc_format`, or `view`.

## Validation

Run the focused tests:

```bash
node --test test/mcp-atlassian-connector.test.js test/mcp-install-check.test.js
```

Run install proof with heartbeat output:

```bash
npm run mcp:check -- --emit-heartbeat --json
```

The heartbeat should include:

- `mcp_atlassian_connector`
- `mcp_connector_profile_jira_confluence`
- `mcp_atlassian_token`
- `mcp_atlassian_tenant`
- `mcp_atlassian_scopes`

The detail fields are bounded metadata only. They must not include access
tokens, issue keys, page ids, request bodies, or raw tool output.

## Works Cited

Atlassian. "Get issue." *Jira Cloud Platform REST API*,
https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/.
Accessed 4 July 2026.

Atlassian. "Get page by id." *Confluence Cloud REST API v2*,
https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/.
Accessed 4 July 2026.
