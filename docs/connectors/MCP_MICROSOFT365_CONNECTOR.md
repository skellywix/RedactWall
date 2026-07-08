# Microsoft 365 MCP Connector

RedactWall ships a first-party Microsoft 365 Graph connector for MCP runtimes.
It fetches text-readable OneDrive or SharePoint driveItem content, SharePoint
site page text, and SharePoint list item fields through Microsoft Graph, then
calls the matching `sanitize*()` helper before returning a tool result to the
model. Every operation shares the same guarantee: RedactWall scans and redacts
the Graph response before any model receives it.

This connector is intentionally narrow. It protects text-readable content
first. Office document conversion, PDF parsing, site search, and folder walking
should be added as separate capabilities after pilot needs are clear.

## Operations

| Tool factory | Operation | Graph request |
| --- | --- | --- |
| `createDriveItemContentTool` | `driveItem.getContent` | `GET /drives/{driveId}/items/{itemId}/content` |
| `createSitePageContentTool` | `sites.page.get` | `GET /sites/{siteId}/pages/{pageId}/microsoft.graph.sitePage?$expand=canvasLayout` |
| `createListItemFieldsTool` | `sites.listItem.get` | `GET /sites/{siteId}/lists/{listId}/items/{itemId}?$expand=fields` |

`sites.page.get` extracts text from the page's `canvasLayout` web parts
(`innerHtml` values converted to plain text). `sites.listItem.get` serializes
the expanded `fields` object to bounded `key: value` lines, including only
string, number, and boolean values and excluding system fields (`id`,
`@odata.*`, `ContentType`, `Edit`, `LinkTitle*`).

## Runtime Inputs

Required:

- `driveId` and `itemId` for `driveItem.getContent`
- `siteId` and `pageId` for `sites.page.get`
- `siteId`, `listId`, and `itemId` for `sites.listItem.get`
- Microsoft Graph access token supplied as `accessToken`,
  `M365_GRAPH_ACCESS_TOKEN`, or `MICROSOFT_GRAPH_ACCESS_TOKEN`

`siteId` accepts the composite Graph site id (hostname, site collection GUID,
and site GUID separated by commas). `pageId`, `listId`, and list `itemId` must
be numeric or GUID ids. The connector rejects ids with path separators or other
unexpected characters before building a Graph URL.

Optional:

- `M365_TENANT_ID` or `AZURE_TENANT_ID` for connector health evidence
- `M365_GRAPH_SCOPES` or `MICROSOFT_GRAPH_SCOPES` for connector health evidence
- `maxBytes` to reduce the default 512 KB text limit (applies to every
  operation)

## Usage

```js
const {
  createDriveItemContentTool,
  createListItemFieldsTool,
  createSitePageContentTool,
  microsoft365ConnectorHealth,
} = require('./sensors/mcp-guard/connectors/microsoft365');

const shared = {
  accessToken: process.env.M365_GRAPH_ACCESS_TOKEN,
  agent: 'claude-desktop',
  guardOptions: {
    server: process.env.REDACTWALL_URL,
    key: process.env.INGEST_API_KEY,
  },
};

const fetchMicrosoft365File = createDriveItemContentTool(shared);
const fetchSharePointPage = createSitePageContentTool(shared);
const fetchSharePointListItem = createListItemFieldsTool(shared);

const fileResult = await fetchMicrosoft365File({
  driveId: 'drive-item-container-id',
  itemId: 'drive-item-id',
});

const pageResult = await fetchSharePointPage({
  siteId: 'contoso.sharepoint.com,<site-collection-guid>,<site-guid>',
  pageId: '<site-page-guid>',
});

const listItemResult = await fetchSharePointListItem({
  siteId: 'contoso.sharepoint.com,<site-collection-guid>,<site-guid>',
  listId: '<list-guid>',
  itemId: '42',
});

const health = microsoft365ConnectorHealth({
  tenantId: process.env.M365_TENANT_ID,
  scopes: ['Files.Read', 'Sites.Read.All'],
}, true, 'OAuth probe ok');
```

Every result is safe to return to the MCP client. If RedactWall detects
sensitive content, the result contains a single redacted text block. The
control plane receives sanitized evidence only: redacted text, masked findings,
categories, risk metadata, destination label, and sensor version.

## Permission Guidance

For delegated pilots, prefer the least privileged `Files.Read` scope when the
agent only needs files the signed-in user can access. Use `Files.Read.All` only
when the customer has approved broader file read access.

The SharePoint site page and list item operations additionally require
`Sites.Read.All` (delegated) or `Sites.Selected` (app-only) with explicit site
grants. Prefer `Sites.Selected` plus per-site grants for app-only production
designs so the connector can only read approved sites.

Do not place Graph access tokens, refresh tokens, client secrets, or tenant
secrets in source code, package artifacts, screenshots, logs, or heartbeat
details.

`npm run mcp:check` reports optional Microsoft 365 connector health when these
environment values are present. It records token presence, tenant presence, and
scope count only. It does not print or post the Graph access token.

## Limits

- The driveItem operation rejects unsupported binary content types by default.
- Every operation rejects content larger than the configured byte limit before
  returning it to the model.
- The connector does not include `driveId`, `itemId`, `siteId`, `listId`, or
  `pageId` in the returned `structuredContent`; connector IDs can encode
  sensitive business context.
- List item serialization skips nested object fields (lookups, people,
  attachments metadata); only string, number, and boolean values are returned.
- The connector does not parse Office, PDF, image, or scanned content yet.

## Works Cited

Microsoft. "Get DriveItem Content." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/graph/api/driveitem-get-content?view=graph-rest-1.0.
Accessed 28 June 2026.

Microsoft. "Get SitePage." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/graph/api/sitepage-get?view=graph-rest-1.0.
Accessed 4 July 2026.

Microsoft. "Get ListItem." *Microsoft Learn*, Microsoft,
https://learn.microsoft.com/en-us/graph/api/listitem-get?view=graph-rest-1.0.
Accessed 4 July 2026.

Microsoft. "Microsoft Graph Permissions Reference." *Microsoft Learn*,
Microsoft, https://learn.microsoft.com/en-us/graph/permissions-reference.
Accessed 28 June 2026.
