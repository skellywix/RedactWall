# Google Drive MCP Connector

RedactWall ships a first-party Google Drive connector for MCP runtimes. It
downloads text-readable Drive blob files or exports Google Workspace documents,
then calls `sanitizeDriveFileContent()` before returning a tool result to the
model.

This connector is intentionally narrow. It protects read-only file content
first. Folder walking, shared-drive search, Docs comments, labels, image
classification, and PDF parsing should be added as separate capabilities after
pilot needs are clear.

## Runtime Inputs

Required:

- `fileId`
- Google Drive access token supplied as `accessToken`,
  `GOOGLE_DRIVE_ACCESS_TOKEN`, or `GOOGLE_WORKSPACE_ACCESS_TOKEN`

Optional:

- `mimeType` to skip metadata lookup when the caller already knows the file type
- `exportMimeType` for Google Workspace documents
- `GOOGLE_WORKSPACE_CUSTOMER_ID` or `GOOGLE_WORKSPACE_DOMAIN` for connector
  health evidence
- `GOOGLE_DRIVE_SCOPES` or `GOOGLE_WORKSPACE_SCOPES` for connector health
  evidence
- `maxBytes` to reduce the default 512 KB text download limit

## Usage

```js
const {
  createDriveFileContentTool,
  googleDriveConnectorHealth,
} = require('./sensors/mcp-guard/connectors/google-drive');

const fetchGoogleDriveFile = createDriveFileContentTool({
  accessToken: process.env.GOOGLE_DRIVE_ACCESS_TOKEN,
  agent: 'claude-desktop',
  guardOptions: {
    server: process.env.REDACTWALL_URL,
    key: process.env.INGEST_API_KEY,
  },
});

const result = await fetchGoogleDriveFile({
  fileId: 'opaque-drive-file-id',
});

const health = googleDriveConnectorHealth({
  workspaceDomain: process.env.GOOGLE_WORKSPACE_DOMAIN,
  scopes: ['https://www.googleapis.com/auth/drive.readonly'],
}, true, 'OAuth probe ok');
```

`result` is safe to return to the MCP client. If RedactWall detects sensitive
content, the result contains a single redacted text block. The control plane
receives sanitized evidence only: redacted text, masked findings, categories,
risk metadata, destination label, and sensor version.

## Download And Export Behavior

The connector follows the official Google Drive API split:

- Blob files use `files.get` with `alt=media`.
- Google Workspace documents use `files.export` with a text-oriented export
  MIME type.

When `mimeType` is omitted, the connector fetches bounded metadata first and
then chooses media download versus document export. The returned
`structuredContent` contains connector, operation, content type, byte count,
transfer mode, and MIME type only. It does not include `fileId`, filename,
document URL, access token, or raw file text outside the sanitized MCP result.

## Permission Guidance

For delegated pilots, prefer the least privileged read-only Drive scope:
`https://www.googleapis.com/auth/drive.readonly`. Use broader Google Workspace
scopes only after the customer approves the access boundary.

Do not place Google access tokens, refresh tokens, client secrets, customer
IDs that identify sensitive tenants, document IDs, or document URLs in source
code, package artifacts, screenshots, logs, or heartbeat details.

`npm run mcp:check` reports optional Google Drive connector health when these
environment values are present. It records token presence, optional tenant
presence, and scope count only. It does not print or post the access token.

## Limits

- The connector rejects unsupported binary content types by default.
- The connector rejects content larger than the configured byte limit before
  returning it to the model.
- Google Workspace exports use text-oriented formats by default:
  Google Docs and Slides to `text/plain`, Sheets to `text/csv`, and Drawings to
  `image/svg+xml`.
- The connector does not parse PDFs, scanned files, images, or rich Office
  documents yet.

## Works Cited

Google. "Download and export files." *Google for Developers*,
https://developers.google.com/workspace/drive/api/guides/manage-downloads.
Accessed 4 July 2026.

Google. "Method: files.get." *Google for Developers*,
https://developers.google.com/workspace/drive/api/reference/rest/v3/files/get.
Accessed 4 July 2026.

Google. "Method: files.export." *Google for Developers*,
https://developers.google.com/workspace/drive/api/reference/rest/v3/files/export.
Accessed 4 July 2026.

Google. "Export MIME types for Google Workspace documents."
*Google for Developers*,
https://developers.google.com/workspace/drive/api/guides/ref-export-formats.
Accessed 4 July 2026.
