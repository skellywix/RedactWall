# MCP Database Read-Only Connector

The database connector gives MCP agents bounded, read-only SQLite access for
pilot reporting and internal lookup workflows. RedactWall opens the database in
read-only mode, rejects write-capable SQL, bounds the result, runs rows through
the shared MCP guard, and returns only the sanitized MCP result to the model.

## What It Covers

- SQLite database files addressed by `sqlite://`, `file:`, or absolute paths.
- Optional `file:` URI `mode=ro` enforcement when a mode is supplied.
- Single-statement `SELECT` or `WITH` queries.
- Schema inspection for tables and views.
- Bounded row count, bounded JSON response size, and metadata-only query hash.
- MCP health and registry proof without DSNs, raw SQL text, row values, or
  database file paths in health details.

## Environment

Set these values in the MCP guard environment:

| Variable | Purpose |
| --- | --- |
| `MCP_DATABASE_DSN` | Absolute SQLite path, `sqlite://` path, or `file:` URI. |
| `MCP_DATABASE_LABEL` | Friendly label for health evidence. Defaults to `read-only-db`. |
| `MCP_DATABASE_SCOPES` | Optional scope evidence override. Defaults to `readonly`. |

Compatibility aliases are also accepted: `DATABASE_READONLY_DSN`,
`DATABASE_READONLY_LABEL`, and `DATABASE_READONLY_SCOPES`.

## Runtime

Use the connector helpers from
`sensors/mcp-guard/connectors/database-readonly.js`:

```js
const {
  createDatabaseReadonlyQueryTool,
  createDatabaseSchemaTool,
} = require('./sensors/mcp-guard/connectors/database-readonly');

const queryDatabase = createDatabaseReadonlyQueryTool({ agent: 'cursor-agent' });
const inspectSchema = createDatabaseSchemaTool({ agent: 'cursor-agent' });
```

The query tool accepts `sql` and optional `limit`. The schema tool accepts an
optional `limit`. Query results are wrapped with an outer `LIMIT`, normalized to
JSON-safe values, and scanned before model use.

## SQL Boundary

The connector rejects:

- Empty SQL.
- Statements longer than 5,000 characters.
- Semicolons and comments.
- Statements not starting with `SELECT` or `WITH`.
- Write or connection-control operations such as `INSERT`, `UPDATE`, `DELETE`,
  `CREATE`, `DROP`, `ALTER`, `ATTACH`, `DETACH`, `VACUUM`, `PRAGMA`, and
  transaction commands.

This is an MCP guardrail, not a replacement for database permissions. Use a
read-only database copy or a database user with the least privilege available.

## Validation

Run the focused tests:

```bash
node --test test/mcp-database-readonly-connector.test.js test/mcp-install-check.test.js
```

Run install proof with heartbeat output:

```bash
npm run mcp:check -- --emit-heartbeat --json
```

The heartbeat should include:

- `mcp_database_readonly_connector`
- `mcp_connector_profile_database_readonly`
- `mcp_database_readonly_dsn`
- `mcp_database_readonly_label`
- `mcp_database_readonly_scopes`

The detail fields are bounded metadata only. They must not include DSNs,
absolute file paths, raw SQL, row values, or raw tool output.

## Works Cited

SQLite. "URI Filenames In SQLite." *SQLite Documentation*,
https://sqlite.org/uri.html. Accessed 4 July 2026.

WiseLibs. "better-sqlite3 API." *GitHub*,
https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md.
Accessed 4 July 2026.
