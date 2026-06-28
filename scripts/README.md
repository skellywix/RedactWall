# Scripts

This folder holds operational commands behind `package.json` scripts. Prefer
the `npm run ...` aliases so arguments and cross-platform details stay in one
place.

## Common Commands

| Job | Command |
|-----|---------|
| Local setup | `npm run setup` |
| Production-style setup | `npm run setup:prod` |
| Start server | `npm start` |
| Full local gate | `npm run review:ci` |
| Detection eval | `npm run eval` |
| Demo guide drift check | `npm run docs:demo-guide:check` |

## Packaging And Release

| Job | Command |
|-----|---------|
| Browser extension package | `npm run package:extension` |
| Browser release readiness | `npm run release:extension:check` |
| Endpoint agent package | `npm run package:endpoint-agent` |
| MCP guard package | `npm run package:mcp-guard` |

## Install Checks

| Surface | Command |
|---------|---------|
| Endpoint agent | `npm run endpoint:check` |
| MCP guard | `npm run mcp:check` |
| Deployment preflight | `npm run setup:check` |

## Evidence And Maintenance

| Job | Command |
|-----|---------|
| Create backup | `npm run backup` |
| Verify backup | `npm run backup:verify` |
| Restore backup | `npm run backup:restore` |
| Export evidence pack | `npm run evidence:pack` |
| Export zipped evidence pack | `npm run evidence:pack:zip` |
| Refresh generated demo docs | `npm run docs:demo-guide` |
| Check docs sync task | `npm run docs:sync:check` |

Never print or commit real customer prompt text, ingest keys, handoff secrets,
OCR output, clipboard text, or local file contents from these scripts.
