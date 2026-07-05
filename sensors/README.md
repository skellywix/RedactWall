# Sensors

RedactWall has three sensor surfaces. They all run the shared detector locally
and send bounded evidence to the control plane.

| Sensor | Path | What it covers |
|--------|------|----------------|
| Browser extension | `browser-extension/` | AI chat typing, paste, file drop/upload, response copy, shadow-AI discovery |
| Endpoint agent | `endpoint-agent/` | Watched files, native handoff events, protected upload, clipboard guard, OCR, endpoint AI tool inventory |
| MCP guard | `mcp-guard/` | MCP tool results before content reaches a model |
| Agent hooks | `agent-hooks/` | Claude Code prompts, shell commands, and MCP tool calls before model/tool execution |

## Shared Engine Rule

The canonical detector lives in `detection-engine/detect.js`.

After detector edits, run:

```bash
npm run sync-engine
npm run sync-check
```

Do not hand-edit `browser-extension/lib/detect.js`; it is a synced copy.

## Install Validation

| Sensor | Validation command |
|--------|--------------------|
| Browser extension | `npm run release:extension:check` |
| Endpoint agent | `npm run endpoint:check` |
| MCP guard | `npm run mcp:check` |
| Agent hooks | `npm run agent-hooks:check` |

Use `../docs/DEPLOYMENT.md` for operator details and
`../docs/TECHNICIAN_DEPLOYMENT_GUIDE.md` for customer handoff.
