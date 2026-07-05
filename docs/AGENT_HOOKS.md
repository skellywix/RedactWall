# Agent Hooks (Claude Code)

The agent-hooks sensor extends "three sensors, one brain" to the developer-agent
path. It scans **prompts, shell commands, and MCP tool calls** issued through
Claude Code and applies the same org policy the browser extension and endpoint
agent apply — blocking secrets, PII, and prompt-injection **before** they reach
the model or the shell.

Everything is decided **on the box**. Unlike a cloud DLP that must ship agent
content to a remote service to classify it, this sensor runs `detection-engine`
locally and never sends prompt or command text anywhere to make a decision. The
control plane receives only a **label-only, post-decision** telemetry record
(e.g. `US_SSN`, `SECRET_KEY`), and only for warn/block events.

## What it covers

| Claude Code event | What is scanned | Channel |
|-------------------|-----------------|---------|
| `UserPromptSubmit` | the prompt text | `agent_prompt` |
| `PreToolUse` (Bash) | the shell command + description | `agent_shell` |
| `PreToolUse` (`mcp__*`) | the MCP tool call (name + input) | `agent_mcp` |

MCP tool calls are additionally checked against the policy's
`mcpAllowedTools` / `mcpBlockedTools` / `mcpApprovalRequiredTools` lists — the
same wildcard rules the MCP guard enforces — so a blocked tool is denied and an
approval-required tool prompts (`ask`) before it runs.

## Install

The hook reads `INGEST_API_KEY` and `SENTINEL_URL` (or `PROMPTWALL_URL`) from the
environment or `~/.promptwall/agent-hooks.env`. The **ingest key is never written
into `settings.json`.**

```bash
# preview the settings snippet without writing anything
npm run agent-hooks:install -- --print

# merge into ~/.claude/settings.json (idempotent)
npm run agent-hooks:install

# or into the current repo's .claude/settings.json
npm run agent-hooks:install -- --project

# remove only PromptWall-owned entries
npm run agent-hooks:install -- --uninstall

# verify the install and register presence in the fleet/coverage matrix
npm run agent-hooks:check
npm run agent-hooks:check -- --heartbeat
```

## Enforcement semantics

- A **hard-stop entity** (`alwaysBlock`, e.g. `US_SSN`, `SECRET_KEY`,
  `PRIVATE_KEY`, `CANARY_TOKEN`) always blocks, regardless of enforcement mode.
- Otherwise the org's `enforcementMode` maps to the decision: `block` → deny,
  `warn` → `ask`, `redact`/`justify` → deny (no rewrite path in v1).
- With the control plane unreachable, enforcement still happens against a cached
  or conservative built-in policy; telemetry is best-effort.
- On malformed input or any internal error the hook **fails open** (exit 0) so it
  never breaks the agent. It exits `2` only to deliberately block.

## Scope and limits

- This is a **coverage + audit** control, not a tamper-proof one: a developer who
  edits `~/.claude/settings.json` can remove the hook. `npm run agent-hooks:check`
  detects absence, and the fleet matrix shows the sensor's presence per identity.
- v1 targets **Claude Code**. Cursor and VS Code use different, less stable hook
  protocols; the decision/report core is protocol-agnostic, so an adapter is a
  small follow-up.
- Raw LLM responses are not intercepted here — the OpenAI-compatible gateway
  (`gateway/`) is the surface that scans and blocks model **output**.

## Privacy

No prompt text, shell command text, MCP tool input, or unmasked PII/secret value
is ever written to the hook's output or the telemetry payload — only finding
**types** and `maskValue` output. This is enforced by `test/agent-hooks.test.js`.
