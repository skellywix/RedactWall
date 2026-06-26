---
name: google-workspace
description: Unified agent access to 50+ Google Workspace APIs (Gmail, Drive, Docs, Sheets, Calendar, Chat) via the gws CLI + its built-in MCP server. For PromptSentinel, use it to assemble compliance evidence into Sheets/Docs, draft examiner-facing reports, and route alerts to Chat. Wraps the external gws tool.
---

# Google Workspace (gws)

`gws` discovers every Workspace API through Google's Discovery Service and exposes a unified interface with a built-in MCP server — closes the gap between "agent that codes" and "agent that operates."

## Install (run it yourself — I don't run installers; OAuth approval is yours to grant)
```
npm install -g @googleworkspace/cli
gws mcp -s drive,gmail,calendar,sheets,docs,chat
```

## PromptSentinel uses
- **Compliance evidence pack:** export detection stats + audit-chain verification results into a Sheet; generate the quarterly "how do we know no member data went to ChatGPT" Doc an NCUA examiner asks for.
- **Exec/board digest:** weekly summary (from `weekly-review-loop`) drafted into a Doc and posted to a Chat space.
- **Alert routing:** high-severity blocked-prompt notifications to a security Chat channel.
- **Calendar:** schedule the recurring security-scan and review windows.

## Rules
- This is operational glue, not a data store for sensitive content — never paste raw member PII into Sheets/Docs. Use redacted/aggregate figures only (consistent with the product's own posture).
- OAuth scopes and consent are the user's to approve; I won't authenticate or accept scopes on your behalf.
- Prefer least-privilege scope selection in `gws mcp -s ...` — only the APIs a given workflow needs.
