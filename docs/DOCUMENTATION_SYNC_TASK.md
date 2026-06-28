# Documentation Sync Task

PromptWall has a local Windows scheduled task that keeps generated documentation
current and pushes documentation-only updates to the branch's configured GitHub
upstream.

## Schedule

- Task name: `\PromptWall\PromptWall Documentation Sync`
- Trigger: daily at 9:00 AM local machine time
- Action: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/sync-docs.ps1`
- Log file: `%LOCALAPPDATA%\PromptWall\logs\docs-sync.log`

Install or refresh the task from the active repo folder:

```powershell
npm run docs:sync:install-task
```

## What It Does

1. Fetches `origin` and fast-forwards the current branch when safe.
2. Runs `npm run docs:demo-guide` to refresh generated guide sections.
3. Runs `npm run docs:demo-guide:check`.
4. Runs `npm run review:ci` before committing changed docs.
5. Commits tracked Markdown documentation changes with
   `docs: sync generated documentation`.
6. Pushes to the branch upstream and verifies `HEAD` matches `@{u}`.

The sync is intentionally documentation-only. It refuses to run when staged
changes, non-document tracked changes, divergent Git history, or unpushed
non-document commits are present. Untracked files are left alone.

For a read-only health check:

```powershell
npm run docs:sync:check
```

For a local run that skips the GitHub push:

```powershell
npm run docs:sync -- -NoPush
```
