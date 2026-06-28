# Examiner Evidence Pack Task

PromptWall can register a local Windows scheduled task that generates sanitized
examiner evidence packs from `config/evidence-schedule.json`.

## Schedule

- Task name: `\PromptWall\PromptWall Examiner Evidence Pack`
- Default trigger: every 13 weeks on Sunday at 11:00 PM local machine time
- Action: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run-evidence-pack.ps1`
- Log file: `%LOCALAPPDATA%\PromptWall\logs\evidence-pack.log`

Create the customer schedule file before installing the task:

```powershell
Copy-Item config\evidence-schedule.example.json config\evidence-schedule.json
notepad config\evidence-schedule.json
```

Install or refresh the task from the active repo folder:

```powershell
npm run evidence:pack:install-task
```

For a weekly pilot run:

```powershell
npm run evidence:pack:install-task -- -Cadence Weekly -DayOfWeek Friday -At "10:00 PM"
```

## What It Does

1. Runs `npm run evidence:pack:scheduled -- <config>`.
2. Writes the scheduled pack to the configured `outDir`.
3. Appends run status and CLI output to the local task log.
4. Leaves raw prompt bodies, retained sealed prompts, token vaults, release
   tokens, decision notes, and uploaded file bytes out of the generated pack.

The task arguments include only the repo path, schedule config path, and log
path. Secrets stay in the existing environment or local runtime configuration.

For a direct manual run without registering Task Scheduler:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\run-evidence-pack.ps1 `
  -ConfigPath config\evidence-schedule.json
```
