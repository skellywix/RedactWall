# Examiner Evidence Pack Schedules

PromptWall can register recurring jobs that generate sanitized examiner evidence
packs from a schedule config. Use Windows Task Scheduler on pilot workstations
and systemd timers on Linux or AWS customer-silo hosts.

## Windows Task Scheduler

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

## Linux systemd Timer

For Docker customer-silo hosts, put the schedule config in the mounted data
folder so the container sees it at `/data/evidence-schedule.json`:

```bash
sudo cp config/evidence-schedule.example.json /var/lib/promptwall/evidence-schedule.json
sudo editor /var/lib/promptwall/evidence-schedule.json
```

Set `outDir` inside that file to `/data/evidence-packs`, then install the
timer:

```bash
sudo npm run evidence:pack:install-systemd -- \
  --mode docker \
  --container promptwall \
  --config /data/evidence-schedule.json \
  --on-calendar quarterly
```

For a local Linux repo checkout without Docker:

```bash
sudo npm run evidence:pack:install-systemd -- \
  --mode npm \
  --project-dir /opt/promptwall \
  --config config/evidence-schedule.json \
  --on-calendar weekly
```

The installer writes:

- `/usr/local/bin/promptwall-run-evidence-pack`
- `/etc/promptwall/evidence-pack.env`
- `/etc/systemd/system/promptwall-evidence-pack.service`
- `/etc/systemd/system/promptwall-evidence-pack.timer`
- `/var/log/promptwall/evidence-pack.log`

The timer uses `Persistent=true`, so a missed run executes after the host comes
back online. The unit environment contains scheduler metadata only: mode, repo
or container name, config path, and log path. It does not include admin
passwords, ingest keys, encryption keys, raw prompt bodies, release tokens, or
uploaded file bytes.

Run a one-off pack through the installed service:

```bash
sudo systemctl start promptwall-evidence-pack.service
```

For a direct Linux run without registering systemd:

```bash
npm run evidence:pack:run-linux -- \
  --mode npm \
  --project-dir "$PWD" \
  --config config/evidence-schedule.json \
  --log /tmp/promptwall-evidence-pack.log
```
