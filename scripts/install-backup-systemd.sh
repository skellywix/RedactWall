#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="redactwall-backup"
MODE="npm"
PROJECT_DIR="/opt/redactwall"
BACKUP_DIR=""
LOG_PATH="/var/log/redactwall/backup.log"
CONTAINER_NAME="redactwall"
ON_CALENDAR="daily"
RANDOMIZED_DELAY="15m"
RETENTION_DAYS="30"
UNINSTALL=0

usage() {
  cat <<'USAGE'
Usage: install-backup-systemd.sh [options]

Installs a systemd timer that backs up the RedactWall SQLite evidence store
with `npm run backup` and prunes backups older than the retention window.
Defaults target a repo checkout at /opt/redactwall; docker mode targets the
customer-silo shape where /var/lib/redactwall is mounted into the container
at /data.

Options:
  --service-name <name>       systemd service/timer base name. Default: redactwall-backup.
  --mode npm|docker          Runner mode. Default: npm.
  --project-dir <path>       Repo checkout for npm mode. Default: /opt/redactwall.
  --backup-dir <path>        Backup output dir. npm default: <project-dir>/backups.
                             docker default: /data/backups (inside the container).
  --retention-days <days>    Delete backups older than this many days. Default: 30.
  --log <path>               Log path. Default: /var/log/redactwall/backup.log.
  --container <name>         Docker container for docker mode. Default: redactwall.
  --on-calendar <expr>       systemd OnCalendar expression. Default: daily.
  --randomized-delay <span>  systemd RandomizedDelaySec. Default: 15m.
  --uninstall                Disable and remove the service and timer, then exit.
  -h, --help                 Show this help.
USAGE
}

backup_dir_was_set=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-name)
      SERVICE_NAME="${2:?missing service name}"
      shift 2
      ;;
    --mode)
      MODE="${2:?missing mode}"
      shift 2
      ;;
    --project-dir)
      PROJECT_DIR="${2:?missing project dir}"
      shift 2
      ;;
    --backup-dir)
      BACKUP_DIR="${2:?missing backup dir}"
      backup_dir_was_set=1
      shift 2
      ;;
    --retention-days)
      RETENTION_DAYS="${2:?missing retention days}"
      shift 2
      ;;
    --log)
      LOG_PATH="${2:?missing log path}"
      shift 2
      ;;
    --container)
      CONTAINER_NAME="${2:?missing container name}"
      shift 2
      ;;
    --on-calendar)
      ON_CALENDAR="${2:?missing OnCalendar expression}"
      shift 2
      ;;
    --randomized-delay)
      RANDOMIZED_DELAY="${2:?missing randomized delay}"
      shift 2
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
  "${SUDO[@]}" systemctl disable --now "$SERVICE_NAME.timer" 2>/dev/null || true
  "${SUDO[@]}" rm -f "/etc/systemd/system/$SERVICE_NAME.service" "/etc/systemd/system/$SERVICE_NAME.timer"
  "${SUDO[@]}" systemctl daemon-reload
  echo "Removed systemd timer: $SERVICE_NAME.timer"
  exit 0
fi

case "$MODE" in
  npm|docker) ;;
  *)
    echo "Unsupported backup mode: $MODE" >&2
    exit 2
    ;;
esac

if ! [[ "$RETENTION_DAYS" =~ ^[0-9]+$ ]] || [[ "$RETENTION_DAYS" -lt 1 ]]; then
  echo "Invalid --retention-days: $RETENTION_DAYS (need a positive integer)" >&2
  exit 2
fi

if [[ "$backup_dir_was_set" -eq 0 ]]; then
  if [[ "$MODE" == "docker" ]]; then
    BACKUP_DIR="/data/backups"
  else
    BACKUP_DIR="$PROJECT_DIR/backups"
  fi
fi

after_units="network-online.target"
if [[ "$MODE" == "docker" ]]; then
  after_units="network-online.target docker.service"
fi

# The prune runs as a second ExecStart of the oneshot service, so it only
# executes after a successful backup — a failing backup never deletes the
# older good copies. systemd passes `redactwall-*` to find without shell
# globbing, which is exactly what -name expects.
if [[ "$MODE" == "docker" ]]; then
  working_dir_line=""
  backup_exec="/usr/bin/env docker exec \"$CONTAINER_NAME\" node scripts/backup-store.js create \"$BACKUP_DIR\""
  prune_exec="/usr/bin/env docker exec \"$CONTAINER_NAME\" find \"$BACKUP_DIR\" -maxdepth 1 -type f -name redactwall-* -mtime +$RETENTION_DAYS -delete"
else
  working_dir_line="WorkingDirectory=$PROJECT_DIR"
  backup_exec="/usr/bin/env npm run backup -- --out \"$BACKUP_DIR\""
  prune_exec="/usr/bin/env find \"$BACKUP_DIR\" -maxdepth 1 -type f -name redactwall-* -mtime +$RETENTION_DAYS -delete"
fi

tmp_service="$(mktemp)"
tmp_timer="$(mktemp)"
trap 'rm -f "$tmp_service" "$tmp_timer"' EXIT

cat > "$tmp_service" <<EOF
[Unit]
Description=Back up the RedactWall SQLite evidence store
After=$after_units
Wants=network-online.target

[Service]
Type=oneshot
$working_dir_line
ExecStart=$backup_exec
ExecStart=$prune_exec
StandardOutput=append:$LOG_PATH
StandardError=append:$LOG_PATH
User=root
Group=root
Nice=5
EOF

cat > "$tmp_timer" <<EOF
[Unit]
Description=Run RedactWall evidence store backup on schedule

[Timer]
OnCalendar=$ON_CALENDAR
Persistent=true
RandomizedDelaySec=$RANDOMIZED_DELAY
Unit=$SERVICE_NAME.service

[Install]
WantedBy=timers.target
EOF

if [[ "$MODE" == "npm" ]]; then
  "${SUDO[@]}" install -d -m 0750 "$BACKUP_DIR"
fi
"${SUDO[@]}" install -m 0644 "$tmp_service" "/etc/systemd/system/$SERVICE_NAME.service"
"${SUDO[@]}" install -m 0644 "$tmp_timer" "/etc/systemd/system/$SERVICE_NAME.timer"
"${SUDO[@]}" install -d -m 0750 "$(dirname "$LOG_PATH")"
"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable --now "$SERVICE_NAME.timer"

echo "Installed systemd timer: $SERVICE_NAME.timer"
echo "Schedule: $ON_CALENDAR"
echo "Mode: $MODE"
echo "Backup dir: $BACKUP_DIR"
echo "Retention: $RETENTION_DAYS day(s)"
echo "Log: $LOG_PATH"
echo "Run now: sudo systemctl start $SERVICE_NAME.service"
echo "Inspect timer: systemctl list-timers $SERVICE_NAME.timer"
echo "Uninstall: sudo bash scripts/install-backup-systemd.sh --uninstall"
