#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="promptwall-evidence-pack"
MODE="docker"
PROJECT_DIR="/opt/promptwall"
CONFIG_PATH=""
LOG_PATH="/var/log/promptwall/evidence-pack.log"
CONTAINER_NAME="promptwall"
ON_CALENDAR="quarterly"
RANDOMIZED_DELAY="1h"
INSTALL_BIN="/usr/local/bin/promptwall-run-evidence-pack"
ENV_FILE="/etc/promptwall/evidence-pack.env"

usage() {
  cat <<'USAGE'
Usage: install-evidence-pack-systemd.sh [options]

Installs a systemd timer for recurring sanitized PromptWall examiner evidence
packs. Defaults target the Docker customer-silo shape where /var/lib/promptwall
is mounted into the container at /data.

Options:
  --service-name <name>       systemd service/timer base name. Default: promptwall-evidence-pack.
  --mode npm|docker          Runner mode. Default: docker.
  --project-dir <path>       Repo checkout for npm mode. Default: /opt/promptwall.
  --config <path>            Schedule config path. Docker default: /data/evidence-schedule.json.
                             npm default: config/evidence-schedule.json.
  --log <path>               Log path. Default: /var/log/promptwall/evidence-pack.log.
  --container <name>         Docker container for docker mode. Default: promptwall.
  --on-calendar <expr>       systemd OnCalendar expression. Default: quarterly.
  --randomized-delay <span>  systemd RandomizedDelaySec. Default: 1h.
  -h, --help                 Show this help.
USAGE
}

config_was_set=0
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
    --config)
      CONFIG_PATH="${2:?missing config path}"
      config_was_set=1
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

case "$MODE" in
  npm|docker) ;;
  *)
    echo "Unsupported evidence pack mode: $MODE" >&2
    exit 2
    ;;
esac

if [[ "$config_was_set" -eq 0 ]]; then
  if [[ "$MODE" == "docker" ]]; then
    CONFIG_PATH="/data/evidence-schedule.json"
  else
    CONFIG_PATH="config/evidence-schedule.json"
  fi
fi

after_units="network-online.target"
if [[ "$MODE" == "docker" ]]; then
  after_units="network-online.target docker.service"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER_SRC="$SCRIPT_DIR/run-evidence-pack.sh"
[[ -f "$RUNNER_SRC" ]] || { echo "Runner not found: $RUNNER_SRC" >&2; exit 1; }

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  SUDO=()
else
  SUDO=(sudo)
fi

quote_env() {
  local value="$1"
  value="${value//\'/\'\\\'\'}"
  printf "'%s'" "$value"
}

tmp_env="$(mktemp)"
tmp_service="$(mktemp)"
tmp_timer="$(mktemp)"
trap 'rm -f "$tmp_env" "$tmp_service" "$tmp_timer"' EXIT

cat > "$tmp_env" <<EOF
PROMPTWALL_EVIDENCE_MODE=$(quote_env "$MODE")
PROMPTWALL_EVIDENCE_PROJECT_DIR=$(quote_env "$PROJECT_DIR")
PROMPTWALL_EVIDENCE_CONFIG=$(quote_env "$CONFIG_PATH")
PROMPTWALL_EVIDENCE_LOG=$(quote_env "$LOG_PATH")
PROMPTWALL_EVIDENCE_CONTAINER=$(quote_env "$CONTAINER_NAME")
EOF

cat > "$tmp_service" <<EOF
[Unit]
Description=Generate sanitized PromptWall examiner evidence pack
After=$after_units
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_BIN
User=root
Group=root
Nice=5
EOF

cat > "$tmp_timer" <<EOF
[Unit]
Description=Run sanitized PromptWall examiner evidence pack on schedule

[Timer]
OnCalendar=$ON_CALENDAR
Persistent=true
RandomizedDelaySec=$RANDOMIZED_DELAY
Unit=$SERVICE_NAME.service

[Install]
WantedBy=timers.target
EOF

"${SUDO[@]}" install -D -m 0755 "$RUNNER_SRC" "$INSTALL_BIN"
"${SUDO[@]}" install -d -m 0750 "$(dirname "$ENV_FILE")"
"${SUDO[@]}" install -m 0600 "$tmp_env" "$ENV_FILE"
"${SUDO[@]}" install -m 0644 "$tmp_service" "/etc/systemd/system/$SERVICE_NAME.service"
"${SUDO[@]}" install -m 0644 "$tmp_timer" "/etc/systemd/system/$SERVICE_NAME.timer"
"${SUDO[@]}" install -d -m 0750 "$(dirname "$LOG_PATH")"
"${SUDO[@]}" systemctl daemon-reload
"${SUDO[@]}" systemctl enable --now "$SERVICE_NAME.timer"

echo "Installed systemd timer: $SERVICE_NAME.timer"
echo "Schedule: $ON_CALENDAR"
echo "Mode: $MODE"
echo "Config: $CONFIG_PATH"
echo "Log: $LOG_PATH"
echo "Run now: sudo systemctl start $SERVICE_NAME.service"
echo "Inspect timer: systemctl list-timers $SERVICE_NAME.timer"
