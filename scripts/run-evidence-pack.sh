#!/usr/bin/env bash
set -euo pipefail

MODE="${PROMPTWALL_EVIDENCE_MODE:-npm}"
PROJECT_DIR="${PROMPTWALL_EVIDENCE_PROJECT_DIR:-/opt/promptwall}"
CONFIG_PATH="${PROMPTWALL_EVIDENCE_CONFIG:-config/evidence-schedule.json}"
LOG_PATH="${PROMPTWALL_EVIDENCE_LOG:-/var/log/promptwall/evidence-pack.log}"
CONTAINER_NAME="${PROMPTWALL_EVIDENCE_CONTAINER:-promptwall}"

usage() {
  cat <<'USAGE'
Usage: run-evidence-pack.sh [options]

Runs a scheduled sanitized PromptWall examiner evidence pack.

Options:
  --mode npm|docker       Run from a local repo checkout or inside a Docker container.
  --project-dir <path>    Repo checkout for npm mode. Default: /opt/promptwall.
  --config <path>         Schedule config path. Relative npm paths resolve under project dir.
  --log <path>            Log path. Default: /var/log/promptwall/evidence-pack.log.
  --container <name>      Docker container name for docker mode. Default: promptwall.
  -h, --help              Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
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

mkdir -p "$(dirname "$LOG_PATH")"

log() {
  printf '[%s] %s\n' "$(date -Is)" "$*" >> "$LOG_PATH"
}

die() {
  log "$*"
  echo "$*" >&2
  exit 1
}

resolve_npm_config() {
  if [[ "$CONFIG_PATH" = /* ]]; then
    printf '%s\n' "$CONFIG_PATH"
  else
    printf '%s\n' "$PROJECT_DIR/$CONFIG_PATH"
  fi
}

run_npm_mode() {
  [[ -d "$PROJECT_DIR" ]] || die "PromptWall project dir not found: $PROJECT_DIR"
  local resolved_config
  resolved_config="$(resolve_npm_config)"
  [[ -f "$resolved_config" ]] || die "Evidence schedule config not found: $resolved_config"

  (
    cd "$PROJECT_DIR"
    npm run evidence:pack:scheduled -- "$resolved_config"
  ) >> "$LOG_PATH" 2>&1
}

run_docker_mode() {
  command -v docker >/dev/null 2>&1 || die "docker command not found"
  docker inspect "$CONTAINER_NAME" >/dev/null 2>&1 || die "PromptWall container not found: $CONTAINER_NAME"
  docker exec "$CONTAINER_NAME" test -f "$CONFIG_PATH" >/dev/null 2>&1 \
    || die "Evidence schedule config not found inside $CONTAINER_NAME: $CONFIG_PATH"

  docker exec "$CONTAINER_NAME" npm run evidence:pack:scheduled -- "$CONFIG_PATH" >> "$LOG_PATH" 2>&1
}

log "Starting PromptWall scheduled evidence pack in $MODE mode with config $CONFIG_PATH"
case "$MODE" in
  npm)
    if run_npm_mode; then
      log "Scheduled evidence pack completed"
    else
      status=$?
      log "Scheduled evidence pack failed with exit code $status"
      exit "$status"
    fi
    ;;
  docker)
    if run_docker_mode; then
      log "Scheduled evidence pack completed"
    else
      status=$?
      log "Scheduled evidence pack failed with exit code $status"
      exit "$status"
    fi
    ;;
  *)
    die "Unsupported evidence pack mode: $MODE"
    ;;
esac
