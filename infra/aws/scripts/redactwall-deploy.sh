#!/bin/bash
set -euo pipefail

DEPLOY_LOCK=/run/redactwall-deploy.lock
if [ "$(printenv REDACTWALL_DEPLOY_LOCK_HELD 2>/dev/null || true)" = 1 ]; then
  : # redactwall-cfn-update owns the same lock across cfn-init and this command.
else
  exec 9>"$DEPLOY_LOCK"
  flock 9
fi
MAINTENANCE_LATCH=/etc/redactwall/maintenance-latch.json
if [ -L "$MAINTENANCE_LATCH" ] || [ -e "$MAINTENANCE_LATCH" ]; then
  echo "A maintenance latch is active; ordinary deployment is blocked" >&2
  exit 1
fi
DATA_VOLUME_ROOT=/var/lib/redactwall
APP_DATA_DIR=/var/lib/redactwall/runtime
RECOVERY_PARENT=/var/lib/redactwall/recovery
DATA_VOLUME_MARKER=/var/lib/redactwall/.redactwall-volume-identity.json
MOUNTED_DATA_SOURCE=$(readlink -f "$(findmnt -n -o SOURCE --target "$DATA_VOLUME_ROOT" 2>/dev/null || true)" 2>/dev/null || true)
MOUNTED_DATA_SERIAL=$(lsblk -ndo SERIAL "$MOUNTED_DATA_SOURCE" 2>/dev/null | tr -d '-' | tr '[:upper:]' '[:lower:]')
EXPECTED_DATA_SERIAL=$(printf '%s' '${DataVolumeId}' | tr -d '-' | tr '[:upper:]' '[:lower:]')
if ! mountpoint -q "$DATA_VOLUME_ROOT" \
  || [ -z "$MOUNTED_DATA_SOURCE" ] || [ "$MOUNTED_DATA_SERIAL" != "$EXPECTED_DATA_SERIAL" ]; then
  echo "The retained RedactWall data volume is not mounted at the authoritative path" >&2
  exit 1
fi
if [ -L "$DATA_VOLUME_MARKER" ] || [ ! -f "$DATA_VOLUME_MARKER" ] \
  || [ "$(stat -c '%u:%g:%a:%h' "$DATA_VOLUME_MARKER")" != '0:0:600:1' ] \
  || ! jq -e --arg volumeId '${DataVolumeId}' --arg sourceVolumeId '${SourceDataVolumeId}' --arg tenantId '${TenantId}' \
    --arg filesystemUuid "$(findmnt -n -o UUID --target "$DATA_VOLUME_ROOT")" \
    'type == "object"
     and (($sourceVolumeId == "" and .version == 3 and (keys | sort) == ["filesystemUuid","tenantId","version","volumeId"])
       or ($sourceVolumeId != "" and .version == 4 and (keys | sort) == ["filesystemUuid","sourceVolumeId","tenantId","version","volumeId"] and .sourceVolumeId == $sourceVolumeId))
     and .volumeId == $volumeId and .tenantId == $tenantId and .filesystemUuid == $filesystemUuid' \
    "$DATA_VOLUME_MARKER" >/dev/null; then
  echo "The retained RedactWall data-volume identity contract is invalid" >&2
  exit 1
fi
if [ -L "$APP_DATA_DIR" ] || [ ! -d "$APP_DATA_DIR" ] \
  || [ "$(stat -c '%u:%g:%a' "$APP_DATA_DIR")" != '1000:1000:700' ]; then
  echo "The existing RedactWall runtime directory is not trusted private state" >&2
  exit 1
fi
if [ -e /etc/redactwall ] || [ -L /etc/redactwall ]; then
  if [ -L /etc/redactwall ] || [ ! -d /etc/redactwall ] \
    || [ "$(stat -c '%u:%g:%a' /etc/redactwall)" != '0:0:700' ]; then
    echo "The existing RedactWall deployment directory is not trusted private state" >&2
    exit 1
  fi
else
  install -d -m 700 -o root -g root /etc/redactwall
fi
if [ -e /etc/redactwall/license ] || [ -L /etc/redactwall/license ]; then
  if [ -L /etc/redactwall/license ] || [ ! -d /etc/redactwall/license ] \
    || [ "$(stat -c '%u:%g:%a' /etc/redactwall/license)" != '0:0:700' ]; then
    echo "The host-managed license directory is not trusted root-owned state" >&2
    exit 1
  fi
else
  install -d -m 700 -o root -g root /etc/redactwall/license
fi
DEPLOY_DEVICE=$(stat -c '%d' /etc/redactwall)
if [ "$DEPLOY_DEVICE" = 0 ]; then
  echo "The private deployment journal has no stable filesystem identity" >&2
  exit 1
fi

LICENSE_FINAL=/etc/redactwall/license/redactwall.lic
DEPLOY_STATE_DIR=/etc/redactwall
DEPLOY_JOURNAL=/etc/redactwall/license-deploy-journal.json
DEPLOY_COMMITTED=0
COMMIT_ATTEMPTED=0
ROLLBACK_RECOVERED=0
COMMITTED_CLEANUP_PENDING=0
TX_ID=
TX_PHASE=
PREVIOUS_CONTAINER_ID=
PREVIOUS_CONTAINER_RUNNING=false
PREVIOUS_IMAGE_URI=
CANDIDATE_CONTAINER_ID=
PRIOR_LICENSE_JSON=null
CANDIDATE_LICENSE_JSON=null
LICENSE_CHANGED=false
DESIRED_IMAGE_URI='${ImageUri}'
DESIRED_SECRET_ARN='${SecretArn}'
DESIRED_LICENSE_SECRET_VERSION_ID='${LicenseSecretVersionId}'
DESIRED_CONFIG_SHA256='${DesiredConfigSha256}'
DESIRED_TEMPLATE_SHA256='${DeploymentTemplateSha256}'
DESIRED_PROTOCOL_SHA256='${DeploymentProtocolSha256}'
IMAGE_URI="$DESIRED_IMAGE_URI"
SECRET_ARN="$DESIRED_SECRET_ARN"
LICENSE_SECRET_VERSION_ID="$DESIRED_LICENSE_SECRET_VERSION_ID"
CONFIG_SHA256="$DESIRED_CONFIG_SHA256"
TEMPLATE_SHA256="$DESIRED_TEMPLATE_SHA256"
PROTOCOL_SHA256="$DESIRED_PROTOCOL_SHA256"
TX_IMAGE_URI="$DESIRED_IMAGE_URI"
TX_SECRET_ARN="$DESIRED_SECRET_ARN"
TX_LICENSE_SECRET_VERSION_ID="$DESIRED_LICENSE_SECRET_VERSION_ID"
TX_CONFIG_SHA256="$DESIRED_CONFIG_SHA256"
TX_TEMPLATE_SHA256="$DESIRED_TEMPLATE_SHA256"
TX_PROTOCOL_SHA256="$DESIRED_PROTOCOL_SHA256"
RECOVERY_BACKUP_NAME=
RECOVERY_MANIFEST_NAME=
APPLIED_STATE=/etc/redactwall/applied-deployment.json
ASSERT_APPLIED_COMMAND=/usr/local/sbin/redactwall-assert-applied

path_present() {
  [ -e "$1" ] || [ -L "$1" ]
}

close_fd() {
  eval "exec $1<&-"
}

desired_contract_applied() {
  [ -x "$ASSERT_APPLIED_COMMAND" ] \
    && "$ASSERT_APPLIED_COMMAND" \
      --image-uri "$DESIRED_IMAGE_URI" --secret-version-id "$DESIRED_LICENSE_SECRET_VERSION_ID" \
      --config-sha256 "$DESIRED_CONFIG_SHA256" --template-sha256 "$DESIRED_TEMPLATE_SHA256" \
      --protocol-sha256 "$DESIRED_PROTOCOL_SHA256" >/dev/null 2>&1
}

reset_transaction_contract_to_desired() {
  TX_ID=
  TX_PHASE=
  PREVIOUS_CONTAINER_ID=
  PREVIOUS_CONTAINER_RUNNING=false
  PREVIOUS_IMAGE_URI=
  CANDIDATE_CONTAINER_ID=
  PRIOR_LICENSE_JSON=null
  CANDIDATE_LICENSE_JSON=null
  LICENSE_CHANGED=false
  RECOVERY_BACKUP_NAME=
  RECOVERY_MANIFEST_NAME=
  LICENSE_STAGE=
  LICENSE_ROLLBACK=
  LICENSE_RETIRED=
  PREVIOUS_CONTAINER_NAME=
  CANDIDATE_CONTAINER_NAME=
  RECOVERY_DIR=
  DEPLOY_COMMITTED=0
  COMMIT_ATTEMPTED=0
  ROLLBACK_RECOVERED=0
  COMMITTED_CLEANUP_PENDING=0
  IMAGE_URI="$DESIRED_IMAGE_URI"
  SECRET_ARN="$DESIRED_SECRET_ARN"
  LICENSE_SECRET_VERSION_ID="$DESIRED_LICENSE_SECRET_VERSION_ID"
  CONFIG_SHA256="$DESIRED_CONFIG_SHA256"
  TEMPLATE_SHA256="$DESIRED_TEMPLATE_SHA256"
  PROTOCOL_SHA256="$DESIRED_PROTOCOL_SHA256"
  TX_IMAGE_URI="$DESIRED_IMAGE_URI"
  TX_SECRET_ARN="$DESIRED_SECRET_ARN"
  TX_LICENSE_SECRET_VERSION_ID="$DESIRED_LICENSE_SECRET_VERSION_ID"
  TX_CONFIG_SHA256="$DESIRED_CONFIG_SHA256"
  TX_TEMPLATE_SHA256="$DESIRED_TEMPLATE_SHA256"
  TX_PROTOCOL_SHA256="$DESIRED_PROTOCOL_SHA256"
}

artifact_json() {
  artifact_path=$1
  expected_uid=$2
  expected_gid=$3
  expected_mode=$4
  max_bytes=$5
  if [ -L "$artifact_path" ] || [ ! -f "$artifact_path" ]; then return 1; fi
  exec {artifact_fd}< "$artifact_path" || return 1
  artifact_handle="/proc/$BASHPID/fd/$artifact_fd"
  handle_before=$(stat -Lc '%d|%i|%h|%s|%u|%g|%a|%y|%z' -- "$artifact_handle") || {
    close_fd "$artifact_fd"
    return 1
  }
  path_before=$(stat -c '%d|%i|%h|%s|%u|%g|%a|%y|%z' -- "$artifact_path") || {
    close_fd "$artifact_fd"
    return 1
  }
  if [ "$handle_before" != "$path_before" ]; then
    close_fd "$artifact_fd"
    return 1
  fi
  IFS='|' read -r artifact_dev artifact_ino artifact_nlink artifact_size artifact_uid artifact_gid artifact_mode artifact_mtime artifact_ctime <<< "$handle_before"
  if [ "$artifact_dev" = 0 ] || [ "$artifact_ino" = 0 ] \
    || [ "$artifact_nlink" != 1 ] || [ "$artifact_uid" != "$expected_uid" ] \
    || [ "$artifact_gid" != "$expected_gid" ] || [ "$artifact_mode" != "$expected_mode" ] \
    || [ "$artifact_size" -gt "$max_bytes" ]; then
    close_fd "$artifact_fd"
    return 1
  fi
  artifact_sha=$(sha256sum -- "$artifact_handle" | awk '{print $1}') || {
    close_fd "$artifact_fd"
    return 1
  }
  handle_after=$(stat -Lc '%d|%i|%h|%s|%u|%g|%a|%y|%z' -- "$artifact_handle") || {
    close_fd "$artifact_fd"
    return 1
  }
  path_after=$(stat -c '%d|%i|%h|%s|%u|%g|%a|%y|%z' -- "$artifact_path") || {
    close_fd "$artifact_fd"
    return 1
  }
  close_fd "$artifact_fd"
  if [ "$handle_before" != "$handle_after" ] || [ "$handle_before" != "$path_after" ] \
    || ! [[ "$artifact_sha" =~ ^[a-f0-9]{64}$ ]]; then return 1; fi
  jq -cn \
    --arg dev "$artifact_dev" --arg ino "$artifact_ino" --arg nlink "$artifact_nlink" \
    --arg size "$artifact_size" --arg uid "$artifact_uid" --arg gid "$artifact_gid" \
    --arg mode "$artifact_mode" --arg sha256 "$artifact_sha" \
    '{dev:$dev,ino:$ino,nlink:$nlink,size:$size,uid:$uid,gid:$gid,mode:$mode,sha256:$sha256}'
}

artifact_matches() {
  match_path=$1
  expected_json=$2
  match_uid=$3
  match_gid=$4
  match_mode=$5
  match_max=$6
  current_json=$(artifact_json "$match_path" "$match_uid" "$match_gid" "$match_mode" "$match_max") || return 1
  jq -en --argjson current "$current_json" --argjson expected "$expected_json" '$current == $expected' >/dev/null
}

same_license_bytes() {
  left_json=$1
  right_json=$2
  jq -en --argjson left "$left_json" --argjson right "$right_json" \
    '$left.size == $right.size and $left.sha256 == $right.sha256' >/dev/null
}

sync_parent() {
  sync -f -- "$(dirname -- "$1")"
}

remove_exact_private_artifact() {
  remove_path=$1
  remove_json=$2
  if ! path_present "$remove_path"; then return 0; fi
  artifact_matches "$remove_path" "$remove_json" 1000 1000 400 65536 || return 1
  rm -- "$remove_path" || return 1
  if path_present "$remove_path"; then return 1; fi
  sync_parent "$remove_path"
}

move_exact_to_private() {
  move_source=$1
  move_destination=$2
  move_json=$3
  if path_present "$move_destination" \
    || ! artifact_matches "$move_source" "$move_json" 1000 1000 400 65536; then return 1; fi
  mv -nT -- "$move_source" "$move_destination" || return 1
  if path_present "$move_source" \
    || ! artifact_matches "$move_destination" "$move_json" 1000 1000 400 65536; then
    if ! path_present "$move_source" && path_present "$move_destination"; then
      mv -nT -- "$move_destination" "$move_source" >/dev/null 2>&1 || true
    fi
    return 1
  fi
  sync_parent "$move_source"
  sync_parent "$move_destination"
}

publish_exact_private() {
  publish_source=$1
  publish_destination=$2
  publish_json=$3
  if path_present "$publish_destination" \
    || ! artifact_matches "$publish_source" "$publish_json" 1000 1000 400 65536; then return 1; fi
  mv -nT -- "$publish_source" "$publish_destination" || return 1
  if path_present "$publish_source" \
    || ! artifact_matches "$publish_destination" "$publish_json" 1000 1000 400 65536; then return 1; fi
  sync_parent "$publish_source"
  sync_parent "$publish_destination"
}

transaction_paths() {
  LICENSE_STAGE="$DEPLOY_STATE_DIR/license.stage.$TX_ID"
  LICENSE_ROLLBACK="$DEPLOY_STATE_DIR/license.rollback.$TX_ID"
  LICENSE_RETIRED="$DEPLOY_STATE_DIR/license.retired.$TX_ID"
  PREVIOUS_CONTAINER_NAME="redactwall-previous-$TX_ID"
  CANDIDATE_CONTAINER_NAME="redactwall-candidate-$TX_ID"
  RECOVERY_DIR="$RECOVERY_PARENT/$TX_ID"
}

journal_write() {
  TX_PHASE=$1
  journal_tmp=$(mktemp "$DEPLOY_STATE_DIR/.license-deploy-journal.XXXXXX")
  jq -cn \
    --arg tx "$TX_ID" --arg phase "$TX_PHASE" \
    --arg imageUri "$TX_IMAGE_URI" \
    --arg secretArn "$TX_SECRET_ARN" --arg desiredConfigSha256 "$TX_CONFIG_SHA256" \
    --arg templateSha256 "$TX_TEMPLATE_SHA256" --arg protocolSha256 "$TX_PROTOCOL_SHA256" \
    --arg secretVersionId "$TX_LICENSE_SECRET_VERSION_ID" \
    --arg previousContainerId "$PREVIOUS_CONTAINER_ID" \
    --arg previousImageUri "$PREVIOUS_IMAGE_URI" \
    --argjson previousContainerRunning "$PREVIOUS_CONTAINER_RUNNING" \
    --arg candidateContainerId "$CANDIDATE_CONTAINER_ID" \
    --argjson priorLicense "$PRIOR_LICENSE_JSON" \
    --argjson candidateLicense "$CANDIDATE_LICENSE_JSON" \
    --argjson licenseChanged "$LICENSE_CHANGED" \
    --arg recoveryBackupName "$RECOVERY_BACKUP_NAME" --arg recoveryManifestName "$RECOVERY_MANIFEST_NAME" \
    '{version:1,tx:$tx,phase:$phase,imageUri:$imageUri,secretArn:$secretArn,
      secretVersionId:$secretVersionId,desiredConfigSha256:$desiredConfigSha256,
      templateSha256:$templateSha256,protocolSha256:$protocolSha256,
      previousContainerId:$previousContainerId,
      previousImageUri:$previousImageUri,
      previousContainerRunning:$previousContainerRunning,
      candidateContainerId:$candidateContainerId,
      priorLicense:$priorLicense,candidateLicense:$candidateLicense,
      licenseChanged:$licenseChanged,recoveryBackupName:$recoveryBackupName,
      recoveryManifestName:$recoveryManifestName}' > "$journal_tmp"
  chmod 600 "$journal_tmp"
  sync -f -- "$journal_tmp"
  mv -fT -- "$journal_tmp" "$DEPLOY_JOURNAL"
  sync -f -- "$DEPLOY_STATE_DIR"
  if [ "$(printenv REDACTWALL_DEPLOY_TEST_CRASH_AFTER 2>/dev/null || true)" = "$TX_PHASE" ]; then
    kill -KILL "$BASHPID"
  fi
}

valid_snapshot_json() {
  jq -e '
    type == "object"
    and (keys | sort) == ["dev","gid","ino","mode","nlink","sha256","size","uid"]
    and all(.dev,.ino,.nlink,.size,.uid,.gid,.mode,.sha256; type == "string")
    and (.dev | test("^[1-9][0-9]*$")) and (.ino | test("^[1-9][0-9]*$"))
    and .nlink == "1" and (.size | test("^[0-9]+$"))
    and .uid == "1000" and .gid == "1000" and .mode == "400"
    and (.sha256 | test("^[a-f0-9]{64}$"))
  ' >/dev/null
}

journal_load() {
  journal_before=$(artifact_json "$DEPLOY_JOURNAL" 0 0 600 32768) || return 1
  if [ "$(printf '%s' "$journal_before" | jq -r '.dev')" != "$DEPLOY_DEVICE" ]; then return 1; fi
  journal_text=$(cat -- "$DEPLOY_JOURNAL") || return 1
  artifact_matches "$DEPLOY_JOURNAL" "$journal_before" 0 0 600 32768 || return 1
  printf '%s' "$journal_text" | jq -e '
    type == "object"
    and (keys | sort) == ["candidateContainerId","candidateLicense","desiredConfigSha256","imageUri","licenseChanged","phase","previousContainerId","previousContainerRunning","previousImageUri","priorLicense","protocolSha256","recoveryBackupName","recoveryManifestName","secretArn","secretVersionId","templateSha256","tx","version"]
    and .version == 1
    and (.tx | type == "string" and test("^[a-f0-9]{32}$"))
    and (.imageUri | type == "string" and test("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com(?:\\.cn)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$"))
    and (.secretArn | type == "string" and test("^arn:(aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$"))
    and (.desiredConfigSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and (.templateSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and (.protocolSha256 | type == "string" and test("^[a-f0-9]{64}$"))
    and (.phase == "prepared" or .phase == "previous_moved" or .phase == "prior_secured"
      or .phase == "candidate_published" or .phase == "license_unchanged"
      or .phase == "candidate_created" or .phase == "candidate_started"
      or .phase == "candidate_ready" or .phase == "candidate_named" or .phase == "committed")
    and (.secretVersionId | type == "string" and test("^[A-Za-z0-9-]{32,64}$"))
    and (.previousContainerId | type == "string" and test("^$|^[a-f0-9]{64}$"))
    and (.previousImageUri | type == "string" and test("^$|^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com(?:\\.cn)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$"))
    and (.recoveryBackupName | type == "string" and test("^$|^[A-Za-z0-9._-]{1,180}$"))
    and (.recoveryManifestName | type == "string" and test("^$|^[A-Za-z0-9._-]{1,180}$"))
    and ((.previousContainerId == "" and .previousImageUri == "" and .recoveryBackupName == "" and .recoveryManifestName == "")
      or (.previousContainerId != "" and .previousImageUri != "" and .recoveryBackupName != "" and .recoveryManifestName != ""))
    and (.candidateContainerId | type == "string" and test("^$|^[a-f0-9]{64}$"))
    and (.previousContainerRunning | type == "boolean")
    and (.licenseChanged | type == "boolean")
    and (.priorLicense == null or (.priorLicense | type == "object"))
    and (.candidateLicense | type == "object")
  ' >/dev/null || return 1
  TX_ID=$(printf '%s' "$journal_text" | jq -r '.tx')
  TX_PHASE=$(printf '%s' "$journal_text" | jq -r '.phase')
  TX_IMAGE_URI=$(printf '%s' "$journal_text" | jq -r '.imageUri')
  TX_SECRET_ARN=$(printf '%s' "$journal_text" | jq -r '.secretArn')
  TX_CONFIG_SHA256=$(printf '%s' "$journal_text" | jq -r '.desiredConfigSha256')
  TX_TEMPLATE_SHA256=$(printf '%s' "$journal_text" | jq -r '.templateSha256')
  TX_PROTOCOL_SHA256=$(printf '%s' "$journal_text" | jq -r '.protocolSha256')
  TX_LICENSE_SECRET_VERSION_ID=$(printf '%s' "$journal_text" | jq -r '.secretVersionId')
  PREVIOUS_CONTAINER_ID=$(printf '%s' "$journal_text" | jq -r '.previousContainerId')
  PREVIOUS_IMAGE_URI=$(printf '%s' "$journal_text" | jq -r '.previousImageUri')
  PREVIOUS_CONTAINER_RUNNING=$(printf '%s' "$journal_text" | jq -c '.previousContainerRunning')
  CANDIDATE_CONTAINER_ID=$(printf '%s' "$journal_text" | jq -r '.candidateContainerId')
  PRIOR_LICENSE_JSON=$(printf '%s' "$journal_text" | jq -c '.priorLicense')
  CANDIDATE_LICENSE_JSON=$(printf '%s' "$journal_text" | jq -c '.candidateLicense')
  LICENSE_CHANGED=$(printf '%s' "$journal_text" | jq -c '.licenseChanged')
  RECOVERY_BACKUP_NAME=$(printf '%s' "$journal_text" | jq -r '.recoveryBackupName')
  RECOVERY_MANIFEST_NAME=$(printf '%s' "$journal_text" | jq -r '.recoveryManifestName')
  if [ "$PRIOR_LICENSE_JSON" != null ]; then
    printf '%s' "$PRIOR_LICENSE_JSON" | valid_snapshot_json || return 1
  fi
  printf '%s' "$CANDIDATE_LICENSE_JSON" | valid_snapshot_json || return 1
  transaction_paths
}

journal_clear() {
  if ! path_present "$DEPLOY_JOURNAL"; then return 0; fi
  journal_identity=$(artifact_json "$DEPLOY_JOURNAL" 0 0 600 32768) || return 1
  rm -- "$DEPLOY_JOURNAL" || return 1
  if path_present "$DEPLOY_JOURNAL"; then return 1; fi
  sync -f -- "$DEPLOY_STATE_DIR"
}

container_id_named() {
  docker inspect -f '{{.Id}}' "$1" 2>/dev/null || true
}

discover_candidate_id() {
  discovered_ids=$(docker ps -aq --no-trunc --filter "label=com.redactwall.deploy=$TX_ID") || return 1
  discovered_count=$(printf '%s\n' "$discovered_ids" | sed '/^$/d' | wc -l)
  if [ "$discovered_count" -gt 1 ]; then return 1; fi
  discovered_id=$(printf '%s\n' "$discovered_ids" | sed -n '1p')
  if [ -n "$discovered_id" ]; then
    discovered_label=$(docker inspect -f '{{index .Config.Labels "com.redactwall.deploy"}}' "$discovered_id" 2>/dev/null || true)
    if [ "$discovered_label" != "$TX_ID" ]; then return 1; fi
  fi
  printf '%s' "$discovered_id"
}

remove_candidate_confirmed() {
  discovered_id=$(discover_candidate_id) || return 1
  if [ -n "$CANDIDATE_CONTAINER_ID" ] && [ -n "$discovered_id" ] \
    && [ "$CANDIDATE_CONTAINER_ID" != "$discovered_id" ]; then return 1; fi
  candidate_id=$CANDIDATE_CONTAINER_ID
  if [ -z "$candidate_id" ]; then candidate_id=$discovered_id; fi
  if [ -z "$candidate_id" ]; then return 0; fi
  if ! docker inspect "$candidate_id" >/dev/null 2>&1; then
    [ -z "$discovered_id" ]
    return
  fi
  candidate_label=$(docker inspect -f '{{index .Config.Labels "com.redactwall.deploy"}}' "$candidate_id" 2>/dev/null || true)
  if [ "$candidate_label" != "$TX_ID" ]; then return 1; fi
  docker rm -f "$candidate_id" >/dev/null || return 1
  if docker inspect "$candidate_id" >/dev/null 2>&1; then return 1; fi
  remaining_candidate_id=$(discover_candidate_id) || return 1
  [ -z "$remaining_candidate_id" ]
}

quarantine_candidate_license() {
  if path_present "$LICENSE_RETIRED"; then
    artifact_matches "$LICENSE_RETIRED" "$CANDIDATE_LICENSE_JSON" 1000 1000 400 65536
    return
  fi
  move_exact_to_private "$LICENSE_FINAL" "$LICENSE_RETIRED" "$CANDIDATE_LICENSE_JSON"
}

restore_license_transaction() {
  if [ "$LICENSE_CHANGED" != true ]; then
    if [ "$PRIOR_LICENSE_JSON" = null ]; then return 1; fi
    artifact_matches "$LICENSE_FINAL" "$PRIOR_LICENSE_JSON" 1000 1000 400 65536 || return 1
  elif [ "$PRIOR_LICENSE_JSON" = null ]; then
    if path_present "$LICENSE_FINAL"; then
      artifact_matches "$LICENSE_FINAL" "$CANDIDATE_LICENSE_JSON" 1000 1000 400 65536 || return 1
      quarantine_candidate_license || return 1
    fi
  elif path_present "$LICENSE_FINAL" \
    && artifact_matches "$LICENSE_FINAL" "$PRIOR_LICENSE_JSON" 1000 1000 400 65536; then
    true
  else
    artifact_matches "$LICENSE_ROLLBACK" "$PRIOR_LICENSE_JSON" 1000 1000 400 65536 || return 1
    if path_present "$LICENSE_FINAL"; then
      artifact_matches "$LICENSE_FINAL" "$CANDIDATE_LICENSE_JSON" 1000 1000 400 65536 || return 1
      quarantine_candidate_license || return 1
    fi
    if path_present "$LICENSE_FINAL"; then return 1; fi
    publish_exact_private "$LICENSE_ROLLBACK" "$LICENSE_FINAL" "$PRIOR_LICENSE_JSON" || return 1
  fi
  if path_present "$LICENSE_ROLLBACK"; then return 1; fi
  return 0
}

create_runtime_recovery_point() {
  [ -n "$PREVIOUS_CONTAINER_ID" ] || return 0
  [ "$PREVIOUS_CONTAINER_RUNNING" = true ] || return 1
  PREVIOUS_IMAGE_URI=$(docker inspect -f '{{.Config.Image}}' "$PREVIOUS_CONTAINER_ID") || return 1
  [[ "$PREVIOUS_IMAGE_URI" =~ ^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(\.cn)?/[a-z0-9]+([._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$ ]] || return 1
  container_recovery="/data/.deployment-recovery-$TX_ID"
  recovery_result=$(docker exec "$PREVIOUS_CONTAINER_ID" node scripts/backup-store.js create --out "$container_recovery") || return 1
  container_backup=$(printf '%s' "$recovery_result" | jq -er '.file | select(type == "string" and startswith("/data/"))') || return 1
  container_manifest=$(printf '%s' "$recovery_result" | jq -er '.manifestFile | select(type == "string" and startswith("/data/"))') || return 1
  docker exec "$PREVIOUS_CONTAINER_ID" node scripts/backup-store.js verify --file "$container_backup" --manifest "$container_manifest" >/dev/null || return 1
  source_recovery="$APP_DATA_DIR/$(basename "$container_recovery")"
  [ -d "$source_recovery" ] && [ ! -L "$source_recovery" ] || return 1
  if path_present "$RECOVERY_PARENT"; then
    [ ! -L "$RECOVERY_PARENT" ] && [ -d "$RECOVERY_PARENT" ] \
      && [ "$(stat -c '%u:%g:%a' "$RECOVERY_PARENT")" = '0:0:700' ] || return 1
  else
    mkdir -- "$RECOVERY_PARENT" || return 1
    chown root:root "$RECOVERY_PARENT" && chmod 700 "$RECOVERY_PARENT" \
      && sync -f "$DATA_VOLUME_ROOT" || return 1
  fi
  if path_present "$RECOVERY_DIR"; then return 1; fi
  mkdir -- "$RECOVERY_DIR" || return 1
  chown root:root "$RECOVERY_DIR" && chmod 700 "$RECOVERY_DIR" || return 1
  artifact_count=0
  while IFS= read -r artifact; do
    [ -f "$artifact" ] && [ ! -L "$artifact" ] && [ "$(stat -c '%h:%u:%g:%a' "$artifact")" = '1:1000:1000:600' ] || return 1
    artifact_count=$((artifact_count + 1))
    [ "$artifact_count" -le 8 ] || return 1
    target="$RECOVERY_DIR/$(basename "$artifact")"
    cp --reflink=never -- "$artifact" "$target" || return 1
    chown root:root "$target" && chmod 600 "$target" && sync -f "$target" || return 1
  done < <(find "$source_recovery" -mindepth 1 -maxdepth 1 -type f -print)
  [ "$artifact_count" -ge 4 ] || return 1
  RECOVERY_BACKUP_NAME=$(basename "$container_backup")
  RECOVERY_MANIFEST_NAME=$(basename "$container_manifest")
  [[ "$RECOVERY_BACKUP_NAME" =~ ^[A-Za-z0-9._-]{1,180}$ ]] && [[ "$RECOVERY_MANIFEST_NAME" =~ ^[A-Za-z0-9._-]{1,180}$ ]] || return 1
  sync -f "$RECOVERY_DIR" && sync -f "$RECOVERY_PARENT"
  docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --cap-drop ALL --security-opt no-new-privileges --env-file /etc/redactwall/env \
    -v "$RECOVERY_DIR:/recovery:ro" --entrypoint node "$PREVIOUS_IMAGE_URI" \
    scripts/backup-store.js verify --file "/recovery/$RECOVERY_BACKUP_NAME" \
    --manifest "/recovery/$RECOVERY_MANIFEST_NAME" >/dev/null
}

restore_runtime_recovery_point() {
  [ -n "$PREVIOUS_CONTAINER_ID" ] || return 0
  [ -d "$RECOVERY_DIR" ] && [ ! -L "$RECOVERY_DIR" ] || return 1
  docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
    --cap-drop ALL --security-opt no-new-privileges --env-file /etc/redactwall/env \
    -v "$APP_DATA_DIR:/data" -v "$RECOVERY_DIR:/recovery:ro" --entrypoint node "$PREVIOUS_IMAGE_URI" \
    scripts/backup-store.js restore --file "/recovery/$RECOVERY_BACKUP_NAME" \
    --manifest "/recovery/$RECOVERY_MANIFEST_NAME" --to /data/redactwall.db --force >/dev/null || return 1
  docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --cap-drop ALL --security-opt no-new-privileges --env-file /etc/redactwall/env \
    -v "$APP_DATA_DIR:/data" --entrypoint node "$PREVIOUS_IMAGE_URI" \
    -e 'const db=require("./server/db");const result=db.verifyAuditChain();db._db.close();process.exit(result.ok?0:1)' >/dev/null
}

cleanup_rollback_artifacts() {
  if path_present "$LICENSE_STAGE"; then
    remove_exact_private_artifact "$LICENSE_STAGE" "$CANDIDATE_LICENSE_JSON" || return 1
  fi
  if path_present "$LICENSE_RETIRED"; then
    remove_exact_private_artifact "$LICENSE_RETIRED" "$CANDIDATE_LICENSE_JSON" || return 1
  fi
  if path_present "$LICENSE_ROLLBACK"; then return 1; fi
}

restore_previous_container() {
  current_id=$(container_id_named redactwall)
  previous_named_id=$(container_id_named "$PREVIOUS_CONTAINER_NAME")
  if [ -z "$PREVIOUS_CONTAINER_ID" ]; then
    [ -z "$current_id" ] && [ -z "$previous_named_id" ]
    return
  fi
  if [ "$previous_named_id" = "$PREVIOUS_CONTAINER_ID" ]; then
    if [ -n "$current_id" ]; then return 1; fi
    docker rename "$PREVIOUS_CONTAINER_ID" redactwall || return 1
    [ "$(container_id_named redactwall)" = "$PREVIOUS_CONTAINER_ID" ] || return 1
  elif [ "$current_id" != "$PREVIOUS_CONTAINER_ID" ]; then
    return 1
  fi
  previous_running=$(docker inspect -f '{{.State.Running}}' "$PREVIOUS_CONTAINER_ID" 2>/dev/null || true)
  if [ "$PREVIOUS_CONTAINER_RUNNING" = true ]; then
    if [ "$previous_running" != true ]; then docker start "$PREVIOUS_CONTAINER_ID" >/dev/null || return 1; fi
    [ "$(docker inspect -f '{{.State.Running}}' "$PREVIOUS_CONTAINER_ID" 2>/dev/null || true)" = true ] || return 1
  elif [ "$previous_running" = true ]; then
    return 1
  fi
}

publish_applied_state() {
  artifact_matches "$LICENSE_FINAL" "$CANDIDATE_LICENSE_JSON" 1000 1000 400 65536 || return 1
  [ "$(container_id_named redactwall)" = "$CANDIDATE_CONTAINER_ID" ] || return 1
  [ "$(docker inspect -f '{{.State.Running}}' "$CANDIDATE_CONTAINER_ID" 2>/dev/null || true)" = true ] || return 1
  applied_tmp=$(mktemp "$DEPLOY_STATE_DIR/.applied-deployment.XXXXXX")
  jq -cn \
    --arg imageUri "$TX_IMAGE_URI" \
    --arg secretArn "$TX_SECRET_ARN" --arg desiredConfigSha256 "$TX_CONFIG_SHA256" \
    --arg templateSha256 "$TX_TEMPLATE_SHA256" --arg protocolSha256 "$TX_PROTOCOL_SHA256" \
    --arg secretVersionId "$TX_LICENSE_SECRET_VERSION_ID" \
    --arg containerId "$CANDIDATE_CONTAINER_ID" \
    --arg licenseSha256 "$(printf '%s' "$CANDIDATE_LICENSE_JSON" | jq -r '.sha256')" \
    --arg dataVolumeId '${DataVolumeId}' \
    --arg dataFilesystemUuid "$(findmnt -n -o UUID --target "$DATA_VOLUME_ROOT")" \
    --arg recoveryPath "$([ -n "$PREVIOUS_CONTAINER_ID" ] && printf '%s' "$RECOVERY_DIR" || true)" \
    --arg committedAt "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" \
    '{version:1,imageUri:$imageUri,secretArn:$secretArn,secretVersionId:$secretVersionId,
      desiredConfigSha256:$desiredConfigSha256,templateSha256:$templateSha256,protocolSha256:$protocolSha256,
      containerId:$containerId,licenseSha256:$licenseSha256,
      dataVolumeId:$dataVolumeId,dataFilesystemUuid:$dataFilesystemUuid,
      committedAt:$committedAt,recoveryPath:(if $recoveryPath == "" then null else $recoveryPath end),warnings:[]}' > "$applied_tmp"
  chmod 600 "$applied_tmp"
  sync -f -- "$applied_tmp"
  mv -fT -- "$applied_tmp" "$APPLIED_STATE"
  sync -f -- "$DEPLOY_STATE_DIR"
}

applied_state_matches_transaction() {
  artifact_json "$APPLIED_STATE" 0 0 600 32768 >/dev/null || return 1
  expected_recovery_path=
  if [ -n "$PREVIOUS_CONTAINER_ID" ]; then expected_recovery_path=$RECOVERY_DIR; fi
  jq -e \
    --arg imageUri "$TX_IMAGE_URI" --arg secretArn "$TX_SECRET_ARN" \
    --arg secretVersionId "$TX_LICENSE_SECRET_VERSION_ID" --arg desiredConfigSha256 "$TX_CONFIG_SHA256" \
    --arg templateSha256 "$TX_TEMPLATE_SHA256" --arg protocolSha256 "$TX_PROTOCOL_SHA256" \
    --arg containerId "$CANDIDATE_CONTAINER_ID" \
    --arg licenseSha256 "$(printf '%s' "$CANDIDATE_LICENSE_JSON" | jq -r '.sha256')" \
    --arg dataVolumeId '${DataVolumeId}' --arg recoveryPath "$expected_recovery_path" '
      type == "object"
      and (keys | sort) == ["committedAt","containerId","dataFilesystemUuid","dataVolumeId","desiredConfigSha256","imageUri","licenseSha256","protocolSha256","recoveryPath","secretArn","secretVersionId","templateSha256","version","warnings"]
      and .version == 1 and .imageUri == $imageUri and .secretArn == $secretArn
      and .secretVersionId == $secretVersionId and .desiredConfigSha256 == $desiredConfigSha256
      and .templateSha256 == $templateSha256 and .protocolSha256 == $protocolSha256
      and .containerId == $containerId and .licenseSha256 == $licenseSha256
      and .dataVolumeId == $dataVolumeId
      and .recoveryPath == (if $recoveryPath == "" then null else $recoveryPath end)
      and (.warnings | type == "array" and all(.[]; type == "string" and test("^[a-z0-9_]{1,80}$")))
    ' "$APPLIED_STATE" >/dev/null
}

mutate_applied_warning() {
  warning_operation=$1
  warning_code=$2
  [ "$warning_operation" = add ] || [ "$warning_operation" = remove ] || return 1
  [[ "$warning_code" =~ ^[a-z0-9_]{1,80}$ ]] || return 1
  state_identity=$(artifact_json "$APPLIED_STATE" 0 0 600 32768) || return 1
  warning_tmp=$(mktemp "$DEPLOY_STATE_DIR/.applied-warning.XXXXXX")
  if [ "$warning_operation" = add ]; then
    jq --arg warning "$warning_code" '.warnings = ((.warnings + [$warning]) | unique)' "$APPLIED_STATE" > "$warning_tmp"
  else
    jq --arg warning "$warning_code" '.warnings = [.warnings[] | select(. != $warning)]' "$APPLIED_STATE" > "$warning_tmp"
  fi
  chmod 600 "$warning_tmp"
  sync -f "$warning_tmp"
  artifact_matches "$APPLIED_STATE" "$state_identity" 0 0 600 32768 || return 1
  mv -fT "$warning_tmp" "$APPLIED_STATE"
  sync -f "$DEPLOY_STATE_DIR"
}

record_applied_warning() {
  mutate_applied_warning add "$1"
}

clear_applied_warning() {
  mutate_applied_warning remove "$1"
}

applied_warning_present() {
  warning_code=$1
  [[ "$warning_code" =~ ^[a-z0-9_]{1,80}$ ]] || return 1
  artifact_json "$APPLIED_STATE" 0 0 600 32768 >/dev/null || return 1
  jq -e --arg warning "$warning_code" '.warnings | index($warning) != null' "$APPLIED_STATE" >/dev/null
}

cleanup_committed_transaction() {
  cleanup_ok=1
  if [ -z "$CANDIDATE_CONTAINER_ID" ]; then return 1; fi
  committed_candidate_label=$(docker inspect -f '{{index .Config.Labels "com.redactwall.deploy"}}' "$CANDIDATE_CONTAINER_ID" 2>/dev/null || true)
  committed_candidate_running=$(docker inspect -f '{{.State.Running}}' "$CANDIDATE_CONTAINER_ID" 2>/dev/null || true)
  if ! docker inspect "$CANDIDATE_CONTAINER_ID" >/dev/null 2>&1 \
    || [ "$(container_id_named redactwall)" != "$CANDIDATE_CONTAINER_ID" ] \
    || [ "$committed_candidate_label" != "$TX_ID" ] \
    || [ "$committed_candidate_running" != true ]; then
    return 1
  fi
  if ! applied_state_matches_transaction; then publish_applied_state || return 1; fi
  if [ -n "$PREVIOUS_CONTAINER_ID" ] && docker inspect "$PREVIOUS_CONTAINER_ID" >/dev/null 2>&1; then
    if ! docker rm -f "$PREVIOUS_CONTAINER_ID" >/dev/null \
      || docker inspect "$PREVIOUS_CONTAINER_ID" >/dev/null 2>&1; then cleanup_ok=0; fi
  fi
  if path_present "$LICENSE_ROLLBACK"; then
    if [ "$PRIOR_LICENSE_JSON" = null ] \
      || ! remove_exact_private_artifact "$LICENSE_ROLLBACK" "$PRIOR_LICENSE_JSON"; then cleanup_ok=0; fi
  fi
  if path_present "$LICENSE_STAGE"; then
    if ! remove_exact_private_artifact "$LICENSE_STAGE" "$CANDIDATE_LICENSE_JSON"; then cleanup_ok=0; fi
  fi
  if path_present "$LICENSE_RETIRED"; then
    if ! remove_exact_private_artifact "$LICENSE_RETIRED" "$CANDIDATE_LICENSE_JSON"; then cleanup_ok=0; fi
  fi
  [ "$cleanup_ok" -eq 1 ]
}

mark_committed_cleanup_pending() {
  COMMITTED_CLEANUP_PENDING=1
  if ! applied_state_matches_transaction || ! record_applied_warning committed_cleanup_pending; then
    echo "REDACTWALL_COMMITTED_DEGRADED=committed_cleanup_warning_persistence_failed" >&2
    return 1
  fi
  echo "REDACTWALL_APPLIED_WARNING=committed_cleanup_pending"
}

reconcile_committed_cleanup() {
  if ! cleanup_committed_transaction; then
    mark_committed_cleanup_pending
    return
  fi
  if ! journal_clear; then
    mark_committed_cleanup_pending
    return
  fi
  if applied_warning_present committed_cleanup_pending; then
    if ! clear_applied_warning committed_cleanup_pending; then
      COMMITTED_CLEANUP_PENDING=1
      echo "REDACTWALL_APPLIED_WARNING=committed_cleanup_pending"
      return 0
    fi
  fi
  COMMITTED_CLEANUP_PENDING=0
}

rollback_transaction() {
  remove_candidate_confirmed || return 1
  restore_license_transaction || return 1
  restore_runtime_recovery_point || return 1
  restore_previous_container || return 1
  ROLLBACK_RECOVERED=1
  cleanup_rollback_artifacts || return 1
  journal_clear
}

reconcile_existing_transaction() {
  if ! path_present "$DEPLOY_JOURNAL"; then
    if path_present "$APPLIED_STATE" && applied_warning_present committed_cleanup_pending; then
      if ! clear_applied_warning committed_cleanup_pending; then
        COMMITTED_CLEANUP_PENDING=1
        echo "REDACTWALL_APPLIED_WARNING=committed_cleanup_pending"
      fi
    fi
    return 0
  fi
  journal_load || {
    echo "The private deployment journal is invalid; no recovery artifact was changed" >&2
    return 1
  }
  if [ "$TX_PHASE" = committed ]; then
    reconcile_committed_cleanup
    return
  fi
  rollback_transaction || {
    if [ "$ROLLBACK_RECOVERED" -eq 1 ]; then
      echo "The prior deployment was restored; exact private cleanup artifacts remain journaled" >&2
    else
      echo "An interrupted deployment could not be reconciled safely; changed replacements and exact recovery artifacts were retained" >&2
    fi
    return 1
  }
}

# END REDACTWALL_LICENSE_DEPLOY_PROTOCOL

reconcile_existing_transaction

if desired_contract_applied; then
  exit 0
fi
if [ "$COMMITTED_CLEANUP_PENDING" -eq 1 ]; then
  echo "A new deployment cannot begin until committed cleanup reconciliation succeeds" >&2
  exit 1
fi

reset_transaction_contract_to_desired
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --version-id "$LICENSE_SECRET_VERSION_ID" --region '${AWS::Region}' --query SecretString --output text)
printf '%s' "$SECRET_JSON" | jq -e '
  type == "object"
  and ((keys - [
    "ADMIN_PASSWORD","ADMIN_TOTP_SECRET","REDACTWALL_SECRET","REDACTWALL_DATA_KEY",
    "REDACTWALL_LICENSE","REDACTWALL_LICENSE_PUBLIC_KEY_B64","INGEST_API_KEY",
    "OPERATOR_USER","OPERATOR_PASSWORD","APPROVER_USER","APPROVER_PASSWORD",
    "AUDITOR_USER","AUDITOR_PASSWORD","SCIM_BEARER_TOKEN",
    "OIDC_ISSUER","OIDC_CLIENT_ID","OIDC_CLIENT_SECRET","OIDC_REDIRECT_URI",
    "OIDC_AUTHORIZATION_ENDPOINT","OIDC_TOKEN_ENDPOINT","OIDC_JWKS_URI","OIDC_SCOPE",
    "SIEM_WEBHOOK_URL","SIEM_WEBHOOK_TOKEN","REDACTWALL_LICENSE_SERVER_URL",
    "REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN","REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN",
    "REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN","REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN",
    "REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED","REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED",
    "REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS","REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS",
    "REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64","REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64",
    "REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64","REDACTWALL_ENTITLEMENT_KEY_ID",
    "REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64","REDACTWALL_ENTITLEMENT_NEXT_KEY_ID"
  ]) | length) == 0
  and (. as $secret | [
    "ADMIN_PASSWORD","ADMIN_TOTP_SECRET","REDACTWALL_SECRET","REDACTWALL_DATA_KEY",
    "REDACTWALL_LICENSE","REDACTWALL_LICENSE_PUBLIC_KEY_B64","INGEST_API_KEY",
    "REDACTWALL_LICENSE_SERVER_URL","REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN",
    "REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN",
    "REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED","REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED",
    "REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64","REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64",
    "REDACTWALL_ENTITLEMENT_KEY_ID"
  ] | all(. as $key |
    ($secret | has($key)) and ($secret[$key] | type == "string") and ($secret[$key] | length > 0)
  ))
  and all(.[]; type == "string")
  and (.REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED == "true" or .REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED == "false")
  and (.REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED == "true" or .REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED == "false")
  and ((has("REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64")) == (has("REDACTWALL_ENTITLEMENT_NEXT_KEY_ID")))
' >/dev/null || {
  echo "The selected secret version has unknown, missing, or non-string fields" >&2
  exit 1
}
secret() {
  printf '%s' "$SECRET_JSON" | jq -er --arg key "$1" '
    (.[$key] // "") as $value |
    if ($value | type) != "string"
       or ($value | test("[\u0000-\u001f\u007f]"))
       or ($value != ($value | sub("^[[:space:]]+"; "") | sub("[[:space:]]+$"; "")))
    then error("invalid secret value") else $value end
  '
}

ADMIN_PASSWORD=$(secret ADMIN_PASSWORD)
ADMIN_TOTP_SECRET=$(secret ADMIN_TOTP_SECRET)
REDACTWALL_SECRET=$(secret REDACTWALL_SECRET)
REDACTWALL_DATA_KEY=$(secret REDACTWALL_DATA_KEY)
REDACTWALL_LICENSE_PUBLIC_KEY_B64=$(secret REDACTWALL_LICENSE_PUBLIC_KEY_B64)
INGEST_API_KEY=$(secret INGEST_API_KEY)
OPERATOR_USER=$(secret OPERATOR_USER)
OPERATOR_PASSWORD=$(secret OPERATOR_PASSWORD)
APPROVER_USER=$(secret APPROVER_USER)
APPROVER_PASSWORD=$(secret APPROVER_PASSWORD)
AUDITOR_USER=$(secret AUDITOR_USER)
AUDITOR_PASSWORD=$(secret AUDITOR_PASSWORD)
SCIM_BEARER_TOKEN=$(secret SCIM_BEARER_TOKEN)
OIDC_ISSUER=$(secret OIDC_ISSUER)
OIDC_CLIENT_ID=$(secret OIDC_CLIENT_ID)
OIDC_CLIENT_SECRET=$(secret OIDC_CLIENT_SECRET)
OIDC_REDIRECT_URI=$(secret OIDC_REDIRECT_URI)
OIDC_AUTHORIZATION_ENDPOINT=$(secret OIDC_AUTHORIZATION_ENDPOINT)
OIDC_TOKEN_ENDPOINT=$(secret OIDC_TOKEN_ENDPOINT)
OIDC_JWKS_URI=$(secret OIDC_JWKS_URI)
OIDC_SCOPE=$(secret OIDC_SCOPE)
SIEM_WEBHOOK_URL=$(secret SIEM_WEBHOOK_URL)
SIEM_WEBHOOK_TOKEN=$(secret SIEM_WEBHOOK_TOKEN)
REDACTWALL_LICENSE_SERVER_URL=$(secret REDACTWALL_LICENSE_SERVER_URL)
REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN=$(secret REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN)
REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN=$(secret REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN)
REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN=$(secret REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN)
REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN=$(secret REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN)
REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED=$(secret REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED)
REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED=$(secret REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED)
REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS=$(secret REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS)
REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS=$(secret REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS)
REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64=$(secret REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64)
REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64=$(secret REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64)
REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64=$(secret REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64)
REDACTWALL_ENTITLEMENT_KEY_ID=$(secret REDACTWALL_ENTITLEMENT_KEY_ID)
REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64=$(secret REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64)
REDACTWALL_ENTITLEMENT_NEXT_KEY_ID=$(secret REDACTWALL_ENTITLEMENT_NEXT_KEY_ID)
REDACTWALL_LICENSE=$(secret REDACTWALL_LICENSE)

LICENSE_BYTES=$(printf '%s' "$REDACTWALL_LICENSE" | wc -c)
if [ "$LICENSE_BYTES" -gt 65535 ] \
  || ! [[ "$REDACTWALL_LICENSE" =~ ^[A-Za-z0-9+/]+={0,2}\.[A-Za-z0-9+/]+={0,2}$ ]]; then
  echo "The customer license secret is malformed" >&2
  exit 1
fi
LICENSE_PAYLOAD_B64=$(printf '%s' "$REDACTWALL_LICENSE" | cut -d. -f1)
if ! printf '%s' "$LICENSE_PAYLOAD_B64" \
  | base64 --decode \
  | jq -e --arg tenant '${TenantId}' --arg deployment '${DeploymentId}' '
      type == "object"
      and (.customerId | type) == "string"
      and .customerId == $tenant
      and (.deploymentId | type) == "string"
      and .deploymentId == $deployment
      and .status == "active"
      and (.plan == "standard" or .plan == "enterprise")
      and (.seats | type) == "number"
      and (.seats | floor) == .seats
      and .seats > 0
      and (.expires | type) == "string"
      and (.expires | length) > 0
    ' >/dev/null 2>&1; then
  echo "The outage fallback payload is not active for this exact customer deployment" >&2
  exit 1
fi

umask 077
ENV_TMP=$(mktemp /etc/redactwall/env.XXXXXX)
{
  printf '%s\n' \
    'PORT=4000' \
    'NODE_ENV=production' \
    'HTTPS=true' \
    'COOKIE_SECURE=true' \
    'TRUST_PROXY=1' \
    'REDACTWALL_DATA_DIR=/data' \
    'REDACTWALL_DB_PATH=/data/redactwall.db' \
    'REDACTWALL_POLICY_PATH=/data/policy.json' \
    'REDACTWALL_CUSTOM_DETECTORS_PATH=/data/custom-detectors.json' \
    'REDACTWALL_LICENSE_PATH=/license/redactwall.lic' \
    'REDACTWALL_LICENSE_MANAGED_EXTERNALLY=true' \
    'REDACTWALL_VENDOR_STATE_PATH=/data/redactwall.vendor' \
    'REDACTWALL_PUBLIC_URL=https://${PublicHostname}' \
    'REDACTWALL_LICENSE_MODE=connected' \
    'REDACTWALL_SAAS_MODE=true' \
    'REDACTWALL_TENANT_ID=${TenantId}' \
    'REDACTWALL_CONNECTED_DEPLOYMENT_ID=${DeploymentId}' \
    'REDACTWALL_REQUIRE_TENANT_CONTEXT=true' \
    'REDACTWALL_REQUIRE_USER_IDENTITY=true' \
    'ADMIN_USER=admin' \
    'REDACTWALL_REQUEST_TIMEOUT_MS=10000' \
    'SIEM_ALERT_MIN_RISK=25' \
    'SIEM_ALERT_MIN_SEVERITY=3'
  printf 'ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD"
  printf 'ADMIN_TOTP_SECRET=%s\n' "$ADMIN_TOTP_SECRET"
  printf 'OPERATOR_USER=%s\n' "$OPERATOR_USER"
  printf 'OPERATOR_PASSWORD=%s\n' "$OPERATOR_PASSWORD"
  printf 'APPROVER_USER=%s\n' "$APPROVER_USER"
  printf 'APPROVER_PASSWORD=%s\n' "$APPROVER_PASSWORD"
  printf 'AUDITOR_USER=%s\n' "$AUDITOR_USER"
  printf 'AUDITOR_PASSWORD=%s\n' "$AUDITOR_PASSWORD"
  printf 'REDACTWALL_SECRET=%s\n' "$REDACTWALL_SECRET"
  printf 'REDACTWALL_DATA_KEY=%s\n' "$REDACTWALL_DATA_KEY"
  printf 'REDACTWALL_LICENSE_PUBLIC_KEY_B64=%s\n' "$REDACTWALL_LICENSE_PUBLIC_KEY_B64"
  printf 'INGEST_API_KEY=%s\n' "$INGEST_API_KEY"
  printf 'SCIM_BEARER_TOKEN=%s\n' "$SCIM_BEARER_TOKEN"
  printf 'OIDC_ISSUER=%s\n' "$OIDC_ISSUER"
  printf 'OIDC_CLIENT_ID=%s\n' "$OIDC_CLIENT_ID"
  printf 'OIDC_CLIENT_SECRET=%s\n' "$OIDC_CLIENT_SECRET"
  printf 'OIDC_REDIRECT_URI=%s\n' "$OIDC_REDIRECT_URI"
  printf 'OIDC_AUTHORIZATION_ENDPOINT=%s\n' "$OIDC_AUTHORIZATION_ENDPOINT"
  printf 'OIDC_TOKEN_ENDPOINT=%s\n' "$OIDC_TOKEN_ENDPOINT"
  printf 'OIDC_JWKS_URI=%s\n' "$OIDC_JWKS_URI"
  printf 'OIDC_SCOPE=%s\n' "$OIDC_SCOPE"
  printf 'SIEM_WEBHOOK_URL=%s\n' "$SIEM_WEBHOOK_URL"
  printf 'SIEM_WEBHOOK_TOKEN=%s\n' "$SIEM_WEBHOOK_TOKEN"
  printf 'REDACTWALL_LICENSE_SERVER_URL=%s\n' "$REDACTWALL_LICENSE_SERVER_URL"
  printf 'REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN=%s\n' "$REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN"
  printf 'REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN=%s\n' "$REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN"
  printf 'REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN=%s\n' "$REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN"
  printf 'REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN=%s\n' "$REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN"
  printf 'REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED=%s\n' "$REDACTWALL_VENDOR_CONTROL_DIAGNOSTICS_ENABLED"
  printf 'REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED=%s\n' "$REDACTWALL_VENDOR_CONTROL_SHADOW_INTELLIGENCE_ENABLED"
  printf 'REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS=%s\n' "$REDACTWALL_VENDOR_CONTROL_HEARTBEAT_INTERVAL_MS"
  printf 'REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS=%s\n' "$REDACTWALL_VENDOR_CONTROL_TIMEOUT_MS"
  printf 'REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64=%s\n' "$REDACTWALL_LICENSE_VERDICT_PUBLIC_KEY_B64"
  printf 'REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64=%s\n' "$REDACTWALL_LICENSE_VERDICT_NEXT_PUBLIC_KEY_B64"
  printf 'REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64=%s\n' "$REDACTWALL_ENTITLEMENT_PUBLIC_KEY_B64"
  printf 'REDACTWALL_ENTITLEMENT_KEY_ID=%s\n' "$REDACTWALL_ENTITLEMENT_KEY_ID"
  printf 'REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64=%s\n' "$REDACTWALL_ENTITLEMENT_NEXT_PUBLIC_KEY_B64"
  printf 'REDACTWALL_ENTITLEMENT_NEXT_KEY_ID=%s\n' "$REDACTWALL_ENTITLEMENT_NEXT_KEY_ID"
} > "$ENV_TMP"
chmod 600 "$ENV_TMP"
sync -f "$ENV_TMP"
mv -f "$ENV_TMP" /etc/redactwall/env
sync -f /etc/redactwall

REGISTRY=$(printf '%s' "$IMAGE_URI" | cut -d/ -f1)
aws ecr get-login-password --region '${AWS::Region}' | docker login --username AWS --password-stdin "$REGISTRY"
docker pull "$IMAGE_URI"
if ! printf '%s\n' "$REDACTWALL_LICENSE" \
  | docker run --rm -i \
      --network none \
      --read-only \
      --tmpfs /tmp:rw,noexec,nosuid,size=16m \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --env-file /etc/redactwall/env \
      --entrypoint node \
      "$IMAGE_URI" \
      -e 'const fs=require("fs"),license=require("./server/license"),preflight=require("./server/preflight");
        const result=license.verifyLicenseText(fs.readFileSync(0,"utf8"),{expectedCustomerId:process.env.REDACTWALL_TENANT_ID,env:process.env});
        const state=result.ok?license.evaluate(result.payload):"unlicensed";
        const managed=license.managedLicenseHealth({env:process.env,status:{state,payload:result.payload||null,reason:result.reason||null}});
        const status=preflight.configStatus({env:process.env,requireLicenseBinding:true,adminPasswordIsDefault:false,
          ingestKeyIsDefault:false,secretSource:"env",dataCryptoEnabled:true,cookieSecure:true,managedLicenseHealth:managed});
        const required=["license_mode","license_root_trust_anchor","managed_license_source","connected_offline_fallback",
          "connected_license_url","connected_license_auth","connected_license_optional_channels","connected_license_legacy_auth",
          "connected_license_timing","connected_license_tenant_id","connected_license_deployment_id",
          "connected_license_verdict_key","connected_entitlement_keys","license_customer_binding","saas_tenant_id",
          "saas_seat_limit","saas_tenant_context","saas_user_identity"];
        const checks=new Map(status.checks.map(item=>[item.id,item.ok]));
        process.exit(result.ok&&state==="active"&&managed.connectedFallbackCompatible===true
          &&required.every(id=>checks.get(id)===true)?0:1);'; then
  echo "The selected secret failed connected production preflight for this exact customer deployment" >&2
  exit 1
fi

TX_ID=$(tr -d '-' < /proc/sys/kernel/random/uuid)
if ! [[ "$TX_ID" =~ ^[a-f0-9]{32}$ ]]; then
  echo "A collision-resistant deployment transaction id could not be created" >&2
  exit 1
fi
transaction_paths
for transaction_path in "$LICENSE_STAGE" "$LICENSE_ROLLBACK" "$LICENSE_RETIRED"; do
  if path_present "$transaction_path"; then
    echo "A private deployment transaction path already exists" >&2
    exit 1
  fi
done
existing_candidate_id=$(discover_candidate_id) || {
  echo "Deployment transaction labels are ambiguous" >&2
  exit 1
}
if [ -n "$(container_id_named "$PREVIOUS_CONTAINER_NAME")" ] \
  || [ -n "$(container_id_named "$CANDIDATE_CONTAINER_NAME")" ] \
  || [ -n "$existing_candidate_id" ]; then
  echo "A deployment transaction container name or label already exists" >&2
  exit 1
fi

if path_present "$LICENSE_FINAL"; then
  PRIOR_LICENSE_JSON=$(artifact_json "$LICENSE_FINAL" 1000 1000 400 65536) || {
    echo "The existing customer license is not a stable owner-only single-link file" >&2
    exit 1
  }
  if [ "$(printf '%s' "$PRIOR_LICENSE_JSON" | jq -r '.dev')" != "$DEPLOY_DEVICE" ]; then
    echo "The existing customer license is not on the journal filesystem" >&2
    exit 1
  fi
fi

umask 077
set -o noclobber
exec {license_stage_fd}> "$LICENSE_STAGE"
set +o noclobber
printf '%s\n' "$REDACTWALL_LICENSE" >&$license_stage_fd
chown 1000:1000 "/proc/$BASHPID/fd/$license_stage_fd"
chmod 400 "/proc/$BASHPID/fd/$license_stage_fd"
sync -f -- "/proc/$BASHPID/fd/$license_stage_fd"
CANDIDATE_LICENSE_JSON=$(artifact_json "$LICENSE_STAGE" 1000 1000 400 65536) || {
  close_fd "$license_stage_fd"
  echo "The staged customer license could not be identity-bound" >&2
  exit 1
}
close_fd "$license_stage_fd"
cleanup_unjournaled_stage() {
  unjournaled_exit=$?
  trap - EXIT
  if path_present "$LICENSE_STAGE" \
    && ! remove_exact_private_artifact "$LICENSE_STAGE" "$CANDIDATE_LICENSE_JSON"; then
    echo "An exact private pre-journal staging artifact was retained" >&2
  fi
  exit "$unjournaled_exit"
}
trap cleanup_unjournaled_stage EXIT
if [ "$(printf '%s' "$CANDIDATE_LICENSE_JSON" | jq -r '.dev')" != "$DEPLOY_DEVICE" ]; then
  echo "The staged customer license is not on the data filesystem" >&2
  exit 1
fi

if [ "$PRIOR_LICENSE_JSON" != null ] \
  && same_license_bytes "$PRIOR_LICENSE_JSON" "$CANDIDATE_LICENSE_JSON"; then
  remove_exact_private_artifact "$LICENSE_STAGE" "$CANDIDATE_LICENSE_JSON"
  LICENSE_CHANGED=false
  CANDIDATE_LICENSE_JSON=$PRIOR_LICENSE_JSON
else
  LICENSE_CHANGED=true
fi

PREVIOUS_CONTAINER_ID=$(container_id_named redactwall)
if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
  if ! [[ "$PREVIOUS_CONTAINER_ID" =~ ^[a-f0-9]{64}$ ]]; then
    echo "The current RedactWall container identity is invalid" >&2
    exit 1
  fi
  PREVIOUS_CONTAINER_RUNNING=$(docker inspect -f '{{.State.Running}}' "$PREVIOUS_CONTAINER_ID")
  if [ "$PREVIOUS_CONTAINER_RUNNING" != true ] && [ "$PREVIOUS_CONTAINER_RUNNING" != false ]; then
    echo "The current RedactWall container state is invalid" >&2
    exit 1
  fi
fi

create_runtime_recovery_point || {
  echo "A verified pre-update runtime recovery point could not be created" >&2
  exit 1
}

journal_write prepared

rollback_deploy() {
  exit_code=$?
  trap - EXIT
  if [ "$DEPLOY_COMMITTED" -eq 1 ]; then
    reconcile_committed_cleanup || exit 70
    exit 0
  fi
  if [ "$COMMIT_ATTEMPTED" -eq 1 ]; then
    if ! journal_load; then
      echo "RedactWall commit outcome is uncertain; no candidate, license, or recovery artifact was changed" >&2
      exit 1
    fi
    if [ "$TX_PHASE" = committed ]; then
      reconcile_committed_cleanup || exit 70
      exit 0
    fi
  fi
  if ! rollback_transaction; then
    if [ "$ROLLBACK_RECOVERED" -eq 1 ]; then
      echo "RedactWall rollback restored the prior deployment; exact private cleanup artifacts remain journaled" >&2
    else
      echo "RedactWall rollback stopped before changing an unproven replacement; exact recovery artifacts were retained" >&2
    fi
    exit 1
  fi
  exit "$exit_code"
}
trap rollback_deploy EXIT

if [ -n "$PREVIOUS_CONTAINER_ID" ]; then
  if [ "$PREVIOUS_CONTAINER_RUNNING" = true ]; then
    docker stop -t 30 "$PREVIOUS_CONTAINER_ID" >/dev/null
  fi
  [ "$(container_id_named redactwall)" = "$PREVIOUS_CONTAINER_ID" ]
  docker rename "$PREVIOUS_CONTAINER_ID" "$PREVIOUS_CONTAINER_NAME"
  [ "$(container_id_named "$PREVIOUS_CONTAINER_NAME")" = "$PREVIOUS_CONTAINER_ID" ]
fi
journal_write previous_moved

if [ "$LICENSE_CHANGED" = true ]; then
  if [ "$PRIOR_LICENSE_JSON" != null ]; then
    move_exact_to_private "$LICENSE_FINAL" "$LICENSE_ROLLBACK" "$PRIOR_LICENSE_JSON"
  elif path_present "$LICENSE_FINAL"; then
    echo "A replacement appeared at the customer license path before publication" >&2
    exit 1
  fi
  journal_write prior_secured
  publish_exact_private "$LICENSE_STAGE" "$LICENSE_FINAL" "$CANDIDATE_LICENSE_JSON"
  journal_write candidate_published
else
  journal_write license_unchanged
fi
unset REDACTWALL_LICENSE LICENSE_PAYLOAD_B64 SECRET_JSON \
  ADMIN_PASSWORD ADMIN_TOTP_SECRET OPERATOR_PASSWORD APPROVER_PASSWORD AUDITOR_PASSWORD \
  REDACTWALL_SECRET REDACTWALL_DATA_KEY INGEST_API_KEY SCIM_BEARER_TOKEN OIDC_CLIENT_SECRET \
  SIEM_WEBHOOK_TOKEN REDACTWALL_VENDOR_CONTROL_HEARTBEAT_TOKEN \
  REDACTWALL_VENDOR_CONTROL_ACKNOWLEDGEMENT_TOKEN REDACTWALL_VENDOR_CONTROL_DIAGNOSTIC_TOKEN \
  REDACTWALL_VENDOR_CONTROL_SHADOW_CANDIDATE_TOKEN

set +e
candidate_create_output=$(docker create \
  --name "$CANDIDATE_CONTAINER_NAME" \
  --label "com.redactwall.deploy=$TX_ID" \
  --hostname redactwall \
  --restart unless-stopped \
  --init \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --stop-timeout 30 \
  --env-file /etc/redactwall/env \
  -p 4000:4000 \
  -v /var/lib/redactwall/runtime:/data \
  --mount type=bind,src="$LICENSE_FINAL",dst=/license/redactwall.lic,readonly \
  --log-driver=awslogs \
  --log-opt awslogs-region='${AWS::Region}' \
  --log-opt awslogs-group='${AppLogGroup}' \
  --log-opt awslogs-stream='${TenantId}' \
  "$IMAGE_URI" 2>&1)
candidate_create_status=$?
set -e
CANDIDATE_CONTAINER_ID=$(discover_candidate_id) || {
  echo "The candidate container identity is ambiguous" >&2
  exit 1
}
if [ -n "$CANDIDATE_CONTAINER_ID" ]; then journal_write candidate_created; fi
if [ "$candidate_create_status" -ne 0 ] || [ -z "$CANDIDATE_CONTAINER_ID" ] \
  || [ "$candidate_create_output" != "$CANDIDATE_CONTAINER_ID" ]; then
  echo "The candidate container could not be created with a bound identity" >&2
  exit 1
fi
unset candidate_create_output
docker start "$CANDIDATE_CONTAINER_ID" >/dev/null
[ "$(docker inspect -f '{{.State.Running}}' "$CANDIDATE_CONTAINER_ID" 2>/dev/null || true)" = true ]
journal_write candidate_started

READY=0
for attempt in $(seq 1 60); do
  CONTAINER_STATE=$(docker inspect -f '{{.State.Status}}' "$CANDIDATE_CONTAINER_ID" 2>/dev/null || echo missing)
  case "$CONTAINER_STATE" in
    exited|dead|restarting|missing)
      echo "RedactWall container entered terminal deployment state: $CONTAINER_STATE" >&2
      exit 1
      ;;
  esac
  HEALTH_STATUS=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$CANDIDATE_CONTAINER_ID" 2>/dev/null || echo missing)
  if [ "$HEALTH_STATUS" = "unhealthy" ]; then
    echo "RedactWall container health check failed" >&2
    exit 1
  fi
  if [ "$CONTAINER_STATE" = "running" ] && [ "$HEALTH_STATUS" = "healthy" ] \
    && curl --fail --silent --show-error --max-time 3 http://127.0.0.1:4000/readyz >/dev/null; then
    READY=1
    break
  fi
  sleep 5
done
if [ "$READY" -ne 1 ]; then
  echo "RedactWall did not become ready before the deployment deadline" >&2
  exit 1
fi
journal_write candidate_ready

artifact_matches "$LICENSE_FINAL" "$CANDIDATE_LICENSE_JSON" 1000 1000 400 65536 || {
  echo "The installed customer license changed before deployment commit" >&2
  exit 1
}
if [ -n "$(container_id_named redactwall)" ]; then
  echo "The canonical RedactWall container name was replaced before commit" >&2
  exit 1
fi
docker rename "$CANDIDATE_CONTAINER_ID" redactwall
[ "$(container_id_named redactwall)" = "$CANDIDATE_CONTAINER_ID" ]
journal_write candidate_named
COMMIT_ATTEMPTED=1
journal_write committed
DEPLOY_COMMITTED=1
trap - EXIT

reconcile_committed_cleanup || exit 70

if ! (
  set -e
  mkdir -p /var/log/redactwall
  docker cp redactwall:/app/scripts/run-evidence-pack.sh /usr/local/bin/redactwall-run-evidence-pack
  chmod 755 /usr/local/bin/redactwall-run-evidence-pack

if [ ! -f /var/lib/redactwall/runtime/evidence-schedule.json ]; then
  docker cp redactwall:/app/config/evidence-schedule.example.json /var/lib/redactwall/runtime/evidence-schedule.json
  jq '.outDir = "/data/evidence-packs" | .generatedBy = "aws-systemd-evidence-export"' \
    /var/lib/redactwall/runtime/evidence-schedule.json > /tmp/redactwall-evidence-schedule.json
  mv /tmp/redactwall-evidence-schedule.json /var/lib/redactwall/runtime/evidence-schedule.json
  chown 1000:1000 /var/lib/redactwall/runtime/evidence-schedule.json
  chmod 600 /var/lib/redactwall/runtime/evidence-schedule.json
fi

cat > /etc/redactwall/evidence-pack.env <<'EOF'
REDACTWALL_EVIDENCE_MODE='docker'
REDACTWALL_EVIDENCE_PROJECT_DIR='/app'
REDACTWALL_EVIDENCE_CONFIG='/data/evidence-schedule.json'
REDACTWALL_EVIDENCE_LOG='/var/log/redactwall/evidence-pack.log'
REDACTWALL_EVIDENCE_CONTAINER='redactwall'
EOF
chmod 600 /etc/redactwall/evidence-pack.env

cat > /etc/systemd/system/redactwall-evidence-pack.service <<'EOF'
[Unit]
Description=Generate sanitized RedactWall examiner evidence pack
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/redactwall/evidence-pack.env
ExecStart=/usr/local/bin/redactwall-run-evidence-pack
User=root
Group=root
Nice=5
EOF

cat > /etc/systemd/system/redactwall-evidence-pack.timer <<'EOF'
[Unit]
Description=Run sanitized RedactWall examiner evidence pack on schedule

[Timer]
OnCalendar=quarterly
Persistent=true
RandomizedDelaySec=1h
Unit=redactwall-evidence-pack.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now redactwall-evidence-pack.timer
); then
  if ! record_applied_warning evidence_scheduler_setup_failed; then
    echo "REDACTWALL_COMMITTED_DEGRADED=evidence_scheduler_warning_persistence_failed" >&2
    exit 70
  fi
  echo "REDACTWALL_APPLIED_WARNING=evidence_scheduler_setup_failed" >&2
fi
