#!/bin/sh
set -eu

if [ "${REDACTWALL_SKIP_POLICY_SEED:-}" != "1" ]; then
  node scripts/seed-runtime-policy.js
fi
exec "$@"
