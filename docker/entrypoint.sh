#!/usr/bin/env bash
set -euo pipefail

export NO_PASSWORD_PORT="${NO_PASSWORD_PORT:-9000}"
export NO_PASSWORD_CADDY_ADMIN_ADDRESS="${NO_PASSWORD_CADDY_ADMIN_ADDRESS:-127.0.0.1:2019}"
export NO_PASSWORD_CADDY_CONFIG_PATH="${NO_PASSWORD_CADDY_CONFIG_PATH:-/app/data/caddy/managed.Caddyfile}"
export HOME=/app/data
export XDG_CONFIG_HOME=/app/data/caddy/config
export XDG_DATA_HOME=/app/data/caddy/data

mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" /app/data/caddy

caddy_config=/etc/caddy/Caddyfile
if [ -f "$NO_PASSWORD_CADDY_CONFIG_PATH" ]; then
  caddy_config="$NO_PASSWORD_CADDY_CONFIG_PATH"
fi

/app/nopassword-server &
server_pid=$!

caddy run --config "$caddy_config" --adapter caddyfile &
caddy_pid=$!

terminate() {
  kill -TERM "$server_pid" "$caddy_pid" 2>/dev/null || true
}

trap terminate INT TERM

set +e
wait -n "$server_pid" "$caddy_pid"
status=$?
set -e

terminate
wait "$server_pid" "$caddy_pid" 2>/dev/null || true

exit "$status"
