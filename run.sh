#!/usr/bin/env bash
# Start Warden: API + web console. Host and port come from config/settings.json; PORT=xxxx overrides.
cd "$(dirname "$0")"
export PYTHONPATH="$PWD/backend${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m warden.api.server ${PORT:+--port "$PORT"} "$@"
