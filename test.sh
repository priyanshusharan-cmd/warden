#!/usr/bin/env bash
# Run the backend test suite.
cd "$(dirname "$0")"
export PYTHONPATH="$PWD/backend${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m unittest discover -s backend/tests -t backend "$@"
