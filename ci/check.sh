#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

printf '%s\n' 'Running unit tests...'
python3 -m unittest discover -s "$ROOT/tests" -t "$ROOT" -v

printf '%s\n' 'Compiling Python sources...'
python3 -m compileall -q -f "$ROOT/src" "$ROOT/tests" "$ROOT/examples"

printf '%s\n' 'All checks passed.'
