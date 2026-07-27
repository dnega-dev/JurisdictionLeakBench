#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$ROOT/.benchmark-output"}
mkdir -p "$OUTPUT_DIR"

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

python3 -m jurisdiction_leak_bench generate \
  --seed 1337 --output "$OUTPUT_DIR/corpus.json"
python3 -m jurisdiction_leak_bench run \
  --corpus "$OUTPUT_DIR/corpus.json" --output "$OUTPUT_DIR/run.json"
python3 -m jurisdiction_leak_bench report \
  "$OUTPUT_DIR/run.json" --format junit --output "$OUTPUT_DIR/results.xml"
python3 -m jurisdiction_leak_bench report \
  "$OUTPUT_DIR/run.json" --format sarif --output "$OUTPUT_DIR/results.sarif"

printf 'Artifacts written to %s\n' "$OUTPUT_DIR"
