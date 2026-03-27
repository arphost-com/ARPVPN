#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
GIT_BIN="${GIT_BIN:-$(command -v git || true)}"

if [[ -z "$GIT_BIN" && -x /usr/bin/git ]]; then
  GIT_BIN="/usr/bin/git"
fi

if [[ -z "$GIT_BIN" ]]; then
  echo "git is required to validate generated API artifacts." >&2
  exit 1
fi

"$PYTHON_BIN" scripts/generate_openapi.py
"$PYTHON_BIN" scripts/generate_sdk.py

"$GIT_BIN" diff --exit-code -- docs/source/api/openapi.v1.yaml sdk/python
