#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"

"$PYTHON_BIN" scripts/generate_openapi.py
"$PYTHON_BIN" scripts/generate_sdk.py

git diff --exit-code -- docs/source/api/openapi.v1.yaml sdk/python
