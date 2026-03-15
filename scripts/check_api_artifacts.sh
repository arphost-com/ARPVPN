#!/usr/bin/env bash
set -euo pipefail

python3 scripts/generate_openapi.py
python3 scripts/generate_sdk.py

git diff --exit-code -- docs/source/api/openapi.v1.yaml sdk/python
