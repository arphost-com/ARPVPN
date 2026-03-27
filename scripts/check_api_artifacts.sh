#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"

snapshot_path() {
  "$PYTHON_BIN" - "$1" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
hasher = hashlib.sha256()

if not path.exists():
    hasher.update(b"<missing>")
elif path.is_file():
    hasher.update(path.name.encode("utf-8"))
    hasher.update(b"\0")
    hasher.update(path.read_bytes())
else:
    for file_path in sorted(candidate for candidate in path.rglob("*") if candidate.is_file()):
        rel = file_path.relative_to(path)
        hasher.update(str(rel).encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(file_path.read_bytes())

print(hasher.hexdigest())
PY
}

openapi_before="$(snapshot_path docs/source/api/openapi.v1.yaml)"
sdk_before="$(snapshot_path sdk/python)"

"$PYTHON_BIN" scripts/generate_openapi.py
"$PYTHON_BIN" scripts/generate_sdk.py

openapi_after="$(snapshot_path docs/source/api/openapi.v1.yaml)"
sdk_after="$(snapshot_path sdk/python)"

if [[ "$openapi_before" != "$openapi_after" || "$sdk_before" != "$sdk_after" ]]; then
  echo "Generated API artifacts are stale. Regenerate docs/source/api/openapi.v1.yaml and sdk/python." >&2
  exit 1
fi
