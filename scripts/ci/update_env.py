#!/usr/bin/env python3
"""Atomically update a restricted set of keys in a Docker Compose env file."""

from __future__ import annotations

import os
import re
import stat
import sys
import tempfile
from pathlib import Path


KEY_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")


def main() -> None:
    if len(sys.argv) < 3:
        raise SystemExit("usage: update_env.py ENV_FILE KEY=VALUE [KEY=VALUE ...]")

    env_path = Path(sys.argv[1])
    updates: dict[str, str] = {}
    for assignment in sys.argv[2:]:
        key, separator, value = assignment.partition("=")
        if separator != "=" or not KEY_PATTERN.fullmatch(key):
            raise SystemExit(f"invalid environment assignment: {assignment!r}")
        if "\n" in value or "\r" in value or "\x00" in value:
            raise SystemExit(f"invalid control character in value for {key}")
        updates[key] = value

    original = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
    output: list[str] = []
    written: set[str] = set()
    for line in original.splitlines():
        candidate = line.split("=", 1)[0]
        if candidate in updates:
            if candidate not in written:
                output.append(f"{candidate}={updates[candidate]}")
                written.add(candidate)
            continue
        output.append(line)

    for key, value in updates.items():
        if key not in written:
            output.append(f"{key}={value}")

    env_path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode = stat.S_IMODE(env_path.stat().st_mode) if env_path.exists() else 0o660
    fd, temporary_name = tempfile.mkstemp(prefix=f".{env_path.name}.", dir=env_path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(output).rstrip("\n") + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, existing_mode)
        os.replace(temporary_path, env_path)
    finally:
        temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
