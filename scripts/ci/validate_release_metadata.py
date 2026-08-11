#!/usr/bin/env python3
"""Validate that all canonical ARPVPN release declarations are synchronized."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def match_version(path: Path, pattern: str) -> str:
    match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
    if match is None:
        raise SystemExit(f"Unable to find a release version in {path.relative_to(ROOT)}")
    return match.group(1)


def main() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    versions = {
        "pyproject.toml": str(pyproject["tool"]["poetry"]["version"]),
        "arpvpn/__version__.py": match_version(
            ROOT / "arpvpn/__version__.py", r"^release\s*=\s*['\"]([^'\"]+)['\"]"
        ),
        "docs/source/conf.py": match_version(
            ROOT / "docs/source/conf.py", r"^release\s*=\s*['\"]([^'\"]+)['\"]"
        ),
        "docs/source/api/openapi.v1.yaml": match_version(
            ROOT / "docs/source/api/openapi.v1.yaml",
            r"^info:\s*\n(?:^[ \t]+.*\n)*?^[ \t]+version:\s*([^\s#]+)",
        ),
    }

    expected = versions["pyproject.toml"]
    if not SEMVER.fullmatch(expected):
        raise SystemExit(f"Canonical release is not a stable semantic version: {expected}")

    mismatches = {name: version for name, version in versions.items() if version != expected}
    if mismatches:
        rendered = ", ".join(f"{name}={version}" for name, version in mismatches.items())
        raise SystemExit(f"Release metadata mismatch; expected {expected}: {rendered}")

    changelog = (ROOT / "docs/source/changelog.rst").read_text(encoding="utf-8")
    if re.search(rf"^{re.escape(expected)}\s*$", changelog, re.MULTILINE) is None:
        raise SystemExit(f"docs/source/changelog.rst has no {expected} release heading")

    print(f"Release metadata is synchronized at {expected}.")


if __name__ == "__main__":
    main()
