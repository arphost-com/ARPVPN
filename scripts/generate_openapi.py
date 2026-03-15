#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from scripts.api_contract_tools import build_openapi_document, dump_yaml


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the live ARPVPN OpenAPI document.")
    parser.add_argument("--output", default="docs/source/api/openapi.v1.yaml", help="Output YAML path.")
    parser.add_argument("--version", default=None, help="Override API version in the generated document.")
    args = parser.parse_args()

    if args.version:
        version = args.version
    else:
        from arpvpn import __version__
        version = getattr(__version__, "release", "unknown")

    document = build_openapi_document(version)
    output_path = Path(args.output)
    dump_yaml(document, output_path)
    print(f"Generated OpenAPI document at {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
