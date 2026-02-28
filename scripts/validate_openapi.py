#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - depends on runtime environment
    yaml = None


def validate_openapi_document(path: Path) -> int:
    if yaml is None:
        print("ERROR: PyYAML is required to validate OpenAPI docs. Install dependency 'PyYAML'.")
        return 1

    if not path.exists():
        print(f"ERROR: OpenAPI file not found: {path}")
        return 1

    with path.open("r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle)

    errors = []
    if not isinstance(document, dict):
        errors.append("Top-level document must be a mapping.")
        document = {}

    openapi_version = str(document.get("openapi", "") or "")
    if not openapi_version.startswith("3."):
        errors.append("openapi must be a 3.x value.")

    info = document.get("info", {})
    if not isinstance(info, dict):
        errors.append("info must be an object.")
        info = {}
    if not str(info.get("version", "")).strip():
        errors.append("info.version is required.")

    paths = document.get("paths", {})
    if not isinstance(paths, dict) or not paths:
        errors.append("paths must be a non-empty object.")
        paths = {}

    operation_ids = set()
    for route_path, route_item in paths.items():
        if not str(route_path).startswith("/api/v1"):
            errors.append(f"Path '{route_path}' must start with /api/v1.")
        if not isinstance(route_item, dict):
            errors.append(f"Path item for '{route_path}' must be an object.")
            continue
        for method, operation in route_item.items():
            if method.lower() not in {"get", "post", "put", "delete", "patch"}:
                continue
            if not isinstance(operation, dict):
                errors.append(f"Operation '{method.upper()} {route_path}' must be an object.")
                continue
            operation_id = str(operation.get("operationId", "")).strip()
            if not operation_id:
                errors.append(f"Operation '{method.upper()} {route_path}' is missing operationId.")
                continue
            if operation_id in operation_ids:
                errors.append(f"Duplicate operationId '{operation_id}'.")
                continue
            operation_ids.add(operation_id)

    if errors:
        print("OpenAPI validation failed:")
        for err in errors:
            print(f"- {err}")
        return 1

    print(
        f"OpenAPI validation passed for {path} "
        f"(version={openapi_version}, operations={len(operation_ids)})"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate ARPVPN OpenAPI source document.")
    parser.add_argument(
        "--file",
        default="docs/source/api/openapi.v1.yaml",
        help="Path to the OpenAPI YAML file.",
    )
    args = parser.parse_args(argv)
    return validate_openapi_document(Path(args.file))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
