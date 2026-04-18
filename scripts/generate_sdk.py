#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.api_contract_tools import load_yaml


def render_client(document: Dict[str, Any]) -> str:
    lines: List[str] = [
        'from __future__ import annotations',
        '',
        'from typing import Any, Dict, Optional',
        'from urllib.parse import urljoin',
        '',
        'import requests',
        '',
        '',
        'class ArpvpnApiClient:',
        '    def __init__(self, base_url: str, bearer_token: str = "", timeout: int = 30, verify: bool = True, session: Optional[requests.Session] = None):',
        '        self.base_url = base_url.rstrip("/") + "/"',
        '        self.timeout = timeout',
        '        self.verify = verify',
        '        self.session = session or requests.Session()',
        '        self.bearer_token = bearer_token',
        '',
        '    def set_bearer_token(self, token: str):',
        '        self.bearer_token = token',
        '',
        '    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, payload: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:',
        '        request_headers: Dict[str, str] = dict(headers or {})',
        '        if self.bearer_token:',
        '            request_headers.setdefault("Authorization", f"Bearer {self.bearer_token}")',
        '        response = self.session.request(',
        '            method.upper(),',
        '            urljoin(self.base_url, path.lstrip("/")),',
        '            params=params,',
        '            json=payload,',
        '            headers=request_headers,',
        '            timeout=self.timeout,',
        '            verify=self.verify,',
        '        )',
        '        response.raise_for_status()',
        '        content_type = response.headers.get("Content-Type", "")',
        '        if "application/json" in content_type:',
        '            return response.json()',
        '        return response.text',
        '',
    ]

    for path, path_item in sorted(document.get("paths", {}).items()):
        for method, operation in sorted(path_item.items()):
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            operation_id = str(operation.get("operationId", "call_operation") or "call_operation")
            method_name = operation_id[4:] if operation_id.startswith("api_") else operation_id
            params = [param["name"] for param in operation.get("parameters", []) if param.get("in") == "path"]
            signature_parts = ["self"] + params
            if operation.get("requestBody"):
                signature_parts.append("payload: Optional[Dict[str, Any]] = None")
            else:
                signature_parts.append("payload: Optional[Dict[str, Any]] = None")
            signature_parts.append("params: Optional[Dict[str, Any]] = None")
            signature_parts.append("headers: Optional[Dict[str, str]] = None")
            path_expr = path
            for param in params:
                path_expr = path_expr.replace(f"{{{param}}}", f"{{{param}}}")
            lines.append(f"    def {method_name}({', '.join(signature_parts)}) -> Any:")
            if params:
                lines.append(f'        path = f"{path_expr}"')
            else:
                lines.append(f'        path = "{path_expr}"')
            lines.append(f'        return self._request("{method.upper()}", path, params=params, payload=payload, headers=headers)')
            lines.append('')
    return "\n".join(lines).rstrip() + "\n"


def write_sdk(document: Dict[str, Any], output_dir: Path):
    package_dir = output_dir / "arpvpn_api_client"
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "__init__.py").write_text(
        'from .client import ArpvpnApiClient\n\n__all__ = ["ArpvpnApiClient"]\n',
        encoding="utf-8",
    )
    (package_dir / "client.py").write_text(render_client(document), encoding="utf-8")
    (output_dir / "README.md").write_text(
        "# ARPVPN Python SDK\n\nGenerated from `docs/source/api/openapi.v1.yaml`.\n",
        encoding="utf-8",
    )
    (output_dir / "pyproject.toml").write_text(
        """[project]\nname = \"arpvpn-api-client\"\nversion = \"0.1.0\"\ndescription = \"Generated Python client for ARPVPN\"\nrequires-python = \">=3.10\"\ndependencies = [\"requests>=2.32.0\"]\n\n[build-system]\nrequires = [\"setuptools>=68\"]\nbuild-backend = \"setuptools.build_meta\"\n""",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the ARPVPN Python SDK from OpenAPI.")
    parser.add_argument("--openapi", default="docs/source/api/openapi.v1.yaml", help="OpenAPI YAML path.")
    parser.add_argument("--output", default="sdk/python", help="SDK output directory.")
    args = parser.parse_args()

    document = load_yaml(Path(args.openapi))
    write_sdk(document, Path(args.output))
    print(f"Generated Python SDK in {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
