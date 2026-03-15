#!/usr/bin/env bash
set -euo pipefail

python3 scripts/validate_openapi.py
./scripts/check_api_artifacts.sh

pytest -q \
  arpvpn/tests/default/test_api_auth.py \
  arpvpn/tests/default/test_api_cookie_csrf.py \
  arpvpn/tests/default/test_api_feature_flags.py \
  arpvpn/tests/default/test_api_authorization_matrix.py \
  arpvpn/tests/default/test_api_schema_registry.py \
  arpvpn/tests/default/test_api_ui_parity.py \
  arpvpn/tests/default/test_tenant_user_invitation_api.py \
  arpvpn/tests/default/test_tenant_runtime_api.py \
  arpvpn/tests/default/test_user_bulk_api.py \
  arpvpn/tests/default/test_wireguard_api.py \
  arpvpn/tests/default/test_statistics_api.py \
  arpvpn/tests/default/test_tls_api.py \
  arpvpn/tests/default/test_system_api.py \
  arpvpn/tests/default/test_mesh_planner.py \
  arpvpn/tests/default/test_mesh_api.py
