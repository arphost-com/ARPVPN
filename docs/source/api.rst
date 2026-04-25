API
===

ARPVPN API v1 uses the ``/api/v1`` path with compatibility guarantees defined in:

- ``API_VERSIONING.md``
- ``API_CHANGELOG_PROCESS.md``

OpenAPI source of truth:

- ``docs/source/api/openapi.v1.yaml``

The OpenAPI source is validated in CI by:

- ``scripts/validate_openapi.py``

Current API shape includes authentication, profile, setup, system, statistics, traffic/RRD graphs,
WireGuard controls, and related security endpoints.
