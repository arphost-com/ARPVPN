API
===

ARPVPN API v1 uses the ``/api/v1`` path with compatibility guarantees defined in:

- ``API_VERSIONING.md``
- ``API_CHANGELOG_PROCESS.md``

OpenAPI source of truth:

- ``docs/source/api/openapi.v1.yaml``
- ``API_COVERAGE.md`` for the implemented route surface and current coverage gaps

The OpenAPI source is validated in CI by:

- ``scripts/validate_openapi.py``

Current API shape:

- Hybrid REST and action-style API
- Strongest implemented areas: auth, statistics, RRD access, themes, and TLS
- Still incomplete for full platform automation: users, WireGuard CRUD, tenant management, and system operations

Documentation note:

- The live route surface in code is currently broader than the published OpenAPI file.
- Use ``API_COVERAGE.md`` together with the OpenAPI document when evaluating current capability.
