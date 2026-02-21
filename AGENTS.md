# ARPVPN Codex Guardrails

Use these mandatory security rules for every change in this repository.

- Never use `shell=True` with subprocess execution.
- Never redirect users to request-controlled URLs; only redirect to allowlisted `url_for()` endpoints.
- Keep Flask debug server bound to loopback only.
- Never use Jinja `|safe` for request/data-driven values; use default escaping and `|tojson` for JavaScript literals.
- Never inject untrusted variables directly into `href`/`src` attributes.
- Use cryptographically secure randomness (`secrets`) for generated security-relevant values.
- Docker images must run as non-root, use absolute `WORKDIR`, and include a `HEALTHCHECK`.
- Keep dependency lockfiles current when security advisories exist.
- Keep test-only insecure settings in test scope and exclude tests/generated docs from production security scans.
