# ARPVPN Codex Guardrails

Use these mandatory security rules for every change in this repository.

Reference: `SECURITY_ANTI_PATTERNS.md` (compiled from scan sheets 1 + 2).

- Never use `shell=True` with subprocess execution.
- Never redirect users to request-controlled URLs; only redirect to allowlisted `url_for()` endpoints.
- Keep Flask debug server bound to loopback only by default.
- Never use Jinja `|safe` for request/data-driven values; use default escaping and `|tojson` for JavaScript literals.
- Never inject untrusted variables directly into `href`/`src` attributes, and always keep attributes quoted.
- Never hardcode credentials, API keys, or weak default passwords.
- Use cryptographically secure randomness (`secrets`) for generated security-relevant values.
- Do not rely on `assert` for production security checks; use explicit validation and error handling.
- Docker images must run as non-root, use absolute `WORKDIR`, include a `HEALTHCHECK`, and use current supported base images.
- Keep dependency manifests and lockfiles current when vulnerabilities are reported.
- Keep test-only insecure settings in test scope and annotate scan exceptions with explicit rule IDs.
- Do not commit generated docs output (`docs/source/_build/`); only commit source docs.
