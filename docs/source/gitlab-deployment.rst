GitLab Deployment
=================

This project is configured to publish Docker images to GitLab Container Registry using ``.gitlab-ci.yml``.

Prerequisites
-------------

1. GitLab project exists at your instance URL (for you: ``http://10.10.10.96:8929/``).
2. Container Registry is enabled at instance and project level.
3. A GitLab Runner is attached to the project and uses Docker executor in ``privileged`` mode.

Runner configuration (required)
-------------------------------

Register a runner and ensure Docker executor is privileged.

Minimal ``config.toml`` example:

.. code-block:: toml

    [[runners]]
      name = "arpvpn-docker"
      url = "http://10.10.10.96:8929/"
      token = "REDACTED"
      executor = "docker"

      [runners.docker]
        image = "docker:27.1.1"
        privileged = true
        tls_verify = false
        volumes = ["/cache"]

Registry TLS/CA notes
---------------------

If your registry uses an internal or self-signed certificate, install the CA cert on the runner host so Docker and dind trust it.

If your registry is configured as insecure HTTP (not recommended), configure dind accordingly at runner level.

CI publish behavior
-------------------

GitLab publish jobs are split by release line.

1. Run the required ``unit_tests`` job (``pytest`` deterministic unit subset).
2. Build package artifact via ``build.sh``.
3. Build Docker image.
4. Push branch/tag-specific image tags:

   * ``main`` + ``v1.*`` tags:
      * ``$CI_REGISTRY_IMAGE:stable``
      * ``$CI_REGISTRY_IMAGE:1.2.x``
      * ``$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA`` (branch builds)
      * ``$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG`` (tag builds)
   * ``codex/multitenant-v2`` + ``v2.*`` tags:
      * ``$CI_REGISTRY_IMAGE:v2-latest``
      * ``$CI_REGISTRY_IMAGE:v2-$CI_COMMIT_SHORT_SHA`` (branch builds)
      * ``$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG`` (tag builds)

Optional environment/integration suite
--------------------------------------

The full pytest suite is available as ``integration_tests_env`` and is intended for runners/hosts
with WireGuard/network tooling available.

- Trigger by setting pipeline variable ``RUN_ENV_INTEGRATION_TESTS=1``.
- This job is non-blocking (``allow_failure``) and does not gate image publication.

Deploying ARPVPN with compose
-----------------------------

On your deployment host:

.. code-block:: bash

    docker login <your-registry>
    docker compose -f docker/docker-compose.yaml up -d

Set ``ARPVPN_IMAGE`` in compose/.env when using a non-default registry path.
