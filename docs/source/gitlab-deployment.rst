GitLab Deployment
=================

This project publishes Docker images to GitLab Container Registry using ``.gitlab-ci.yml``.

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

If your registry is configured as insecure HTTP, configure dind accordingly at runner level.

CI publish behavior
-------------------

1. Run the required ``unit_tests`` job.
2. Build the package artifact via ``build.sh``.
3. Build the Docker image.
4. Push branch or tag specific image tags:

   * default branch builds:
      * ``$CI_REGISTRY_IMAGE:latest``
      * ``$CI_REGISTRY_IMAGE:2.x``
      * ``$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA``
   * ``v2.*`` tags:
      * ``$CI_REGISTRY_IMAGE:latest``
      * ``$CI_REGISTRY_IMAGE:2.x``
      * ``$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG``

Optional environment or integration suite
-----------------------------------------

The full pytest suite is available as ``integration_tests_env`` and is intended for runners or hosts with WireGuard and network tooling available.

- Trigger by setting pipeline variable ``RUN_ENV_INTEGRATION_TESTS=1``.
- This job is non-blocking (``allow_failure``) and does not gate image publication.

API contract suite
------------------

The repository also runs ``api_contract_tests`` as a non-blocking CI job.

- Validates ``docs/source/api/openapi.v1.yaml``.
- Runs the focused API or security regression subset from ``scripts/run-api-contract-tests.sh``.
- Keeps the existing ``unit_tests`` subset as the hard gate while still reporting API drift early.
- Supports feature-flagged rollout of API groups through environment variables such as ``ARPVPN_FEATURE_API_MESH=0`` or ``ARPVPN_FEATURE_API_WIREGUARD=0``.

Deploying ARPVPN with compose
-----------------------------

On your deployment host:

.. code-block:: bash

    docker login <your-registry>
    docker compose -f docker/docker-compose.yaml up -d

Set ``ARPVPN_IMAGE`` in compose ``.env`` when using a non-default registry path.

docker02 clean validation workflow
----------------------------------

Use only these two ARPVPN clone paths on ``docker02``:

- ``/home/debian/docker/arpvpn``
- ``/home/debian/docker/arpvpn-mutlitenant``

For a full validation run:

1. Delete the target clone directory.
2. Re-clone the repository into one of the two paths above.
3. Run validation from that fresh clone with a unique container name, cookie suffix, data directory, and test ports.

Fresh standalone multitenant validation was completed on ``2026-03-26`` from the clean ``docker02`` clone at ``/home/debian/docker/arpvpn-mutlitenant``.
