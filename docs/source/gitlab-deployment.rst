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

On push to default branch (or tags), pipeline will:

1. Build package artifact via ``build.sh``.
2. Build Docker image.
3. Push:

   * ``$CI_REGISTRY_IMAGE:stable``
   * ``$CI_REGISTRY_IMAGE:$CI_COMMIT_SHORT_SHA``

Deploying ARPVPN with compose
-----------------------------

On your deployment host:

.. code-block:: bash

    docker login <your-registry>
    export ARPVPN_IMAGE="<your-registry>/<group>/<project>:stable"
    docker compose -f docker/docker-compose.yaml up -d

The compose file defaults to ``arpvpn:stable`` if ``ARPVPN_IMAGE`` is not set.
