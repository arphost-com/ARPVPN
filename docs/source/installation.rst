Installation
============

As a systemd service
--------------------

1. Download `any release <https://github.com/arphost-com/ARPVPN/releases>`__.
2. Extract it and run the installation script:

    .. code-block:: bash

        chmod +x install.sh
        sudo ./install.sh
3. Run ARPVPN:

    .. code-block:: bash

        sudo systemctl start arpvpn.service

Using docker
------------

1. Copy ``docker/docker-compose.yaml``, ``docker/.env.example``, and ``docker/up.sh`` from this repository.
2. Create a local ``.env`` file and set values for your host:

    .. code-block:: bash

        cp .env.example .env

   Important variables:

   * ``ARPVPN_IMAGE`` (image/tag to run)
   * ``ARPVPN_RUNTIME_USER`` (runtime user inside container, default ``arpvpn``)
   * ``ARPVPN_CONTAINER_NAME`` (container name; set unique value per stack)
   * ``ARPVPN_SECURE_COOKIES`` (``0`` for mixed HTTP/HTTPS, ``1`` for strict HTTPS)
   * ``ARPVPN_HTTP_PORT`` (HTTP bind port, default ``8085``)
   * ``ARPVPN_HTTPS_PORT`` (HTTPS bind port, default ``8086``)
   * ``DATA_FOLDER`` (host path mounted to ``/data``)

   Suggested image tags by release line:

   * v1 ``main``: ``10.10.10.96:5050/arphost/arpvpn:stable``
   * v2 ``codex/multitenant-v2``: ``10.10.10.96:5050/arphost/arpvpn:v2-latest``

3. Create/validate data folder ownership and start:

    .. code-block:: bash

        ./up.sh pull
        ./up.sh up -d --force-recreate arpvpn

4. If data folder was created previously as root, fix ownership once:

    .. code-block:: bash

        sudo chown -R "$(id -u):$(id -g)" ./data

.. note::
    For side-by-side v1 and v2 installs, use separate ``DATA_FOLDER`` paths and different host ports.
