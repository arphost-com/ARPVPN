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

1. Copy the ``docker/docker-compose.yaml`` file from this repository.
2. Set values directly in compose (or in a ``.env`` file):

    .. code-block:: yaml

        services:
          arpvpn:
            image: 10.10.10.96:5050/arphost/arpvpn:stable
            user: "1000:1000"
            environment:
              ARPVPN_SECURE_COOKIES: "0"
              ARPVPN_UID: "1000"
              ARPVPN_GID: "1000"

3. Run ARPVPN:

    .. code-block:: bash

        sudo docker compose up -d --force-recreate arpvpn

.. note::
    You can check all available tags in your GitLab project's Container Registry.
