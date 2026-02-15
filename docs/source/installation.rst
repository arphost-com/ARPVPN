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
2. Set your GitLab container image:

    .. code-block:: bash

        export ARPVPN_IMAGE="registry.example.com/group/project/arpvpn:stable"

3. Run ARPVPN:

    .. code-block:: bash

        sudo docker-compose up -d

.. note::
    You can check all available tags in your GitLab project's Container Registry.
