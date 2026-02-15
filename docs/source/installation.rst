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

1. Download the ``docker-compose.yaml`` file `from the repository <https://raw.githubusercontent.com/arphost-com/ARPVPN/main/docker/docker-compose.yaml>`__.
2. Run ARPVPN:

    .. code-block:: bash

        sudo docker-compose up -d

.. note::
    You can check all available tags `here <https://github.com/arphost-com/ARPVPN/pkgs/container/arpvpn/versions>`__.
