Contributing
============

.. note::

    This repository is the ARPVPN project.

You may contribute by opening issues, commenting on existing ones, and creating pull requests with new features and bug fixes.

Git flow
--------

Do not work directly on ``main``. Create a feature branch from ``main`` and open a pull request back into ``main`` once the work is ready.

.. code-block:: bash

    git clone <your-fork-or-local-path>
    cd arpvpn
    git checkout -b your-feature-branch

Requirements
------------

You will need to install the following Linux packages:

.. code-block::

    sudo iproute2 python3 python3-venv wireguard-tools iptables libpcre3 libpcre3-dev uwsgi uwsgi-plugin-python3

Dependency management
---------------------

`Poetry <https://python-poetry.org/>`__ is used to handle packaging and dependencies.

.. code-block:: bash

    poetry config virtualenvs.in-project true
    poetry install

Validation
----------

Validate the OpenAPI contract and generated artifacts before publishing changes:

.. code-block:: bash

    python3 scripts/validate_openapi.py
    ./scripts/check_api_artifacts.sh

Building
--------

To build ARPVPN, use ``build.sh``. It generates a ``dist`` folder containing the release artifact.

CI/CD
-----

Use the repository's configured CI provider to run required test and package jobs for pull requests targeting ``main``.

.. warning::

    The ``main`` branch is used to publish release images and should only receive reviewed pull requests.
