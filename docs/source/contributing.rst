Contributing
============

.. note::

    This repository is the private ARPVPN line.

You may contribute by opening issues, commenting on existing ones, and creating merge requests with new features and bug fixes.

Git flow
--------

Do not work directly on ``main``. Create a feature branch from ``main`` and open a GitLab merge request back into ``main`` once the work is ready.

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

Testing
-------

`PyTest <https://docs.pytest.org/>`__ and `Coverage <https://coverage.readthedocs.io/>`__ are used for tests and coverage reports.

Run the test suite with Poetry:

.. code-block:: bash

    poetry run pytest

Building
--------

To build ARPVPN, use ``build.sh``. It generates a ``dist`` folder containing the release artifact.

CI/CD
-----

GitLab CI is used to implement the pipeline. When merge requests targeting ``main`` are opened, the required test and package jobs run automatically.

.. warning::

    The ``main`` branch is used to publish release images and should only receive reviewed merge requests.
