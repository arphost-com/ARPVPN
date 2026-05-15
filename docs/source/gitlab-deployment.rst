GitLab Deployment Pipeline
==========================

ARPVPN uses GitLab CI for private image publishing and deployment promotion. The
repository is public, so the pipeline file must never contain secrets, host keys,
tokens, passwords, private hostnames, or private paths.

The workflow is guarded so it runs only when the GitLab project visibility is
``private``. Deployment jobs add stricter guards and run only when all of these
are true:

* The GitLab project visibility is ``private``.
* The commit is on the default branch.
* The ref is protected.

This keeps public repository contents separate from private deployment execution
and prevents docker02 or production credentials from being used by public CI.

Pipeline flow
-------------

1. ``test`` installs dependencies, compiles the package and tests, runs pytest,
   validates OpenAPI, and checks generated API artifacts.
2. ``docker:build`` builds ``docker/Dockerfile`` and publishes the commit image
   plus the ``stable`` tag to the private GitLab registry.
3. ``deploy:docker02`` automatically pulls the commit image on docker02, updates
   the configured Compose environment file, starts the service, waits for the
   container health state, and optionally checks ``STAGING_HEALTH_URL``.
4. ``deploy:production`` is manual. It is available only after docker02 passes,
   and deploys the same commit image to production.
5. ``rollback:production`` is manual and deploys ``PROD_ROLLBACK_IMAGE``.

Required private variables
--------------------------

Set these as masked, protected CI/CD variables in the private GitLab project.
Do not commit their values.

Registry pull token:

* ``DEPLOY_REGISTRY_USER``
* ``DEPLOY_REGISTRY_PASSWORD``

docker02 staging:

* ``STAGING_SSH_HOST``
* ``STAGING_SSH_USER``
* ``STAGING_SSH_PRIVATE_KEY``
* ``STAGING_DEPLOY_PATH``

Optional docker02 variables:

* ``STAGING_ENV_FILE``; defaults to ``.env``
* ``STAGING_COMPOSE_PROJECT``; defaults to ``arpvpn_docker02``
* ``STAGING_SERVICE``; defaults to ``arpvpn``
* ``STAGING_URL``
* ``STAGING_HEALTH_URL``

Production:

* ``PROD_SSH_HOST``
* ``PROD_SSH_USER``
* ``PROD_SSH_PRIVATE_KEY``
* ``PROD_DEPLOY_PATH``

Optional production variables:

* ``PROD_ENV_FILE``; defaults to ``.env``
* ``PROD_COMPOSE_PROJECT``; defaults to ``arpvpn_prod``
* ``PROD_SERVICE``; defaults to ``arpvpn``
* ``PROD_URL``
* ``PROD_HEALTH_URL``
* ``PROD_ROLLBACK_IMAGE``; required only for the rollback job

Operational notes
-----------------

Keep deployment runners private and disable public pipeline visibility in the
GitLab project settings. Protect the default branch and all deployment variables
before enabling the staging or production jobs.

Production deployment is intentionally manual. Pushes to the default branch can
build and validate on docker02 automatically, but an operator must approve the
``deploy:production`` job before production changes.
