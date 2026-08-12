GitLab Deployment Pipeline
==========================

ARPVPN uses its private GitLab project as the authoritative CI/CD and deployment
source. The public GitHub repository is updated only by the final manual
``publish:github`` job after the same GitLab commit has completed production
deployment. The pipeline contains no credentials, private hostnames, or private
deployment paths.

The workflow runs only when ``CI_PROJECT_VISIBILITY`` is ``private``. Host
deployment jobs require the protected default branch. Docker03 production,
rollback, and GitHub publication remain explicit manual actions.

Runner routing
--------------

* ``docker02-shell`` runs validation, tests, repository security, image build and
  scan, development deployment, smoke validation, and image promotion.
* ``docker03`` runs the final manual production and rollback jobs.
* Both are shell runners on their target Docker hosts. Deployment uses the local
  ``debian`` service account through passwordless non-interactive ``sudo``;
  ``gitlab-runner`` remains an orchestration account and must not own deployment
  or runtime data.

Pipeline flow
-------------

1. ``validate:repository`` checks release metadata, pipeline YAML, Compose
   rendering with CI-only values, and Git whitespace.
2. ``test:python`` compiles the source, runs the complete pytest suite, validates
   OpenAPI, and verifies generated API artifacts.
3. Dedicated security jobs run Semgrep, Trivy repository scanning, Gitleaks,
   TruffleHog, Dependency-Check, and Bandit. High-signal findings block the build
   and reports are retained for one week.
4. ``build:image`` builds the versioned release archive and container, pushes the
   commit tag, resolves the registry digest, and exports that immutable digest as
   a dotenv artifact.
5. ``security:image`` blocks root/no-user images, missing health checks, embedded
   version mismatches, and high/critical Trivy image findings.
6. ``deploy:docker02`` runs automatically on protected ``main``. It validates
   deployment/data paths, installs Compose helpers as ``debian``, repairs the
   runtime data ownership, and starts the immutable digest without building on
   the host.
7. ``smoke:docker02`` requires Docker health ``healthy``, verifies the exact
   running digest and release version, checks a loopback HTTP/HTTPS endpoint, and
   rejects app-critical files owned by ``gitlab-runner``.
8. ``publish:validated-image`` runs only after development smoke succeeds. It
   publishes the immutable digest as ``3.0.6`` and ``stable`` and refuses to
   overwrite an existing version tag with another digest.
9. ``deploy:production`` is a final manual job on docker03. It consumes the same
   immutable digest and restores the previously running registry image if the
   new production smoke test fails. Restoration verifies the exact prior image
   ID before reusing a locally cached image, so recovery does not depend on the
   current project credentials having pull access to an older repository.
10. ``rollback:production`` is a separate manual job requiring an explicit
    registry image through ``PROD_ROLLBACK_IMAGE``.
11. ``publish:github`` becomes available only after successful production. It
    uses an allowlisted HTTPS repository, refuses divergent/non-fast-forward
    publication, never force-pushes, and obtains its token only through
    ``GIT_ASKPASS``.

Required protected variables
----------------------------

All values belong in the private GitLab project. Do not add them to repository
files. Paths and URLs do not need masking but must be protected. The GitHub token
must be both protected and masked.

Docker02 development:

* ``STAGING_DEPLOY_PATH``
* ``STAGING_DATA_FOLDER`` (must be inside ``STAGING_DEPLOY_PATH``)
* ``STAGING_ENV_FILE``
* ``STAGING_CONTAINER_NAME``
* ``STAGING_COMPOSE_PROJECT``
* ``STAGING_HTTP_PORT``
* ``STAGING_HTTPS_PORT``
* ``STAGING_URL``
* ``STAGING_HEALTH_URL`` (loopback HTTP/HTTPS only)

Docker03 production:

* ``PROD_DEPLOY_PATH``
* ``PROD_DATA_FOLDER`` (must be inside ``PROD_DEPLOY_PATH``)
* ``PROD_ENV_FILE``
* ``PROD_CONTAINER_NAME``
* ``PROD_COMPOSE_PROJECT``
* ``PROD_HTTP_PORT``
* ``PROD_HTTPS_PORT``
* ``PROD_URL``
* ``PROD_HEALTH_URL`` (loopback HTTP/HTTPS only)

Publication and rollback:

* ``GITHUB_PUSH_TOKEN``: protected and masked token used only by
  ``publish:github``.
* ``PROD_ROLLBACK_IMAGE``: supplied when an operator explicitly runs the manual
  rollback job; use a trusted immutable registry digest.

GitLab provides ``CI_REGISTRY_USER`` and ``CI_REGISTRY_PASSWORD`` to jobs. The
pipeline keeps Docker authentication in per-job temporary directories and does
not persist registry credentials under the deployment user.

Operational safeguards
----------------------

Development and production use separate resource groups, preventing overlapping
host-network deployments. Deployment paths are canonicalized and restricted to
approved host path classes, runtime data must remain under the deployment path,
and only the fixed ``debian`` service user performs deployment-path work.

Production is never automatic. To release, allow all development and security
jobs to finish, independently verify the docker02 application behavior, then run
``deploy:production`` manually. If production fails, inspect the failed job and
the restored container before considering another promotion. Run
``publish:github`` separately only after the GitLab deployment is complete.
