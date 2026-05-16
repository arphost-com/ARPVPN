FROM python:3.14-slim-trixie

ARG ARPVPN_UID=1000
ARG ARPVPN_GID=1000

ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    INSTALL_PATH="/var/www/arpvpn" \
    DATA_PATH="/var/www/arpvpn/data" \
    EXPORTED_PATH="/data"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      iproute2 \
      iptables \
      openssl \
      rrdtool \
      sudo \
      wireguard-tools \
      uwsgi \
      uwsgi-plugin-python3 && \
    rm -rf /var/lib/apt/lists/*

# Create the runtime user early so install.sh can reuse the same account.
RUN groupadd -g "${ARPVPN_GID}" arpvpn && \
    useradd -u "${ARPVPN_UID}" -g arpvpn -s /bin/bash -m arpvpn

WORKDIR /tmp/arpvpn
COPY . /tmp/arpvpn

RUN set -eu; \
    if [ ! -f requirements.txt ] && [ -f pyproject.toml ]; then \
      python3 -m pip install --no-cache-dir poetry==2.3.4 poetry-plugin-export==1.10.0; \
      poetry export --without-hashes -f requirements.txt -o requirements.txt; \
    fi; \
    if [ -x ./install.sh ]; then \
      install_script="./install.sh"; \
    elif [ -x ./scripts/install.sh ]; then \
      install_script="./scripts/install.sh"; \
    else \
      echo "Unable to locate install.sh in the build context." >&2; \
      exit 1; \
    fi; \
    chmod +x "$install_script"; \
    "$install_script"

# Create data directory with correct ownership
RUN mkdir -p "$EXPORTED_PATH" && \
    chown -R arpvpn:arpvpn "$EXPORTED_PATH" && \
    rm -rf /tmp/arpvpn*

ENV PATH="/var/www/arpvpn/venv/bin:$PATH"

WORKDIR /data

COPY --chown=arpvpn:arpvpn --chmod=755 docker/entrypoint.sh /entrypoint.sh

USER arpvpn

EXPOSE 8085 8086

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import os, urllib.request; p = os.environ.get('ARPVPN_HTTP_PORT', '8085'); urllib.request.urlopen(f'http://localhost:{p}', timeout=5).read()" \
    || python3 -c "import os, ssl, urllib.request; p = os.environ.get('ARPVPN_HTTPS_PORT', '8086'); ctx = ssl._create_unverified_context(); urllib.request.urlopen(f'https://localhost:{p}', context=ctx, timeout=5).read()" \
    || exit 1

CMD ["/bin/bash", "/entrypoint.sh"]
