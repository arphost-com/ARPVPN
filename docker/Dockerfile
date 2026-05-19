FROM python:3.14-slim-trixie

ARG ARPVPN_UID=1000
ARG ARPVPN_GID=1000
ARG POETRY_VERSION=2.4.1
ARG POETRY_PLUGIN_EXPORT_VERSION=1.10.0
ARG WIREGUARD_TOOLS_VERSION=1.0.20260223
ARG WIREGUARD_TOOLS_SHA256=af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf

ENV PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    INSTALL_PATH="/var/www/arpvpn" \
    DATA_PATH="/var/www/arpvpn/data" \
    EXPORTED_PATH="/data" \
    ARPVPN_WIREGUARD_TOOLS_FROM_SOURCE=1 \
    ARPVPN_WIREGUARD_TOOLS_VERSION="${WIREGUARD_TOOLS_VERSION}" \
    ARPVPN_WIREGUARD_TOOLS_SHA256="${WIREGUARD_TOOLS_SHA256}"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      gcc \
      iproute2 \
      iptables \
      libc6-dev \
      make \
      openssl \
      pkg-config \
      rrdtool \
      sudo \
      uwsgi \
      uwsgi-plugin-python3 \
      xz-utils && \
    rm -rf /var/lib/apt/lists/*

# Create the runtime user early so install.sh can reuse the same account.
RUN groupadd -g "${ARPVPN_GID}" arpvpn && \
    useradd -u "${ARPVPN_UID}" -g arpvpn -s /bin/bash -m arpvpn

WORKDIR /tmp/arpvpn
COPY . /tmp/arpvpn

RUN set -eu; \
    if [ ! -f requirements.txt ] && [ -f pyproject.toml ]; then \
      python3 -m pip install --no-cache-dir "poetry==${POETRY_VERSION}" "poetry-plugin-export==${POETRY_PLUGIN_EXPORT_VERSION}"; \
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
    "$install_script"; \
    apt-get purge -y --auto-remove curl gcc libc6-dev make pkg-config xz-utils; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

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
