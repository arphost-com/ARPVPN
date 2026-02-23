FROM python:3.12-slim-trixie as python-base
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
ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:$PATH"

# Create non-root user early
RUN groupadd -g "${ARPVPN_GID}" arpvpn && \
    useradd -u "${ARPVPN_UID}" -g arpvpn -s /bin/bash -m arpvpn

COPY dist/*.tar.gz /tmp/arpvpn.tar.gz
RUN mkdir /tmp/arpvpn && tar -xf /tmp/arpvpn.tar.gz -C /tmp/arpvpn
WORKDIR /tmp/arpvpn
RUN chmod +x ./install.sh && ./install.sh

# Create data directory with correct ownership
RUN mkdir -p $EXPORTED_PATH && \
    chown -R arpvpn:arpvpn $EXPORTED_PATH && \
    rm -rf /tmp/arpvpn*

WORKDIR /data

COPY --chown=arpvpn:arpvpn --chmod=755 docker/entrypoint.sh /entrypoint.sh

# Switch to non-root user
USER arpvpn

EXPOSE 8080

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import os, urllib.request; port = os.environ.get('ARPVPN_HTTP_PORT', '8080'); urllib.request.urlopen(f'http://localhost:{port}').read()" || exit 1

CMD /bin/bash /entrypoint.sh
