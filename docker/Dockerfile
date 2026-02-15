FROM python:3.9-slim-bullseye as python-base
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
COPY dist/*.tar.gz arpvpn.tar.gz
RUN mkdir arpvpn && tar -xf arpvpn.tar.gz -C arpvpn
WORKDIR arpvpn
RUN chmod +x ./install.sh && ./install.sh
WORKDIR $EXPORTED_PATH
RUN rm -rf /arpvpn*

EXPOSE 8080

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD /bin/bash /entrypoint.sh
