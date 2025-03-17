FROM debian:stable-slim

WORKDIR /app

RUN --mount=type=cache,mode=0755,id=apt-cache,target=/var/apt-cache \
    APT_CACHE_DIR=/var/apt-cache \
    apt-get update && apt-get -y upgrade

RUN --mount=type=cache,mode=0755,id=apt-cache,target=/var/apt-cache \
    APT_CACHE_DIR=/var/apt-cache \
    apt-get -y install --no-install-recommends --no-show-upgraded \
    python3 python3-pip python3-venv python3-dev libkrb5-dev krb5-user \
    gcc make curl \
    && python3 --version

ADD requirements.txt client.py service.py Makefile /app/

RUN --mount=type=cache,mode=0755,id=pip-cache,target=/var/pip-cache \
    PIP_CACHE_DIR=/var/pip-cache \
    make venv

COPY --chown=nobody:nogroup krbbrb/krb5.conf /app/_krbbrb/krb5.conf
COPY --chown=nobody:nogroup _certs* /app/_certs

EXPOSE 3443

ENV KRB5CCNAME=/tmp/krb5cc \
    KRB5_KTNAME=/app/_krbbrb/my.keytab \
    KRB5_CONFIG=/app/_krbbrb/krb5.conf \
    KRB5_TRACE=

USER nobody
