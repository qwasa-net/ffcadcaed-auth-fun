FROM debian:stable-slim

RUN --mount=type=cache,mode=0755,id=apt-cache,target=/var/apt-cache \
    APT_CACHE_DIR=/var/apt-cache \
    apt-get update && apt-get -y upgrade

RUN --mount=type=cache,mode=0755,id=apt-cache,target=/var/apt-cache \
    APT_CACHE_DIR=/var/apt-cache \
    apt-get -y install --no-install-recommends \
    krb5-kdc krb5-admin-server krb5-config

#
COPY krbbrb/krb5.conf /etc/krb5.conf
COPY krbbrb/krb.sh /krb.sh

#
RUN chmod +x /krb.sh

#
VOLUME /_keytabs

EXPOSE 88 464 749

#
CMD ["/bin/bash", "/krb.sh"]