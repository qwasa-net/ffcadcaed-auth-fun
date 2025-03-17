#!/bin/bash
set -e

PASSWD=${PASSWD:-"passwd"}


rm -rfv /var/lib/krb5kdc/principal*
kdb5_util create -s -P "${PASSWD}" || true

mkdir -pv /_keytabs
rm -rfv /_keytabs/*

kadmin.local -q "add_principal -pw ${PASSWD} CLIENT"
kadmin.local -q "ktadd -norandkey -k /_keytabs/client.keytab CLIENT"

kadmin.local -q "add_principal -randkey SERVICE/service"
kadmin.local -q "ktadd -norandkey -k /_keytabs/service.keytab SERVICE/service"

chmod 644 /_keytabs/*.keytab

ls -l /_keytabs
klist -k /_keytabs/client.keytab
klist -k /_keytabs/service.keytab

mkdir -pv /etc/krb5kdc/
echo '*/admin@DEV.LOCAL *' > /etc/krb5kdc/kadm5.acl

kadmin.local -q 'list_principals'

krb5kdc
kadmind -nofork