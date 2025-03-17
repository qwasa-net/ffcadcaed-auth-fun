#!/bin/bash
set -e

CLIENT_PASS=${CLIENT_PASS:-"passwd"}
CLIENT_NAME=${CLIENT_NAME:-"CLIENT"}
SERVICE_NAME=${SERVICE_NAME:-"SERVICE"}
SERVICE_HOST=${SERVICE_HOST:-"localhost"}

rm -rfv /var/lib/krb5kdc/principal*
kdb5_util create -s -P "${CLIENT_PASS}" || true

mkdir -pv /_keytabs
rm -rfv /_keytabs/*

kadmin.local -q "add_principal -pw ${CLIENT_PASS} ${CLIENT_NAME}"
kadmin.local -q "ktadd -norandkey -k /_keytabs/client.keytab ${CLIENT_NAME}"

kadmin.local -q "add_principal -randkey ${SERVICE_NAME}/${SERVICE_HOST}"
kadmin.local -q "ktadd -norandkey -k /_keytabs/service.keytab ${SERVICE_NAME}/${SERVICE_HOST}"

chmod 644 /_keytabs/*.keytab

ls -l /_keytabs
klist -k /_keytabs/client.keytab
klist -k /_keytabs/service.keytab

mkdir -pv /etc/krb5kdc/
echo '*/admin@DEV.LOCAL *' > /etc/krb5kdc/kadm5.acl

kadmin.local -q 'list_principals'

krb5kdc
kadmind -nofork