#!/bin/bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Lakehouse-overlay Ozone bootstrap, run inside the OM container:
#   docker compose exec ozone-om bash /scripts/setup-lakehouse-acls.sh
#
# Nessie authenticates through the proxy as the Keycloak service account
# `service-account-nessie` (client-credentials grant → STS web identity);
# alice writes Iceberg data files with her own credentials. Both need the
# volume traversal grants plus full access to the warehouse bucket.
set -e

if [ ! -x /opt/hadoop/bin/ozone ] && ! command -v ozone >/dev/null; then
    echo "This script must run inside the Ozone OM container" >&2
    exit 1
fi

echo "Granting user:service-account-nessie:rwlc on /s3v"
ozone sh volume addacl -a "user:service-account-nessie:rwlc" /s3v 2>/dev/null \
    || echo "  (grant already present)"

echo "Creating /s3v/lakehouse (Iceberg warehouse)"
ozone sh bucket info /s3v/lakehouse >/dev/null 2>&1 \
    || ozone sh bucket create /s3v/lakehouse

for grant in "user:service-account-nessie:a" "user:alice:a"; do
    echo "Granting ${grant} on /s3v/lakehouse"
    ozone sh bucket addacl -a "$grant" /s3v/lakehouse 2>/dev/null \
        || echo "  (grant already present)"
done

echo
echo "Current /s3v/lakehouse ACLs:"
ozone sh bucket getacl /s3v/lakehouse
