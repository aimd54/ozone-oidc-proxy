#!/bin/bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Ozone-side ACL bootstrap (architecture.md), run inside the OM container:
#   docker compose exec ozone-om bash /scripts/setup-volume-acls.sh
#
# Grants on the S3 volume /s3v:
#   r (read) + l (list)   , required for any S3 traversal
#   w (write) + c (create): bucket creation through the S3 API: OM checks
#                            WRITE on the volume for CreateBucket (verified
#                            against 2.1.1 via om-audit;)
# Per-bucket grants stay per-user/per-bucket (see the e2e script and).
set -e

if [ ! -x /opt/hadoop/bin/ozone ] && ! command -v ozone >/dev/null; then
    echo "This script must run inside the Ozone OM container" >&2
    exit 1
fi

# carol authenticates via the stub second issuer (deploy/compose/stub-issuer).
for user in alice bob carol; do
    echo "Granting user:${user}:rwlc on /s3v"
    ozone sh volume addacl -a "user:${user}:rwlc" /s3v 2>/dev/null \
        || echo "  (grant already present)"
done

echo
echo "Current /s3v ACLs:"
ozone sh volume getacl /s3v
