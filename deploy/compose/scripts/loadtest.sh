#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Load test (architecture.md exit criterion): drives SigV4 GET traffic through
# the proxy and fails unless the proxy-side verification overhead p99 stays
# under 1 ms (read from the verification_duration_seconds histogram).
#
#   ./deploy/compose/scripts/loadtest.sh          # after make up && make init
#   N=20000 C=50 ./deploy/compose/scripts/loadtest.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
NETWORK="ozone-oidc-proxy_oidc-net"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PROXY_URL="${PROXY_URL:-http://localhost:9000}"
ROLE_ARN="arn:ozone:iam::dev:role/oidc"
N="${N:-5000}"
C="${C:-20}"

echo "== building loadtest binary"
(cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o bin/loadtest ./deploy/compose/loadtest)

echo "== minting temporary credentials (alice)"
TOKEN=$(curl -sf "$KEYCLOAK_URL/realms/ozone/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=ozone-s3 \
    -d username=alice -d password=password123 | jq -r .access_token)
STS=$(curl -sf "$PROXY_URL/" -d Action=AssumeRoleWithWebIdentity \
    -d RoleArn="$ROLE_ARN" -d RoleSessionName=loadtest -d WebIdentityToken="$TOKEN")
AKID=$(grep -oP '(?<=<AccessKeyId>)[^<]+' <<<"$STS")
SECRET=$(grep -oP '(?<=<SecretAccessKey>)[^<]+' <<<"$STS")
SESSION=$(grep -oP '(?<=<SessionToken>)[^<]+' <<<"$STS")
[ -n "$AKID" ] || { echo "STS exchange failed: $STS" >&2; exit 1; }

BUCKET="loadtest-$RANDOM"
echo "== creating bucket $BUCKET"
docker run --rm --network "$NETWORK" -e AWS_DEFAULT_REGION=us-east-1 \
    -e "AWS_ACCESS_KEY_ID=$AKID" -e "AWS_SECRET_ACCESS_KEY=$SECRET" \
    -e "AWS_SESSION_TOKEN=$SESSION" amazon/aws-cli:latest \
    --endpoint-url http://proxy:9000 s3 mb "s3://$BUCKET" >/dev/null

echo "== running: $N requests, concurrency $C"
docker run --rm --network "$NETWORK" -v "$ROOT/bin/loadtest:/loadtest:ro" \
    busybox:stable /loadtest \
    -endpoint http://proxy:9000 -admin http://proxy:9090 \
    -bucket "$BUCKET" -akid "$AKID" -secret "$SECRET" -token "$SESSION" \
    -n "$N" -c "$C"
