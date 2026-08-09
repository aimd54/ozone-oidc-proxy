#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# The shortest path from a running stack to a working S3 call: sign in as a
# lab user, exchange the OIDC token for temporary credentials, and round-trip
# an object through the proxy. Run after `make up && make init`, or use
# `make demo`, which chains all three.
#
#   ./examples/compose/scripts/demo.sh
#
# The aws CLI runs containerized on the compose network, so it is not needed
# on the host. For the full acceptance matrix, run `make e2e` instead.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f $HERE/../docker-compose.yml"
NETWORK="ozone-oidc-proxy_oidc-net"
AWS_IMAGE="amazon/aws-cli:latest"

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PROXY_URL="${PROXY_URL:-http://localhost:9000}"
ROLE_ARN="arn:ozone:iam::dev:role/oidc"
USERNAME="alice"
BUCKET="demo-$RANDOM"
PAYLOAD="hello from the ozone oidc proxy"

step() { printf '\n\033[1;34m== %s\033[0m\n' "$1"; }
info() { printf '   %s\n' "$1"; }
die()  { printf '\n\033[0;31mFAILED\033[0m %s\n' "$1" >&2; exit 1; }

aws_run() { # <extra docker args...> -- <aws args...>
    local docker_args=()
    while [ "$1" != "--" ]; do docker_args+=("$1"); shift; done
    shift
    docker run --rm -i --network "$NETWORK" -e AWS_DEFAULT_REGION=us-east-1 \
        "${docker_args[@]}" "$AWS_IMAGE" --endpoint-url http://proxy:9000 "$@"
}

aws_as() { # <AKID> <SECRET> <SESSION> <aws args...>
    local akid="$1" secret="$2" session="$3"; shift 3
    aws_run -e "AWS_ACCESS_KEY_ID=$akid" -e "AWS_SECRET_ACCESS_KEY=$secret" \
        -e "AWS_SESSION_TOKEN=$session" -- "$@"
}

# Pull the aws CLI image up front. Otherwise docker writes pull progress to
# stderr in the middle of the first command and it lands in captured output.
if ! docker image inspect "$AWS_IMAGE" >/dev/null 2>&1; then
    info "pulling $AWS_IMAGE (first run only)"
    docker pull -q "$AWS_IMAGE" >/dev/null 2>&1 || die "could not pull $AWS_IMAGE"
fi

step "1/4  Sign in as $USERNAME and get an OIDC token"
TOKEN=$(curl -sf "$KEYCLOAK_URL/realms/ozone/protocol/openid-connect/token" \
    -d grant_type=password -d client_id=ozone-s3 \
    -d "username=$USERNAME" -d "password=password123" | jq -r '.access_token // empty')
[ -n "$TOKEN" ] || die "no token from the identity provider. Is the stack up (make up && make init)?"
info "got a JWT, aud=$(cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.aud | if type=="array" then join(",") else . end')"
info "(the password grant is a lab shortcut; humans use 'bin/ozone-login')"

step "2/4  Exchange it at the proxy's STS for temporary credentials"
ERRLOG=$(mktemp); trap 'rm -f "$ERRLOG"' EXIT
CREDS=$(aws_run -- sts assume-role-with-web-identity \
    --role-arn "$ROLE_ARN" --role-session-name demo \
    --web-identity-token "$TOKEN" --output json 2>"$ERRLOG") \
    || die "token exchange failed: $(cat "$ERRLOG")"
read -r AKID SECRET SESSION <<<"$(jq -r '.Credentials | "\(.AccessKeyId) \(.SecretAccessKey) \(.SessionToken)"' <<<"$CREDS" 2>/dev/null)"
[ -n "$AKID" ] && [ "$AKID" != "null" ] || die "exchange returned no credentials: $CREDS"
case "$AKID" in
    OZPX*) info "minted $AKID (the secret and session token stay out of this output)" ;;
    *)     die "expected an OZPX... access key ID, got '$AKID'" ;;
esac

step "3/4  Use them like any other S3 credentials"
aws_as "$AKID" "$SECRET" "$SESSION" s3 mb "s3://$BUCKET" >/dev/null 2>&1 \
    || die "could not create bucket $BUCKET"
info "created s3://$BUCKET"
printf '%s' "$PAYLOAD" | aws_as "$AKID" "$SECRET" "$SESSION" s3 cp - "s3://$BUCKET/hello.txt" >/dev/null 2>&1 \
    || die "could not upload the object"
GOT=$(aws_as "$AKID" "$SECRET" "$SESSION" s3 cp "s3://$BUCKET/hello.txt" - 2>/dev/null)
[ "$GOT" = "$PAYLOAD" ] || die "round-trip mismatch: read back '$GOT', wrote '$PAYLOAD'"
info "uploaded and read back ${#PAYLOAD} bytes, byte-identical"

step "4/4  Confirm Ozone attributed it to the OIDC user, not to a shared key"
OWNER=$($COMPOSE exec -T ozone-om ozone sh bucket info "/s3v/$BUCKET" 2>/dev/null | jq -r '.owner // empty')
[ "$OWNER" = "$USERNAME" ] \
    || die "bucket owner is '$OWNER', expected '$USERNAME'. Identity injection is not working."
info "ozone sh bucket info /s3v/$BUCKET → owner: $OWNER"

cat <<EOF

$(printf '\033[0;32mWorked.\033[0m') $USERNAME signed in with OIDC, got short-lived credentials, and
Ozone recorded them as the owner of s3://$BUCKET. Its native ACLs now apply
to that user, with no Kerberos and no static access key anywhere.

Next:
  bin/ozone-login -issuer http://keycloak:8080/realms/ozone   # the human flow
  make e2e                                                    # full acceptance suite
  make portal-up                                              # browser credential page

Clean up this bucket:
  docker compose -f examples/compose/docker-compose.yml exec ozone-om \\
    ozone sh bucket delete /s3v/$BUCKET
EOF
