#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end test suite for the compose stack: the M1 exit criteria of
# DESIGN.md §11.3 plus M2 checks — presigned URLs, the multipart matrix
# (2.1.1 ListParts/ListMultipartUploads ACL enforcement, §9.2), the human
# credential UX, the second issuer (stub IdP) and client smoke tests
# (boto3, mc, s3a). Run from anywhere after `make up && make init`:
#
#   ./deploy/compose/scripts/e2e.sh
#
# Requires on the host: docker, curl, jq. AWS CLI runs containerized
# (amazon/aws-cli) on the compose network, so it is not needed locally.
# Expired-JWT and expired-temp-credential paths are covered by unit tests
# (clock-injected); everything else is exercised live here.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="docker compose -f $HERE/../docker-compose.yml"
NETWORK="ozone-oidc-proxy_oidc-net"
AWS_IMAGE="amazon/aws-cli:latest"

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PROXY_URL="${PROXY_URL:-http://localhost:9000}"
ADMIN_URL="${ADMIN_URL:-http://localhost:9090}"
ROLE_ARN="arn:ozone:iam::dev:role/oidc"
BUCKET="acl-test-$RANDOM"

PASS=0
FAIL=0

step() { printf '\n\033[1;34m== %s\033[0m\n' "$1"; }
ok()   { printf '  \033[0;32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
ko()   { printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; shift; [ $# -gt 0 ] && printf '       %s\n' "$@"; FAIL=$((FAIL + 1)); }

# expect_ok <description> <command...>
expect_ok() {
    local desc="$1"; shift
    local out
    if out=$("$@" 2>&1); then ok "$desc"; else ko "$desc" "$out"; fi
}

# expect_fail_with <description> <needle> <command...> — command must fail AND
# its combined output must contain the needle.
expect_fail_with() {
    local desc="$1" needle="$2"; shift 2
    local out
    if out=$("$@" 2>&1); then
        ko "$desc" "command unexpectedly succeeded: $out"
    elif grep -q "$needle" <<<"$out"; then
        ok "$desc"
    else
        ko "$desc" "expected error containing '$needle', got: $out"
    fi
}

# aws_run <extra docker args...> -- <aws args...>
aws_run() {
    local docker_args=()
    while [ "$1" != "--" ]; do docker_args+=("$1"); shift; done
    shift
    docker run --rm -i --network "$NETWORK" -e AWS_DEFAULT_REGION=us-east-1 \
        "${docker_args[@]}" "$AWS_IMAGE" --endpoint-url "${AWS_EP:-http://proxy:9000}" "$@"
}

# aws_as <AKID> <SECRET> <SESSION> <aws args...>
aws_as() {
    local akid="$1" secret="$2" session="$3"; shift 3
    local env_args=(-e "AWS_ACCESS_KEY_ID=$akid" -e "AWS_SECRET_ACCESS_KEY=$secret")
    [ -n "$session" ] && env_args+=(-e "AWS_SESSION_TOKEN=$session")
    aws_run "${env_args[@]}" -- "$@"
}

# aws_vol <hostdir> <AKID> <SECRET> <SESSION> <aws args...> — aws_as with
# <hostdir> mounted at /work (multipart bodies, downloads).
aws_vol() {
    local dir="$1" akid="$2" secret="$3" session="$4"; shift 4
    local env_args=(-v "$dir:/work" -e "AWS_ACCESS_KEY_ID=$akid" -e "AWS_SECRET_ACCESS_KEY=$secret")
    [ -n "$session" ] && env_args+=(-e "AWS_SESSION_TOKEN=$session")
    aws_run "${env_args[@]}" -- "$@"
}

get_token() { # <username> <password>
    curl -sf "$KEYCLOAK_URL/realms/ozone/protocol/openid-connect/token" \
        -d grant_type=password -d client_id=ozone-s3 \
        -d "username=$1" -d "password=$2" | jq -r '.access_token // empty'
}

exchange() { # <jwt> → "AKID SECRET SESSION" on stdout
    aws_run -- sts assume-role-with-web-identity \
        --role-arn "$ROLE_ARN" --role-session-name e2e \
        --web-identity-token "$1" --output json |
        jq -r '.Credentials | "\(.AccessKeyId) \(.SecretAccessKey) \(.SessionToken)"'
}

b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }

echo "ozone-oidc-proxy e2e — bucket: $BUCKET"

step "Token acquisition (Keycloak ROPC)"
ALICE_TOKEN=$(get_token alice password123)
BOB_TOKEN=$(get_token bob password123)
[ -n "$ALICE_TOKEN" ] && ok "alice obtained a JWT" || ko "alice obtained a JWT"
[ -n "$BOB_TOKEN" ] && ok "bob obtained a JWT" || ko "bob obtained a JWT"
[ -n "$ALICE_TOKEN" ] || { echo "Cannot continue without tokens"; exit 1; }
AUD=$(cut -d. -f2 <<<"$ALICE_TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.aud' )
grep -q "ozone-s3" <<<"$AUD" && ok "token carries aud=ozone-s3 (audience mapper)" \
    || ko "token carries aud=ozone-s3 (audience mapper)" "aud=$AUD"

step "STS AssumeRoleWithWebIdentity"
read -r A_AKID A_SECRET A_SESSION < <(exchange "$ALICE_TOKEN") || true
if [[ "${A_AKID:-}" == OZPX* && -n "$A_SECRET" && -n "$A_SESSION" ]]; then
    ok "alice exchanged JWT for temp credentials ($A_AKID)"
else
    ko "alice exchanged JWT for temp credentials" "got: ${A_AKID:-none}"
    exit 1
fi
read -r B_AKID B_SECRET B_SESSION < <(exchange "$BOB_TOKEN") || true
[[ "${B_AKID:-}" == OZPX* ]] && ok "bob exchanged JWT for temp credentials ($B_AKID)" \
    || ko "bob exchanged JWT for temp credentials"

expect_fail_with "disallowed RoleArn is rejected (AccessDenied)" "AccessDenied" \
    aws_run -- sts assume-role-with-web-identity \
    --role-arn "arn:ozone:iam::dev:role/evil" --role-session-name e2e \
    --web-identity-token "$ALICE_TOKEN"

FORGED="$(printf '{"alg":"none","typ":"JWT"}' | b64url).$(printf '{"iss":"https://evil.example","aud":"ozone-s3","preferred_username":"mallory","exp":9999999999}' | b64url)."
FORGED_OUT=$(curl -s "$PROXY_URL/" -d Action=AssumeRoleWithWebIdentity \
    -d RoleArn="$ROLE_ARN" -d WebIdentityToken="$FORGED")
grep -q "InvalidIdentityToken" <<<"$FORGED_OUT" \
    && ok "forged/unknown-issuer JWT rejected (InvalidIdentityToken)" \
    || ko "forged/unknown-issuer JWT rejected" "$FORGED_OUT"

step "SigV4 lane: alice creates and uses a bucket through the proxy"
expect_ok "alice: aws s3 mb s3://$BUCKET" \
    aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 mb "s3://$BUCKET"

OWNER=$($COMPOSE exec -T ozone-om ozone sh bucket info "/s3v/$BUCKET" 2>/dev/null | jq -r '.owner // empty')
if [ "$OWNER" = "alice" ]; then
    ok "bucket owner attributed to OIDC user (owner=alice) — synthetic header accepted by stock 2.1.1"
else
    ko "bucket owner attributed to OIDC user" "owner='$OWNER' (day-0 check §11.1#1 failed)"
fi

echo "hello from the oidc proxy" | aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 cp - "s3://$BUCKET/hello.txt" >/dev/null 2>&1 \
    && ok "alice: put object" || ko "alice: put object"
GOT=$(aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 cp "s3://$BUCKET/hello.txt" - 2>/dev/null)
[ "$GOT" = "hello from the oidc proxy" ] && ok "alice: get object round-trips" \
    || ko "alice: get object round-trips" "got: $GOT"

step "SigV4 verification failures"
expect_fail_with "tampered secret → SignatureDoesNotMatch" "SignatureDoesNotMatch" \
    aws_as "$A_AKID" "${A_SECRET}x" "$A_SESSION" s3 ls "s3://$BUCKET"
expect_fail_with "wrong session token → InvalidToken" "InvalidToken" \
    aws_as "$A_AKID" "$A_SECRET" "${A_SESSION}x" s3 ls "s3://$BUCKET"

step "Native ACLs through the proxy (alice/bob matrix)"
expect_fail_with "bob denied on alice's bucket" "AccessDenied" \
    aws_as "$B_AKID" "$B_SECRET" "$B_SESSION" s3 ls "s3://$BUCKET"
expect_ok "grant user:bob:rl on /s3v/$BUCKET (ozone sh)" \
    $COMPOSE exec -T ozone-om ozone sh bucket addacl -a user:bob:rl "/s3v/$BUCKET"
expect_ok "bob can list after the grant" \
    aws_as "$B_AKID" "$B_SECRET" "$B_SESSION" s3 ls "s3://$BUCKET"

step "Multipart uploads (2.1.1 ListParts/ListMultipartUploads ACL matrix)"
MPU_BUCKET="mpu-test-$RANDOM"
MPU_KEY="assembled.bin"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
dd if=/dev/urandom of="$WORK/part1" bs=1M count=5 status=none
dd if=/dev/urandom of="$WORK/part2" bs=1M count=5 status=none

expect_ok "alice: aws s3 mb s3://$MPU_BUCKET" \
    aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 mb "s3://$MPU_BUCKET"

MPU_OUT=$(aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3api create-multipart-upload \
    --bucket "$MPU_BUCKET" --key "$MPU_KEY" --output json 2>&1)
UPLOAD_ID=$(jq -r '.UploadId // empty' <<<"$MPU_OUT" 2>/dev/null)
[ -n "$UPLOAD_ID" ] && ok "alice: CreateMultipartUpload" \
    || ko "alice: CreateMultipartUpload" "$MPU_OUT"

ETAG1=$(aws_vol "$WORK" "$A_AKID" "$A_SECRET" "$A_SESSION" s3api upload-part \
    --bucket "$MPU_BUCKET" --key "$MPU_KEY" --part-number 1 --upload-id "$UPLOAD_ID" \
    --body /work/part1 --output json 2>/dev/null | jq '.ETag // empty')
ETAG2=$(aws_vol "$WORK" "$A_AKID" "$A_SECRET" "$A_SESSION" s3api upload-part \
    --bucket "$MPU_BUCKET" --key "$MPU_KEY" --part-number 2 --upload-id "$UPLOAD_ID" \
    --body /work/part2 --output json 2>/dev/null | jq '.ETag // empty')
{ [ -n "$ETAG1" ] && [ -n "$ETAG2" ]; } && ok "alice: UploadPart x2 (5 MiB each)" \
    || ko "alice: UploadPart x2" "etags: '$ETAG1' '$ETAG2'"

aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3api list-parts \
    --bucket "$MPU_BUCKET" --key "$MPU_KEY" --upload-id "$UPLOAD_ID" --output json 2>/dev/null \
    | jq -e '.Parts | length == 2' >/dev/null \
    && ok "alice: ListParts shows both parts (owner)" \
    || ko "alice: ListParts shows both parts (owner)"
aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3api list-multipart-uploads \
    --bucket "$MPU_BUCKET" --output json 2>/dev/null | grep -q "$UPLOAD_ID" \
    && ok "alice: ListMultipartUploads shows the open upload (owner)" \
    || ko "alice: ListMultipartUploads shows the open upload (owner)"

expect_fail_with "bob: ListMultipartUploads denied without grant (HDDS-14894)" "AccessDenied" \
    aws_as "$B_AKID" "$B_SECRET" "$B_SESSION" s3api list-multipart-uploads --bucket "$MPU_BUCKET"
expect_fail_with "bob: ListParts denied without grant (HDDS-14898)" "AccessDenied" \
    aws_as "$B_AKID" "$B_SECRET" "$B_SESSION" s3api list-parts \
    --bucket "$MPU_BUCKET" --key "$MPU_KEY" --upload-id "$UPLOAD_ID"

expect_ok "grant user:bob:rl on /s3v/$MPU_BUCKET (ozone sh)" \
    $COMPOSE exec -T ozone-om ozone sh bucket addacl -a user:bob:rl "/s3v/$MPU_BUCKET"
expect_ok "bob: ListMultipartUploads allowed with rl" \
    aws_as "$B_AKID" "$B_SECRET" "$B_SESSION" s3api list-multipart-uploads --bucket "$MPU_BUCKET"
expect_ok "bob: ListParts allowed with rl" \
    aws_as "$B_AKID" "$B_SECRET" "$B_SESSION" s3api list-parts \
    --bucket "$MPU_BUCKET" --key "$MPU_KEY" --upload-id "$UPLOAD_ID"

printf '{"Parts":[{"ETag":%s,"PartNumber":1},{"ETag":%s,"PartNumber":2}]}' \
    "$ETAG1" "$ETAG2" > "$WORK/parts.json"
COMPLETE_OUT=$(aws_vol "$WORK" "$A_AKID" "$A_SECRET" "$A_SESSION" s3api complete-multipart-upload \
    --bucket "$MPU_BUCKET" --key "$MPU_KEY" --upload-id "$UPLOAD_ID" \
    --multipart-upload file:///work/parts.json 2>&1) \
    && ok "alice: CompleteMultipartUpload" \
    || ko "alice: CompleteMultipartUpload" "$COMPLETE_OUT"
aws_vol "$WORK" "$A_AKID" "$A_SECRET" "$A_SESSION" s3 cp \
    "s3://$MPU_BUCKET/$MPU_KEY" /work/assembled.down >/dev/null 2>&1
cat "$WORK/part1" "$WORK/part2" | cmp -s - "$WORK/assembled.down" \
    && ok "assembled object round-trips byte-identical (10 MiB)" \
    || ko "assembled object round-trips byte-identical (10 MiB)"

ABORT_ID=$(aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3api create-multipart-upload \
    --bucket "$MPU_BUCKET" --key doomed.bin --output json 2>/dev/null | jq -r '.UploadId // empty')
expect_ok "alice: AbortMultipartUpload" \
    aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3api abort-multipart-upload \
    --bucket "$MPU_BUCKET" --key doomed.bin --upload-id "$ABORT_ID"
aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3api list-multipart-uploads \
    --bucket "$MPU_BUCKET" --output json 2>/dev/null | grep -q "$ABORT_ID" \
    && ko "aborted upload no longer listed" \
    || ok "aborted upload no longer listed"

dd if=/dev/urandom of="$WORK/big.bin" bs=1M count=10 status=none
aws_vol "$WORK" "$A_AKID" "$A_SECRET" "$A_SESSION" s3 cp /work/big.bin \
    "s3://$MPU_BUCKET/big.bin" >/dev/null 2>&1 \
    && ok "alice: 10 MiB aws s3 cp upload (automatic multipart)" \
    || ko "alice: 10 MiB aws s3 cp upload (automatic multipart)"
aws_vol "$WORK" "$A_AKID" "$A_SECRET" "$A_SESSION" s3 cp \
    "s3://$MPU_BUCKET/big.bin" /work/big.down >/dev/null 2>&1
cmp -s "$WORK/big.bin" "$WORK/big.down" \
    && ok "10 MiB download matches upload" \
    || ko "10 MiB download matches upload"

step "Bearer lane"
BEARER_GET=$(curl -s -H "Authorization: Bearer $ALICE_TOKEN" "$PROXY_URL/$BUCKET/hello.txt")
[ "$BEARER_GET" = "hello from the oidc proxy" ] && ok "GET object with Bearer JWT" \
    || ko "GET object with Bearer JWT" "got: $BEARER_GET"
BEARER_PUT_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
    -H "Authorization: Bearer $ALICE_TOKEN" --data-binary "bearer write" \
    "$PROXY_URL/$BUCKET/bearer.txt")
[ "$BEARER_PUT_CODE" = "200" ] && ok "PUT object with Bearer JWT" \
    || ko "PUT object with Bearer JWT" "http $BEARER_PUT_CODE"
BAD_BEARER=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer not.a.token" "$PROXY_URL/$BUCKET/hello.txt")
[ "$BAD_BEARER" = "403" ] && ok "garbage Bearer rejected with 403" \
    || ko "garbage Bearer rejected with 403" "http $BAD_BEARER"

step "Presigned URLs (query auth)"
# The URL is minted offline against http://proxy:9000, so the anonymous fetch
# must happen on the compose network for the signed Host header to match.
PRESIGNED=$(aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 presign "s3://$BUCKET/hello.txt" --expires-in 120 | tr -d '[:space:]')
[[ "$PRESIGNED" == http://proxy:9000/* ]] && ok "alice minted a presigned URL" \
    || ko "alice minted a presigned URL" "got: $PRESIGNED"
curl_net() { docker run --rm --network "$NETWORK" curlimages/curl:latest -s "$@"; }
PRESIGNED_GET=$(curl_net "$PRESIGNED")
[ "$PRESIGNED_GET" = "hello from the oidc proxy" ] && ok "anonymous fetch of presigned URL round-trips" \
    || ko "anonymous fetch of presigned URL round-trips" "got: $PRESIGNED_GET"
TAMPERED_GET=$(curl_net "$PRESIGNED&admin=true")
grep -q "SignatureDoesNotMatch" <<<"$TAMPERED_GET" && ok "tampered presigned URL → SignatureDoesNotMatch" \
    || ko "tampered presigned URL → SignatureDoesNotMatch" "$TAMPERED_GET"
SHORT=$(aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 presign "s3://$BUCKET/hello.txt" --expires-in 1 | tr -d '[:space:]')
sleep 2
EXPIRED_GET=$(curl_net "$SHORT")
grep -q "Request has expired" <<<"$EXPIRED_GET" && ok "expired presigned URL → AccessDenied (Request has expired)" \
    || ko "expired presigned URL → AccessDenied (Request has expired)" "$EXPIRED_GET"

step "Human credential UX (device flow + portal)"
# Browser pages redirect to the pinned issuer host; curl resolves it locally.
kcurl() { curl -s --resolve keycloak:8080:127.0.0.1 "$@"; }
form_action() { # <html file> → first form action, entities unescaped
    grep -o '<form[^>]*action="[^"]*"' "$1" | head -1 |
        grep -o 'action="[^"]*"' | sed 's/^action="//; s/"$//; s/\&amp;/\&/g'
}

DEV_JSON=$(curl -s -d client_id=ozone-s3 -d scope=openid \
    "$KEYCLOAK_URL/realms/ozone/protocol/openid-connect/auth/device")
DEV_CODE=$(jq -r '.device_code // empty' <<<"$DEV_JSON")
DEV_VERIFY=$(jq -r '.verification_uri_complete // empty' <<<"$DEV_JSON")
[ -n "$DEV_CODE" ] && ok "device grant enabled on ozone-s3 (ozone-login)" \
    || ko "device grant enabled on ozone-s3 (ozone-login)" "$DEV_JSON"

HUX_JAR="$WORK/hux.jar"
kcurl -c "$HUX_JAR" -L "$DEV_VERIFY" -o "$WORK/hux1.html"
kcurl -b "$HUX_JAR" -c "$HUX_JAR" -L -d username=alice -d password=password123 \
    "$(form_action "$WORK/hux1.html")" -o "$WORK/hux2.html"
CONSENT=$(grep -o 'name="code" value="[^"]*"' "$WORK/hux2.html" | sed 's/.*value="//; s/"$//')
kcurl -b "$HUX_JAR" -c "$HUX_JAR" -L -d "code=$CONSENT" -d "accept=Yes" \
    "http://keycloak:8080$(form_action "$WORK/hux2.html")" -o "$WORK/hux3.html"
grep -q "Device Login Successful" "$WORK/hux3.html" \
    && ok "device verification completed in the browser (login + consent)" \
    || ko "device verification completed in the browser (login + consent)"

DEV_TOKEN=$(curl -s -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
    -d device_code="$DEV_CODE" -d client_id=ozone-s3 \
    "$KEYCLOAK_URL/realms/ozone/protocol/openid-connect/token" | jq -r '.access_token // empty')
[ -n "$DEV_TOKEN" ] && ok "device-flow token issued" || ko "device-flow token issued"
DEV_STS=$(curl -s "$PROXY_URL/" -d Action=AssumeRoleWithWebIdentity \
    -d RoleArn="$ROLE_ARN" -d RoleSessionName=device-e2e -d WebIdentityToken="$DEV_TOKEN")
grep -qE "<AccessKeyId>OZPX" <<<"$DEV_STS" \
    && ok "device-flow token exchanges at STS (aud mapper on the device grant)" \
    || ko "device-flow token exchanges at STS" "$DEV_STS"

if docker ps --format '{{.Names}}' | grep -q '^oidc-oauth2-proxy$'; then
    PORTAL_JAR="$WORK/portal.jar"
    kcurl -c "$PORTAL_JAR" -b "$PORTAL_JAR" -L "http://localhost:4180/" -o "$WORK/portal1.html"
    kcurl -b "$PORTAL_JAR" -c "$PORTAL_JAR" -L -d username=alice -d password=password123 \
        "$(form_action "$WORK/portal1.html")" -o "$WORK/portal2.html"
    grep -q "Minted for <strong>alice" "$WORK/portal2.html" \
        && ok "portal minted credentials after browser sign-in (oauth2-proxy)" \
        || ko "portal minted credentials after browser sign-in (oauth2-proxy)"
    P_AKID=$(grep -oE 'AWS_ACCESS_KEY_ID=[A-Z0-9]+' "$WORK/portal2.html" | head -1 | cut -d= -f2)
    P_SECRET=$(grep -oE 'AWS_SECRET_ACCESS_KEY=[A-Za-z0-9_-]+' "$WORK/portal2.html" | head -1 | cut -d= -f2)
    P_TOKEN=$(grep -oE 'AWS_SESSION_TOKEN=[A-Za-z0-9_-]+' "$WORK/portal2.html" | head -1 | cut -d= -f2)
    expect_ok "portal credentials work on the data path (aws s3 ls)" \
        aws_as "$P_AKID" "$P_SECRET" "$P_TOKEN" s3 ls
else
    echo "  SKIP portal checks (overlay not running — make portal-up)"
fi

step "Second issuer (stub IdP, multi-issuer registry)"
# The stub issuer publishes no host port (its /token mints arbitrary
# identities), so minting runs on the compose network via curl_net.
stub_token() { # <username> [aud-csv]
    local args=(-d "username=$1")
    [ $# -gt 1 ] && args+=(-d "aud=$2")
    curl_net -f -X POST "${args[@]}" http://stub-issuer:8081/token |
        jq -r '.access_token // empty'
}

CAROL_TOKEN=$(stub_token carol)
[ -n "$CAROL_TOKEN" ] && ok "carol obtained a JWT from the stub issuer" \
    || ko "carol obtained a JWT from the stub issuer"
C_ISS=$(cut -d. -f2 <<<"$CAROL_TOKEN" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.iss')
[ "$C_ISS" = "http://stub-issuer:8081" ] && ok "token iss is the stub issuer" \
    || ko "token iss is the stub issuer" "iss=$C_ISS"

read -r C_AKID C_SECRET C_SESSION < <(exchange "$CAROL_TOKEN") || true
[[ "${C_AKID:-}" == OZPX* ]] && ok "stub token exchanged at STS (discovery + username_claim=uid)" \
    || ko "stub token exchanged at STS" "got: ${C_AKID:-none}"

C_BUCKET="stub-test-$RANDOM"
expect_ok "carol: aws s3 mb s3://$C_BUCKET" \
    aws_as "$C_AKID" "$C_SECRET" "$C_SESSION" s3 mb "s3://$C_BUCKET"
C_OWNER=$($COMPOSE exec -T ozone-om ozone sh bucket info "/s3v/$C_BUCKET" 2>/dev/null | jq -r '.owner // empty')
[ "$C_OWNER" = "carol" ] && ok "bucket owner attributed via the second issuer (owner=carol)" \
    || ko "bucket owner attributed via the second issuer" "owner='$C_OWNER'"

echo "stub issuer payload" | aws_as "$C_AKID" "$C_SECRET" "$C_SESSION" s3 cp - "s3://$C_BUCKET/hi.txt" >/dev/null 2>&1 \
    && ok "carol: put object" || ko "carol: put object"
C_GOT=$(curl -s -H "Authorization: Bearer $CAROL_TOKEN" "$PROXY_URL/$C_BUCKET/hi.txt")
[ "$C_GOT" = "stub issuer payload" ] && ok "Bearer lane accepts the stub-issuer token" \
    || ko "Bearer lane accepts the stub-issuer token" "got: $C_GOT"

expect_fail_with "alice (keycloak issuer) denied on carol's bucket" "AccessDenied" \
    aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 ls "s3://$C_BUCKET"
WRONG_AUD=$(stub_token mallory ozone-s3)
STS_ERR=$(curl -s "$PROXY_URL/" -d Action=AssumeRoleWithWebIdentity -d RoleArn="$ROLE_ARN" \
    -d RoleSessionName=e2e -d WebIdentityToken="$WRONG_AUD")
grep -q "InvalidIdentityToken" <<<"$STS_ERR" \
    && ok "stub token with keycloak's audience rejected (per-issuer aud)" \
    || ko "stub token with keycloak's audience rejected (per-issuer aud)" "$STS_ERR"

step "Client smoke tests (boto3, mc, s3a)"
# Three real clients, containerized (first run pulls python:3.12-slim,
# minio/mc and apache/hadoop:3.4.1 — the last is ~2 GB; boto3 is pip-installed
# in the container, so this step needs egress). boto3 proves the §6.9 env-var
# web-identity auto-exchange; mc proves MC_HOST session-token aliases and
# streaming SigV4 uploads (STREAMING-AWS4-HMAC-SHA256-PAYLOAD seed
# signature); s3a (Hadoop 3.4 / AWS SDK v2) is the heaviest real consumer.
# Note: the apache/hadoop image logs s3a metrics INFO lines to stdout, so
# byte comparisons go through in-container files (-get + md5sum), never -cat.

printf '%s' "$ALICE_TOKEN" > "$WORK/token.jwt"
cat > "$WORK/boto3_smoke.py" <<'PYEOF'
"""Credentials must come from botocore's own web-identity auto-exchange
(AWS_ROLE_ARN + AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ENDPOINT_URL_STS) —
no explicit keys anywhere."""
import sys

import boto3

bucket = sys.argv[1]
session = boto3.Session()
creds = session.get_credentials().get_frozen_credentials()
print(f"AKID={creds.access_key}")

s3 = session.client("s3")
s3.put_object(Bucket=bucket, Key="boto3.txt", Body=b"boto3 via web identity")
body = s3.get_object(Bucket=bucket, Key="boto3.txt")["Body"].read()
if body != b"boto3 via web identity":
    sys.exit(f"round-trip mismatch: {body!r}")
print("ROUNDTRIP=ok")
PYEOF
BOTO_OUT=$(docker run --rm --network "$NETWORK" -v "$WORK:/work:ro" \
    -e AWS_ROLE_ARN="$ROLE_ARN" -e AWS_WEB_IDENTITY_TOKEN_FILE=/work/token.jwt \
    -e AWS_ROLE_SESSION_NAME=boto3-e2e \
    -e AWS_ENDPOINT_URL_STS=http://proxy:9000 -e AWS_ENDPOINT_URL_S3=http://proxy:9000 \
    -e AWS_DEFAULT_REGION=us-east-1 \
    python:3.12-slim sh -c "pip install -q boto3 2>/dev/null && python /work/boto3_smoke.py $BUCKET" 2>&1)
grep -qE '^AKID=OZPX' <<<"$BOTO_OUT" \
    && ok "boto3 auto-exchanged web identity via env vars (no explicit creds)" \
    || ko "boto3 auto-exchanged web identity via env vars" "$BOTO_OUT"
grep -q '^ROUNDTRIP=ok' <<<"$BOTO_OUT" \
    && ok "boto3 put/get round-trips" || ko "boto3 put/get round-trips" "$BOTO_OUT"

# The hadoop image runs as uid 1000, not root, and $WORK is mktemp-0700:
# mount a world-readable subdir instead (bind mounts skip parent perms).
mkdir -p "$WORK/pub" && chmod 755 "$WORK/pub"
dd if=/dev/urandom of="$WORK/pub/smoke.bin" bs=1M count=8 status=none
chmod 644 "$WORK/pub/smoke.bin"
SMOKE_MD5=$(md5sum "$WORK/pub/smoke.bin" | awk '{print $1}')
mc_run() { # <shell command using the "ozone" alias>
    docker run --rm --network "$NETWORK" -v "$WORK/pub:/work:ro" \
        -e MC_HOST_ozone="http://$A_AKID:$A_SECRET:$A_SESSION@proxy:9000" \
        --entrypoint sh minio/mc:latest -c "$1"
}
expect_ok "mc ls via MC_HOST alias (session token in the URL)" \
    mc_run "mc ls ozone/$BUCKET"
MC_CP_OUT=$(mc_run "mc --debug cp /work/smoke.bin ozone/$BUCKET/mc.bin" 2>&1)
grep -q "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" <<<"$MC_CP_OUT" \
    && ok "mc upload used the streaming seed signature (STREAMING-AWS4-HMAC-SHA256-PAYLOAD)" \
    || ko "mc upload used the streaming seed signature" "$(tail -3 <<<"$MC_CP_OUT")"
MC_BACK=$(mc_run "mc cat ozone/$BUCKET/mc.bin | md5sum" | awk '{print $1}')
[ "$MC_BACK" = "$SMOKE_MD5" ] && ok "mc 8 MiB streamed round-trip byte-identical" \
    || ko "mc 8 MiB streamed round-trip byte-identical" "md5 $MC_BACK != $SMOKE_MD5"

S3A_OPTS="-D fs.s3a.endpoint=http://proxy:9000 -D fs.s3a.endpoint.region=us-east-1 \
 -D fs.s3a.path.style.access=true -D fs.s3a.connection.ssl.enabled=false \
 -D fs.s3a.aws.credentials.provider=org.apache.hadoop.fs.s3a.TemporaryAWSCredentialsProvider \
 -D fs.s3a.access.key=$A_AKID -D fs.s3a.secret.key=$A_SECRET -D fs.s3a.session.token=$A_SESSION"
S3A_OUT=$(docker run --rm --network "$NETWORK" -v "$WORK/pub:/work:ro" \
    -e HADOOP_OPTIONAL_TOOLS=hadoop-aws --entrypoint sh apache/hadoop:3.4.1 -c "
    hadoop fs $S3A_OPTS -put -f /work/smoke.bin s3a://$BUCKET/s3a.bin &&
    hadoop fs $S3A_OPTS -ls s3a://$BUCKET/s3a.bin &&
    hadoop fs $S3A_OPTS -get s3a://$BUCKET/s3a.bin /tmp/s3a.bin &&
    hadoop fs $S3A_OPTS -get s3a://$BUCKET/mc.bin /tmp/mc.bin &&
    md5sum /tmp/s3a.bin /tmp/mc.bin" 2>&1)
grep -q " 8388608 " <<<"$S3A_OUT" && ok "s3a: put + ls (8 MiB, exact size)" \
    || ko "s3a: put + ls (8 MiB, exact size)" "$(tail -5 <<<"$S3A_OUT")"
grep -qE "$SMOKE_MD5\s+/tmp/s3a\.bin" <<<"$S3A_OUT" && ok "s3a: get round-trip md5-identical" \
    || ko "s3a: get round-trip md5-identical" "$(tail -5 <<<"$S3A_OUT")"
grep -qE "$SMOKE_MD5\s+/tmp/mc\.bin" <<<"$S3A_OUT" \
    && ok "cross-client: s3a reads mc's streamed object byte-identical" \
    || ko "cross-client: s3a reads mc's streamed object byte-identical" "$(tail -5 <<<"$S3A_OUT")"

step "HA / valkey / resign / revocation (M3)"
if docker ps --format '{{.Names}}' | grep -q '^oidc-proxy-b$'; then
    # Replica B (:9001 host, proxy-b:9000 in-network) shares the valkey store
    # with A and forwards in resign mode. Bash dynamic scoping: the local
    # AWS_EP is visible inside aws_run.
    aws_b_as() { local AWS_EP=http://proxy-b:9000; aws_as "$@"; }
    exchange_b() { local AWS_EP=http://proxy-b:9000; exchange "$@"; }
    ADMIN_B_URL="http://localhost:9091"
    HA_BUCKET="ha-test-$RANDOM"

    read -r H_AKID H_SECRET H_SESSION < <(exchange "$ALICE_TOKEN") || true
    [[ "${H_AKID:-}" == OZPX* ]] && ok "minted on replica A (valkey-backed STS)" \
        || ko "minted on replica A" "got: ${H_AKID:-none}"

    expect_ok "A-minted credentials create a bucket via replica B (shared store)" \
        aws_b_as "$H_AKID" "$H_SECRET" "$H_SESSION" s3 mb "s3://$HA_BUCKET"
    HA_OWNER=$($COMPOSE exec -T ozone-om ozone sh bucket info "/s3v/$HA_BUCKET" 2>/dev/null | jq -r '.owner // empty')
    [ "$HA_OWNER" = "alice" ] && ok "resign mode attributes correctly (owner=alice via re-signed header)" \
        || ko "resign mode attributes correctly" "owner='$HA_OWNER'"
    echo "resign round-trip" | aws_b_as "$H_AKID" "$H_SECRET" "$H_SESSION" s3 cp - "s3://$HA_BUCKET/r.txt" >/dev/null 2>&1 \
        && [ "$(aws_b_as "$H_AKID" "$H_SECRET" "$H_SESSION" s3 cp "s3://$HA_BUCKET/r.txt" - 2>/dev/null)" = "resign round-trip" ] \
        && ok "object round-trips through replica B (resign mode)" \
        || ko "object round-trips through replica B (resign mode)"

    read -r R_AKID R_SECRET R_SESSION < <(exchange_b "$ALICE_TOKEN") || true
    [[ "${R_AKID:-}" == OZPX* ]] \
        && aws_as "$R_AKID" "$R_SECRET" "$R_SESSION" s3 ls "s3://$HA_BUCKET" >/dev/null 2>&1 \
        && ok "B-minted credentials verified on replica A (reverse direction)" \
        || ko "B-minted credentials verified on replica A (reverse direction)"

    REVOKE_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$ADMIN_B_URL/credentials/$H_AKID")
    [ "$REVOKE_CODE" = "204" ] && ok "admin revocation on replica B returns 204" \
        || ko "admin revocation on replica B returns 204" "http $REVOKE_CODE"
    REVOKED=""
    for _ in $(seq 1 10); do
        HA_OUT=$(aws_as "$H_AKID" "$H_SECRET" "$H_SESSION" s3 ls "s3://$HA_BUCKET" 2>&1)
        grep -q "InvalidAccessKeyId" <<<"$HA_OUT" && REVOKED=yes && break
        sleep 0.5
    done
    [ -n "$REVOKED" ] && ok "revocation on B rejected by A (store delete + cache invalidation)" \
        || ko "revocation on B rejected by A" "$HA_OUT"
    REVOKE2=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$ADMIN_B_URL/credentials/$H_AKID")
    [ "$REVOKE2" = "404" ] && ok "second revocation returns 404" \
        || ko "second revocation returns 404" "http $REVOKE2"

    # Persistence: replica B restarts, credentials minted before must survive
    # (they live in valkey, not process memory).
    docker restart oidc-proxy-b >/dev/null 2>&1
    for _ in $(seq 1 30); do curl -sf "$ADMIN_B_URL/healthz" >/dev/null 2>&1 && break; sleep 1; done
    aws_b_as "$R_AKID" "$R_SECRET" "$R_SESSION" s3 ls "s3://$HA_BUCKET" >/dev/null 2>&1 \
        && ok "credentials survive a replica restart (valkey persistence)" \
        || ko "credentials survive a replica restart (valkey persistence)"
else
    echo "  SKIP HA checks (overlay not running — make ha-up)"
fi

step "TLS edge (HAProxy overlay)"
if docker ps --format '{{.Names}}' | grep -q '^oidc-haproxy$'; then
    # TLS terminates at HAProxy; the Host header (signed by SigV4) passes
    # through untouched, so signatures minted for haproxy:8443 verify.
    EDGE_EP="https://haproxy:8443"
    AWS_EP="$EDGE_EP" expect_ok "aws s3 ls via the TLS edge" \
        aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" s3 ls "s3://$BUCKET" --no-verify-ssl
    EDGE_PRESIGNED=$(AWS_EP="$EDGE_EP" aws_as "$A_AKID" "$A_SECRET" "$A_SESSION" \
        s3 presign "s3://$BUCKET/hello.txt" --expires-in 120 2>/dev/null | tr -d '[:space:]')
    [[ "$EDGE_PRESIGNED" == https://haproxy:8443/* ]] \
        && ok "presigned URL minted for the https edge endpoint" \
        || ko "presigned URL minted for the https edge endpoint" "got: $EDGE_PRESIGNED"
    EDGE_GET=$(curl_net -k "$EDGE_PRESIGNED")
    [ "$EDGE_GET" = "hello from the oidc proxy" ] \
        && ok "anonymous https fetch of the presigned URL round-trips" \
        || ko "anonymous https fetch of the presigned URL round-trips" "got: $EDGE_GET"
    EDGE_ANON=$(curl_net -k -o /dev/null -w '%{http_code}' "$EDGE_EP/$BUCKET/hello.txt")
    [ "$EDGE_ANON" = "403" ] && ok "strict 403 preserved through the edge" \
        || ko "strict 403 preserved through the edge" "http $EDGE_ANON"
else
    echo "  SKIP TLS edge checks (overlay not running — make edge-up)"
fi

step "Strict mode (no anonymous fallback)"
expect_fail_with "plain SigV4 with AWS_ACCESS_KEY_ID=alice → InvalidAccessKeyId" "InvalidAccessKeyId" \
    aws_as alice x "" s3 ls "s3://$BUCKET"
ANON=$(curl -s -o /dev/null -w '%{http_code}' "$PROXY_URL/$BUCKET/hello.txt")
[ "$ANON" = "403" ] && ok "anonymous request rejected with 403" \
    || ko "anonymous request rejected with 403" "http $ANON"
if curl -s --max-time 3 http://localhost:9878/ >/dev/null 2>&1; then
    ko "S3 Gateway must not be reachable from the host"
else
    ok "S3 Gateway is not reachable from the host (trust boundary)"
fi

step "Admin surface"
curl -sf "$ADMIN_URL/healthz" >/dev/null && ok "/healthz" || ko "/healthz"
METRICS=$(curl -sf "$ADMIN_URL/metrics")
for metric in sts_exchanges_total bearer_auth_total sigv4_verifications_total presigned_verifications_total active_credentials; do
    grep -q "$metric" <<<"$METRICS" && ok "metric $metric exposed" || ko "metric $metric exposed"
done

printf '\n\033[1m== Summary: %d passed, %d failed ==\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
