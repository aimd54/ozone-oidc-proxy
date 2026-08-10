#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Stands up a kind cluster running Apache Ozone from the official chart,
# Keycloak, and this proxy, then proves the whole path: an OIDC sign-in
# becomes temporary S3 credentials, a real object round-trips, Ozone records
# the OIDC user as the bucket owner, and nothing reaches the S3 Gateway
# except the proxy.
#
#   bash ./up.sh          # build it and run the checks
#   bash ./up.sh down     # delete the cluster
#
# Needs: kind, kubectl, helm, docker, python3. About 4 GB of free memory.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLUSTER="${CLUSTER:-ozpx-k8s}"
CTX="kind-$CLUSTER"
OZONE_CHART_VERSION="${OZONE_CHART_VERSION:-0.3.0}"
PROXY="http://ozpx-ozone-oidc-proxy:9000"

kube() { kubectl --context "$CTX" "$@"; }
step() { printf '\n\033[1;34m== %s\033[0m\n' "$1"; }
ok()   { printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
ko()   { printf '  \033[0;31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; FAILED=$((FAILED + 1)); }
FAILED=0

# probe_code <url> prints the HTTP status a pod in the cluster sees, or 000
# when nothing answers. Retried: on a loaded node `kubectl run -i` can return
# before the container has written anything, and an empty answer here would
# read as a failed assertion rather than as the race it is. 000 is a real
# result (that is what a blocked request looks like), so only an empty string
# counts as "ask again".
probe_code() {
    local url="$1" out=""
    for _ in 1 2 3; do
        out=$(kube run "probe-$RANDOM$RANDOM" --rm -i --restart=Never \
            --image=curlimages/curl:latest --quiet -- \
            -s -m 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)
        [ -n "$out" ] && break
    done
    printf '%s' "$out"
}

if [ "${1:-}" = "down" ]; then
    kind delete cluster --name "$CLUSTER"
    exit 0
fi

step "kind cluster $CLUSTER"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "  already exists, reusing"
else
    kind create cluster --name "$CLUSTER" --wait 180s >/dev/null
fi

step "Images into the cluster (avoids pulling 1.5 GB twice)"
docker image inspect apache/ozone:2.1.1 >/dev/null 2>&1 || docker pull apache/ozone:2.1.1
(cd "$ROOT" && make docker-build >/dev/null)
kind load docker-image apache/ozone:2.1.1 ozone-oidc-proxy:dev --name "$CLUSTER" >/dev/null

step "Apache Ozone (official chart $OZONE_CHART_VERSION)"
helm repo add ozone https://apache.github.io/ozone-helm-charts/ >/dev/null 2>&1 || true
helm repo update ozone >/dev/null
helm upgrade --install ozone ozone/ozone --version "$OZONE_CHART_VERSION" \
    -f "$HERE/ozone-values.yaml" --kube-context "$CTX" >/dev/null
kube rollout status statefulset/ozone-scm --timeout=300s >/dev/null
kube rollout status statefulset/ozone-om --timeout=300s >/dev/null
kube rollout status statefulset/ozone-s3g --timeout=300s >/dev/null
kube rollout status statefulset/ozone-datanode --timeout=300s >/dev/null
echo "  scm, om, datanode, s3g are up"

# The chart pins hdds.scm.safemode.min.datanode to "3" in its templates, with
# no value to override it and no reference to datanode.replicas. One Datanode
# therefore never satisfies the rule, SCM stays in safe mode, and every write
# hangs until the client gives up. Forcing the exit is the supported escape;
# on three or more Datanodes this is unnecessary.
step "SCM safe mode"
if kube exec ozone-scm-0 -c scm -- ozone admin safemode status 2>/dev/null | grep -q 'is in safe mode'; then
    kube exec ozone-scm-0 -c scm -- ozone admin safemode exit >/dev/null 2>&1
    echo "  forced exit (single Datanode; see the note in README.md)"
fi
kube exec ozone-scm-0 -c scm -- ozone admin safemode status 2>/dev/null | grep -q 'out of safe mode' \
    && echo "  SCM is out of safe mode"

step "Keycloak, realm imported at startup"
kube create configmap keycloak-realm \
    --from-file=ozone-realm.json="$HERE/keycloak-realm.json" \
    --dry-run=client -o yaml | kube apply -f - >/dev/null
kube apply -f "$HERE/keycloak.yaml" >/dev/null
kube rollout status deployment/keycloak --timeout=300s >/dev/null
echo "  realm ozone, client ozone-s3, users alice and bob"

step "The proxy"
helm upgrade --install ozpx "$ROOT/charts/ozone-oidc-proxy" \
    -f "$HERE/proxy-values.yaml" --kube-context "$CTX" >/dev/null
kube rollout status deployment/ozpx-ozone-oidc-proxy --timeout=300s >/dev/null
echo "  up, with the S3 Gateway lockdown policy applied"

step "Volume ACLs"
kube exec ozone-om-0 -- ozone sh volume addacl -a user:alice:rwlc /s3v >/dev/null 2>&1
kube exec ozone-om-0 -- ozone sh volume addacl -a user:bob:rl /s3v >/dev/null 2>&1
echo "  alice rwlc, bob rl on /s3v"

# ----------------------------------------------------------------------------
# From here on everything asserts a positive state, never merely that a
# command exited 0. In this system the real defects report success.
# ----------------------------------------------------------------------------

step "Sign in as alice and exchange the token"
TOKEN=$(kube run tok-$RANDOM --rm -i --restart=Never --image=curlimages/curl:latest --quiet -- \
    -s -X POST http://keycloak:8080/realms/ozone/protocol/openid-connect/token \
    -d grant_type=password -d client_id=ozone-s3 \
    -d username=alice -d password=password123 2>/dev/null \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
[ -n "$TOKEN" ] && ok "Keycloak issued a JWT for alice" || ko "Keycloak issued a JWT for alice"

AUD=$(python3 -c "
import base64,json
p='$TOKEN'.split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p))['aud'])")
[ "$AUD" = "ozone-s3" ] && ok "token carries aud=ozone-s3 (the audience mapper)" \
    || ko "token carries aud=ozone-s3" "got aud=$AUD"

STS=$(kube run sts-$RANDOM --rm -i --restart=Never --image=curlimages/curl:latest --quiet -- \
    -s -X POST "$PROXY/" -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'Action=AssumeRoleWithWebIdentity' --data-urlencode 'Version=2011-06-15' \
    --data-urlencode 'RoleArn=arn:ozone:iam::dev:role/oidc' \
    --data-urlencode 'RoleSessionName=k8s' \
    --data-urlencode "WebIdentityToken=$TOKEN" 2>/dev/null)
AK=$(sed -n 's;.*<AccessKeyId>\(.*\)</AccessKeyId>.*;\1;p' <<<"$STS")
SK=$(sed -n 's;.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*;\1;p' <<<"$STS")
ST=$(sed -n 's;.*<SessionToken>\(.*\)</SessionToken>.*;\1;p' <<<"$STS")
case "$AK" in
    OZPX*) ok "STS minted temporary credentials ($AK)" ;;
    *)     ko "STS minted temporary credentials" "$(head -6 <<<"$STS")" ;;
esac

step "A real S3 round-trip through the proxy"
BUCKET="k8s-demo-$RANDOM"
OUT=$(kube run aws-$RANDOM --rm -i --restart=Never --image=amazon/aws-cli:latest --quiet \
    --env AWS_ACCESS_KEY_ID="$AK" --env AWS_SECRET_ACCESS_KEY="$SK" \
    --env AWS_SESSION_TOKEN="$ST" --env AWS_DEFAULT_REGION=us-east-1 \
    --command -- sh -c "
        set -e
        E=$PROXY
        aws --endpoint-url \$E s3 mb s3://$BUCKET
        echo 'hello from kubernetes' > /tmp/o.txt
        aws --endpoint-url \$E s3 cp /tmp/o.txt s3://$BUCKET/o.txt
        aws --endpoint-url \$E s3 cp s3://$BUCKET/o.txt /tmp/back.txt
        echo \"READBACK:\$(cat /tmp/back.txt)\"
    " 2>&1)
grep -q 'READBACK:hello from kubernetes' <<<"$OUT" \
    && ok "put and get round-trip, content byte-identical" \
    || ko "put and get round-trip" "$(tail -4 <<<"$OUT")"

step "What Ozone actually recorded"
OWNER=$(kube exec ozone-om-0 -- ozone sh bucket info "/s3v/$BUCKET" 2>/dev/null \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["owner"])')
[ "$OWNER" = "alice" ] \
    && ok "bucket owner is the OIDC user, not a shared key (owner=$OWNER)" \
    || ko "bucket owner is the OIDC user" "owner=$OWNER, expected alice"

SIZE=$(kube exec ozone-om-0 -- ozone sh key info "/s3v/$BUCKET/o.txt" 2>/dev/null \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["dataSize"])')
[ "$SIZE" = "22" ] && ok "the object is in Ozone at the right size (${SIZE} bytes)" \
    || ko "the object is in Ozone at the right size" "dataSize=$SIZE, expected 22"

step "The boundary"
CODE=$(probe_code "$PROXY/$BUCKET/o.txt")
[ "$CODE" = "403" ] && ok "unauthenticated request refused with 403" \
    || ko "unauthenticated request refused with 403" "got $CODE"

# The one that matters most. Ozone runs with security disabled, so a pod that
# can reach the S3 Gateway directly can act as any user. The chart's lockdown
# policy is what prevents it, and this asserts the policy is enforced rather
# than merely rendered.
DIRECT=$(probe_code http://ozone-s3g-rest:9878/)
[ "$DIRECT" = "000" ] \
    && ok "S3 Gateway unreachable except through the proxy (NetworkPolicy enforced)" \
    || ko "S3 Gateway unreachable except through the proxy" "a bypass pod got HTTP $DIRECT"

printf '\n'
if [ "$FAILED" -eq 0 ]; then
    printf '\033[0;32mAll checks passed.\033[0m alice signed in with OIDC, got short-lived\n'
    printf 'credentials, and Ozone recorded her as the owner of s3://%s.\n' "$BUCKET"
    printf '\nTear down with: bash ./up.sh down\n'
else
    printf '\033[0;31m%d check(s) failed.\033[0m\n' "$FAILED"
    exit 1
fi
