#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Helm chart smoke test on a throwaway kind cluster: lint, install with the
# in-chart valkey (valkey store, 2 replicas), wait Ready, probe the admin
# surface, assert the NetworkPolicies rendered, tear down. Requires: kind,
# helm, kubectl, docker, and the ozone-oidc-proxy:dev image (make docker-build).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART="$HERE/ozone-oidc-proxy"
CLUSTER="ozpx-smoke"
RELEASE="ozpx"

PASS=0
FAIL=0
ok() { echo "  PASS $1"; PASS=$((PASS + 1)); }
ko() { echo "  FAIL $1"; FAIL=$((FAIL + 1)); }

echo "== helm lint"
helm lint "$CHART"

echo "== creating kind cluster $CLUSTER"
kind create cluster --name "$CLUSTER" --wait 120s >/dev/null
trap 'kind delete cluster --name "$CLUSTER" >/dev/null 2>&1' EXIT
kind load docker-image ozone-oidc-proxy:dev valkey/valkey:8 --name "$CLUSTER"

echo "== helm install (valkey store, 2 replicas)"
STORE_KEY=$(head -c 32 /dev/urandom | base64 -w0)
# The chart ships an unresolvable placeholder issuer on purpose, so a real
# one has to be supplied here. Nothing in this smoke test exchanges a token;
# the value only has to be a well-formed issuer the config validator accepts.
if ! helm install "$RELEASE" "$CHART" \
    --set replicaCount=2 \
    --set valkey.enabled=true \
    --set storeKey.create=true \
    --set "storeKey.value=$STORE_KEY" \
    --set config.credential_store.type=valkey \
    --set "config.credential_store.valkey.addr=$RELEASE-ozone-oidc-proxy-valkey:6379" \
    --set "networkPolicy.s3gPodSelector.app=ozone-s3g" \
    --set "config.issuers[0].name=corp-idp" \
    --set "config.issuers[0].issuer=https://idp.example.com" \
    --set "config.issuers[0].audiences[0]=ozone-s3" \
    --set "config.issuers[0].username_claim=preferred_username" \
    --wait --timeout 180s; then
    echo "== install failed; diagnostics:"
    kubectl get pods -o wide
    kubectl describe pods | grep -A8 "Events:"
    kubectl logs -l app.kubernetes.io/name=ozone-oidc-proxy --all-containers --tail 20 || true
    exit 1
fi

kubectl get deploy "$RELEASE-ozone-oidc-proxy" -o jsonpath='{.status.readyReplicas}' | grep -q '^2$' \
    && ok "2 proxy replicas Ready (valkey-backed readiness probe)" \
    || ko "2 proxy replicas Ready"

PF_LOG=$(mktemp)
kubectl port-forward "svc/$RELEASE-ozone-oidc-proxy" 19090:9090 >"$PF_LOG" 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null; rm -f "$PF_LOG"; kind delete cluster --name "$CLUSTER" >/dev/null 2>&1' EXIT
# Wait for the forward to actually establish; if the process dies, show why.
for _ in $(seq 1 40); do
    grep -q "Forwarding from" "$PF_LOG" && break
    if ! kill -0 $PF 2>/dev/null; then
        echo "== port-forward died:"; cat "$PF_LOG"; break
    fi
    sleep 0.5
done
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:19090/healthz >/dev/null 2>&1 && break; sleep 0.5; done
curl -sf http://127.0.0.1:19090/healthz >/dev/null && ok "/healthz through the Service" || ko "/healthz through the Service"
curl -sf http://127.0.0.1:19090/readyz >/dev/null && ok "/readyz (store reachable)" || ko "/readyz (store reachable)"
curl -sf http://127.0.0.1:19090/metrics | grep -q go_goroutines && ok "/metrics exposed" || ko "/metrics exposed"
REVOKE=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE http://127.0.0.1:19090/credentials/OZPXDOESNOTEXIST0000)
[ "$REVOKE" = "404" ] && ok "revocation endpoint responds (404 for unknown AKID)" \
    || ko "revocation endpoint responds" "http $REVOKE"

NP=$(kubectl get networkpolicy -o name)
grep -q "$RELEASE-ozone-oidc-proxy-ingress" <<<"$NP" && ok "proxy ingress NetworkPolicy rendered" || ko "proxy ingress NetworkPolicy rendered"
grep -q "$RELEASE-ozone-oidc-proxy-s3g-lockdown" <<<"$NP" && ok "s3g lockdown NetworkPolicy rendered" || ko "s3g lockdown NetworkPolicy rendered"
grep -q "$RELEASE-ozone-oidc-proxy-valkey" <<<"$NP" && ok "valkey NetworkPolicy rendered" || ko "valkey NetworkPolicy rendered"

if [ "$FAIL" -gt 0 ]; then
    echo "== failures; diagnostics:"
    echo "-- port-forward log:"; cat "$PF_LOG"
    kubectl get pods -o wide
    kubectl logs -l app.kubernetes.io/name=ozone-oidc-proxy --all-containers --tail 20 || true
fi

printf '\n== helm smoke: %d passed, %d failed ==\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
