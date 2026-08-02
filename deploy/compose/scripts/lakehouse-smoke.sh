#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Lakehouse-overlay smoke checks: Nessie is healthy and version-storing,
# its web-identity token file is being refreshed, the Iceberg REST facade
# answers, and Jupyter is serving. The full walkthrough (including actual
# table writes over OIDC credentials) is the notebook —
#   docker compose exec jupyter jupyter nbconvert --to notebook --execute \
#       ozone-oidc-tour.ipynb --output /tmp/executed.ipynb
set -uo pipefail

NETWORK="ozone-oidc-proxy_oidc-net"
CURL_IMAGE="curlimages/curl:latest"

PASS=0
FAIL=0
ok() { printf '  \033[0;32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
ko() { printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; shift; [ $# -gt 0 ] && printf '       %s\n' "$@"; FAIL=$((FAIL + 1)); }
curl_net() { docker run --rm --network "$NETWORK" "$CURL_IMAGE" -s "$@"; }

echo "lakehouse smoke — nessie + iceberg REST + jupyter"

CFG=$(curl_net http://nessie:19120/api/v2/config)
grep -q '"defaultBranch"' <<<"$CFG" && ok "nessie API v2 answers (defaultBranch present)" \
    || ko "nessie API v2 answers" "$CFG"

ICEBERG=$(curl_net -o /dev/null -w '%{http_code}' "http://nessie:19120/iceberg/v1/config?warehouse=warehouse")
[ "$ICEBERG" = "200" ] && ok "Iceberg REST facade answers (/iceberg/v1/config)" \
    || ko "Iceberg REST facade answers" "http $ICEBERG"

if docker exec oidc-nessie test -s /tokens/nessie.jwt 2>/dev/null; then
    ok "web-identity token file present (refresher sidecar)"
else
    ko "web-identity token file present (refresher sidecar)"
fi

JUP=$(curl_net -o /dev/null -w '%{http_code}' http://jupyter:8888/api)
[ "$JUP" = "200" ] && ok "jupyter serving (http://localhost:8890)" \
    || ko "jupyter serving" "http $JUP"

printf '\n\033[1m== Summary: %d passed, %d failed ==\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
