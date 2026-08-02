#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Self-signed certificate for the HAProxy TLS edge overlay, the lab
# stand-in for the production edge's real certificate. Produces
# certs/edge.pem (key+cert combined, the format HAProxy expects) and keeps
# certs/edge.crt as the CA bundle clients can pin (curl --cacert,
# aws --ca-bundle). Everything under certs/ is gitignored.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS="$HERE/certs"
mkdir -p "$CERTS"

if [ -s "$CERTS/edge.pem" ]; then
    echo "edge certificate already present: $CERTS/edge.pem"
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERTS/edge.key" -out "$CERTS/edge.crt" \
    -subj "/CN=haproxy" \
    -addext "subjectAltName=DNS:haproxy,DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

cat "$CERTS/edge.crt" "$CERTS/edge.key" > "$CERTS/edge.pem"
# World-readable on purpose: lab-only self-signed material, and the haproxy
# image runs unprivileged (a root-owned 600 file would be unreadable there).
chmod 644 "$CERTS/edge.pem" "$CERTS/edge.crt"
echo "edge certificate written: $CERTS/edge.pem (SAN: haproxy, localhost, 127.0.0.1)"
