#!/usr/bin/env bash
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0
#
# Checks that this machine resolves the issuer hostname to the local stack.
#
# Tokens must carry iss=http://keycloak:8080/realms/ozone exactly, so the lab
# pins that hostname and everything that talks to the identity provider from
# the host uses it: the credential portal, the device-flow sign-in page, and
# ozone-login. A browser without the entry reports a plain connection failure
# that points at nothing, which is why this check exists rather than a line in
# the documentation alone.
#
# The acceptance suite does not need the entry (it passes curl --resolve), and
# neither does the demo (it reaches the identity provider on localhost).
set -uo pipefail

ISSUER_HOST="${ISSUER_HOST:-keycloak}"
ISSUER_PORT="${ISSUER_PORT:-8080}"

# Any HTTP status means the name resolved and something answered, which is the
# whole question here. Do not probe a realm path: realms are created by
# `make init` and the identity provider keeps no volume, so a realm probe would
# report a name-resolution problem whenever the realm merely had not been
# provisioned yet.
reachable() { [ "$(curl -s -o /dev/null -m 3 -w '%{http_code}' "$1" 2>/dev/null)" != "000" ]; }

if reachable "http://${ISSUER_HOST}:${ISSUER_PORT}/"; then
    echo "Host resolves '${ISSUER_HOST}' to the running stack. Browser sign-in will work."
    exit 0
fi

# Distinguish "the entry is missing" from "the stack is not running": the
# identity provider answers on localhost either way once it is up.
if ! reachable "http://localhost:${ISSUER_PORT}/"; then
    cat >&2 <<EOF

Nothing is answering on localhost:${ISSUER_PORT}, so this check cannot tell whether
'${ISSUER_HOST}' resolves. Start the stack first:

    make up

EOF
    exit 1
fi

cat >&2 <<EOF

The stack is running, but this machine does not resolve '${ISSUER_HOST}'.

Browser sign-in and ozone-login will fail with a connection error, because
tokens must carry iss=http://${ISSUER_HOST}:${ISSUER_PORT}/realms/<realm> exactly, so the
host is sent that name verbatim rather than localhost.

Add the entry, then run this again:

    echo '127.0.0.1 ${ISSUER_HOST}' | sudo tee -a /etc/hosts

EOF
exit 1
