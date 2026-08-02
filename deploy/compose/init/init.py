#!/usr/bin/env python3
# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0

"""Provision Keycloak for the ozone-oidc-proxy PoC stack.

Creates (idempotently):
  - realm `ozone`
  - public client `ozone-s3` with Direct Access Grants (ROPC, PoC only) and
    the OAuth device grant (ozone-login), an *audience mapper* adding
    aud=ozone-s3 (Keycloak's default aud=account would fail the proxy's
    mandatory audience check, DESIGN.md §6.2), and a 1h access-token
    lifespan so temp-credential TTLs aren't capped at the realm default of
    5 minutes (§6.9)
  - confidential client `ozone-portal` for oauth2-proxy in front of the
    credential portal (authorization code flow; same aud=ozone-s3 mapper so
    the forwarded access token passes the proxy's STS)
  - test users alice and bob (password123)

Idempotent: safe to re-run against an existing realm.
"""

import os
import sys
import time

import requests

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
KEYCLOAK_HEALTH_URL = os.getenv("KEYCLOAK_HEALTH_URL", "http://keycloak:9000")
ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin123")
REALM = os.getenv("REALM", "ozone")
CLIENT_ID = os.getenv("CLIENT_ID", "ozone-s3")
AUDIENCE = os.getenv("AUDIENCE", "ozone-s3")
ACCESS_TOKEN_LIFESPAN = os.getenv("ACCESS_TOKEN_LIFESPAN", "3600")
PORTAL_CLIENT_ID = os.getenv("PORTAL_CLIENT_ID", "ozone-portal")
PORTAL_CLIENT_SECRET = os.getenv("PORTAL_CLIENT_SECRET", "portal-secret-123")
PORTAL_REDIRECT_URI = os.getenv("PORTAL_REDIRECT_URI", "http://localhost:4180/oauth2/callback")
NESSIE_CLIENT_ID = os.getenv("NESSIE_CLIENT_ID", "nessie")
NESSIE_CLIENT_SECRET = os.getenv("NESSIE_CLIENT_SECRET", "nessie-secret-123")

USERS = [
    {"username": "alice", "password": "password123", "email": "alice@example.com",
     "firstName": "Alice", "lastName": "Anderson"},
    {"username": "bob", "password": "password123", "email": "bob@example.com",
     "firstName": "Bob", "lastName": "Brown"},
]


def wait_for_keycloak(timeout=180):
    url = f"{KEYCLOAK_HEALTH_URL}/health/ready"
    print(f"Waiting for Keycloak at {url}...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            if requests.get(url, timeout=5).status_code == 200:
                print("Keycloak is ready")
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    sys.exit(f"Keycloak did not become ready within {timeout}s")


def admin_session():
    resp = requests.post(
        f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
        timeout=10,
    )
    resp.raise_for_status()
    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {resp.json()['access_token']}"
    return session


def create_realm(kc):
    resp = kc.post(f"{KEYCLOAK_URL}/admin/realms", json={
        "realm": REALM,
        "enabled": True,
        "displayName": "Ozone S3 Realm",
    })
    if resp.status_code == 201:
        print(f"Realm '{REALM}' created")
    elif resp.status_code == 409:
        print(f"Realm '{REALM}' already exists")
    else:
        resp.raise_for_status()


def upsert_client(kc, config):
    """Create or update a client; returns its UUID."""
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients"
    client_id = config["clientId"]
    resp = kc.post(clients_url, json=config)
    if resp.status_code == 201:
        uuid = resp.headers["Location"].rsplit("/", 1)[-1]
        print(f"Client '{client_id}' created")
    elif resp.status_code == 409:
        found = kc.get(clients_url, params={"clientId": client_id}).json()
        uuid = found[0]["id"]
        config["id"] = uuid
        kc.put(f"{clients_url}/{uuid}", json=config).raise_for_status()
        print(f"Client '{client_id}' already exists, updated")
    else:
        resp.raise_for_status()
    return uuid


def ensure_audience_mapper(kc, uuid, client_id):
    """Access tokens must carry aud=ozone-s3 or the proxy rejects them (§6.2)."""
    mappers_url = (f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{uuid}"
                   "/protocol-mappers/models")
    mapper = {
        "name": "ozone-s3-audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.custom.audience": AUDIENCE,
            "access.token.claim": "true",
            "id.token.claim": "false",
        },
    }
    existing = {m["name"]: m["id"] for m in kc.get(mappers_url).json()}
    if mapper["name"] in existing:
        mapper["id"] = existing[mapper["name"]]
        kc.put(f"{mappers_url}/{mapper['id']}", json=mapper).raise_for_status()
        print(f"Audience mapper on '{client_id}' updated (aud={AUDIENCE})")
    else:
        kc.post(mappers_url, json=mapper).raise_for_status()
        print(f"Audience mapper on '{client_id}' created (aud={AUDIENCE})")


def create_client(kc):
    uuid = upsert_client(kc, {
        "clientId": CLIENT_ID,
        "name": "Ozone S3 (proxy PoC)",
        "enabled": True,
        "protocol": "openid-connect",
        # Public + ROPC: PoC-only convenience (DESIGN.md decision #5); the
        # portal and ozone-login are the human paths since M2. The device
        # grant serves ozone-login.
        "publicClient": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": True,
        "attributes": {
            "access.token.lifespan": ACCESS_TOKEN_LIFESPAN,
            "oauth2.device.authorization.grant.enabled": "true",
        },
    })
    ensure_audience_mapper(kc, uuid, CLIENT_ID)


def create_portal_client(kc):
    uuid = upsert_client(kc, {
        "clientId": PORTAL_CLIENT_ID,
        "name": "Credential portal (oauth2-proxy)",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": PORTAL_CLIENT_SECRET,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": [PORTAL_REDIRECT_URI],
        "attributes": {"access.token.lifespan": ACCESS_TOKEN_LIFESPAN},
    })
    ensure_audience_mapper(kc, uuid, PORTAL_CLIENT_ID)


def create_nessie_client(kc):
    """Machine identity for the lakehouse overlay: Nessie exchanges a
    client-credentials token (preferred_username=service-account-nessie)
    for temp S3 credentials at the proxy STS — no static S3 secret."""
    uuid = upsert_client(kc, {
        "clientId": NESSIE_CLIENT_ID,
        "name": "Nessie catalog (service account, lakehouse overlay)",
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": NESSIE_CLIENT_SECRET,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "attributes": {"access.token.lifespan": ACCESS_TOKEN_LIFESPAN},
    })
    ensure_audience_mapper(kc, uuid, NESSIE_CLIENT_ID)


def create_users(kc):
    users_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/users"
    for user in USERS:
        resp = kc.post(users_url, json={
            "username": user["username"],
            "email": user["email"],
            "firstName": user["firstName"],
            "lastName": user["lastName"],
            "enabled": True,
            "emailVerified": True,
        })
        if resp.status_code == 201:
            uuid = resp.headers["Location"].rsplit("/", 1)[-1]
            print(f"User '{user['username']}' created")
        elif resp.status_code == 409:
            uuid = kc.get(users_url, params={"username": user["username"]}).json()[0]["id"]
            print(f"User '{user['username']}' already exists")
        else:
            resp.raise_for_status()
            continue
        kc.put(f"{users_url}/{uuid}/reset-password", json={
            "type": "password",
            "value": user["password"],
            "temporary": False,
        }).raise_for_status()


def main():
    print("=== ozone-oidc-proxy Keycloak provisioning ===")
    wait_for_keycloak()
    kc = admin_session()
    create_realm(kc)
    create_client(kc)
    create_portal_client(kc)
    create_nessie_client(kc)
    create_users(kc)
    print("\nDone. Test users:")
    for user in USERS:
        print(f"  - {user['username']} / {user['password']}")
    print(f"\nToken endpoint: {KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token")
    print(f"Clients: {CLIENT_ID} (public: ROPC + device grant), "
          f"{PORTAL_CLIENT_ID} (confidential, code flow), "
          f"{NESSIE_CLIENT_ID} (service account, client credentials); "
          f"audience: {AUDIENCE}")


if __name__ == "__main__":
    main()
