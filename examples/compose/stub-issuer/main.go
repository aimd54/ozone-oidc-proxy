// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// stub-issuer is a minimal static OIDC issuer for the compose lab only
// (a second issuer, an OIDC stub standing in for the
// proprietary endpoint"). It proves the proxy's multi-issuer registry,
// OIDC discovery and per-issuer audiences/username_claim against a
// non-Keycloak discovery shape.
//
// It serves:
//
//	GET  /.well-known/openid-configuration
//	GET  /jwks
//	POST /token   form: username (required), aud (default $STUB_AUDIENCE),
//	              ttl (seconds, default 600) → {"access_token": ..., ...}
//
// SECURITY: /token mints an RS256 JWT for any requested identity with no
// authentication whatsoever; that is the point of a test stub. It must
// never be reachable outside the lab network (compose publishes no port).
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

const kid = "stub-2026"

func main() {
	listen := env("STUB_LISTEN", ":8081")
	issuer := env("STUB_ISSUER", "http://stub-issuer:8081")
	audience := env("STUB_AUDIENCE", "ozone-data")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate RSA key: %v", err)
	}

	discovery, _ := json.Marshal(map[string]any{
		"issuer":                                issuer,
		"jwks_uri":                              issuer + "/jwks",
		"token_endpoint":                        issuer + "/token",
		"response_types_supported":              []string{"token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
	jwks, _ := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": kid,
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}},
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(discovery)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		username := r.PostFormValue("username")
		if username == "" {
			http.Error(w, `{"error":"invalid_request","error_description":"username required"}`, http.StatusBadRequest)
			return
		}
		ttl := 600
		if s := r.PostFormValue("ttl"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				ttl = n
			}
		}
		aud := audience
		if s := r.PostFormValue("aud"); s != "" {
			aud = s
		}
		now := time.Now()
		// sub is deliberately username-policy-invalid ("|"): if the proxy
		// ever fell back to sub instead of the configured username_claim,
		// the mint would fail loudly rather than mis-attribute.
		claims := map[string]any{
			"iss": issuer,
			"sub": "stub|" + username,
			"uid": username,
			"aud": strings.Split(aud, ","),
			"iat": now.Unix(),
			"nbf": now.Unix(),
			"exp": now.Add(time.Duration(ttl) * time.Second).Unix(),
		}
		token, err := signJWT(key, claims)
		if err != nil {
			http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   ttl,
		})
		// #nosec G706 -- %q escapes control characters, so a crafted
		// username cannot forge log lines.
		log.Printf("minted token: uid=%q aud=%q ttl=%ds", username, aud, ttl)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Printf("stub-issuer listening on %s (issuer=%s, audience=%s)", listen, issuer, audience)
	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// signJWT builds an RS256 JWT: base64url(header).base64url(claims) signed
// with RSASSA-PKCS1-v1_5 over SHA-256.
func signJWT(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
