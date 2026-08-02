// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

const minimalYAML = `
upstream:
  s3_endpoint: http://ozone-s3g:9878
issuers:
  - name: keycloak
    issuer: https://keycloak.local/realms/ozone
    audiences: [ozone-s3]
`

func TestDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != "0.0.0.0:9000" || cfg.AdminListen != "0.0.0.0:9090" {
		t.Errorf("listen defaults wrong: %q %q", cfg.Listen, cfg.AdminListen)
	}
	if cfg.Upstream.ForwardMode != ForwardModeRewrite {
		t.Errorf("forward_mode default = %q", cfg.Upstream.ForwardMode)
	}
	if !cfg.DataPath.BearerEnabled() || !cfg.DataPath.StrictEnabled() {
		t.Error("accept_bearer and strict must default to true")
	}
	if cfg.STS.MaxDuration != 3600 {
		t.Errorf("sts.max_duration default = %d", cfg.STS.MaxDuration)
	}
	if cfg.CredentialStore.Type != StoreMemory {
		t.Errorf("credential_store.type default = %q", cfg.CredentialStore.Type)
	}
	if cfg.Security.SigV4ClockSkew.Std() != 15*time.Minute {
		t.Errorf("sigv4_clock_skew default = %v", cfg.Security.SigV4ClockSkew.Std())
	}
	if got := cfg.Security.AllowedSigningAlgs; len(got) != 2 || got[0] != "RS256" || got[1] != "ES256" {
		t.Errorf("allowed_signing_algs default = %v", got)
	}
	if cfg.Security.Region != "us-east-1" {
		t.Errorf("region default = %q", cfg.Security.Region)
	}
	if cfg.Issuers[0].UsernameClaim != "preferred_username" {
		t.Errorf("username_claim default = %q", cfg.Issuers[0].UsernameClaim)
	}
}

func TestFullExample(t *testing.T) {
	// The example from DESIGN.md §6.6 must parse as-is.
	cfg, err := Parse([]byte(`
listen: 0.0.0.0:9000
admin_listen: 0.0.0.0:9090

upstream:
  s3_endpoint: http://ozone-s3g:9878
  forward_mode: rewrite

data_path:
  accept_bearer: true
  strict: true

issuers:
  - name: keycloak
    issuer: https://keycloak.local/realms/ozone
    audiences: [ozone-s3]
    username_claim: preferred_username
  - name: corp-dev
    issuer: https://token.corp.example
    jwks_uri: https://token.corp.example/keys
    audiences: [s3]
    username_claim: sub

sts:
  max_duration: 3600
  role_arn_allowlist: ["arn:ozone:iam::dev:role/oidc"]

credential_store:
  type: memory

security:
  sigv4_clock_skew: 15m
  allowed_signing_algs: [RS256, ES256]
  region: us-east-1

username_policy:
  pattern: "^[A-Za-z0-9._@-]{1,64}$"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Issuers) != 2 || cfg.Issuers[1].JWKSURI != "https://token.corp.example/keys" {
		t.Errorf("issuers not parsed: %+v", cfg.Issuers)
	}
	if len(cfg.STS.RoleARNAllowlist) != 1 {
		t.Errorf("role_arn_allowlist not parsed: %v", cfg.STS.RoleARNAllowlist)
	}
}

func TestUsernamePolicy(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	valid := []string{"alice", "bob.smith", "a_b@example.com"[0:5], "user@corp", "x-1_2.3"}
	for _, u := range valid {
		if !cfg.UsernamePolicy.Validate(u) {
			t.Errorf("Validate(%q) = false, want true", u)
		}
	}
	invalid := []string{"", "a/b", "tenant$user", "spaced name", strings.Repeat("a", 65)}
	for _, u := range invalid {
		if cfg.UsernamePolicy.Validate(u) {
			t.Errorf("Validate(%q) = true, want false", u)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing upstream", "issuers: [{name: a, issuer: http://x, audiences: [s3]}]", "s3_endpoint is required"},
		{"no issuers", "upstream: {s3_endpoint: http://x}", "at least one issuer"},
		{"empty audiences", `
upstream: {s3_endpoint: http://x}
issuers: [{name: a, issuer: http://kc}]`, "audiences must not be empty"},
		{"unknown forward mode", `
upstream: {s3_endpoint: http://x, forward_mode: passthrough}
issuers: [{name: a, issuer: http://kc, audiences: [s3]}]`, "forward_mode"},
		{"valkey without addr", `
upstream: {s3_endpoint: http://x}
credential_store: {type: valkey}
issuers: [{name: a, issuer: http://kc, audiences: [s3]}]`, "valkey.addr"},
		{"unknown store type", `
upstream: {s3_endpoint: http://x}
credential_store: {type: etcd}
issuers: [{name: a, issuer: http://kc, audiences: [s3]}]`, "credential_store.type"},
		{"HS256 allowlisted", `
upstream: {s3_endpoint: http://x}
security: {allowed_signing_algs: [HS256]}
issuers: [{name: a, issuer: http://kc, audiences: [s3]}]`, "not a supported asymmetric algorithm"},
		{"duplicate issuer name", `
upstream: {s3_endpoint: http://x}
issuers:
  - {name: a, issuer: http://kc1, audiences: [s3]}
  - {name: a, issuer: http://kc2, audiences: [s3]}`, "duplicate issuer name"},
		{"relative issuer URL", `
upstream: {s3_endpoint: http://x}
issuers: [{name: a, issuer: keycloak/realms/z, audiences: [s3]}]`, "absolute http(s) URL"},
		{"unknown key", `
upstream: {s3_endpoint: http://x}
issuers: [{name: a, issuer: http://kc, audiences: [s3]}]
tls: {}`, "field tls not found"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("OZPX_LISTEN", "127.0.0.1:1234")
	t.Setenv("OZPX_UPSTREAM_S3_ENDPOINT", "http://other:9878")
	t.Setenv("OZPX_STRICT", "false")
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Listen != "127.0.0.1:1234" {
		t.Errorf("OZPX_LISTEN not applied: %q", cfg.Listen)
	}
	if cfg.Upstream.S3Endpoint != "http://other:9878" {
		t.Errorf("OZPX_UPSTREAM_S3_ENDPOINT not applied: %q", cfg.Upstream.S3Endpoint)
	}
	if cfg.DataPath.StrictEnabled() {
		t.Error("OZPX_STRICT=false not applied")
	}
}

func TestValkeyStoreAccepted(t *testing.T) {
	cfg, err := Parse([]byte(`
upstream: {s3_endpoint: http://s3g:9878}
credential_store: {type: valkey, valkey: {addr: "valkey:6379"}}
issuers: [{name: a, issuer: http://kc, audiences: [s3]}]`))
	if err != nil {
		t.Fatalf("valkey store rejected: %v", err)
	}
	if cfg.CredentialStore.Type != StoreValkey || cfg.CredentialStore.Valkey.Addr != "valkey:6379" {
		t.Errorf("valkey config parsed wrong: %+v", cfg.CredentialStore)
	}
	if cfg.CredentialStore.Valkey.KeyEnv != "OZPX_STORE_KEY" {
		t.Errorf("key_env default = %q, want OZPX_STORE_KEY", cfg.CredentialStore.Valkey.KeyEnv)
	}
}

func TestResignModeAccepted(t *testing.T) {
	cfg, err := Parse([]byte(`
upstream: {s3_endpoint: http://s3g:9878, forward_mode: resign}
issuers: [{name: a, issuer: http://kc, audiences: [s3]}]`))
	if err != nil {
		t.Fatalf("resign mode rejected: %v", err)
	}
	if cfg.Upstream.ForwardMode != ForwardModeResign {
		t.Errorf("forward_mode = %q, want resign", cfg.Upstream.ForwardMode)
	}
}
