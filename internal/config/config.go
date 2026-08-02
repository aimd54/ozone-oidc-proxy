// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package config loads and validates the proxy configuration:
// a YAML file, a small set of OZPX_* environment overrides, defaults, and
// fail-fast validation so that a misconfigured proxy never starts.
package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// ForwardModeRewrite forwards the client request with the Authorization header
// rewritten (synthetic header and AKID substitution).
const ForwardModeRewrite = "rewrite"

// ForwardModeResign replaces the Authorization header with a freshly computed,
// internally consistent SigV4 signature toward the upstream,
// robust to upstream parser hardening.
const ForwardModeResign = "resign"

// StoreMemory is the in-process credential store (single replica).
const StoreMemory = "memory"

// StoreValkey is the shared credential store: encrypted values
// in valkey, multi-replica capable.
const StoreValkey = "valkey"

// supportedSigningAlgs are the JWT signature algorithms the proxy is able and
// willing to verify. Symmetric (HS*) and "none" are excluded by construction.
var supportedSigningAlgs = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
}

// Duration is a time.Duration that unmarshals from YAML strings like "15m".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"15m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Std returns the underlying time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

type Config struct {
	Listen      string `yaml:"listen"`
	AdminListen string `yaml:"admin_listen"`

	Upstream        Upstream        `yaml:"upstream"`
	DataPath        DataPath        `yaml:"data_path"`
	Issuers         []Issuer        `yaml:"issuers"`
	STS             STS             `yaml:"sts"`
	CredentialStore CredentialStore `yaml:"credential_store"`
	Security        Security        `yaml:"security"`
	UsernamePolicy  UsernamePolicy  `yaml:"username_policy"`
}

type Upstream struct {
	S3Endpoint  string `yaml:"s3_endpoint"`
	ForwardMode string `yaml:"forward_mode"`
}

type DataPath struct {
	// Pointers so that an omitted key gets its default (true) rather than the
	// zero value.
	AcceptBearer *bool `yaml:"accept_bearer"`
	Strict       *bool `yaml:"strict"`
}

// BearerEnabled reports whether the Bearer lane is on (default true).
func (d DataPath) BearerEnabled() bool { return d.AcceptBearer == nil || *d.AcceptBearer }

// StrictEnabled reports whether strict mode is on (default true). Non-strict
// operation is deliberately opt-in: it turns the proxy into an open relay
// toward an unsecured Ozone.
func (d DataPath) StrictEnabled() bool { return d.Strict == nil || *d.Strict }

type Issuer struct {
	Name          string   `yaml:"name"`
	Issuer        string   `yaml:"issuer"`
	JWKSURI       string   `yaml:"jwks_uri"`
	Audiences     []string `yaml:"audiences"`
	UsernameClaim string   `yaml:"username_claim"`
}

type STS struct {
	// MaxDuration caps DurationSeconds, in seconds.
	MaxDuration      int      `yaml:"max_duration"`
	RoleARNAllowlist []string `yaml:"role_arn_allowlist"`
}

type CredentialStore struct {
	Type   string      `yaml:"type"`
	Valkey ValkeyStore `yaml:"valkey"`
}

// ValkeyStore configures the valkey credential store. The AES-256 value
// encryption key is read from the environment variable named by key_env,
// key material never lives in the config file.
type ValkeyStore struct {
	Addr   string `yaml:"addr"`
	KeyEnv string `yaml:"key_env"`
}

type Security struct {
	SigV4ClockSkew     Duration `yaml:"sigv4_clock_skew"`
	AllowedSigningAlgs []string `yaml:"allowed_signing_algs"`
	Region             string   `yaml:"region"`
}

type UsernamePolicy struct {
	Pattern string `yaml:"pattern"`

	regex *regexp.Regexp
}

// Validate reports whether a username extracted from a token is acceptable to
// place into the synthetic Credential header. The default pattern rejects "/"
// (breaks Credential scope parsing) and "$" (reserved by Ozone multi-tenancy).
func (p UsernamePolicy) Validate(username string) bool {
	return p.regex != nil && p.regex.MatchString(username)
}

// Load reads the YAML file at path, applies OZPX_* environment overrides and
// defaults, and validates the result.
func Load(path string) (*Config, error) {
	// #nosec G304 -- the config path is operator-supplied by definition
	// (-config flag / OZPX_CONFIG); there is no untrusted input here.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse is Load for in-memory YAML (used by tests).
func Parse(raw []byte) (*Config, error) {
	cfg := &Config{}
	if err := unmarshalStrict(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyEnv()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return cfg, nil
}

func unmarshalStrict(raw []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

// applyEnv overrides scalar settings from the environment. Only the knobs that
// plausibly differ between otherwise identical deployments are exposed.
func (c *Config) applyEnv() {
	if v := os.Getenv("OZPX_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("OZPX_ADMIN_LISTEN"); v != "" {
		c.AdminListen = v
	}
	if v := os.Getenv("OZPX_UPSTREAM_S3_ENDPOINT"); v != "" {
		c.Upstream.S3Endpoint = v
	}
	if v := os.Getenv("OZPX_STRICT"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.DataPath.Strict = &b
		}
	}
	if v := os.Getenv("OZPX_ACCEPT_BEARER"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			c.DataPath.AcceptBearer = &b
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:9000"
	}
	if c.AdminListen == "" {
		c.AdminListen = "0.0.0.0:9090"
	}
	if c.Upstream.ForwardMode == "" {
		c.Upstream.ForwardMode = ForwardModeRewrite
	}
	if c.STS.MaxDuration == 0 {
		c.STS.MaxDuration = 3600
	}
	if c.CredentialStore.Type == "" {
		c.CredentialStore.Type = StoreMemory
	}
	if c.CredentialStore.Valkey.KeyEnv == "" {
		c.CredentialStore.Valkey.KeyEnv = "OZPX_STORE_KEY"
	}
	if c.Security.SigV4ClockSkew == 0 {
		c.Security.SigV4ClockSkew = Duration(15 * time.Minute)
	}
	if len(c.Security.AllowedSigningAlgs) == 0 {
		c.Security.AllowedSigningAlgs = []string{"RS256", "ES256"}
	}
	if c.Security.Region == "" {
		c.Security.Region = "us-east-1"
	}
	if c.UsernamePolicy.Pattern == "" {
		c.UsernamePolicy.Pattern = `^[A-Za-z0-9._@-]{1,64}$`
	}
	for i := range c.Issuers {
		if c.Issuers[i].UsernameClaim == "" {
			c.Issuers[i].UsernameClaim = "preferred_username"
		}
	}
}

func (c *Config) validate() error {
	if c.Upstream.S3Endpoint == "" {
		return fmt.Errorf("upstream.s3_endpoint is required")
	}
	if err := checkHTTPURL("upstream.s3_endpoint", c.Upstream.S3Endpoint); err != nil {
		return err
	}
	if c.Upstream.ForwardMode != ForwardModeRewrite && c.Upstream.ForwardMode != ForwardModeResign {
		return fmt.Errorf("upstream.forward_mode %q not supported (%q or %q)",
			c.Upstream.ForwardMode, ForwardModeRewrite, ForwardModeResign)
	}
	switch c.CredentialStore.Type {
	case StoreMemory:
	case StoreValkey:
		if c.CredentialStore.Valkey.Addr == "" {
			return fmt.Errorf("credential_store.valkey.addr is required when credential_store.type is %q", StoreValkey)
		}
	default:
		return fmt.Errorf("credential_store.type %q not supported (%q or %q)",
			c.CredentialStore.Type, StoreMemory, StoreValkey)
	}
	if len(c.Issuers) == 0 {
		return fmt.Errorf("at least one issuer must be configured")
	}
	seenName := map[string]bool{}
	seenIss := map[string]bool{}
	for i, iss := range c.Issuers {
		where := fmt.Sprintf("issuers[%d]", i)
		if iss.Name == "" {
			return fmt.Errorf("%s: name is required", where)
		}
		if seenName[iss.Name] {
			return fmt.Errorf("%s: duplicate issuer name %q", where, iss.Name)
		}
		seenName[iss.Name] = true
		if iss.Issuer == "" {
			return fmt.Errorf("%s (%s): issuer URL is required", where, iss.Name)
		}
		if seenIss[iss.Issuer] {
			return fmt.Errorf("%s (%s): duplicate issuer URL %q", where, iss.Name, iss.Issuer)
		}
		seenIss[iss.Issuer] = true
		if err := checkHTTPURL(where+".issuer", iss.Issuer); err != nil {
			return err
		}
		if iss.JWKSURI != "" {
			if err := checkHTTPURL(where+".jwks_uri", iss.JWKSURI); err != nil {
				return err
			}
		}
		// aud verification is mandatory: an empty list would
		// silently accept any audience, the classic Keycloak gap.
		if len(iss.Audiences) == 0 {
			return fmt.Errorf("%s (%s): audiences must not be empty", where, iss.Name)
		}
	}
	if c.STS.MaxDuration <= 0 {
		return fmt.Errorf("sts.max_duration must be positive")
	}
	if c.Security.SigV4ClockSkew.Std() <= 0 {
		return fmt.Errorf("security.sigv4_clock_skew must be positive")
	}
	for _, alg := range c.Security.AllowedSigningAlgs {
		if !supportedSigningAlgs[alg] {
			return fmt.Errorf("security.allowed_signing_algs: %q is not a supported asymmetric algorithm", alg)
		}
	}
	re, err := regexp.Compile(c.UsernamePolicy.Pattern)
	if err != nil {
		return fmt.Errorf("username_policy.pattern: %w", err)
	}
	c.UsernamePolicy.regex = re
	return nil
}

func checkHTTPURL(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s: %q must be an absolute http(s) URL", field, raw)
	}
	return nil
}
