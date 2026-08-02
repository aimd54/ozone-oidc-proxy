// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package oidc validates OIDC JWTs from multiple configured issuers
// (DESIGN.md §6.2): exact iss match, JWKS signature verification with
// refresh-on-unknown-kid, algorithm allowlist, exp/nbf with skew, mandatory
// audience intersection, username-claim extraction and sanitization.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/aimd54/ozone-oidc-proxy/internal/config"
)

// Error kinds, matched with errors.Is by callers to shape AWS/S3 error
// responses. Everything under ErrTokenInvalid maps to InvalidIdentityToken.
var (
	ErrUnknownIssuer     = errors.New("token issuer is not configured")
	ErrTokenExpired      = errors.New("token is expired")
	ErrTokenInvalid      = errors.New("token is invalid")
	ErrBadUsername       = errors.New("username claim rejected by policy")
	ErrIssuerUnavailable = errors.New("issuer JWKS unavailable")
)

// jwtSkew is the leeway applied to exp/nbf checks.
const jwtSkew = 60 * time.Second

// refreshCooldown rate-limits forced JWKS refreshes triggered by unknown kids,
// so a flood of garbage tokens cannot hammer the IdP (single-flight + cooldown).
const refreshCooldown = 10 * time.Second

// Identity is the authenticated result handed to the STS and Bearer lanes.
type Identity struct {
	Username   string
	Subject    string
	IssuerName string
	IssuerURL  string
	Expiry     time.Time
}

type issuerState struct {
	cfg config.Issuer

	mu          sync.Mutex
	jwksURL     string // resolved lazily (explicit jwks_uri or OIDC discovery)
	lastRefresh time.Time
}

// Validator validates raw JWTs against the configured issuer registry.
type Validator struct {
	byIssuerURL map[string]*issuerState
	allowedAlgs map[string]bool
	policy      config.UsernamePolicy
	cache       *jwk.Cache
	httpClient  *http.Client
	now         func() time.Time
}

// Option customizes the Validator (tests).
type Option func(*Validator)

// WithHTTPClient sets the client used for discovery and JWKS fetches.
func WithHTTPClient(c *http.Client) Option { return func(v *Validator) { v.httpClient = c } }

// WithClock overrides the time source.
func WithClock(now func() time.Time) Option { return func(v *Validator) { v.now = now } }

// New builds a Validator from the configuration. JWKS URLs are resolved lazily
// on first use so the proxy can start before its IdPs (or their realms) exist.
// ctx bounds the background JWKS auto-refresh machinery.
func New(ctx context.Context, cfg *config.Config, opts ...Option) (*Validator, error) {
	v := &Validator{
		byIssuerURL: make(map[string]*issuerState, len(cfg.Issuers)),
		allowedAlgs: make(map[string]bool, len(cfg.Security.AllowedSigningAlgs)),
		policy:      cfg.UsernamePolicy,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		now:         time.Now,
	}
	for _, alg := range cfg.Security.AllowedSigningAlgs {
		v.allowedAlgs[alg] = true
	}
	for _, iss := range cfg.Issuers {
		v.byIssuerURL[iss.Issuer] = &issuerState{cfg: iss}
	}
	for _, opt := range opts {
		opt(v)
	}
	v.cache = jwk.NewCache(ctx, jwk.WithErrSink(discardErrSink{}))
	return v, nil
}

// discardErrSink silences background refresh errors; failures surface on the
// request path as ErrIssuerUnavailable instead.
type discardErrSink struct{}

func (discardErrSink) Error(error) {}

// Validate runs the full §6.2 chain and returns the mapped identity.
func (v *Validator) Validate(ctx context.Context, raw string) (*Identity, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: empty token", ErrTokenInvalid)
	}

	// Step 1: read iss without verifying, to select the issuer.
	unverified, err := jwt.ParseInsecure([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed JWT: %w", ErrTokenInvalid, err)
	}
	iss, ok := v.byIssuerURL[unverified.Issuer()]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIssuer, unverified.Issuer())
	}

	// Step 3 (before signature work): algorithm allowlist from the protected
	// header. none/HS* can never appear in the allowlist (config-enforced).
	msg, err := jws.Parse([]byte(raw))
	if err != nil || len(msg.Signatures()) == 0 {
		return nil, fmt.Errorf("%w: not a signed JWT", ErrTokenInvalid)
	}
	hdr := msg.Signatures()[0].ProtectedHeaders()
	alg := hdr.Algorithm()
	if !v.allowedAlgs[alg.String()] {
		return nil, fmt.Errorf("%w: algorithm %q not allowed", ErrTokenInvalid, alg.String())
	}
	kid := hdr.KeyID()
	if kid == "" {
		return nil, fmt.Errorf("%w: missing kid header", ErrTokenInvalid)
	}

	// Step 2: signature via the issuer's JWKS (refresh on unknown kid).
	key, err := v.lookupKey(ctx, iss, kid)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse([]byte(raw),
		jwt.WithKey(alg, key),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(jwtSkew),
		jwt.WithRequiredClaim("exp"),
		jwt.WithClock(jwt.ClockFunc(v.now)),
	)
	// Step 4: exp/nbf (jwt.WithValidate above) and audience intersection.
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired()) {
			return nil, fmt.Errorf("%w: exp in the past", ErrTokenExpired)
		}
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
	if !intersects(token.Audience(), iss.cfg.Audiences) {
		return nil, fmt.Errorf("%w: aud %v does not include any of %v",
			ErrTokenInvalid, token.Audience(), iss.cfg.Audiences)
	}

	// Steps 5–6: username claim with sub fallback, then policy sanitation.
	username := stringClaim(token, iss.cfg.UsernameClaim)
	if username == "" {
		username = token.Subject()
	}
	if username == "" {
		return nil, fmt.Errorf("%w: no %s or sub claim", ErrBadUsername, iss.cfg.UsernameClaim)
	}
	if !v.policy.Validate(username) {
		return nil, fmt.Errorf("%w: %q", ErrBadUsername, username)
	}

	return &Identity{
		Username:   username,
		Subject:    token.Subject(),
		IssuerName: iss.cfg.Name,
		IssuerURL:  iss.cfg.Issuer,
		Expiry:     token.Expiration(),
	}, nil
}

// lookupKey returns the JWKS key for kid, forcing one rate-limited refresh if
// the kid is unknown (key rotation).
func (v *Validator) lookupKey(ctx context.Context, iss *issuerState, kid string) (jwk.Key, error) {
	jwksURL, err := v.resolveJWKS(ctx, iss)
	if err != nil {
		return nil, err
	}
	set, err := v.cache.Get(ctx, jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrIssuerUnavailable, err)
	}
	if key, ok := set.LookupKeyID(kid); ok {
		return key, nil
	}

	iss.mu.Lock()
	needRefresh := v.now().Sub(iss.lastRefresh) > refreshCooldown
	if needRefresh {
		iss.lastRefresh = v.now()
	}
	iss.mu.Unlock()
	if needRefresh {
		if set, err = v.cache.Refresh(ctx, jwksURL); err != nil {
			return nil, fmt.Errorf("%w: refresh: %w", ErrIssuerUnavailable, err)
		}
	} else {
		// Another request refreshed moments ago; reuse its result.
		if set, err = v.cache.Get(ctx, jwksURL); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrIssuerUnavailable, err)
		}
	}
	if key, ok := set.LookupKeyID(kid); ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: unknown kid %q", ErrTokenInvalid, kid)
}

// resolveJWKS returns the issuer's JWKS URL, resolving it on first use from
// the explicit jwks_uri or OIDC discovery, and registers it with the cache.
func (v *Validator) resolveJWKS(ctx context.Context, iss *issuerState) (string, error) {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	if iss.jwksURL != "" {
		return iss.jwksURL, nil
	}

	jwksURL := iss.cfg.JWKSURI
	if jwksURL == "" {
		var err error
		if jwksURL, err = v.discoverJWKS(ctx, iss.cfg.Issuer); err != nil {
			return "", fmt.Errorf("%w: discovery for %s: %w", ErrIssuerUnavailable, iss.cfg.Name, err)
		}
	}
	if err := v.cache.Register(jwksURL,
		jwk.WithHTTPClient(v.httpClient),
		jwk.WithMinRefreshInterval(time.Minute),
	); err != nil {
		return "", fmt.Errorf("%w: register JWKS: %w", ErrIssuerUnavailable, err)
	}
	iss.jwksURL = jwksURL
	return jwksURL, nil
}

func (v *Validator) discoverJWKS(ctx context.Context, issuerURL string) (string, error) {
	wellKnown := issuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d", wellKnown, resp.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode discovery document: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("discovery document has no jwks_uri")
	}
	return doc.JWKSURI, nil
}

func stringClaim(token jwt.Token, name string) string {
	v, ok := token.Get(name)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}
