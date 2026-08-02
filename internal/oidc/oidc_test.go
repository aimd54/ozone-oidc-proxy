// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/aimd54/ozone-oidc-proxy/internal/config"
)

type testIdP struct {
	srv        *httptest.Server
	fetchCount atomic.Int32

	mu   sync.Mutex
	keys jwk.Set // public set currently served

	rsaKey jwk.Key // kid rsa1
	ecKey  jwk.Key // kid ec1
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	idp := &testIdP{}

	rawRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp.rsaKey = mustJWK(t, rawRSA, "rsa1", jwa.RS256)

	rawEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp.ecKey = mustJWK(t, rawEC, "ec1", jwa.ES256)

	idp.setServedKeys(t, idp.rsaKey, idp.ecKey)

	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.fetchCount.Add(1)
		idp.mu.Lock()
		defer idp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(idp.keys)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idp.srv.URL, idp.srv.URL+"/jwks")
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func mustJWK(t *testing.T, raw any, kid string, alg jwa.SignatureAlgorithm) jwk.Key {
	t.Helper()
	key, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatal(err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		t.Fatal(err)
	}
	return key
}

func (idp *testIdP) setServedKeys(t *testing.T, keys ...jwk.Key) {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		pub, err := jwk.PublicKeyOf(k)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.AddKey(pub); err != nil {
			t.Fatal(err)
		}
	}
	idp.mu.Lock()
	idp.keys = set
	idp.mu.Unlock()
}

// claims that produce a valid token for the given issuer unless overridden.
type tokenSpec struct {
	iss      string
	aud      []string
	username string // preferred_username; empty = omit
	sub      string
	exp      time.Duration // relative to now
	nbf      time.Duration
	noExp    bool
}

func (idp *testIdP) sign(t *testing.T, key jwk.Key, alg jwa.SignatureAlgorithm, spec tokenSpec) string {
	t.Helper()
	b := jwt.NewBuilder().Issuer(spec.iss).Subject(spec.sub)
	if len(spec.aud) > 0 {
		b = b.Audience(spec.aud)
	}
	if !spec.noExp {
		if spec.exp == 0 {
			spec.exp = time.Hour
		}
		b = b.Expiration(time.Now().Add(spec.exp))
	}
	if spec.nbf != 0 {
		b = b.NotBefore(time.Now().Add(spec.nbf))
	}
	if spec.username != "" {
		b = b.Claim("preferred_username", spec.username)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(alg, key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func newValidator(t *testing.T, idp *testIdP, explicitJWKS bool) *Validator {
	t.Helper()
	jwksLine := ""
	if explicitJWKS {
		jwksLine = "    jwks_uri: " + idp.srv.URL + "/jwks\n"
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
upstream: {s3_endpoint: http://ozone-s3g:9878}
issuers:
  - name: test-idp
    issuer: %s
%s    audiences: [ozone-s3]
`, idp.srv.URL, jwksLine)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	v, err := New(ctx, cfg, WithHTTPClient(idp.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func baseSpec(idp *testIdP) tokenSpec {
	return tokenSpec{iss: idp.srv.URL, aud: []string{"ozone-s3"}, username: "alice", sub: "sub-1"}
}

func TestValidateHappyPath(t *testing.T) {
	idp := newTestIdP(t)
	v := newValidator(t, idp, true)

	for name, tc := range map[string]struct {
		key jwk.Key
		alg jwa.SignatureAlgorithm
	}{
		"RS256": {idp.rsaKey, jwa.RS256},
		"ES256": {idp.ecKey, jwa.ES256},
	} {
		t.Run(name, func(t *testing.T) {
			id, err := v.Validate(context.Background(), idp.sign(t, tc.key, tc.alg, baseSpec(idp)))
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if id.Username != "alice" || id.IssuerName != "test-idp" || id.Subject != "sub-1" {
				t.Errorf("unexpected identity: %+v", id)
			}
			if time.Until(id.Expiry) < 50*time.Minute {
				t.Errorf("expiry not propagated: %v", id.Expiry)
			}
		})
	}
}

func TestValidateDiscovery(t *testing.T) {
	idp := newTestIdP(t)
	v := newValidator(t, idp, false) // no jwks_uri → .well-known discovery
	id, err := v.Validate(context.Background(), idp.sign(t, idp.rsaKey, jwa.RS256, baseSpec(idp)))
	if err != nil {
		t.Fatalf("Validate via discovery: %v", err)
	}
	if id.Username != "alice" {
		t.Errorf("username = %q", id.Username)
	}
}

func TestValidateRejections(t *testing.T) {
	idp := newTestIdP(t)
	v := newValidator(t, idp, true)
	ctx := context.Background()

	t.Run("expired", func(t *testing.T) {
		spec := baseSpec(idp)
		spec.exp = -time.Hour
		_, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, spec))
		if !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("want ErrTokenExpired, got %v", err)
		}
	})
	t.Run("not yet valid", func(t *testing.T) {
		spec := baseSpec(idp)
		spec.nbf = time.Hour
		_, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, spec))
		if !errors.Is(err, ErrTokenInvalid) || errors.Is(err, ErrTokenExpired) {
			t.Fatalf("want ErrTokenInvalid (nbf), got %v", err)
		}
	})
	t.Run("missing exp", func(t *testing.T) {
		spec := baseSpec(idp)
		spec.noExp = true
		_, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, spec))
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("want ErrTokenInvalid (no exp), got %v", err)
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		spec := baseSpec(idp)
		spec.aud = []string{"account"} // Keycloak default aud, must be rejected
		_, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, spec))
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("want ErrTokenInvalid (aud), got %v", err)
		}
	})
	t.Run("unknown issuer", func(t *testing.T) {
		spec := baseSpec(idp)
		spec.iss = "https://evil.example/realms/ozone"
		_, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, spec))
		if !errors.Is(err, ErrUnknownIssuer) {
			t.Fatalf("want ErrUnknownIssuer, got %v", err)
		}
	})
	t.Run("HS256 rejected", func(t *testing.T) {
		sym, err := jwk.FromRaw([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		_ = sym.Set(jwk.KeyIDKey, "sym1")
		_, err = v.Validate(ctx, idp.sign(t, sym, jwa.HS256, baseSpec(idp)))
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("want ErrTokenInvalid (alg), got %v", err)
		}
	})
	t.Run("alg none rejected", func(t *testing.T) {
		hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
			`{"iss":%q,"aud":"ozone-s3","preferred_username":"alice","exp":%d}`,
			idp.srv.URL, time.Now().Add(time.Hour).Unix())))
		_, err := v.Validate(ctx, hdr+"."+payload+".")
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("want ErrTokenInvalid (none), got %v", err)
		}
	})
	t.Run("garbage token", func(t *testing.T) {
		_, err := v.Validate(ctx, "eyInvalid.jwt.token")
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("want ErrTokenInvalid, got %v", err)
		}
	})
	t.Run("username with slash", func(t *testing.T) {
		spec := baseSpec(idp)
		spec.username = "alice/../bob"
		_, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, spec))
		if !errors.Is(err, ErrBadUsername) {
			t.Fatalf("want ErrBadUsername, got %v", err)
		}
	})
	t.Run("username with tenant dollar", func(t *testing.T) {
		spec := baseSpec(idp)
		spec.username = "tenant$alice"
		_, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, spec))
		if !errors.Is(err, ErrBadUsername) {
			t.Fatalf("want ErrBadUsername, got %v", err)
		}
	})
}

func TestUsernameFallsBackToSub(t *testing.T) {
	idp := newTestIdP(t)
	v := newValidator(t, idp, true)
	spec := baseSpec(idp)
	spec.username = "" // no preferred_username claim
	spec.sub = "service-account-42"
	id, err := v.Validate(context.Background(), idp.sign(t, idp.rsaKey, jwa.RS256, spec))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Username != "service-account-42" {
		t.Errorf("username = %q, want sub fallback", id.Username)
	}
}

func TestKeyRotationRefreshOnUnknownKid(t *testing.T) {
	idp := newTestIdP(t)
	v := newValidator(t, idp, true)
	ctx := context.Background()

	if _, err := v.Validate(ctx, idp.sign(t, idp.rsaKey, jwa.RS256, baseSpec(idp))); err != nil {
		t.Fatalf("initial validate: %v", err)
	}
	initialFetches := idp.fetchCount.Load()

	// Rotate: new key, new kid, old key dropped from the JWKS.
	rawRSA2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa2 := mustJWK(t, rawRSA2, "rsa2", jwa.RS256)
	idp.setServedKeys(t, rsa2)

	id, err := v.Validate(ctx, idp.sign(t, rsa2, jwa.RS256, baseSpec(idp)))
	if err != nil {
		t.Fatalf("validate after rotation: %v", err)
	}
	if id.Username != "alice" {
		t.Errorf("username = %q", id.Username)
	}
	if got := idp.fetchCount.Load(); got != initialFetches+1 {
		t.Errorf("fetch count = %d, want %d (exactly one forced refresh)", got, initialFetches+1)
	}

	// A second unknown kid within the cooldown must NOT trigger another fetch.
	rawRSA3, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa3 := mustJWK(t, rawRSA3, "rsa3", jwa.RS256)
	if _, err := v.Validate(ctx, idp.sign(t, rsa3, jwa.RS256, baseSpec(idp))); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid (unknown kid, cooldown), got %v", err)
	}
	if got := idp.fetchCount.Load(); got != initialFetches+1 {
		t.Errorf("fetch count = %d after cooldown-limited miss, want %d", got, initialFetches+1)
	}
}

func TestMissingKid(t *testing.T) {
	idp := newTestIdP(t)
	v := newValidator(t, idp, true)
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	noKid, err := jwk.FromRaw(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Validate(context.Background(), idp.sign(t, noKid, jwa.RS256, baseSpec(idp)))
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid (missing kid), got %v", err)
	}
}
