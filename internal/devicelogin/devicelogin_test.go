// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package devicelogin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stubIdP scripts the token endpoint: each poll pops the next response.
type stubIdP struct {
	t         *testing.T
	srv       *httptest.Server
	tokenSeq  []any // *oauthError or Token, consumed per token-endpoint call
	tokenCall int
	interval  int
	expiresIn int
}

func newStubIdP(t *testing.T, seq ...any) *stubIdP {
	s := &stubIdP{t: t, tokenSeq: seq, interval: 1, expiresIn: 600}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"device_authorization_endpoint": s.srv.URL + "/device",
			"token_endpoint":                s.srv.URL + "/token",
		})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		if got := r.FormValue("client_id"); got != "ozone-s3" {
			t.Errorf("device auth client_id = %q", got)
		}
		_ = json.NewEncoder(w).Encode(DeviceAuth{
			DeviceCode:              "dev-code-1",
			UserCode:                "ABCD-EFGH",
			VerificationURI:         s.srv.URL + "/verify",
			VerificationURIComplete: s.srv.URL + "/verify?user_code=ABCD-EFGH",
			ExpiresIn:               s.expiresIn,
			Interval:                s.interval,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if s.tokenCall >= len(s.tokenSeq) {
			t.Fatalf("token endpoint called %d times, scripted %d", s.tokenCall+1, len(s.tokenSeq))
		}
		next := s.tokenSeq[s.tokenCall]
		s.tokenCall++
		switch v := next.(type) {
		case *oauthError:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": v.Code, "error_description": v.Description})
		case Token:
			_ = json.NewEncoder(w).Encode(v)
		default:
			t.Fatalf("bad script entry %T", next)
		}
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func newClient(idp *stubIdP, sleeps *[]time.Duration) *Client {
	return &Client{
		Issuer:   idp.srv.URL,
		ClientID: "ozone-s3",
		Scope:    "openid",
		Sleep: func(d time.Duration) {
			if sleeps != nil {
				*sleeps = append(*sleeps, d)
			}
		},
	}
}

func TestDeviceFlowHappyPath(t *testing.T) {
	idp := newStubIdP(t,
		&oauthError{Code: "authorization_pending"},
		&oauthError{Code: "authorization_pending"},
		Token{AccessToken: "jwt-access", RefreshToken: "jwt-refresh", ExpiresIn: 3600},
	)
	idp.interval = 5
	var sleeps []time.Duration
	c := newClient(idp, &sleeps)
	ctx := context.Background()

	ep, err := c.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	da, err := c.Start(ctx, ep)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if da.UserCode != "ABCD-EFGH" || da.VerificationURIComplete == "" {
		t.Errorf("device auth = %+v", da)
	}
	tok, err := c.Poll(ctx, ep, da)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if tok.AccessToken != "jwt-access" || tok.RefreshToken != "jwt-refresh" || tok.ExpiresIn != 3600 {
		t.Errorf("token = %+v", tok)
	}
	if len(sleeps) != 3 || sleeps[0] != 5*time.Second {
		t.Errorf("sleeps = %v, want three 5s intervals", sleeps)
	}
}

func TestDeviceFlowSlowDown(t *testing.T) {
	idp := newStubIdP(t,
		&oauthError{Code: "slow_down"},
		&oauthError{Code: "authorization_pending"},
		Token{AccessToken: "jwt", ExpiresIn: 60},
	)
	idp.interval = 5
	var sleeps []time.Duration
	c := newClient(idp, &sleeps)

	ep, _ := c.Discover(context.Background())
	da, _ := c.Start(context.Background(), ep)
	if _, err := c.Poll(context.Background(), ep, da); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(sleeps) != 3 || sleeps[1] != 10*time.Second || sleeps[2] != 10*time.Second {
		t.Errorf("sleeps = %v, want interval bumped to 10s after slow_down", sleeps)
	}
}

func TestDeviceFlowTerminalErrors(t *testing.T) {
	cases := []struct {
		code string
		want error
	}{
		{"access_denied", ErrAccessDenied},
		{"expired_token", ErrExpired},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			idp := newStubIdP(t, &oauthError{Code: tc.code})
			c := newClient(idp, nil)
			ep, _ := c.Discover(context.Background())
			da, _ := c.Start(context.Background(), ep)
			if _, err := c.Poll(context.Background(), ep, da); !errors.Is(err, tc.want) {
				t.Fatalf("Poll = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDeviceFlowLocalDeadline(t *testing.T) {
	idp := newStubIdP(t, &oauthError{Code: "authorization_pending"})
	idp.expiresIn = 10
	c := newClient(idp, nil)
	base := time.Now()
	elapsed := time.Duration(0)
	// Each 1s sleep advances the fake clock 20s, so the 10s device-code
	// lifetime lapses after a single poll.
	c.Sleep = func(d time.Duration) { elapsed += d * 20 }
	c.Now = func() time.Time { return base.Add(elapsed) }

	ep, _ := c.Discover(context.Background())
	da, _ := c.Start(context.Background(), ep)
	if _, err := c.Poll(context.Background(), ep, da); !errors.Is(err, ErrExpired) {
		t.Fatalf("Poll = %v, want ErrExpired", err)
	}
}

func TestRefresh(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		idp := newStubIdP(t, Token{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresIn: 3600})
		c := newClient(idp, nil)
		ep, _ := c.Discover(context.Background())
		tok, err := c.Refresh(context.Background(), ep, "old-refresh")
		if err != nil || tok.AccessToken != "new-access" {
			t.Fatalf("Refresh = %+v, %v", tok, err)
		}
	})
	t.Run("invalid_grant means session expired", func(t *testing.T) {
		idp := newStubIdP(t, &oauthError{Code: "invalid_grant", Description: "Session not active"})
		c := newClient(idp, nil)
		ep, _ := c.Discover(context.Background())
		if _, err := c.Refresh(context.Background(), ep, "stale"); !errors.Is(err, ErrSessionExpired) {
			t.Fatalf("Refresh = %v, want ErrSessionExpired", err)
		}
	})
}

func TestDiscoverRejectsIssuerWithoutDeviceFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token_endpoint": "http://x/token"})
	}))
	t.Cleanup(srv.Close)
	c := &Client{Issuer: srv.URL, ClientID: "ozone-s3"}
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("Discover accepted an issuer without device_authorization_endpoint")
	}
}

func TestWriteTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "token.jwt")

	if err := WriteTokenFile(path, "first"); err != nil {
		t.Fatal(err)
	}
	if err := WriteTokenFile(path, "second"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "second" {
		t.Fatalf("content = %q, %v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
	dirInfo, _ := os.Stat(filepath.Dir(path))
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", dirInfo.Mode().Perm())
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".token-*"))
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}
