// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package sts

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/config"
	"github.com/aimd54/ozone-oidc-proxy/internal/oidc"
	"github.com/aimd54/ozone-oidc-proxy/internal/store"
)

type stubValidator struct {
	id  *oidc.Identity
	err error
}

func (s stubValidator) Validate(context.Context, string) (*oidc.Identity, error) {
	return s.id, s.err
}

type xmlResponse struct {
	XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
	Result  struct {
		Subject         string `xml:"SubjectFromWebIdentityToken"`
		AssumedRoleUser struct {
			Arn string `xml:"Arn"`
		} `xml:"AssumedRoleUser"`
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		Provider string `xml:"Provider"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
	Meta struct {
		RequestID string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
}

type xmlError struct {
	XMLName xml.Name `xml:"ErrorResponse"`
	Error   struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
	RequestID string `xml:"RequestId"`
}

var testNow = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

func newHandler(v TokenValidator, sts config.STS) (*Handler, *store.Memory) {
	mem := store.NewMemory()
	return &Handler{
		Validator: v,
		Store:     mem,
		STS:       sts,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       func() time.Time { return testNow },
	}, mem
}

func identity(expiry time.Time) *oidc.Identity {
	return &oidc.Identity{
		Username:   "alice",
		Subject:    "sub-1",
		IssuerName: "keycloak",
		IssuerURL:  "http://kc/realms/ozone",
		Expiry:     expiry,
	}
}

func post(h http.Handler, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func baseForm() url.Values {
	return url.Values{
		"Action":          {Action},
		"Version":         {"2011-06-15"},
		"RoleArn":         {"arn:ozone:iam::dev:role/oidc"},
		"RoleSessionName": {"alice-dev"},
		"WebIdentityToken": {
			"header.payload.sig",
		},
	}
}

func decodeSuccess(t *testing.T, rec *httptest.ResponseRecorder) xmlResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	var resp xmlResponse
	if err := xml.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, rec.Body.String())
	}
	return resp
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) xmlError {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, wantStatus, rec.Body.String())
	}
	var resp xmlError
	if err := xml.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error response: %v\n%s", err, rec.Body.String())
	}
	if resp.Error.Code != wantCode {
		t.Fatalf("error code = %q, want %q (message %q)", resp.Error.Code, wantCode, resp.Error.Message)
	}
	return resp
}

func TestExchangeHappyPath(t *testing.T) {
	h, mem := newHandler(
		stubValidator{id: identity(testNow.Add(2 * time.Hour))},
		config.STS{MaxDuration: 3600, RoleARNAllowlist: []string{"arn:ozone:iam::dev:role/oidc"}},
	)
	defer func() { _ = mem.Close() }()

	resp := decodeSuccess(t, post(h, baseForm()))
	creds := resp.Result.Credentials
	if !strings.HasPrefix(creds.AccessKeyID, "OZPX") {
		t.Errorf("AccessKeyId %q missing OZPX prefix", creds.AccessKeyID)
	}
	if creds.SecretAccessKey == "" || creds.SessionToken == "" {
		t.Error("credentials incomplete")
	}
	if resp.Result.Subject != "sub-1" || resp.Result.Provider != "http://kc/realms/ozone" {
		t.Errorf("subject/provider wrong: %+v", resp.Result)
	}
	if !strings.HasSuffix(resp.Result.AssumedRoleUser.Arn, "/alice-dev") {
		t.Errorf("AssumedRoleUser.Arn %q does not echo session name", resp.Result.AssumedRoleUser.Arn)
	}

	// TTL capped by sts.max_duration (3600s), not the 2h token expiry.
	wantExp := testNow.Add(time.Hour)
	if creds.Expiration != wantExp.Format(time.RFC3339) {
		t.Errorf("Expiration = %s, want %s", creds.Expiration, wantExp.Format(time.RFC3339))
	}

	stored, ok, _ := mem.Get(context.Background(), creds.AccessKeyID)
	if !ok {
		t.Fatal("minted credentials not in store")
	}
	if stored.Username != "alice" || stored.SecretAccessKey != creds.SecretAccessKey ||
		stored.SessionToken != creds.SessionToken || !stored.ExpiresAt.Equal(wantExp) {
		t.Errorf("stored record mismatch: %+v", stored)
	}
}

func TestExchangeTTLBounds(t *testing.T) {
	cases := []struct {
		name        string
		tokenExpiry time.Time
		duration    string
		want        time.Time
	}{
		{"jwt expiry wins", testNow.Add(10 * time.Minute), "", testNow.Add(10 * time.Minute)},
		{"DurationSeconds wins", testNow.Add(2 * time.Hour), "600", testNow.Add(10 * time.Minute)},
		{"max_duration wins", testNow.Add(5 * time.Hour), "7200", testNow.Add(time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, mem := newHandler(stubValidator{id: identity(tc.tokenExpiry)}, config.STS{MaxDuration: 3600})
			defer func() { _ = mem.Close() }()
			form := baseForm()
			if tc.duration != "" {
				form.Set("DurationSeconds", tc.duration)
			}
			resp := decodeSuccess(t, post(h, form))
			if got := resp.Result.Credentials.Expiration; got != tc.want.Format(time.RFC3339) {
				t.Errorf("Expiration = %s, want %s", got, tc.want.Format(time.RFC3339))
			}
		})
	}
}

func TestExchangeValidationErrors(t *testing.T) {
	h, mem := newHandler(stubValidator{id: identity(testNow.Add(time.Hour))}, config.STS{MaxDuration: 3600})
	defer func() { _ = mem.Close() }()

	t.Run("missing token", func(t *testing.T) {
		form := baseForm()
		form.Del("WebIdentityToken")
		decodeError(t, post(h, form), http.StatusBadRequest, "ValidationError")
	})
	t.Run("missing RoleArn", func(t *testing.T) {
		form := baseForm()
		form.Del("RoleArn")
		decodeError(t, post(h, form), http.StatusBadRequest, "ValidationError")
	})
	t.Run("bad DurationSeconds", func(t *testing.T) {
		form := baseForm()
		form.Set("DurationSeconds", "-5")
		decodeError(t, post(h, form), http.StatusBadRequest, "ValidationError")
	})
	t.Run("bad RoleSessionName", func(t *testing.T) {
		form := baseForm()
		form.Set("RoleSessionName", "a b c!")
		decodeError(t, post(h, form), http.StatusBadRequest, "ValidationError")
	})
	t.Run("wrong Action", func(t *testing.T) {
		form := baseForm()
		form.Set("Action", "AssumeRole")
		decodeError(t, post(h, form), http.StatusBadRequest, "ValidationError")
	})
	t.Run("GET rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?"+baseForm().Encode(), nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
	})
}

func TestExchangeRoleArnAllowlist(t *testing.T) {
	h, mem := newHandler(
		stubValidator{id: identity(testNow.Add(time.Hour))},
		config.STS{MaxDuration: 3600, RoleARNAllowlist: []string{"arn:ozone:iam::dev:role/other"}},
	)
	defer func() { _ = mem.Close() }()
	decodeError(t, post(h, baseForm()), http.StatusForbidden, "AccessDenied")

	// Empty allowlist accepts any RoleArn.
	h2, mem2 := newHandler(stubValidator{id: identity(testNow.Add(time.Hour))}, config.STS{MaxDuration: 3600})
	defer func() { _ = mem2.Close() }()
	decodeSuccess(t, post(h2, baseForm()))
}

func TestExchangeTokenErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"expired", fmt.Errorf("wrap: %w", oidc.ErrTokenExpired), http.StatusBadRequest, "ExpiredTokenException"},
		{"invalid", fmt.Errorf("wrap: %w", oidc.ErrTokenInvalid), http.StatusBadRequest, "InvalidIdentityToken"},
		{"unknown issuer", fmt.Errorf("wrap: %w", oidc.ErrUnknownIssuer), http.StatusBadRequest, "InvalidIdentityToken"},
		{"bad username", fmt.Errorf("wrap: %w", oidc.ErrBadUsername), http.StatusBadRequest, "InvalidIdentityToken"},
		{"idp down", fmt.Errorf("wrap: %w", oidc.ErrIssuerUnavailable), http.StatusBadRequest, "IDPCommunicationError"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, mem := newHandler(stubValidator{err: tc.err}, config.STS{MaxDuration: 3600})
			defer func() { _ = mem.Close() }()
			decodeError(t, post(h, baseForm()), tc.wantStatus, tc.wantCode)
		})
	}
}

func TestExchangeExpiredAtExchangeTime(t *testing.T) {
	// Token technically valid at validation (skew) but exp−now <= 0.
	h, mem := newHandler(stubValidator{id: identity(testNow.Add(-time.Second))}, config.STS{MaxDuration: 3600})
	defer func() { _ = mem.Close() }()
	decodeError(t, post(h, baseForm()), http.StatusBadRequest, "ExpiredTokenException")
}
