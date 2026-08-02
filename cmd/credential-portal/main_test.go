// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const stsSuccessXML = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>sub-alice</SubjectFromWebIdentityToken>
    <AssumedRoleUser><AssumedRoleId>OZPXROLEID:alice</AssumedRoleId><Arn>arn:ozone:iam::dev:role/oidc/alice</Arn></AssumedRoleUser>
    <Credentials>
      <AccessKeyId>OZPXTESTKEY234567890</AccessKeyId>
      <SecretAccessKey>secret-secret-secret-secret-secret-40ch</SecretAccessKey>
      <SessionToken>sessiontokensessiontokensessiontokensession</SessionToken>
      <Expiration>2026-07-06T13:00:00Z</Expiration>
    </Credentials>
    <Provider>keycloak</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`

const stsErrorXML = `<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>the token was rejected</Message></Error>
  <RequestId>req-2</RequestId>
</ErrorResponse>`

type stsStub struct {
	status   int
	body     string
	lastForm url.Values
}

func (s *stsStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.lastForm = r.PostForm
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(s.status)
		fmt.Fprint(w, s.body)
	})
}

func newPortal(t *testing.T, stub *stsStub) *httptest.Server {
	t.Helper()
	stsSrv := httptest.NewServer(stub.handler())
	t.Cleanup(stsSrv.Close)
	p := &portal{
		stsEndpoint:    stsSrv.URL,
		roleArn:        "arn:ozone:iam::dev:role/oidc",
		publicEndpoint: "http://localhost:9000",
		client:         &http.Client{Timeout: 5 * time.Second},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv := httptest.NewServer(p.handler())
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestPortalMintsAndRenders(t *testing.T) {
	stub := &stsStub{status: http.StatusOK, body: stsSuccessXML}
	srv := newPortal(t, stub)

	resp, body := get(t, srv.URL+"/", map[string]string{
		"X-Forwarded-Access-Token":       "jwt-from-oauth2-proxy",
		"X-Forwarded-Preferred-Username": "alice",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body %s", resp.StatusCode, body)
	}
	for _, want := range []string{
		"OZPXTESTKEY234567890",
		"secret-secret-secret-secret-secret-40ch",
		"sessiontokensessiontokensessiontokensession",
		"export AWS_ACCESS_KEY_ID=OZPXTESTKEY234567890",
		"AWS_ENDPOINT_URL_S3=http://localhost:9000",
		"2026-07-06T13:00:00Z",
		"alice",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if got := stub.lastForm.Get("WebIdentityToken"); got != "jwt-from-oauth2-proxy" {
		t.Errorf("WebIdentityToken forwarded = %q", got)
	}
	if got := stub.lastForm.Get("RoleSessionName"); got != "alice" {
		t.Errorf("RoleSessionName = %q", got)
	}
	if got := stub.lastForm.Get("RoleArn"); got != "arn:ozone:iam::dev:role/oidc" {
		t.Errorf("RoleArn = %q", got)
	}
}

func TestPortalRequiresToken(t *testing.T) {
	srv := newPortal(t, &stsStub{status: http.StatusOK, body: stsSuccessXML})
	resp, body := get(t, srv.URL+"/", nil)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "oauth2-proxy") {
		t.Fatalf("status = %d body %s", resp.StatusCode, body)
	}
}

func TestPortalShowsSTSRejection(t *testing.T) {
	srv := newPortal(t, &stsStub{status: http.StatusBadRequest, body: stsErrorXML})
	resp, body := get(t, srv.URL+"/", map[string]string{"Authorization": "Bearer stale-jwt"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "InvalidIdentityToken") || !strings.Contains(body, "the token was rejected") {
		t.Errorf("error page lacks STS code/message: %s", body)
	}
	if strings.Contains(body, "stale-jwt") {
		t.Error("token echoed back into the page")
	}
}

func TestSessionNameSanitation(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice", "alice"},
		{"alice@example.com", "alice@example.com"},
		{"a lice/b$ c.d", "alicebc.d"}, // spaces, '/' and '$' vanish, '.' survives
		{"@", "portal"},                // too short after cleaning
		{"", "portal"},
		{strings.Repeat("x", 100), strings.Repeat("x", 64)},
	}
	for _, tc := range cases {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Forwarded-Preferred-Username", tc.in)
		if got := sessionName(r); got != tc.want {
			t.Errorf("sessionName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHealthz(t *testing.T) {
	srv := newPortal(t, &stsStub{status: http.StatusOK, body: stsSuccessXML})
	resp, _ := get(t, srv.URL+"/healthz", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
}
