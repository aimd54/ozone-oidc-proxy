// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/aimd54/ozone-oidc-proxy/internal/config"
	"github.com/aimd54/ozone-oidc-proxy/internal/forward"
	"github.com/aimd54/ozone-oidc-proxy/internal/oidc"
	"github.com/aimd54/ozone-oidc-proxy/internal/sigv4"
	"github.com/aimd54/ozone-oidc-proxy/internal/store"
)

var serverNow = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

type upstreamRecorder struct {
	mu   sync.Mutex
	last *http.Request
	body string
}

func (u *upstreamRecorder) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		clone := r.Clone(context.Background())
		u.last = clone
		u.body = string(body)
		u.mu.Unlock()
		w.Header().Set("X-Upstream", "ozone")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "upstream-ok")
	})
}

func (u *upstreamRecorder) lastRequest(t *testing.T) *http.Request {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.last == nil {
		t.Fatal("upstream never received a request")
	}
	return u.last
}

type stubValidator struct {
	fn func(string) (*oidc.Identity, error)
}

func (s stubValidator) Validate(_ context.Context, raw string) (*oidc.Identity, error) {
	return s.fn(raw)
}

func aliceIdentity() *oidc.Identity {
	return &oidc.Identity{
		Username:   "alice",
		Subject:    "sub-alice",
		IssuerName: "keycloak",
		IssuerURL:  "http://kc/realms/ozone",
		Expiry:     serverNow.Add(2 * time.Hour),
	}
}

type testEnv struct {
	proxy    *httptest.Server
	admin    *httptest.Server
	upstream *upstreamRecorder
	store    *store.Memory
}

func newEnv(t *testing.T, cfgYAML string, validate func(string) (*oidc.Identity, error)) *testEnv {
	t.Helper()
	up := &upstreamRecorder{}
	upstreamSrv := httptest.NewServer(up.handler())
	t.Cleanup(upstreamSrv.Close)

	cfg, err := config.Parse([]byte(fmt.Sprintf(cfgYAML, upstreamSrv.URL)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	mem := store.NewMemory()
	t.Cleanup(func() { _ = mem.Close() })

	srv, err := New(cfg, stubValidator{fn: validate}, mem,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		WithClock(func() time.Time { return serverNow }))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	proxySrv := httptest.NewServer(srv.Handler())
	t.Cleanup(proxySrv.Close)
	adminSrv := httptest.NewServer(srv.AdminHandler())
	t.Cleanup(adminSrv.Close)
	return &testEnv{proxy: proxySrv, admin: adminSrv, upstream: up, store: mem}
}

const strictCfg = `
upstream: {s3_endpoint: %s}
issuers: [{name: keycloak, issuer: http://kc/realms/ozone, audiences: [ozone-s3]}]
sts: {max_duration: 3600}
`

func defaultValidate(raw string) (*oidc.Identity, error) {
	switch raw {
	case "good-token":
		return aliceIdentity(), nil
	case "expired-token":
		return nil, fmt.Errorf("wrap: %w", oidc.ErrTokenExpired)
	default:
		return nil, fmt.Errorf("wrap: %w", oidc.ErrTokenInvalid)
	}
}

func mustDo(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func bodyOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSTSDispatch(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)

	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"RoleArn":          {"arn:ozone:iam::dev:role/oidc"},
		"RoleSessionName":  {"alice-dev"},
		"WebIdentityToken": {"good-token"},
	}
	req, _ := http.NewRequest(http.MethodPost, env.proxy.URL+"/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	resp := mustDo(t, req)
	body := bodyOf(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("STS status = %d, body: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "<AccessKeyId>OZPX") || !strings.Contains(body, "SessionToken") {
		t.Errorf("STS response lacks credentials: %s", body)
	}

	// Wrong action on the STS route → AWS-shaped ValidationError.
	form.Set("Action", "AssumeRole")
	req2, _ := http.NewRequest(http.MethodPost, env.proxy.URL+"/", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp2 := mustDo(t, req2)
	if body := bodyOf(t, resp2); resp2.StatusCode != http.StatusBadRequest || !strings.Contains(body, "ValidationError") {
		t.Errorf("wrong action: status %d body %s", resp2.StatusCode, body)
	}
}

func TestBearerLane(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)

	req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket/key.txt", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	req.Header.Set("X-Amz-Security-Token", "should-be-stripped")
	resp := mustDo(t, req)
	if resp.StatusCode != http.StatusOK || bodyOf(t, resp) != "upstream-ok" {
		t.Fatalf("bearer request not proxied: %d", resp.StatusCode)
	}

	fwd := env.upstream.lastRequest(t)
	auth := fwd.Header.Get("Authorization")
	wantCred := "Credential=alice/20260706/us-east-1/s3/aws4_request"
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") || !strings.Contains(auth, wantCred) {
		t.Errorf("synthetic Authorization wrong: %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-date") || !strings.Contains(auth, "Signature=0000") {
		t.Errorf("synthetic Authorization wrong: %q", auth)
	}
	if got := fwd.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
		t.Errorf("X-Amz-Content-Sha256 = %q", got)
	}
	if fwd.Header.Get("X-Amz-Security-Token") != "" {
		t.Error("X-Amz-Security-Token not stripped")
	}
	if got := fwd.Header.Get("X-Amz-Date"); got != serverNow.Format("20060102T150405Z") {
		t.Errorf("X-Amz-Date = %q", got)
	}
}

func TestBearerRejections(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)
	cases := []struct {
		token      string
		wantStatus int
		wantCode   string
	}{
		{"expired-token", http.StatusForbidden, "ExpiredToken"},
		{"garbage", http.StatusForbidden, "AccessDenied"},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		resp := mustDo(t, req)
		body := bodyOf(t, resp)
		if resp.StatusCode != tc.wantStatus || !strings.Contains(body, tc.wantCode) {
			t.Errorf("token %q: status %d body %s (want %d %s)",
				tc.token, resp.StatusCode, body, tc.wantStatus, tc.wantCode)
		}
	}
}

func TestBearerLaneDisabled(t *testing.T) {
	cfg := `
upstream: {s3_endpoint: %s}
data_path: {accept_bearer: false}
issuers: [{name: keycloak, issuer: http://kc/realms/ozone, audiences: [ozone-s3]}]
`
	env := newEnv(t, cfg, defaultValidate)
	req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	resp := mustDo(t, req)
	if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "AccessDenied") {
		t.Errorf("disabled bearer lane: status %d body %s", resp.StatusCode, body)
	}
}

// mintTestCreds puts a known credential set into the store.
func mintTestCreds(t *testing.T, env *testEnv, username string, expiresAt time.Time) store.Credentials {
	t.Helper()
	creds, err := store.Mint(username, "keycloak", expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.Put(context.Background(), creds); err != nil {
		t.Fatal(err)
	}
	return creds
}

// signedRequest builds a SigV4-signed request against the proxy.
func signedRequest(t *testing.T, env *testEnv, creds store.Credentials, method, path, body string) *http.Request {
	t.Helper()
	var rdr io.Reader = strings.NewReader(body)
	req, err := http.NewRequest(method, env.proxy.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	const payloadHash = "UNSIGNED-PAYLOAD"
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	err = signer.SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}, req, payloadHash, "s3", "us-east-1", serverNow)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestSigV4LaneHappyPath(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)
	creds := mintTestCreds(t, env, "alice", serverNow.Add(time.Hour))

	req := signedRequest(t, env, creds, http.MethodPut, "/bucket/data%20file.txt?tagging=", "hello world")
	resp := mustDo(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body %s", resp.StatusCode, bodyOf(t, resp))
	}

	fwd := env.upstream.lastRequest(t)
	auth := fwd.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=alice/20260706/us-east-1/s3/aws4_request") {
		t.Errorf("AKID not rewritten to username: %q", auth)
	}
	if strings.Contains(auth, creds.AccessKeyID) {
		t.Errorf("minted AKID leaked upstream: %q", auth)
	}
	if strings.Contains(auth, "x-amz-security-token") || fwd.Header.Get("X-Amz-Security-Token") != "" {
		t.Errorf("security token leaked upstream: %q", auth)
	}
	if got := fwd.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
		t.Errorf("payload hash not preserved: %q", got)
	}
	env.upstream.mu.Lock()
	gotBody := env.upstream.body
	env.upstream.mu.Unlock()
	if gotBody != "hello world" {
		t.Errorf("body not streamed: %q", gotBody)
	}
	if fwd.URL.Path != "/bucket/data file.txt" && fwd.RequestURI != "/bucket/data%20file.txt?tagging=" {
		t.Errorf("path not preserved: %q / %q", fwd.URL.Path, fwd.RequestURI)
	}
}

func TestSigV4LaneRejections(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)
	valid := mintTestCreds(t, env, "alice", serverNow.Add(time.Hour))
	expired := mintTestCreds(t, env, "bob", serverNow.Add(-time.Minute))

	t.Run("unknown AKID", func(t *testing.T) {
		ghost := valid
		ghost.AccessKeyID = "OZPX0000000000000000"
		req := signedRequest(t, env, ghost, http.MethodGet, "/bucket", "")
		resp := mustDo(t, req)
		if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "InvalidAccessKeyId") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("expired credentials", func(t *testing.T) {
		req := signedRequest(t, env, expired, http.MethodGet, "/bucket", "")
		resp := mustDo(t, req)
		if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "ExpiredToken") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("wrong session token", func(t *testing.T) {
		bad := valid
		bad.SessionToken = strings.Repeat("x", 43)
		req := signedRequest(t, env, bad, http.MethodGet, "/bucket", "")
		resp := mustDo(t, req)
		if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "InvalidToken") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("tampered path", func(t *testing.T) {
		req := signedRequest(t, env, valid, http.MethodGet, "/bucket/a.txt", "")
		tampered, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket/b.txt", nil)
		tampered.Header = req.Header.Clone()
		resp := mustDo(t, tampered)
		if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "SignatureDoesNotMatch") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("clock skew", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
		old := serverNow.Add(-time.Hour)
		if err := signer.SignHTTP(context.Background(), aws.Credentials{
			AccessKeyID: valid.AccessKeyID, SecretAccessKey: valid.SecretAccessKey, SessionToken: valid.SessionToken,
		}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", old); err != nil {
			t.Fatal(err)
		}
		resp := mustDo(t, req)
		if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "RequestTimeTooSkewed") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("malformed authorization", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket", nil)
		req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=broken")
		resp := mustDo(t, req)
		if body := bodyOf(t, resp); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "AuthorizationHeaderMalformed") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
}

// presignedURL mints a presigned URL for creds against the test proxy with
// the real SDK signer (X-Amz-Expires signed in, like the SDK's S3 presigner).
func presignedURL(t *testing.T, env *testEnv, creds store.Credentials, method, pathAndQuery string, expires int, at time.Time) string {
	t.Helper()
	seed, err := http.NewRequest(method, env.proxy.URL+pathAndQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := seed.URL.Query()
	q.Set("X-Amz-Expires", fmt.Sprintf("%d", expires))
	seed.URL.RawQuery = q.Encode()
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	signed, _, err := signer.PresignHTTP(context.Background(), aws.Credentials{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}, seed, "UNSIGNED-PAYLOAD", "s3", "us-east-1", at)
	if err != nil {
		t.Fatalf("PresignHTTP: %v", err)
	}
	return signed
}

func TestPresignedLaneHappyPath(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)
	creds := mintTestCreds(t, env, "alice", serverNow.Add(time.Hour))

	u := presignedURL(t, env, creds, http.MethodGet,
		"/bucket/report%20q3.csv?response-content-type=text%2Fcsv", 300, serverNow)
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body %s", resp.StatusCode, bodyOf(t, resp))
	}

	fwd := env.upstream.lastRequest(t)
	auth := fwd.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=alice/20260706/us-east-1/s3/aws4_request") ||
		!strings.Contains(auth, "SignedHeaders=host;x-amz-date") {
		t.Errorf("synthetic Authorization wrong: %q", auth)
	}
	if strings.Contains(fwd.URL.RawQuery, "X-Amz-") {
		t.Errorf("auth query params leaked upstream: %q", fwd.URL.RawQuery)
	}
	if strings.Contains(fwd.URL.RawQuery, creds.AccessKeyID) || strings.Contains(fwd.URL.RawQuery, creds.SessionToken) {
		t.Errorf("credentials leaked upstream: %q", fwd.URL.RawQuery)
	}
	if !strings.Contains(fwd.URL.RawQuery, "response-content-type=text%2Fcsv") {
		t.Errorf("non-auth query params not preserved: %q", fwd.URL.RawQuery)
	}
	if got := fwd.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
		t.Errorf("X-Amz-Content-Sha256 = %q", got)
	}
	if fwd.Header.Get("X-Amz-Security-Token") != "" {
		t.Error("X-Amz-Security-Token header present upstream")
	}
}

func TestPresignedLaneRejections(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)
	valid := mintTestCreds(t, env, "alice", serverNow.Add(time.Hour))
	expiredCreds := mintTestCreds(t, env, "bob", serverNow.Add(-time.Minute))

	get := func(t *testing.T, u string) (*http.Response, string) {
		t.Helper()
		resp, err := http.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp, bodyOf(t, resp)
	}

	t.Run("expired URL", func(t *testing.T) {
		u := presignedURL(t, env, valid, http.MethodGet, "/bucket/hello.txt", 60,
			serverNow.Add(-10*time.Minute))
		resp, body := get(t, u)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "AccessDenied") ||
			!strings.Contains(body, "Request has expired") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("tampered query", func(t *testing.T) {
		u := presignedURL(t, env, valid, http.MethodGet, "/bucket/hello.txt", 300, serverNow)
		resp, body := get(t, u+"&admin=true")
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "SignatureDoesNotMatch") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("unknown AKID", func(t *testing.T) {
		ghost := valid
		ghost.AccessKeyID = "OZPX0000000000000000"
		u := presignedURL(t, env, ghost, http.MethodGet, "/bucket/hello.txt", 300, serverNow)
		resp, body := get(t, u)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "InvalidAccessKeyId") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("expired credentials", func(t *testing.T) {
		u := presignedURL(t, env, expiredCreds, http.MethodGet, "/bucket/hello.txt", 300, serverNow)
		resp, body := get(t, u)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "ExpiredToken") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("missing session token", func(t *testing.T) {
		tokenless := valid
		tokenless.SessionToken = ""
		u := presignedURL(t, env, tokenless, http.MethodGet, "/bucket/hello.txt", 300, serverNow)
		resp, body := get(t, u)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "InvalidToken") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("malformed query auth", func(t *testing.T) {
		resp, body := get(t, env.proxy.URL+"/bucket/hello.txt?X-Amz-Algorithm=AWS4-HMAC-SHA1")
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "AuthorizationQueryParametersError") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
	t.Run("foreign Authorization header wins over query auth", func(t *testing.T) {
		u := presignedURL(t, env, valid, http.MethodGet, "/bucket/hello.txt", 300, serverNow)
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		req.SetBasicAuth("alice", "pw")
		resp := mustDo(t, req)
		if body := bodyOf(t, resp); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "AccessDenied") {
			t.Errorf("status %d body %s", resp.StatusCode, body)
		}
	})
}

func TestStrictModeBlocksEverythingElse(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)
	cases := map[string]func(*http.Request){
		"no auth":         func(r *http.Request) {},
		"sigv2 style":     func(r *http.Request) { r.Header.Set("Authorization", "AWS alice:signature") },
		"basic auth":      func(r *http.Request) { r.SetBasicAuth("alice", "pw") },
		"plain akid only": func(r *http.Request) { r.Header.Set("Authorization", "alice") },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket", nil)
			mod(req)
			resp := mustDo(t, req)
			body := bodyOf(t, resp)
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "AccessDenied") {
				t.Errorf("status %d body %s, want 403 AccessDenied", resp.StatusCode, body)
			}
		})
	}
	if env.upstream.last != nil {
		t.Error("strict mode leaked a request upstream")
	}
}

func TestNonStrictForwardsUntouched(t *testing.T) {
	cfg := `
upstream: {s3_endpoint: %s}
data_path: {strict: false}
issuers: [{name: keycloak, issuer: http://kc/realms/ozone, audiences: [ozone-s3]}]
`
	env := newEnv(t, cfg, defaultValidate)
	req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket", nil)
	resp := mustDo(t, req)
	if resp.StatusCode != http.StatusOK || bodyOf(t, resp) != "upstream-ok" {
		t.Fatalf("non-strict passthrough failed: %d", resp.StatusCode)
	}
}

func TestAdminEndpoints(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(env.admin.URL + path)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %v %d", path, err, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}

	// Generate one bearer auth, then check metrics exposition.
	req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bucket", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	mustDo(t, req)

	resp, err := http.Get(env.admin.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	metricsBody, _ := io.ReadAll(resp.Body)
	for _, want := range []string{"active_credentials", "bearer_auth_total", "upstream_requests_total"} {
		if !strings.Contains(string(metricsBody), want) {
			t.Errorf("metrics exposition missing %s", want)
		}
	}
}

const resignCfg = `
upstream: {s3_endpoint: %s, forward_mode: resign}
issuers: [{name: keycloak, issuer: http://kc/realms/ozone, audiences: [ozone-s3]}]
sts: {max_duration: 3600}
`

// verifyResigned asserts the forwarded request carries a fully valid SigV4
// header signed with the resign secret and attributed to username (§6.4).
func verifyResigned(t *testing.T, fwd *http.Request, username string) {
	t.Helper()
	auth, err := sigv4.ParseAuthorization(fwd.Header.Get("Authorization"))
	if err != nil {
		t.Fatalf("forwarded Authorization unparseable: %v", err)
	}
	if auth.AccessKeyID != username {
		t.Errorf("forwarded Credential AKID = %q, want %q", auth.AccessKeyID, username)
	}
	err = sigv4.Verify(sigv4.Input{
		Request:   fwd,
		Auth:      auth,
		Secret:    forward.ResignSecret,
		Region:    "us-east-1",
		Service:   "s3",
		Now:       serverNow,
		ClockSkew: time.Minute,
	})
	if err != nil {
		t.Errorf("forwarded signature does not verify with the resign secret: %v", err)
	}
	if fwd.Header.Get("X-Amz-Security-Token") != "" {
		t.Error("session token leaked upstream")
	}
}

func TestResignMode(t *testing.T) {
	env := newEnv(t, resignCfg, defaultValidate)
	creds := mintTestCreds(t, env, "alice", serverNow.Add(time.Hour))

	t.Run("bearer lane", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, env.proxy.URL+"/bkt/obj.txt", nil)
		req.Header.Set("Authorization", "Bearer good-token")
		resp := mustDo(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		verifyResigned(t, env.upstream.lastRequest(t), "alice")
	})

	t.Run("sigv4 lane", func(t *testing.T) {
		resp := mustDo(t, signedRequest(t, env, creds, http.MethodPut, "/bkt/obj.txt", "hello"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		fwd := env.upstream.lastRequest(t)
		verifyResigned(t, fwd, "alice")
		if got := fwd.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
			t.Errorf("client payload hash rewritten to %q", got)
		}
		if strings.Contains(fwd.Header.Get("Authorization"), creds.AccessKeyID) {
			t.Error("minted AKID leaked upstream")
		}
	})

	t.Run("presigned lane", func(t *testing.T) {
		u := presignedURL(t, env, creds, http.MethodGet,
			"/bkt/obj.txt?response-content-type=text%2Fplain", 300, serverNow)
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		resp := mustDo(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		fwd := env.upstream.lastRequest(t)
		verifyResigned(t, fwd, "alice")
		if q := fwd.URL.RawQuery; strings.Contains(q, "X-Amz-Signature") ||
			!strings.Contains(q, "response-content-type") {
			t.Errorf("forwarded query wrong: %q", q)
		}
	})
}

func TestRevocationEndpoint(t *testing.T) {
	env := newEnv(t, strictCfg, defaultValidate)
	creds := mintTestCreds(t, env, "alice", serverNow.Add(time.Hour))

	// Working credentials first, to prove revocation is what breaks them.
	resp := mustDo(t, signedRequest(t, env, creds, http.MethodGet, "/bkt/o", ""))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revocation request = %d, want 200", resp.StatusCode)
	}

	del, _ := http.NewRequest(http.MethodDelete, env.admin.URL+"/credentials/"+creds.AccessKeyID, nil)
	if resp := mustDo(t, del); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /credentials = %d, want 204", resp.StatusCode)
	}

	resp = mustDo(t, signedRequest(t, env, creds, http.MethodGet, "/bkt/o", ""))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(bodyOf(t, resp), "InvalidAccessKeyId") {
		t.Errorf("post-revocation request = %d, want 403 InvalidAccessKeyId", resp.StatusCode)
	}

	del2, _ := http.NewRequest(http.MethodDelete, env.admin.URL+"/credentials/"+creds.AccessKeyID, nil)
	if resp := mustDo(t, del2); resp.StatusCode != http.StatusNotFound {
		t.Errorf("second DELETE = %d, want 404", resp.StatusCode)
	}

	metricsResp := mustDo(t, mustReq(t, http.MethodGet, env.admin.URL+"/metrics"))
	if body := bodyOf(t, metricsResp); !strings.Contains(body, `revocations_total{result="revoked"} 1`) {
		t.Error("revocations_total{result=\"revoked\"} not exposed")
	}
}

func mustReq(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
