// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package sigv4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func TestParseAuthorization(t *testing.T) {
	h := "AWS4-HMAC-SHA256 Credential=OZPXABCDEFGH23456789/20260706/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	auth, err := ParseAuthorization(h)
	if err != nil {
		t.Fatalf("ParseAuthorization: %v", err)
	}
	if auth.AccessKeyID != "OZPXABCDEFGH23456789" || auth.Date != "20260706" ||
		auth.Region != "us-east-1" || auth.Service != "s3" {
		t.Errorf("scope parsed wrong: %+v", auth)
	}
	if len(auth.SignedHeaders) != 3 || auth.SignedHeaders[0] != "host" {
		t.Errorf("signed headers parsed wrong: %v", auth.SignedHeaders)
	}

	// Component order and spacing flexibility.
	reordered := "AWS4-HMAC-SHA256 Signature=" + auth.Signature +
		",SignedHeaders=host;x-amz-date,Credential=AKID/20260101/eu-west-1/s3/aws4_request"
	if _, err := ParseAuthorization(reordered); err != nil {
		t.Errorf("reordered header rejected: %v", err)
	}

	bad := []string{
		"AWS4-HMAC-SHA384 Credential=A/2/3/4/aws4_request, SignedHeaders=host, Signature=" + auth.Signature,
		"AWS4-HMAC-SHA256 Credential=AKID/date/region/aws4_request, SignedHeaders=host, Signature=" + auth.Signature,
		"AWS4-HMAC-SHA256 Credential=AKID/20260101/r/s/aws4_request, Signature=" + auth.Signature,
		"AWS4-HMAC-SHA256 Credential=AKID/20260101/r/s/aws4_request, SignedHeaders=host, Signature=abc",
		"AWS4-HMAC-SHA256 Credential=AKID/20260101/r/s/aws4_request, SignedHeaders=host, Signature=zz" + strings.Repeat("0", 62),
		"AWS4-HMAC-SHA256 Mystery=1, Credential=AKID/20260101/r/s/aws4_request, SignedHeaders=host, Signature=" + auth.Signature,
	}
	for _, h := range bad {
		if _, err := ParseAuthorization(h); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseAuthorization(%q) = %v, want ErrMalformed", h, err)
		}
	}

	if !IsSigV4("AWS4-HMAC-SHA256 Credential=...") || IsSigV4("Bearer abc") {
		t.Error("IsSigV4 misclassifies")
	}
}

// TestAWSTestSuiteGetVanilla pins the implementation to the official AWS SigV4
// test-suite "get-vanilla" vector (secret wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
// region us-east-1, service "service", date 20150830T123600Z).
func TestAWSTestSuiteGetVanilla(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.amazonaws.com/", nil)
	req.Header.Set("X-Amz-Date", "20150830T123600Z")

	const authHeader = "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	auth, err := ParseAuthorization(authHeader)
	if err != nil {
		t.Fatal(err)
	}
	err = Verify(Input{
		Request:   req,
		Auth:      auth,
		Secret:    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "service",
		Now:       time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC),
		ClockSkew: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Verify(get-vanilla) = %v, want nil", err)
	}
}

const (
	testAKID   = "OZPXTESTKEY234567890"
	testSecret = "test-secret-test-secret-test-secret-40ch"
	testToken  = "sessiontokensessiontokensessiontokensession"
)

var signTime = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

// sdkSign signs req with the real AWS SDK v2 signer in S3 mode (no path
// re-escaping) and returns the parsed Authorization.
func sdkSign(t *testing.T, req *http.Request, payloadHash string, withToken bool) *Authorization {
	t.Helper()
	if payloadHash != "" {
		req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	} else {
		payloadHash = emptyBodySHA256
	}
	creds := aws.Credentials{AccessKeyID: testAKID, SecretAccessKey: testSecret}
	if withToken {
		creds.SessionToken = testToken
	}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if err := signer.SignHTTP(context.Background(), creds, req, payloadHash, "s3", "us-east-1", signTime); err != nil {
		t.Fatalf("SignHTTP: %v", err)
	}
	auth, err := ParseAuthorization(req.Header.Get("Authorization"))
	if err != nil {
		t.Fatalf("parse SDK-produced Authorization: %v", err)
	}
	return auth
}

func verifyReq(req *http.Request, auth *Authorization) error {
	return Verify(Input{
		Request:   req,
		Auth:      auth,
		Secret:    testSecret,
		Region:    "us-east-1",
		Service:   "s3",
		Now:       signTime.Add(30 * time.Second),
		ClockSkew: 15 * time.Minute,
	})
}

func TestRoundTripWithAWSSDKSigner(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		url         string
		body        string
		payloadHash string
		withToken   bool
	}{
		{"get root", http.MethodGet, "http://proxy:9000/", "", "", false},
		{"list with query", http.MethodGet,
			"http://proxy:9000/bucket?list-type=2&prefix=data%2F2026%2F&max-keys=50&start-after=a%20b", "", "", false},
		{"path with spaces and unicode", http.MethodGet,
			"http://proxy:9000/bucket/dir%20one/caf%C3%A9%20menu.txt", "", "", true},
		{"put unsigned payload with token", http.MethodPut,
			"http://proxy:9000/bucket/key.txt", "hello world", "UNSIGNED-PAYLOAD", true},
		{"delete with tilde and plus", http.MethodDelete,
			"http://proxy:9000/bucket/a~b%2Bc.txt?versionId=abc.123~xyz", "", "", false},
		{"streaming seed signature", http.MethodPut,
			"http://proxy:9000/bucket/big.bin", "", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			} else {
				body = strings.NewReader("")
			}
			req, err := http.NewRequest(tc.method, tc.url, body)
			if err != nil {
				t.Fatal(err)
			}
			auth := sdkSign(t, req, tc.payloadHash, tc.withToken)
			if err := verifyReq(req, auth); err != nil {
				t.Fatalf("Verify = %v, want nil\nSignedHeaders: %v", err, auth.SignedHeaders)
			}
		})
	}
}

func TestVerifyTamperDetection(t *testing.T) {
	newSigned := func(t *testing.T) (*http.Request, *Authorization) {
		req, err := http.NewRequest(http.MethodPut,
			"http://proxy:9000/bucket/key.txt?partNumber=1", strings.NewReader("data"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Amz-Meta-Owner", "alice")
		auth := sdkSign(t, req, "UNSIGNED-PAYLOAD", true)
		return req, auth
	}

	tampers := map[string]func(*http.Request, *Authorization){
		"path":           func(r *http.Request, _ *Authorization) { r.URL.Path += "x"; r.URL.RawPath = "" },
		"query added":    func(r *http.Request, _ *Authorization) { r.URL.RawQuery += "&uploads=" },
		"query value":    func(r *http.Request, _ *Authorization) { r.URL.RawQuery = "partNumber=2" },
		"method":         func(r *http.Request, _ *Authorization) { r.Method = http.MethodDelete },
		"signed header":  func(r *http.Request, _ *Authorization) { r.Header.Set("X-Amz-Meta-Owner", "mallory") },
		"payload hash":   func(r *http.Request, _ *Authorization) { r.Header.Set("X-Amz-Content-Sha256", emptyBodySHA256) },
		"host":           func(r *http.Request, _ *Authorization) { r.Host = "evil:9000" },
		"signature byte": func(_ *http.Request, a *Authorization) { a.Signature = flipHex(a.Signature) },
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			req, auth := newSigned(t)
			tamper(req, auth)
			if err := verifyReq(req, auth); !errors.Is(err, ErrSignatureMismatch) {
				t.Fatalf("Verify after tamper = %v, want ErrSignatureMismatch", err)
			}
		})
	}

	t.Run("wrong secret", func(t *testing.T) {
		req, auth := newSigned(t)
		err := Verify(Input{
			Request: req, Auth: auth,
			Secret: "another-secret", Region: "us-east-1", Service: "s3",
			Now: signTime, ClockSkew: 15 * time.Minute,
		})
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("Verify = %v, want ErrSignatureMismatch", err)
		}
	})
}

func flipHex(s string) string {
	b := []byte(s)
	if b[0] == '0' {
		b[0] = '1'
	} else {
		b[0] = '0'
	}
	return string(b)
}

func TestVerifyTimeAndScopeChecks(t *testing.T) {
	sign := func(t *testing.T) (*http.Request, *Authorization) {
		req, err := http.NewRequest(http.MethodGet, "http://proxy:9000/bucket", nil)
		if err != nil {
			t.Fatal(err)
		}
		return req, sdkSign(t, req, "", false)
	}

	t.Run("skew exceeded", func(t *testing.T) {
		req, auth := sign(t)
		err := Verify(Input{
			Request: req, Auth: auth, Secret: testSecret,
			Region: "us-east-1", Service: "s3",
			Now: signTime.Add(16 * time.Minute), ClockSkew: 15 * time.Minute,
		})
		if !errors.Is(err, ErrSkew) {
			t.Fatalf("Verify = %v, want ErrSkew", err)
		}
	})
	t.Run("wrong region expectation", func(t *testing.T) {
		req, auth := sign(t)
		err := Verify(Input{
			Request: req, Auth: auth, Secret: testSecret,
			Region: "eu-west-1", Service: "s3",
			Now: signTime, ClockSkew: 15 * time.Minute,
		})
		if !errors.Is(err, ErrScope) {
			t.Fatalf("Verify = %v, want ErrScope", err)
		}
	})
	t.Run("scope date mismatch", func(t *testing.T) {
		req, auth := sign(t)
		auth.Date = "20260705" // yesterday, X-Amz-Date is today
		err := verifyReq(req, auth)
		if !errors.Is(err, ErrScope) {
			t.Fatalf("Verify = %v, want ErrScope", err)
		}
	})
	t.Run("missing date header", func(t *testing.T) {
		req, auth := sign(t)
		req.Header.Del("X-Amz-Date")
		if err := verifyReq(req, auth); !errors.Is(err, ErrMissingDate) {
			t.Fatalf("Verify = %v, want ErrMissingDate", err)
		}
	})
}

// TestServerSideRequestURI ensures verification works on server-form requests
// (RequestURI populated from the wire) with encoded paths.
func TestServerSideRequestURI(t *testing.T) {
	client, err := http.NewRequest(http.MethodGet, "http://proxy:9000/bucket/a%20b.txt?prefix=x%2Fy", nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := sdkSign(t, client, "", false)

	server := httptest.NewRequest(http.MethodGet, "http://proxy:9000/bucket/a%20b.txt?prefix=x%2Fy", nil)
	server.Header = client.Header.Clone()
	server.Host = client.URL.Host
	if err := verifyReq(server, auth); err != nil {
		t.Fatalf("Verify(server-form) = %v, want nil", err)
	}
}
