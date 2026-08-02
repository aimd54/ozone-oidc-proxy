// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package sigv4

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signVerify runs Sign and then verifies its own output like the upstream
// side of resign mode would.
func signVerify(t *testing.T, req *http.Request) {
	t.Helper()
	err := Sign(SignInput{
		Request:     req,
		AccessKeyID: "alice",
		Secret:      "resign-secret",
		Region:      "us-east-1",
		Service:     "s3",
		Now:         signTime,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	auth, err := ParseAuthorization(req.Header.Get("Authorization"))
	if err != nil {
		t.Fatalf("parse signed Authorization: %v", err)
	}
	if auth.AccessKeyID != "alice" {
		t.Errorf("Credential AKID = %q, want alice", auth.AccessKeyID)
	}
	err = Verify(Input{
		Request:   req,
		Auth:      auth,
		Secret:    "resign-secret",
		Region:    "us-east-1",
		Service:   "s3",
		Now:       signTime,
		ClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatalf("Verify(Sign(...)) = %v, want nil", err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	t.Run("vanilla get", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://s3g:9878/bucket/key.txt", nil)
		signVerify(t, req)
		if got := req.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
			t.Errorf("payload hash defaulted to %q, want UNSIGNED-PAYLOAD", got)
		}
	})

	t.Run("unsorted repeated query", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"http://s3g:9878/bucket?prefix=b%20c&delimiter=%2F&prefix=a", nil)
		signVerify(t, req)
	})

	t.Run("streaming payload hash preserved", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "http://s3g:9878/bucket/big.bin", nil)
		req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		signVerify(t, req)
		if got := req.Header.Get("X-Amz-Content-Sha256"); got != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
			t.Errorf("payload hash rewritten to %q, want STREAMING-* preserved", got)
		}
	})

	t.Run("all x-amz headers signed", func(t *testing.T) {
		// SigV4 requires every x-amz-* header to be signed; Ozone rejects
		// aws-chunked uploads whose x-amz-decoded-content-length is unsigned.
		req := httptest.NewRequest(http.MethodPut, "http://s3g:9878/bucket/big.bin", nil)
		req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		req.Header.Set("X-Amz-Decoded-Content-Length", "8388608")
		req.Header.Set("X-Amz-Meta-Origin", "e2e")
		req.Header.Set("Content-Encoding", "aws-chunked")
		signVerify(t, req)
		auth, _ := ParseAuthorization(req.Header.Get("Authorization"))
		want := "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-meta-origin"
		if got := strings.Join(auth.SignedHeaders, ";"); got != want {
			t.Errorf("SignedHeaders = %s, want %s", got, want)
		}
	})

	t.Run("host override", func(t *testing.T) {
		// The client-facing Host differs from the upstream the signature must
		// cover (reverse-proxy rewrite): Sign must adopt the override.
		req := httptest.NewRequest(http.MethodGet, "http://localhost:9000/bucket/key", nil)
		err := Sign(SignInput{
			Request:     req,
			AccessKeyID: "alice",
			Secret:      "resign-secret",
			Region:      "us-east-1",
			Service:     "s3",
			Host:        "s3g:9878",
			Now:         signTime,
		})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if req.Host != "s3g:9878" {
			t.Fatalf("req.Host = %q, want s3g:9878", req.Host)
		}
		auth, err := ParseAuthorization(req.Header.Get("Authorization"))
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(Input{
			Request: req, Auth: auth, Secret: "resign-secret",
			Region: "us-east-1", Service: "s3", Now: signTime, ClockSkew: time.Minute,
		}); err != nil {
			t.Fatalf("Verify with overridden host = %v, want nil", err)
		}
	})
}

// TestSignMatchesSDK pins Sign to the real AWS SDK v2 signer: same request,
// same credentials and time must produce the identical Authorization header
// (both sign exactly host, x-amz-content-sha256 and x-amz-date).
func TestSignMatchesSDK(t *testing.T) {
	mk := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://example.amazonaws.com/test.txt?list-type=2", nil)
		r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		return r
	}

	sdkReq := mk()
	sdkSign(t, sdkReq, "UNSIGNED-PAYLOAD", false)

	ourReq := mk()
	err := Sign(SignInput{
		Request:     ourReq,
		AccessKeyID: testAKID,
		Secret:      testSecret,
		Region:      "us-east-1",
		Service:     "s3",
		Now:         signTime,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got := ourReq.Header.Get("Authorization")
	want := sdkReq.Header.Get("Authorization")
	if got != want {
		t.Errorf("Authorization mismatch:\n got: %s\nwant: %s", got, want)
	}
}
