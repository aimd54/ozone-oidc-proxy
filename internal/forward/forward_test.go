// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package forward

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/sigv4"
)

func TestStripPresignedQuery(t *testing.T) {
	cases := []struct {
		name, query, want string
	}{
		{"auth params removed, others byte-preserved",
			"X-Amz-Algorithm=AWS4-HMAC-SHA256&response-content-type=text%2Fcsv" +
				"&X-Amz-Credential=OZPXKEY%2F20260706%2Fus-east-1%2Fs3%2Faws4_request" +
				"&X-Amz-Date=20260706T120000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host" +
				"&X-Amz-Signature=abcd&X-Amz-Security-Token=tok&uploadId=42",
			"response-content-type=text%2Fcsv&uploadId=42"},
		{"only auth params", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=ff", ""},
		{"no auth params", "prefix=a%20b&list-type=2", "prefix=a%20b&list-type=2"},
		{"empty", "", ""},
		{"unrelated x-amz lowercase kept", "x-amz-meta-tag=1", "x-amz-meta-tag=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://p/bucket/key?"+tc.query, nil)
			StripPresignedQuery(r)
			if r.URL.RawQuery != tc.want {
				t.Errorf("RawQuery = %q, want %q", r.URL.RawQuery, tc.want)
			}
		})
	}
}

func TestApplySynthetic(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "http://p/bucket/key", nil)
	r.Header.Set("X-Amz-Security-Token", "should-vanish")
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

	ApplySynthetic(r, "alice", "us-east-1", now)

	want := "AWS4-HMAC-SHA256 Credential=alice/20260706/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=" + junkSignature
	if got := r.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization = %q\nwant %q", got, want)
	}
	if got := r.Header.Get("X-Amz-Date"); got != "20260706T120000Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
	if got := r.Header.Get("X-Amz-Content-Sha256"); got != "UNSIGNED-PAYLOAD" {
		t.Errorf("X-Amz-Content-Sha256 = %q", got)
	}
	if r.Header.Get("X-Amz-Security-Token") != "" {
		t.Error("X-Amz-Security-Token not stripped")
	}
}

func TestApplyResign(t *testing.T) {
	now := time.Date(2026, 7, 8, 12, 0, 0, 0, time.UTC)
	req := httptest.NewRequest(http.MethodPut, "http://localhost:9000/bkt/obj?uploadId=42", nil)
	req.Header.Set("X-Amz-Security-Token", "tok")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")

	if err := ApplyResign(req, "carol", "s3g:9878", "us-east-1", now); err != nil {
		t.Fatalf("ApplyResign: %v", err)
	}
	if req.Header.Get("X-Amz-Security-Token") != "" {
		t.Error("session token not stripped")
	}
	if req.Host != "s3g:9878" {
		t.Errorf("Host = %q, want upstream host", req.Host)
	}
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		t.Errorf("payload hash rewritten to %q", got)
	}

	auth, err := sigv4.ParseAuthorization(req.Header.Get("Authorization"))
	if err != nil {
		t.Fatalf("resigned header unparseable: %v", err)
	}
	if auth.AccessKeyID != "carol" {
		t.Errorf("Credential AKID = %q, want carol", auth.AccessKeyID)
	}
	err = sigv4.Verify(sigv4.Input{
		Request:   req,
		Auth:      auth,
		Secret:    ResignSecret,
		Region:    "us-east-1",
		Service:   "s3",
		Now:       now,
		ClockSkew: time.Minute,
	})
	if err != nil {
		t.Errorf("resigned header does not verify: %v", err)
	}
}
