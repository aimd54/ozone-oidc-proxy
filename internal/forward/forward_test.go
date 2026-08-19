// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package forward

import (
	"net/http"
	"net/http/httptest"
	"slices"
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

// RewriteAccessKeyID is the identity injection on the primary data path: it
// decides which username Ozone attributes every SigV4 request to. Its two
// siblings above were tested from the start; this one reaches Ozone far more
// often than either.
func TestRewriteAccessKeyID(t *testing.T) {
	// What an AWS SDK actually sends once it holds minted credentials.
	auth := &sigv4.Authorization{
		AccessKeyID: "OZPXP0CQ1HJ6K9R9N5ED",
		Date:        "20260706",
		Region:      "us-east-1",
		Service:     "s3",
		SignedHeaders: []string{
			"host", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token",
		},
		Signature: "5d672d79c15b13162d9279b0855cfba6789a8edb4c122d4c19a4d16f4b1b2f6d",
	}
	r := httptest.NewRequest(http.MethodPut, "http://p/bucket/key", nil)
	r.Header.Set("X-Amz-Security-Token", "the-session-token")
	r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	r.Header.Set("X-Amz-Date", "20260706T120000Z")

	RewriteAccessKeyID(r, auth, "alice")

	got, err := sigv4.ParseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		t.Fatalf("rewritten header does not parse: %v", err)
	}

	// The whole point: Ozone reads this field as the user.
	if got.AccessKeyID != "alice" {
		t.Errorf("Credential access key ID = %q, want alice", got.AccessKeyID)
	}
	// The rest of the credential scope belongs to the client. Inventing any
	// of it here would forward a request other than the one verified.
	if got.Date != auth.Date {
		t.Errorf("scope date = %q, want %q", got.Date, auth.Date)
	}
	if got.Region != auth.Region {
		t.Errorf("scope region = %q, want %q", got.Region, auth.Region)
	}
	if got.Service != auth.Service {
		t.Errorf("scope service = %q, want %q", got.Service, auth.Service)
	}
	// The signature is carried, never recomputed: it is the client's, the
	// proxy has already verified it, and Ozone does not check it.
	if got.Signature != auth.Signature {
		t.Errorf("signature = %q, want the client's %q", got.Signature, auth.Signature)
	}

	// Both halves of removing the session token. Dropping it from one place
	// only leaves a header that names a header it does not carry, or carries
	// a credential-bearing header Ozone was never meant to see.
	if v := r.Header.Get("X-Amz-Security-Token"); v != "" {
		t.Errorf("X-Amz-Security-Token still present: %q", v)
	}
	wantSigned := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if !slices.Equal(got.SignedHeaders, wantSigned) {
		t.Errorf("SignedHeaders = %v, want %v", got.SignedHeaders, wantSigned)
	}

	// Headers the client signed over must survive byte-identical. Replacing
	// the payload hash is what breaks streaming uploads.
	if v := r.Header.Get("X-Amz-Content-Sha256"); v != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		t.Errorf("payload hash rewritten to %q", v)
	}
	if v := r.Header.Get("X-Amz-Date"); v != "20260706T120000Z" {
		t.Errorf("X-Amz-Date rewritten to %q", v)
	}
}

func TestRewriteAccessKeyIDSignedHeaderOrder(t *testing.T) {
	// SignedHeaders is order-significant in SigV4, and the session token can
	// sit anywhere in it depending on the client. Removing an element must
	// not disturb the others.
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"token last",
			[]string{"host", "x-amz-date", "x-amz-security-token"},
			[]string{"host", "x-amz-date"}},
		{"token in the middle",
			[]string{"host", "x-amz-security-token", "x-amz-date"},
			[]string{"host", "x-amz-date"}},
		{"token first",
			[]string{"x-amz-security-token", "host", "x-amz-date"},
			[]string{"host", "x-amz-date"}},
		{"no token to remove",
			[]string{"host", "x-amz-content-sha256", "x-amz-date"},
			[]string{"host", "x-amz-content-sha256", "x-amz-date"}},
		{"a header merely containing the name is kept",
			[]string{"host", "x-amz-security-token-hint", "x-amz-date"},
			[]string{"host", "x-amz-security-token-hint", "x-amz-date"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := &sigv4.Authorization{
				AccessKeyID:   "OZPXP0CQ1HJ6K9R9N5ED",
				Date:          "20260706",
				Region:        "us-east-1",
				Service:       "s3",
				SignedHeaders: tc.in,
				Signature:     "5d672d79c15b13162d9279b0855cfba6789a8edb4c122d4c19a4d16f4b1b2f6d",
			}
			r := httptest.NewRequest(http.MethodGet, "http://p/bucket/key", nil)
			RewriteAccessKeyID(r, auth, "bob")

			got, err := sigv4.ParseAuthorization(r.Header.Get("Authorization"))
			if err != nil {
				t.Fatalf("rewritten header does not parse: %v", err)
			}
			if !slices.Equal(got.SignedHeaders, tc.want) {
				t.Errorf("SignedHeaders = %v, want %v", got.SignedHeaders, tc.want)
			}
		})
	}
}
