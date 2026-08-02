// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package sigv4

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// sdkPresign mints a presigned URL with the real AWS SDK signer and returns
// the equivalent server-form request (wire RequestURI, Host set). X-Amz-Expires
// is placed on the URL before signing, the way the SDK's S3 presigner does.
func sdkPresign(t *testing.T, method, rawURL string, expires int, withToken bool, at time.Time) *http.Request {
	t.Helper()
	seed, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := seed.URL.Query()
	q.Set("X-Amz-Expires", strconv.Itoa(expires))
	seed.URL.RawQuery = q.Encode()

	creds := aws.Credentials{AccessKeyID: testAKID, SecretAccessKey: testSecret}
	if withToken {
		creds.SessionToken = testToken
	}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	signedURL, hdr, err := signer.PresignHTTP(context.Background(), creds, seed, unsignedPayload, "s3", "us-east-1", at)
	if err != nil {
		t.Fatalf("PresignHTTP: %v", err)
	}

	out, err := http.NewRequest(method, signedURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range hdr {
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}
	out.RequestURI = out.URL.RequestURI()
	out.Host = out.URL.Host
	return out
}

func verifyPresignedReq(req *http.Request, p *Presigned, now time.Time) error {
	return VerifyPresigned(PresignInput{
		Request:   req,
		Auth:      p,
		Secret:    testSecret,
		Region:    "us-east-1",
		Service:   "s3",
		Now:       now,
		ClockSkew: 15 * time.Minute,
	})
}

func TestPresignedRoundTripWithAWSSDKSigner(t *testing.T) {
	cases := []struct {
		name      string
		method    string
		url       string
		withToken bool
	}{
		{"get simple", http.MethodGet, "http://proxy:9000/bucket/hello.txt", false},
		{"get with session token", http.MethodGet, "http://proxy:9000/bucket/hello.txt", true},
		{"path with spaces and unicode", http.MethodGet,
			"http://proxy:9000/bucket/dir%20one/caf%C3%A9%20menu.txt", true},
		{"extra query parameters", http.MethodGet,
			"http://proxy:9000/bucket/report.csv?response-content-disposition=attachment%3B%20filename%3D%22q3%20report.csv%22&response-content-type=text%2Fcsv", true},
		{"presigned put", http.MethodPut, "http://proxy:9000/bucket/upload.bin", true},
		{"head object", http.MethodHead, "http://proxy:9000/bucket/hello.txt", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := sdkPresign(t, tc.method, tc.url, 900, tc.withToken, signTime)
			p, err := ParsePresigned(req)
			if err != nil {
				t.Fatalf("ParsePresigned: %v", err)
			}
			if p.AccessKeyID != testAKID {
				t.Errorf("AccessKeyID = %q", p.AccessKeyID)
			}
			if tc.withToken && p.SecurityToken != testToken {
				t.Errorf("SecurityToken = %q, want the session token", p.SecurityToken)
			}
			if err := verifyPresignedReq(req, p, signTime.Add(5*time.Minute)); err != nil {
				t.Fatalf("VerifyPresigned = %v, want nil", err)
			}
		})
	}
}

// TestPresignedAWSDocVector pins the implementation to the worked example in
// the AWS documentation "Authenticating Requests: Using Query Parameters
// (AWS Signature Version 4)": GET /test.txt on examplebucket, 20130524,
// 86400 s validity, secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.
func TestPresignedAWSDocVector(t *testing.T) {
	const u = "https://examplebucket.s3.amazonaws.com/test.txt" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z" +
		"&X-Amz-Expires=86400" +
		"&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	req := httptest.NewRequest(http.MethodGet, u, nil)
	p, err := ParsePresigned(req)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyPresigned(PresignInput{
		Request:   req,
		Auth:      p,
		Secret:    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		Service:   "s3",
		Now:       time.Date(2013, 5, 24, 12, 0, 0, 0, time.UTC),
		ClockSkew: 15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("VerifyPresigned(doc vector) = %v, want nil", err)
	}
}

func TestPresignedValidityWindow(t *testing.T) {
	req := sdkPresign(t, http.MethodGet, "http://proxy:9000/bucket/hello.txt", 300, true, signTime)
	p, err := ParsePresigned(req)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		now     time.Time
		wantErr error
	}{
		{"fresh", signTime.Add(time.Minute), nil},
		{"last second", signTime.Add(300 * time.Second), nil},
		{"just expired", signTime.Add(301 * time.Second), ErrPresignExpired},
		{"long expired", signTime.Add(24 * time.Hour), ErrPresignExpired},
		{"used slightly before its date", signTime.Add(-14 * time.Minute), nil},
		{"dated too far in the future", signTime.Add(-16 * time.Minute), ErrSkew},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPresignedReq(req, p, tc.now)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("VerifyPresigned = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifyPresigned = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestPresignedTamperDetection(t *testing.T) {
	fresh := func(t *testing.T) (*http.Request, *Presigned) {
		req := sdkPresign(t, http.MethodGet, "http://proxy:9000/bucket/hello.txt?uploadId=42", 900, true, signTime)
		p, err := ParsePresigned(req)
		if err != nil {
			t.Fatal(err)
		}
		return req, p
	}

	tampers := map[string]func(*http.Request, *Presigned){
		"signature byte": func(_ *http.Request, p *Presigned) { p.Signature = flipHex(p.Signature) },
		"query added": func(r *http.Request, _ *Presigned) {
			r.URL.RawQuery += "&admin=true"
			r.RequestURI = r.URL.RequestURI()
		},
		"path": func(r *http.Request, _ *Presigned) {
			r.URL.Path += "x"
			r.URL.RawPath = ""
			r.RequestURI = strings.Replace(r.RequestURI, "hello.txt", "hello.txtx", 1)
		},
		"host": func(r *http.Request, _ *Presigned) { r.Host = "evil:9000" },
		"method": func(r *http.Request, _ *Presigned) {
			r.Method = http.MethodDelete
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			req, p := fresh(t)
			tamper(req, p)
			if err := verifyPresignedReq(req, p, signTime); !errors.Is(err, ErrSignatureMismatch) {
				t.Fatalf("VerifyPresigned after tamper = %v, want ErrSignatureMismatch", err)
			}
		})
	}

	t.Run("wrong secret", func(t *testing.T) {
		req, p := fresh(t)
		err := VerifyPresigned(PresignInput{
			Request: req, Auth: p,
			Secret: "another-secret", Region: "us-east-1", Service: "s3",
			Now: signTime, ClockSkew: 15 * time.Minute,
		})
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Fatalf("VerifyPresigned = %v, want ErrSignatureMismatch", err)
		}
	})
	t.Run("wrong expected region", func(t *testing.T) {
		req, p := fresh(t)
		err := VerifyPresigned(PresignInput{
			Request: req, Auth: p,
			Secret: testSecret, Region: "eu-west-1", Service: "s3",
			Now: signTime, ClockSkew: 15 * time.Minute,
		})
		if !errors.Is(err, ErrScope) {
			t.Fatalf("VerifyPresigned = %v, want ErrScope", err)
		}
	})
	t.Run("scope date mismatch", func(t *testing.T) {
		req, p := fresh(t)
		p.Date = "20260705"
		if err := verifyPresignedReq(req, p, signTime); !errors.Is(err, ErrScope) {
			t.Fatalf("VerifyPresigned = %v, want ErrScope", err)
		}
	})
}

func TestParsePresignedRejects(t *testing.T) {
	valid := sdkPresign(t, http.MethodGet, "http://proxy:9000/bucket/hello.txt", 900, true, signTime)
	q := valid.URL.Query()

	newReq := func(mutate func(q map[string][]string)) *http.Request {
		clone := map[string][]string{}
		for k, vs := range q {
			clone[k] = append([]string(nil), vs...)
		}
		mutate(clone)
		u := *valid.URL
		vals := make([]string, 0, len(clone))
		for k, vs := range clone {
			for _, v := range vs {
				vals = append(vals, k+"="+v)
			}
		}
		u.RawQuery = strings.Join(vals, "&")
		req := httptest.NewRequest(http.MethodGet, u.String(), nil)
		return req
	}

	cases := map[string]func(q map[string][]string){
		"missing algorithm":  func(q map[string][]string) { delete(q, "X-Amz-Algorithm") },
		"wrong algorithm":    func(q map[string][]string) { q["X-Amz-Algorithm"] = []string{"AWS4-HMAC-SHA1"} },
		"missing credential": func(q map[string][]string) { delete(q, "X-Amz-Credential") },
		"short scope":        func(q map[string][]string) { q["X-Amz-Credential"] = []string{"AKID/20260706/us-east-1"} },
		"missing signature":  func(q map[string][]string) { delete(q, "X-Amz-Signature") },
		"short signature":    func(q map[string][]string) { q["X-Amz-Signature"] = []string{"abc123"} },
		"missing date":       func(q map[string][]string) { delete(q, "X-Amz-Date") },
		"truncated date":     func(q map[string][]string) { q["X-Amz-Date"] = []string{"20260706"} },
		"missing expires":    func(q map[string][]string) { delete(q, "X-Amz-Expires") },
		"zero expires":       func(q map[string][]string) { q["X-Amz-Expires"] = []string{"0"} },
		"negative expires":   func(q map[string][]string) { q["X-Amz-Expires"] = []string{"-5"} },
		"huge expires":       func(q map[string][]string) { q["X-Amz-Expires"] = []string{"604801"} },
		"textual expires":    func(q map[string][]string) { q["X-Amz-Expires"] = []string{"tomorrow"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePresigned(newReq(mutate)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParsePresigned = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestIsPresigned(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://p/bucket/key", false},
		{"http://p/bucket/key?uploads=&max-parts=10", false},
		{"http://p/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256", true},
		{"http://p/bucket/key?X-Amz-Signature=abc", true},
		{"http://p/bucket/key?x-amz-meta-tag=1", false},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.url, nil)
		if got := IsPresigned(req); got != tc.want {
			t.Errorf("IsPresigned(%s) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
