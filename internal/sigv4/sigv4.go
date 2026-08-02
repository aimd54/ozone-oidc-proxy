// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package sigv4 verifies AWS Signature Version 4 on incoming requests against
// secrets minted by the STS handler. The canonical request is
// rebuilt from the wire: the URI as received, the payload hash exactly as the
// client declared it (UNSIGNED-PAYLOAD / STREAMING-* pass through verbatim, so
// bodies are never buffered and only streaming seed signatures are checked).
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// Algorithm is the only supported signing algorithm.
	Algorithm = "AWS4-HMAC-SHA256"
	// emptyBodySHA256 is sha256(""): used when the client did not declare a
	// payload hash (plain GETs from generic SigV4 clients).
	emptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// amzDateFormat is ISO8601 basic, the X-Amz-Date wire format.
	amzDateFormat = "20060102T150405Z"
)

// Typed verification errors, mapped to S3 error XML by the caller.
var (
	ErrMalformed         = errors.New("malformed SigV4 authorization")
	ErrMissingDate       = errors.New("missing X-Amz-Date")
	ErrSkew              = errors.New("request time too skewed")
	ErrScope             = errors.New("credential scope mismatch")
	ErrSignatureMismatch = errors.New("signature does not match")
)

// Authorization is the parsed SigV4 Authorization header.
type Authorization struct {
	AccessKeyID   string
	Date          string // yyyymmdd credential-scope date
	Region        string
	Service       string
	SignedHeaders []string // lowercase, in the order the client listed them
	Signature     string   // lowercase hex
}

// IsSigV4 reports whether the Authorization header value looks like SigV4.
func IsSigV4(header string) bool {
	return strings.HasPrefix(header, Algorithm+" ")
}

// ParseAuthorization parses an "AWS4-HMAC-SHA256 Credential=..., SignedHeaders=...,
// Signature=..." header. Components may appear in any order.
func ParseAuthorization(header string) (*Authorization, error) {
	rest, ok := strings.CutPrefix(header, Algorithm)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported algorithm", ErrMalformed)
	}
	auth := &Authorization{}
	for _, part := range strings.Split(rest, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found {
			return nil, fmt.Errorf("%w: component %q", ErrMalformed, part)
		}
		var err error
		switch key {
		case "Credential":
			err = auth.setCredential(value)
		case "SignedHeaders":
			err = auth.setSignedHeaders(value)
		case "Signature":
			err = auth.setSignature(value)
		default:
			err = fmt.Errorf("%w: unknown component %q", ErrMalformed, key)
		}
		if err != nil {
			return nil, err
		}
	}
	if auth.AccessKeyID == "" || len(auth.SignedHeaders) == 0 || auth.Signature == "" {
		return nil, fmt.Errorf("%w: missing Credential, SignedHeaders or Signature", ErrMalformed)
	}
	return auth, nil
}

// setCredential parses an "<AKID>/<date>/<region>/<service>/aws4_request"
// credential scope (shared by header and query authentication).
func (a *Authorization) setCredential(value string) error {
	scope := strings.Split(value, "/")
	if len(scope) != 5 || scope[4] != "aws4_request" {
		return fmt.Errorf("%w: credential scope %q", ErrMalformed, value)
	}
	a.AccessKeyID, a.Date, a.Region, a.Service = scope[0], scope[1], scope[2], scope[3]
	if a.AccessKeyID == "" || len(a.Date) != 8 {
		return fmt.Errorf("%w: credential scope %q", ErrMalformed, value)
	}
	return nil
}

func (a *Authorization) setSignedHeaders(value string) error {
	for _, h := range strings.Split(value, ";") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return fmt.Errorf("%w: empty signed header name", ErrMalformed)
		}
		a.SignedHeaders = append(a.SignedHeaders, h)
	}
	return nil
}

func (a *Authorization) setSignature(value string) error {
	sig := strings.ToLower(strings.TrimSpace(value))
	if len(sig) != 64 {
		return fmt.Errorf("%w: signature must be 64 hex chars", ErrMalformed)
	}
	if _, err := hex.DecodeString(sig); err != nil {
		return fmt.Errorf("%w: signature is not hex", ErrMalformed)
	}
	a.Signature = sig
	return nil
}

// Input is everything Verify needs; the request is used read-only.
type Input struct {
	Request   *http.Request
	Auth      *Authorization
	Secret    string
	Region    string // expected region (scope check)
	Service   string // expected service, "s3" on the data path
	Now       time.Time
	ClockSkew time.Duration
}

// Verify recomputes the request signature and compares it in constant time.
func Verify(in Input) error {
	if in.Auth.Service != in.Service {
		return fmt.Errorf("%w: service %q, expected %q", ErrScope, in.Auth.Service, in.Service)
	}
	if in.Auth.Region != in.Region {
		return fmt.Errorf("%w: region %q, expected %q", ErrScope, in.Auth.Region, in.Region)
	}

	amzDate := in.Request.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return ErrMissingDate
	}
	t, err := time.Parse(amzDateFormat, amzDate)
	if err != nil {
		return fmt.Errorf("%w: X-Amz-Date %q", ErrMalformed, amzDate)
	}
	if d := in.Now.Sub(t); d > in.ClockSkew || d < -in.ClockSkew {
		return fmt.Errorf("%w: request time %s vs server time %s",
			ErrSkew, t.UTC().Format(time.RFC3339), in.Now.UTC().Format(time.RFC3339))
	}
	if amzDate[:8] != in.Auth.Date {
		return fmt.Errorf("%w: scope date %s does not match X-Amz-Date %s", ErrScope, in.Auth.Date, amzDate)
	}

	canonical, err := canonicalRequest(in.Request, in.Auth.SignedHeaders)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		Algorithm,
		amzDate,
		in.Auth.Date + "/" + in.Auth.Region + "/" + in.Auth.Service + "/aws4_request",
		hex.EncodeToString(sum[:]),
	}, "\n")

	key := deriveKey(in.Secret, in.Auth.Date, in.Auth.Region, in.Auth.Service)
	expected := hex.EncodeToString(hmacSHA256(key, stringToSign))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(in.Auth.Signature)) != 1 {
		return ErrSignatureMismatch
	}
	return nil
}

// canonicalRequest rebuilds the AWS canonical request from the wire form
// (header authentication: the payload hash is whatever the client declared).
func canonicalRequest(r *http.Request, signedHeaders []string) (string, error) {
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = emptyBodySHA256
	}
	return buildCanonical(r, signedHeaders, "", payloadHash)
}

// buildCanonical assembles the canonical request. skipQueryKey (decoded form)
// is omitted from the canonical query, query authentication excludes
// X-Amz-Signature from its own canonical form.
func buildCanonical(r *http.Request, signedHeaders []string, skipQueryKey, payloadHash string) (string, error) {
	query, err := canonicalQuery(r.URL.RawQuery, skipQueryKey)
	if err != nil {
		return "", err
	}
	var headers strings.Builder
	for _, name := range signedHeaders {
		headers.WriteString(name)
		headers.WriteByte(':')
		headers.WriteString(headerValue(r, name))
		headers.WriteByte('\n')
	}
	return strings.Join([]string{
		r.Method,
		canonicalURI(r),
		query,
		headers.String(),
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n"), nil
}

// canonicalURI returns the request path exactly as it appeared on the wire
// (single-encoded, not normalized, the S3 flavor of SigV4).
func canonicalURI(r *http.Request) string {
	uri := r.RequestURI
	if uri == "" {
		// Client-built request (tests): the escaped path is the wire form.
		return orSlash(r.URL.EscapedPath())
	}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		if u, err := url.ParseRequestURI(uri); err == nil {
			return orSlash(u.EscapedPath())
		}
	}
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	return orSlash(uri)
}

func orSlash(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// canonicalQuery decodes the raw query and re-encodes it with AWS URI-encoding,
// pairs sorted by encoded key then encoded value. skipKey (decoded form, "" for
// none) is left out.
func canonicalQuery(rawQuery, skipKey string) (string, error) {
	if rawQuery == "" {
		return "", nil
	}
	type pair struct{ k, v string }
	var pairs []pair
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		// PathUnescape keeps "+" literal: SigV4 canonical form never uses "+"
		// for spaces, and S3 SDK clients always send %20.
		dk, err := url.PathUnescape(k)
		if err != nil {
			return "", fmt.Errorf("%w: query key %q", ErrMalformed, k)
		}
		dv, err := url.PathUnescape(v)
		if err != nil {
			return "", fmt.Errorf("%w: query value %q", ErrMalformed, v)
		}
		if skipKey != "" && dk == skipKey {
			continue
		}
		pairs = append(pairs, pair{uriEncode(dk, true), uriEncode(dv, true)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	elems := make([]string, len(pairs))
	for i, p := range pairs {
		elems[i] = p.k + "=" + p.v
	}
	return strings.Join(elems, "&"), nil
}

// uriEncode is AWS SigV4 URI-encoding: unreserved characters pass through,
// everything else becomes uppercase percent escapes.
func uriEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// headerValue produces the canonical value for one signed header: values
// joined with ",", surrounding whitespace trimmed, inner runs collapsed.
func headerValue(r *http.Request, lowerName string) string {
	var values []string
	switch lowerName {
	case "host":
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		values = []string{host}
	case "content-length":
		values = r.Header.Values("Content-Length")
		if len(values) == 0 && r.ContentLength >= 0 {
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		}
	default:
		values = r.Header.Values(lowerName)
	}
	trimmed := make([]string, 0, len(values))
	for _, v := range values {
		trimmed = append(trimmed, strings.Join(strings.Fields(v), " "))
	}
	return strings.Join(trimmed, ",")
}

func deriveKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
