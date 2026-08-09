// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Query-string ("presigned URL") SigV4 authentication.
// Same wire-form discipline as header auth: the canonical
// query is rebuilt from the raw query bytes with X-Amz-Signature left out,
// and the payload hash is the literal UNSIGNED-PAYLOAD the S3 query-auth
// scheme prescribes (the signer cannot know the payload when the URL is
// minted).
package sigv4

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxPresignExpires is the AWS cap on X-Amz-Expires: one week, in seconds.
const maxPresignExpires = 604800

// unsignedPayload is the fixed payload hash of S3 query authentication.
const unsignedPayload = "UNSIGNED-PAYLOAD"

// ErrPresignExpired reports a URL used past X-Amz-Date + X-Amz-Expires.
var ErrPresignExpired = errors.New("presigned URL has expired")

// Presigned is the parsed query-auth counterpart of Authorization.
type Presigned struct {
	Authorization
	AmzDate       string        // X-Amz-Date parameter, ISO8601 basic UTC
	Expires       time.Duration // X-Amz-Expires parameter
	SecurityToken string        // X-Amz-Security-Token parameter, "" if absent
}

// IsPresigned reports whether the request attempts SigV4 query authentication
// (either marker parameter counts, so half-built attempts are rejected with a
// precise error instead of falling through to the strict-mode 403).
func IsPresigned(r *http.Request) bool {
	q := r.URL.Query()
	_, hasAlg := q["X-Amz-Algorithm"]
	_, hasSig := q["X-Amz-Signature"]
	return hasAlg || hasSig
}

// IsSigV2Query reports whether the request carries SigV2 query authentication,
// the form an aws CLI emits for a presigned URL when it has not been pinned to
// SigV4. Both markers are required: an access key id on its own is an ordinary
// query parameter, and the pair is what distinguishes a signed URL from one.
// This proxy verifies SigV4 only, and saying so beats a generic rejection.
func IsSigV2Query(r *http.Request) bool {
	q := r.URL.Query()
	_, hasAKID := q["AWSAccessKeyId"]
	_, hasSig := q["Signature"]
	return hasAKID && hasSig
}

// ParsePresigned extracts and validates the auth query parameters.
func ParsePresigned(r *http.Request) (*Presigned, error) {
	q := r.URL.Query()
	if alg := q.Get("X-Amz-Algorithm"); alg != Algorithm {
		return nil, fmt.Errorf("%w: X-Amz-Algorithm %q", ErrMalformed, alg)
	}
	p := &Presigned{
		AmzDate:       q.Get("X-Amz-Date"),
		SecurityToken: q.Get("X-Amz-Security-Token"),
	}
	if err := p.setCredential(q.Get("X-Amz-Credential")); err != nil {
		return nil, err
	}
	if err := p.setSignedHeaders(q.Get("X-Amz-SignedHeaders")); err != nil {
		return nil, err
	}
	if err := p.setSignature(q.Get("X-Amz-Signature")); err != nil {
		return nil, err
	}
	if len(p.AmzDate) != len(amzDateFormat) {
		return nil, fmt.Errorf("%w: X-Amz-Date %q", ErrMalformed, p.AmzDate)
	}
	expires := q.Get("X-Amz-Expires")
	n, err := strconv.Atoi(expires)
	if err != nil {
		return nil, fmt.Errorf("%w: X-Amz-Expires %q is not a number", ErrMalformed, expires)
	}
	if n <= 0 {
		return nil, fmt.Errorf("%w: X-Amz-Expires must be positive", ErrMalformed)
	}
	if n > maxPresignExpires {
		return nil, fmt.Errorf("%w: X-Amz-Expires must be at most %d seconds (one week)", ErrMalformed, maxPresignExpires)
	}
	p.Expires = time.Duration(n) * time.Second
	return p, nil
}

// PresignInput is everything VerifyPresigned needs; the request is read-only.
type PresignInput struct {
	Request   *http.Request
	Auth      *Presigned
	Secret    string
	Region    string // expected region (scope check)
	Service   string // expected service, "s3" on the data path
	Now       time.Time
	ClockSkew time.Duration
}

// VerifyPresigned recomputes a presigned URL's signature and compares it in
// constant time. The URL is valid from X-Amz-Date (with clock-skew tolerance
// for signers slightly ahead of us) until X-Amz-Date + X-Amz-Expires, sharp.
func VerifyPresigned(in PresignInput) error {
	if in.Auth.Service != in.Service {
		return fmt.Errorf("%w: service %q, expected %q", ErrScope, in.Auth.Service, in.Service)
	}
	if in.Auth.Region != in.Region {
		return fmt.Errorf("%w: region %q, expected %q", ErrScope, in.Auth.Region, in.Region)
	}
	t, err := time.Parse(amzDateFormat, in.Auth.AmzDate)
	if err != nil {
		return fmt.Errorf("%w: X-Amz-Date %q", ErrMalformed, in.Auth.AmzDate)
	}
	if in.Auth.AmzDate[:8] != in.Auth.Date {
		return fmt.Errorf("%w: scope date %s does not match X-Amz-Date %s", ErrScope, in.Auth.Date, in.Auth.AmzDate)
	}
	if t.Sub(in.Now) > in.ClockSkew {
		return fmt.Errorf("%w: URL signed at %s, in the future", ErrSkew, t.UTC().Format(time.RFC3339))
	}
	if in.Now.After(t.Add(in.Auth.Expires)) {
		return ErrPresignExpired
	}

	canonical, err := buildCanonical(in.Request, in.Auth.SignedHeaders, "X-Amz-Signature", unsignedPayload)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		Algorithm,
		in.Auth.AmzDate,
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
