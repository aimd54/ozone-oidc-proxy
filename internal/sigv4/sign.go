// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package sigv4

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// signedHeaderNames returns the header set Sign covers, in canonical
// (alphabetical) order: host plus every x-amz-* header on the request. SigV4
// requires all x-amz-* headers to be signed, and strict parsers (Ozone's
// included) reject requests where one, e.g. x-amz-decoded-content-length on
// aws-chunked uploads, is present but unsigned. Everything else passes
// unsigned, so bodies and client headers stream through untouched.
func signedHeaderNames(r *http.Request) []string {
	names := []string{"host"}
	for name := range r.Header {
		if lower := strings.ToLower(name); strings.HasPrefix(lower, "x-amz-") {
			names = append(names, lower)
		}
	}
	sort.Strings(names)
	return names
}

// SignInput describes an outbound signing operation. Used by forward's resign
// mode and by the e2e load generator as a client-side signer.
type SignInput struct {
	Request     *http.Request
	AccessKeyID string
	Secret      string
	Region      string
	Service     string
	// Host, when non-empty, is signed as the host header and becomes
	// Request.Host, so the signature stays valid after a reverse proxy
	// rewrites the outbound Host to that same value.
	Host string
	Now  time.Time
}

// Sign computes a fresh SigV4 signature over host, x-amz-content-sha256 and
// x-amz-date, setting those headers plus Authorization on the request. A
// payload hash already declared on the request (UNSIGNED-PAYLOAD, STREAMING-*,
// a real sum) is kept verbatim; absent one, UNSIGNED-PAYLOAD is declared.
func Sign(in SignInput) error {
	r := in.Request
	if in.Host != "" {
		r.Host = in.Host
	}
	amzDate := in.Now.UTC().Format(amzDateFormat)
	r.Header.Set("X-Amz-Date", amzDate)
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = "UNSIGNED-PAYLOAD"
		r.Header.Set("X-Amz-Content-Sha256", payloadHash)
	}

	signedHeaders := signedHeaderNames(r)
	canonical, err := buildCanonical(r, signedHeaders, "", payloadHash)
	if err != nil {
		return err
	}
	date := amzDate[:8]
	sum := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{
		Algorithm,
		amzDate,
		date + "/" + in.Region + "/" + in.Service + "/aws4_request",
		hex.EncodeToString(sum[:]),
	}, "\n")
	key := deriveKey(in.Secret, date, in.Region, in.Service)
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	r.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
		Algorithm, in.AccessKeyID, date, in.Region, in.Service,
		strings.Join(signedHeaders, ";"), signature))
	return nil
}
