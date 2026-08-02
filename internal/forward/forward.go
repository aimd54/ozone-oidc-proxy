// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package forward carries authenticated requests to the Ozone S3 Gateway with
// the proxy's identity injection: either a fully synthetic
// SigV4 header (Bearer lane) or the client's own header with the access key ID
// swapped for the username (SigV4 lane). Ozone's stock header parser populates
// SignatureInfo from it and OM evaluates native ACLs against that username;
// in unsecured mode the junk signature itself is never checked.
package forward

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/s3err"
	"github.com/aimd54/ozone-oidc-proxy/internal/sigv4"
)

// junkSignature fills the Signature component of synthetic headers: 64 hex
// chars keep Ozone's parser happy, and unsecured mode never verifies them.
const junkSignature = "0000000000000000000000000000000000000000000000000000000000000000"

const amzDateFormat = "20060102T150405Z"

// ApplySynthetic replaces the request's authentication with a synthetic SigV4
// header attributing it to username (Bearer lane).
func ApplySynthetic(r *http.Request, username, region string, now time.Time) {
	now = now.UTC()
	r.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s/%s/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s",
		sigv4.Algorithm, username, now.Format("20060102"), region, junkSignature))
	r.Header.Set("X-Amz-Date", now.Format(amzDateFormat))
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	r.Header.Del("X-Amz-Security-Token")
}

// ResignSecret signs re-signed upstream headers in resign mode. It is
// deliberately not secret: Ozone's unsecured mode never validates signatures,
// the value only makes the forwarded header internally consistent (robust to
// parser hardening). A future secure-mode deployment would provision a real
// shared secret instead.
// #nosec G101 -- deliberately public, see the comment above: it is a
// consistency filler, never an authentication secret.
const ResignSecret = "ozone-oidc-proxy-resign"

// ApplyResign replaces the request's authentication with a freshly computed,
// fully valid SigV4 header attributing it to username (forward_mode
// "resign"). The signature covers the upstream host, the value the reverse
// proxy rewrites Host to; so a verifying upstream could actually check it.
// The client's declared payload hash is preserved (streaming bodies keep
// working); an error can only come from an unparseable query string.
func ApplyResign(r *http.Request, username, upstreamHost, region string, now time.Time) error {
	r.Header.Del("X-Amz-Security-Token")
	return sigv4.Sign(sigv4.SignInput{
		Request:     r,
		AccessKeyID: username,
		Secret:      ResignSecret,
		Region:      region,
		Service:     "s3",
		Host:        upstreamHost,
		Now:         now,
	})
}

// RewriteAccessKeyID rebuilds the verified client Authorization header with
// the access key ID replaced by username (SigV4 lane). The session token
// header is stripped (and dropped from SignedHeaders) before the request
// reaches Ozone; the payload-hash and date headers stay exactly as the client
// sent them so streaming bodies keep working.
func RewriteAccessKeyID(r *http.Request, auth *sigv4.Authorization, username string) {
	signed := make([]string, 0, len(auth.SignedHeaders))
	for _, h := range auth.SignedHeaders {
		if h != "x-amz-security-token" {
			signed = append(signed, h)
		}
	}
	r.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
		sigv4.Algorithm, username, auth.Date, auth.Region, auth.Service,
		strings.Join(signed, ";"), auth.Signature))
	r.Header.Del("X-Amz-Security-Token")
}

// presignedAuthParams are the SigV4 query-auth parameter names (case-sensitive
// per AWS). They are removed before forwarding: the synthetic header carries
// the identity instead, and Ozone must not see half a query signature.
var presignedAuthParams = map[string]struct{}{
	"X-Amz-Algorithm":      {},
	"X-Amz-Credential":     {},
	"X-Amz-Date":           {},
	"X-Amz-Expires":        {},
	"X-Amz-SignedHeaders":  {},
	"X-Amz-Signature":      {},
	"X-Amz-Security-Token": {},
}

// StripPresignedQuery removes the (already verified) SigV4 query-auth
// parameters, leaving every other parameter byte-for-byte as received.
func StripPresignedQuery(r *http.Request) {
	if r.URL.RawQuery == "" {
		return
	}
	parts := strings.Split(r.URL.RawQuery, "&")
	kept := parts[:0]
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, _, _ := strings.Cut(part, "=")
		if decoded, err := url.QueryUnescape(key); err == nil {
			if _, drop := presignedAuthParams[decoded]; drop {
				continue
			}
		}
		kept = append(kept, part)
	}
	r.URL.RawQuery = strings.Join(kept, "&")
}

// NewReverseProxy builds the streaming reverse proxy toward the S3 Gateway.
// onUpstreamResponse (optional) observes upstream status codes for metrics.
func NewReverseProxy(target *url.URL, logger *slog.Logger, onUpstreamResponse func(status int)) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			pr.Out.Host = target.Host
		},
		// Flush promptly so large GETs/PUTs stream instead of buffering.
		FlushInterval: 100 * time.Millisecond,
		ModifyResponse: func(resp *http.Response) error {
			if onUpstreamResponse != nil {
				onUpstreamResponse(resp.StatusCode)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("upstream request failed", "error", err.Error(), "path", r.URL.Path)
			s3err.Write(w, http.StatusBadGateway, s3err.CodeInternalError,
				"upstream S3 gateway unreachable", r.URL.Path, "")
		},
	}
}
