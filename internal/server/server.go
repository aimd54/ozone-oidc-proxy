// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package server dispatches incoming requests to the STS, Bearer and SigV4
// lanes (DESIGN.md §6.1) and enforces strict mode: every data-path request is
// either a valid Bearer JWT or a verified temp-credential SigV4 request, or it
// is rejected with S3-shaped error XML.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aimd54/ozone-oidc-proxy/internal/config"
	"github.com/aimd54/ozone-oidc-proxy/internal/forward"
	"github.com/aimd54/ozone-oidc-proxy/internal/oidc"
	"github.com/aimd54/ozone-oidc-proxy/internal/s3err"
	"github.com/aimd54/ozone-oidc-proxy/internal/sigv4"
	"github.com/aimd54/ozone-oidc-proxy/internal/store"
	"github.com/aimd54/ozone-oidc-proxy/internal/sts"
)

// maxSTSBodyBytes bounds the buffered STS form body; JWTs are a few KB.
const maxSTSBodyBytes = 1 << 20

// Server owns the two HTTP surfaces: the S3/STS listener and the admin one.
type Server struct {
	cfg       *config.Config
	validator sts.TokenValidator
	store     store.Store
	logger    *slog.Logger
	now       func() time.Time

	stsHandler   *sts.Handler
	proxy        http.Handler
	upstreamHost string // resign mode signs the host header with this value
	metrics      *metrics
}

// Option customizes the server (tests).
type Option func(*Server)

// WithClock overrides the time source.
func WithClock(now func() time.Time) Option { return func(s *Server) { s.now = now } }

// New wires the lanes together.
func New(cfg *config.Config, validator sts.TokenValidator, st store.Store, logger *slog.Logger, opts ...Option) (*Server, error) {
	target, err := url.Parse(cfg.Upstream.S3Endpoint)
	if err != nil {
		return nil, fmt.Errorf("upstream.s3_endpoint: %w", err)
	}
	s := &Server{
		cfg:       cfg,
		validator: validator,
		store:     st,
		logger:    logger,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.metrics = newMetrics(st)
	s.stsHandler = &sts.Handler{
		Validator: validator,
		Store:     st,
		STS:       cfg.STS,
		Logger:    logger,
		Now:       s.now,
		OnExchange: func(r sts.Result) {
			s.metrics.stsExchanges.WithLabelValues(orUnknown(r.Issuer), resultLabel(r.Code)).Inc()
		},
	}
	s.proxy = forward.NewReverseProxy(target, logger, s.metrics.observeUpstream)
	s.upstreamHost = target.Host
	return s, nil
}

// applyIdentity injects the authenticated username into the outbound request
// per upstream.forward_mode (§6.4). auth is the client's verified header on
// the SigV4 lane, nil elsewhere.
func (s *Server) applyIdentity(r *http.Request, username string, auth *sigv4.Authorization) {
	if s.cfg.Upstream.ForwardMode == config.ForwardModeResign {
		err := forward.ApplyResign(r, username, s.upstreamHost, s.cfg.Security.Region, s.now())
		if err == nil {
			return
		}
		// Signing only fails on an unparseable query string; fall back to the
		// rewrite shape (identical attribution) rather than failing the request.
		s.logger.Warn("resign failed, falling back to rewrite", "error", err.Error())
	}
	if auth != nil {
		forward.RewriteAccessKeyID(r, auth, username)
		return
	}
	forward.ApplySynthetic(r, username, s.cfg.Security.Region, s.now())
}

// Handler returns the main S3/STS handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

// AdminHandler returns /healthz, /readyz and /metrics.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.store.Count(r.Context()); err != nil {
			http.Error(w, "credential store unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ready")
	})
	mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.registry, promhttp.HandlerOpts{}))
	// Revocation = store delete (§7, M3). This makes the admin listener
	// state-changing and security-sensitive — it is deliberately
	// unauthenticated, so it must never be published beyond an internal
	// boundary (compose binds it to localhost; the Helm chart keeps it
	// ClusterIP behind a NetworkPolicy scoped to the scrape source).
	mux.HandleFunc("DELETE /credentials/{akid}", s.handleRevoke)
	return mux
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	akid := r.PathValue("akid")
	log := s.logger.With("endpoint", "revoke", "access_key_id", akid)

	creds, found, err := s.store.Get(r.Context(), akid)
	if err != nil {
		s.metrics.revocations.WithLabelValues("error").Inc()
		log.Error("revocation lookup failed", "error", err.Error())
		http.Error(w, "credential store unavailable", http.StatusServiceUnavailable)
		return
	}
	if !found {
		s.metrics.revocations.WithLabelValues("unknown").Inc()
		log.Info("revocation of unknown access key ID")
		http.Error(w, "unknown access key ID", http.StatusNotFound)
		return
	}
	if err := s.store.Delete(r.Context(), akid); err != nil {
		s.metrics.revocations.WithLabelValues("error").Inc()
		log.Error("revocation delete failed", "error", err.Error())
		http.Error(w, "credential store unavailable", http.StatusServiceUnavailable)
		return
	}
	s.metrics.revocations.WithLabelValues("revoked").Inc()
	log.Info("credentials revoked", "username", creds.Username, "issuer", creds.Issuer)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	reqID := newRequestID()

	// STS endpoint: POST / with a form body (MinIO-style dispatch, §6.1).
	if s.isSTSRequest(r) {
		r.Body = http.MaxBytesReader(w, r.Body, maxSTSBodyBytes)
		s.stsHandler.ServeHTTP(w, r)
		s.metrics.observeDuration("sts", start)
		return
	}

	authHeader := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(authHeader, "Bearer "):
		s.serveBearer(w, r, strings.TrimPrefix(authHeader, "Bearer "), reqID, start)
	case sigv4.IsSigV4(authHeader):
		s.serveSigV4(w, r, authHeader, reqID, start)
	case authHeader == "" && sigv4.IsPresigned(r):
		s.servePresigned(w, r, reqID, start)
	default:
		s.serveUnauthenticated(w, r, reqID, start)
	}
}

func (s *Server) isSTSRequest(r *http.Request) bool {
	if r.Method != http.MethodPost || (r.URL.Path != "/" && r.URL.Path != "") {
		return false
	}
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && ct == "application/x-www-form-urlencoded"
}

// serveBearer is the secondary data-path lane: a JWT directly on the request.
func (s *Server) serveBearer(w http.ResponseWriter, r *http.Request, token, reqID string, start time.Time) {
	defer s.metrics.observeDuration("bearer", start)
	vstart := time.Now()
	log := s.logger.With("request_id", reqID, "lane", "bearer", "method", r.Method, "path", r.URL.Path)

	if !s.cfg.DataPath.BearerEnabled() {
		s.metrics.bearerAuth.WithLabelValues("unknown", "disabled").Inc()
		log.Info("bearer lane disabled")
		s3err.Write(w, http.StatusForbidden, s3err.CodeAccessDenied,
			"bearer authentication is disabled", r.URL.Path, reqID)
		return
	}
	identity, err := s.validator.Validate(r.Context(), token)
	s.metrics.observeVerification("bearer", vstart)
	if err != nil {
		status, code := mapBearerError(err)
		s.metrics.bearerAuth.WithLabelValues("unknown", code).Inc()
		log.Info("bearer rejected", "error", err.Error(), "code", code)
		s3err.Write(w, status, code, bearerErrorMessage(err), r.URL.Path, reqID)
		return
	}
	s.metrics.bearerAuth.WithLabelValues(identity.IssuerName, "success").Inc()
	log.Info("bearer authenticated", "username", identity.Username, "issuer", identity.IssuerName)

	s.applyIdentity(r, identity.Username, nil)
	s.proxy.ServeHTTP(w, r)
}

// serveSigV4 is the primary data-path lane: SigV4 against minted credentials.
func (s *Server) serveSigV4(w http.ResponseWriter, r *http.Request, authHeader, reqID string, start time.Time) {
	defer s.metrics.observeDuration("sigv4", start)
	vstart := time.Now()
	log := s.logger.With("request_id", reqID, "lane", "sigv4", "method", r.Method, "path", r.URL.Path)

	reject := func(status int, result, code, message string) {
		s.metrics.sigv4Verifies.WithLabelValues(result).Inc()
		log.Info("sigv4 rejected", "code", code, "detail", message)
		s3err.Write(w, status, code, message, r.URL.Path, reqID)
	}

	auth, err := sigv4.ParseAuthorization(authHeader)
	if err != nil {
		reject(http.StatusBadRequest, "malformed", s3err.CodeAuthorizationHeaderMalformed,
			"the Authorization header is malformed")
		return
	}
	log = log.With("access_key_id", auth.AccessKeyID)

	creds, found, err := s.store.Get(r.Context(), auth.AccessKeyID)
	if err != nil {
		reject(http.StatusInternalServerError, "store_error", s3err.CodeInternalError,
			"credential store unavailable")
		return
	}
	if !found {
		reject(http.StatusForbidden, "unknown_akid", s3err.CodeInvalidAccessKeyID,
			"the access key ID does not exist (exchange a token via AssumeRoleWithWebIdentity first)")
		return
	}
	if creds.Expired(s.now()) {
		reject(http.StatusForbidden, "expired", s3err.CodeExpiredToken,
			"the temporary credentials have expired")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Amz-Security-Token")), []byte(creds.SessionToken)) != 1 {
		reject(http.StatusForbidden, "bad_token", s3err.CodeInvalidToken,
			"the security token is missing or does not match the credentials")
		return
	}

	err = sigv4.Verify(sigv4.Input{
		Request:   r,
		Auth:      auth,
		Secret:    creds.SecretAccessKey,
		Region:    s.cfg.Security.Region,
		Service:   "s3",
		Now:       s.now(),
		ClockSkew: s.cfg.Security.SigV4ClockSkew.Std(),
	})
	// The §11.5 histogram covers the pure verification work (store lookup,
	// token compare, signature recompute) — not logging or header rewriting.
	s.metrics.observeVerification("sigv4", vstart)
	if err != nil {
		switch {
		case errors.Is(err, sigv4.ErrSkew):
			reject(http.StatusForbidden, "skew", s3err.CodeRequestTimeTooSkewed,
				"the difference between the request time and the server's time is too large")
		case errors.Is(err, sigv4.ErrScope):
			reject(http.StatusBadRequest, "scope", s3err.CodeAuthorizationHeaderMalformed, err.Error())
		case errors.Is(err, sigv4.ErrMissingDate):
			reject(http.StatusBadRequest, "missing_date", s3err.CodeMissingSecurityHeader,
				"the X-Amz-Date header is required")
		case errors.Is(err, sigv4.ErrMalformed):
			reject(http.StatusBadRequest, "malformed", s3err.CodeAuthorizationHeaderMalformed, err.Error())
		default:
			reject(http.StatusForbidden, "mismatch", s3err.CodeSignatureDoesNotMatch,
				"the request signature does not match the credentials")
		}
		return
	}

	s.metrics.sigv4Verifies.WithLabelValues("success").Inc()
	log.Info("sigv4 verified", "username", creds.Username, "issuer", creds.Issuer)

	s.applyIdentity(r, creds.Username, auth)
	s.proxy.ServeHTTP(w, r)
}

// servePresigned is the query-auth variant of the SigV4 lane (§6.3, M2):
// credentials travel in the query string and the fetch is typically done by a
// bare HTTP client (browser, curl) that knows nothing about SigV4. After
// verification the auth parameters are stripped and the synthetic header
// carries the identity upstream, exactly like the Bearer lane.
func (s *Server) servePresigned(w http.ResponseWriter, r *http.Request, reqID string, start time.Time) {
	defer s.metrics.observeDuration("presigned", start)
	vstart := time.Now()
	log := s.logger.With("request_id", reqID, "lane", "presigned", "method", r.Method, "path", r.URL.Path)

	reject := func(status int, result, code, message string) {
		s.metrics.presignedVerifies.WithLabelValues(result).Inc()
		log.Info("presigned rejected", "code", code, "detail", message)
		s3err.Write(w, status, code, message, r.URL.Path, reqID)
	}

	auth, err := sigv4.ParsePresigned(r)
	if err != nil {
		reject(http.StatusBadRequest, "malformed", s3err.CodeAuthorizationQueryParametersError, err.Error())
		return
	}
	log = log.With("access_key_id", auth.AccessKeyID)

	creds, found, err := s.store.Get(r.Context(), auth.AccessKeyID)
	if err != nil {
		reject(http.StatusInternalServerError, "store_error", s3err.CodeInternalError,
			"credential store unavailable")
		return
	}
	if !found {
		reject(http.StatusForbidden, "unknown_akid", s3err.CodeInvalidAccessKeyID,
			"the access key ID does not exist (exchange a token via AssumeRoleWithWebIdentity first)")
		return
	}
	if creds.Expired(s.now()) {
		reject(http.StatusForbidden, "expired", s3err.CodeExpiredToken,
			"the temporary credentials have expired")
		return
	}
	if subtle.ConstantTimeCompare([]byte(auth.SecurityToken), []byte(creds.SessionToken)) != 1 {
		reject(http.StatusForbidden, "bad_token", s3err.CodeInvalidToken,
			"the security token is missing or does not match the credentials")
		return
	}

	err = sigv4.VerifyPresigned(sigv4.PresignInput{
		Request:   r,
		Auth:      auth,
		Secret:    creds.SecretAccessKey,
		Region:    s.cfg.Security.Region,
		Service:   "s3",
		Now:       s.now(),
		ClockSkew: s.cfg.Security.SigV4ClockSkew.Std(),
	})
	s.metrics.observeVerification("presigned", vstart)
	if err != nil {
		switch {
		case errors.Is(err, sigv4.ErrPresignExpired):
			reject(http.StatusForbidden, "url_expired", s3err.CodeAccessDenied, "Request has expired")
		case errors.Is(err, sigv4.ErrSkew):
			reject(http.StatusForbidden, "skew", s3err.CodeRequestTimeTooSkewed,
				"the presigned URL is dated in the future")
		case errors.Is(err, sigv4.ErrScope), errors.Is(err, sigv4.ErrMalformed):
			reject(http.StatusBadRequest, "malformed", s3err.CodeAuthorizationQueryParametersError, err.Error())
		default:
			reject(http.StatusForbidden, "mismatch", s3err.CodeSignatureDoesNotMatch,
				"the request signature does not match the credentials")
		}
		return
	}

	s.metrics.presignedVerifies.WithLabelValues("success").Inc()
	log.Info("presigned verified", "username", creds.Username, "issuer", creds.Issuer)

	forward.StripPresignedQuery(r)
	s.applyIdentity(r, creds.Username, nil)
	s.proxy.ServeHTTP(w, r)
}

// serveUnauthenticated handles requests with no (or foreign) authentication.
func (s *Server) serveUnauthenticated(w http.ResponseWriter, r *http.Request, reqID string, start time.Time) {
	defer s.metrics.observeDuration("unauthenticated", start)
	log := s.logger.With("request_id", reqID, "lane", "none", "method", r.Method, "path", r.URL.Path)

	if s.cfg.DataPath.StrictEnabled() {
		log.Info("unauthenticated request rejected (strict mode)")
		s3err.Write(w, http.StatusForbidden, s3err.CodeAccessDenied,
			"authentication required: present a Bearer token or temporary SigV4 credentials", r.URL.Path, reqID)
		return
	}
	// Non-strict: pass through untouched. This trusts anyone who can reach the
	// proxy with whatever identity Ozone infers — for lab setups only.
	log.Warn("unauthenticated request forwarded (strict mode disabled)")
	s.proxy.ServeHTTP(w, r)
}

func mapBearerError(err error) (status int, code string) {
	switch {
	case errors.Is(err, oidc.ErrTokenExpired):
		return http.StatusForbidden, s3err.CodeExpiredToken
	case errors.Is(err, oidc.ErrIssuerUnavailable):
		return http.StatusServiceUnavailable, s3err.CodeServiceUnavailable
	default:
		return http.StatusForbidden, s3err.CodeAccessDenied
	}
}

func bearerErrorMessage(err error) string {
	switch {
	case errors.Is(err, oidc.ErrTokenExpired):
		return "the bearer token has expired"
	case errors.Is(err, oidc.ErrIssuerUnavailable):
		return "could not reach the identity provider"
	default:
		return "the bearer token was rejected"
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func newRequestID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "000000000000000000000000"
	}
	return hex.EncodeToString(buf)
}
