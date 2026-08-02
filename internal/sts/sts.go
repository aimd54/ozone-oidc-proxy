// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package sts implements the AssumeRoleWithWebIdentity token exchange
// (architecture.md, "STS"): validate an OIDC JWT, mint temporary credentials bound to
// the mapped username, and answer with AWS-shaped XML so stock AWS SDKs and
// CLIs work unchanged.
package sts

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/config"
	"github.com/aimd54/ozone-oidc-proxy/internal/oidc"
	"github.com/aimd54/ozone-oidc-proxy/internal/store"
)

// Action is the only STS action implemented.
const Action = "AssumeRoleWithWebIdentity"

// TokenValidator is the slice of oidc.Validator the handler needs.
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (*oidc.Identity, error)
}

// Result lets the caller observe exchanges (metrics).
type Result struct {
	Issuer string
	Code   string // "" on success, AWS error code otherwise
}

// Handler serves POST / with Action=AssumeRoleWithWebIdentity.
type Handler struct {
	Validator TokenValidator
	Store     store.Store
	STS       config.STS
	Logger    *slog.Logger
	Now       func() time.Time
	// OnExchange, if set, is called once per exchange attempt.
	OnExchange func(Result)
}

// roleSessionNamePattern mirrors AWS's constraint on RoleSessionName.
var roleSessionNamePattern = regexp.MustCompile(`^[\w+=,.@-]{2,64}$`)

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) done(issuer, code string) {
	if h.OnExchange != nil {
		h.OnExchange(Result{Issuer: issuer, Code: code})
	}
}

// ServeHTTP handles one token exchange.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := newRequestID()
	log := h.Logger.With("request_id", reqID, "handler", "sts")

	if r.Method != http.MethodPost {
		h.done("", codeValidationError)
		writeError(w, http.StatusMethodNotAllowed, codeValidationError, "only POST is supported", reqID)
		return
	}
	if err := r.ParseForm(); err != nil {
		h.done("", codeValidationError)
		writeError(w, http.StatusBadRequest, codeValidationError, "malformed form body", reqID)
		return
	}
	if got := r.PostForm.Get("Action"); got != Action {
		h.done("", codeValidationError)
		writeError(w, http.StatusBadRequest, codeValidationError,
			fmt.Sprintf("unsupported Action %q", got), reqID)
		return
	}

	token := r.PostForm.Get("WebIdentityToken")
	if token == "" {
		h.done("", codeValidationError)
		writeError(w, http.StatusBadRequest, codeValidationError, "WebIdentityToken is required", reqID)
		return
	}
	roleArn := r.PostForm.Get("RoleArn")
	if roleArn == "" {
		h.done("", codeValidationError)
		writeError(w, http.StatusBadRequest, codeValidationError, "RoleArn is required", reqID)
		return
	}
	if len(h.STS.RoleARNAllowlist) > 0 && !contains(h.STS.RoleARNAllowlist, roleArn) {
		h.done("", codeAccessDenied)
		writeError(w, http.StatusForbidden, codeAccessDenied,
			fmt.Sprintf("RoleArn %q is not allowed", roleArn), reqID)
		return
	}
	sessionName := r.PostForm.Get("RoleSessionName")
	if sessionName == "" {
		sessionName = "web-identity"
	}
	if !roleSessionNamePattern.MatchString(sessionName) {
		h.done("", codeValidationError)
		writeError(w, http.StatusBadRequest, codeValidationError, "invalid RoleSessionName", reqID)
		return
	}
	requested := 0
	if v := r.PostForm.Get("DurationSeconds"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			h.done("", codeValidationError)
			writeError(w, http.StatusBadRequest, codeValidationError, "invalid DurationSeconds", reqID)
			return
		}
		requested = n
	}

	identity, err := h.Validator.Validate(r.Context(), token)
	if err != nil {
		code, status := mapTokenError(err)
		h.done("", code)
		log.Info("token exchange rejected", "error", err.Error(), "code", code)
		writeError(w, status, code, publicTokenErrorMessage(err), reqID)
		return
	}

	// Effective TTL = min(jwt.exp − now, DurationSeconds, sts.max_duration).
	now := h.now()
	ttl := identity.Expiry.Sub(now)
	if max := time.Duration(h.STS.MaxDuration) * time.Second; ttl > max {
		ttl = max
	}
	if requested > 0 {
		if req := time.Duration(requested) * time.Second; ttl > req {
			ttl = req
		}
	}
	if ttl <= 0 {
		h.done(identity.IssuerName, codeExpiredToken)
		writeError(w, http.StatusBadRequest, codeExpiredToken, "web identity token is expired", reqID)
		return
	}

	creds, err := store.Mint(identity.Username, identity.IssuerName, now.Add(ttl))
	if err != nil {
		h.done(identity.IssuerName, codeServiceFailure)
		log.Error("minting failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, codeServiceFailure, "credential minting failed", reqID)
		return
	}
	if err := h.Store.Put(r.Context(), creds); err != nil {
		h.done(identity.IssuerName, codeServiceFailure)
		log.Error("credential store put failed", "error", err.Error())
		writeError(w, http.StatusInternalServerError, codeServiceFailure, "credential store unavailable", reqID)
		return
	}

	h.done(identity.IssuerName, "")
	log.Info("token exchange succeeded",
		"username", identity.Username,
		"issuer", identity.IssuerName,
		"access_key_id", creds.AccessKeyID,
		"role_arn", roleArn,
		"role_session_name", sessionName,
		"expires_at", creds.ExpiresAt.UTC().Format(time.RFC3339),
	)
	writeSuccess(w, successData{
		Subject:     identity.Subject,
		Provider:    identity.IssuerURL,
		RoleArn:     roleArn,
		SessionName: sessionName,
		Creds:       creds,
		RequestID:   reqID,
	})
}

// mapTokenError converts oidc errors to (AWS error code, HTTP status).
func mapTokenError(err error) (string, int) {
	switch {
	case errors.Is(err, oidc.ErrTokenExpired):
		return codeExpiredToken, http.StatusBadRequest
	case errors.Is(err, oidc.ErrIssuerUnavailable):
		return codeIDPCommunicationError, http.StatusBadRequest
	default:
		return codeInvalidIdentityToken, http.StatusBadRequest
	}
}

// publicTokenErrorMessage keeps internal detail out of client-facing XML while
// remaining actionable.
func publicTokenErrorMessage(err error) string {
	switch {
	case errors.Is(err, oidc.ErrTokenExpired):
		return "web identity token is expired"
	case errors.Is(err, oidc.ErrIssuerUnavailable):
		return "could not reach the identity provider"
	case errors.Is(err, oidc.ErrUnknownIssuer):
		return "token issuer is not trusted"
	case errors.Is(err, oidc.ErrBadUsername):
		return "token username is not acceptable"
	default:
		return "web identity token could not be validated"
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
