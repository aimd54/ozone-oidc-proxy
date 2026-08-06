// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package devicelogin implements the OAuth 2.0 Device Authorization Grant
// (RFC 8628) against an OIDC issuer, plus token refresh, the guts of the
// ozone-login helper that keeps AWS_WEB_IDENTITY_TOKEN_FILE fresh
// Only the access token ever touches disk; refresh tokens
// stay in process memory.
package devicelogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Typed outcomes of the device-flow conversation.
var (
	// ErrAccessDenied: the user rejected the authorization request.
	ErrAccessDenied = errors.New("authorization request denied")
	// ErrExpired: the device code expired before the user approved it.
	ErrExpired = errors.New("device code expired before approval")
	// ErrSessionExpired: the refresh token is no longer valid.
	ErrSessionExpired = errors.New("session expired, sign in again")
)

// Client drives the device flow against one issuer.
type Client struct {
	Issuer   string // e.g. https://idp.example.com
	ClientID string
	Scope    string // "openid" is enough for the proxy's STS

	HTTP  *http.Client
	Sleep func(time.Duration) // injectable for tests
	Now   func() time.Time
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) sleep(d time.Duration) {
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Endpoints is the slice of OIDC discovery the device flow needs.
type Endpoints struct {
	DeviceAuthorization string `json:"device_authorization_endpoint"`
	Token               string `json:"token_endpoint"`
}

// DeviceAuth is the RFC 8628 device authorization response.
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Token is a token-endpoint success response.
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// oauthError is a token-endpoint error response (RFC 6749 §5.2).
type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *oauthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Discover fetches the issuer's OIDC configuration.
func (c *Client) Discover(ctx context.Context) (Endpoints, error) {
	var ep Endpoints
	u := strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ep, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return ep, fmt.Errorf("OIDC discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ep, fmt.Errorf("OIDC discovery: %s returned %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ep); err != nil {
		return ep, fmt.Errorf("OIDC discovery: %w", err)
	}
	if ep.DeviceAuthorization == "" {
		return ep, fmt.Errorf("issuer %s does not advertise device_authorization_endpoint", c.Issuer)
	}
	if ep.Token == "" {
		return ep, fmt.Errorf("issuer %s does not advertise token_endpoint", c.Issuer)
	}
	return ep, nil
}

// Start begins the device flow: the response carries the URL and code to
// show the user.
func (c *Client) Start(ctx context.Context, ep Endpoints) (DeviceAuth, error) {
	var da DeviceAuth
	form := url.Values{"client_id": {c.ClientID}}
	if c.Scope != "" {
		form.Set("scope", c.Scope)
	}
	if err := c.postForm(ctx, ep.DeviceAuthorization, form, &da); err != nil {
		return da, fmt.Errorf("device authorization: %w", err)
	}
	if da.DeviceCode == "" || da.UserCode == "" {
		return da, errors.New("device authorization: response missing device_code/user_code")
	}
	return da, nil
}

// Poll waits for the user to approve the device and returns the tokens.
// It honors the server's polling interval, slow_down responses, and the
// device-code lifetime.
func (c *Client) Poll(ctx context.Context, ep Endpoints, da DeviceAuth) (Token, error) {
	interval := time.Duration(max(da.Interval, 1)) * time.Second
	deadline := c.now().Add(time.Duration(da.ExpiresIn) * time.Second)
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {da.DeviceCode},
		"client_id":   {c.ClientID},
	}
	for {
		if err := ctx.Err(); err != nil {
			return Token{}, err
		}
		if da.ExpiresIn > 0 && c.now().After(deadline) {
			return Token{}, ErrExpired
		}
		c.sleep(interval)

		var tok Token
		err := c.postForm(ctx, ep.Token, form, &tok)
		if err == nil {
			if tok.AccessToken == "" {
				return Token{}, errors.New("token endpoint returned no access_token")
			}
			return tok, nil
		}
		var oe *oauthError
		if !errors.As(err, &oe) {
			return Token{}, err
		}
		switch oe.Code {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return Token{}, ErrAccessDenied
		case "expired_token":
			return Token{}, ErrExpired
		default:
			return Token{}, err
		}
	}
}

// Refresh exchanges a refresh token for a new token pair.
func (c *Client) Refresh(ctx context.Context, ep Endpoints, refreshToken string) (Token, error) {
	var tok Token
	err := c.postForm(ctx, ep.Token, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {c.ClientID},
	}, &tok)
	if err != nil {
		var oe *oauthError
		if errors.As(err, &oe) && oe.Code == "invalid_grant" {
			return tok, ErrSessionExpired
		}
		return tok, fmt.Errorf("token refresh: %w", err)
	}
	if tok.AccessToken == "" {
		return tok, errors.New("token refresh: response missing access_token")
	}
	return tok, nil
}

// postForm posts a form and decodes JSON; non-2xx with an OAuth error body
// becomes an *oauthError.
func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var oe oauthError
		if json.Unmarshal(body, &oe) == nil && oe.Code != "" {
			return &oe
		}
		return fmt.Errorf("%s returned %d", endpoint, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// WriteTokenFile writes the access token where AWS_WEB_IDENTITY_TOKEN_FILE
// points: parent directory 0700, file 0600, atomic rename so SDKs never read
// a half-written token.
func WriteTokenFile(path, accessToken string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(accessToken); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
