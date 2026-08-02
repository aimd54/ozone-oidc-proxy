// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Command credential-portal is the human path to temporary S3 credentials
// (DESIGN.md §11.4): it runs behind oauth2-proxy, which handles the OIDC
// browser login and forwards the user's access token; the portal exchanges
// that token at the proxy's STS endpoint and renders the credentials with
// copy-paste recipes. It replaces ROPC (curl with a password) for humans.
//
// Configuration is environment-only:
//
//	PORTAL_LISTEN           listen address        (default :8090)
//	PORTAL_STS_ENDPOINT     proxy STS URL         (default http://proxy:9000)
//	PORTAL_ROLE_ARN         RoleArn to assume     (default arn:ozone:iam::dev:role/oidc)
//	PORTAL_PUBLIC_ENDPOINT  endpoint shown in the recipes (default http://localhost:9000)
//
// Secrets are rendered to the authenticated requester only and never logged.
package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// version is stamped by the build (-ldflags "-X main.version=...").
var version = "dev"

type portal struct {
	stsEndpoint    string
	roleArn        string
	publicEndpoint string
	client         *http.Client
	logger         *slog.Logger
}

// stsCredentials mirrors the fields of the AssumeRoleWithWebIdentity
// response the page needs (the proxy's XML shape, internal/sts).
type stsCredentials struct {
	AccessKeyID     string `xml:"AssumeRoleWithWebIdentityResult>Credentials>AccessKeyId"`
	SecretAccessKey string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SecretAccessKey"`
	SessionToken    string `xml:"AssumeRoleWithWebIdentityResult>Credentials>SessionToken"`
	Expiration      string `xml:"AssumeRoleWithWebIdentityResult>Credentials>Expiration"`
	Subject         string `xml:"AssumeRoleWithWebIdentityResult>SubjectFromWebIdentityToken"`
}

type stsError struct {
	Code    string `xml:"Error>Code"`
	Message string `xml:"Error>Message"`
}

func main() {
	p := &portal{
		stsEndpoint:    envOr("PORTAL_STS_ENDPOINT", "http://proxy:9000"),
		roleArn:        envOr("PORTAL_ROLE_ARN", "arn:ozone:iam::dev:role/oidc"),
		publicEndpoint: envOr("PORTAL_PUBLIC_ENDPOINT", "http://localhost:9000"),
		client:         &http.Client{Timeout: 10 * time.Second},
		logger:         slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
	listen := envOr("PORTAL_LISTEN", ":8090")

	srv := &http.Server{
		Addr:              listen,
		Handler:           p.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	p.logger.Info("credential-portal started",
		"version", version, "listen", listen,
		"sts_endpoint", p.stsEndpoint, "role_arn", p.roleArn)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		p.logger.Error("listener failed", "error", err.Error())
		os.Exit(1)
	}
}

func (p *portal) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/", p.serveHome)
	return mux
}

func (p *portal) serveHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	token := bearerToken(r)
	if token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		renderPage(w, pageData{Error: "No identity token on the request. This page must be reached through oauth2-proxy (browser sign-in)."})
		return
	}
	username := sessionName(r)

	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {p.roleArn},
		"RoleSessionName":  {username},
		"WebIdentityToken": {token},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.stsEndpoint+"/", strings.NewReader(form.Encode()))
	if err != nil {
		p.fail(w, "building the STS request failed", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		p.fail(w, "the STS endpoint is unreachable", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		p.fail(w, "reading the STS response failed", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		var e stsError
		_ = xml.Unmarshal(body, &e)
		p.logger.Info("exchange rejected", "user", username, "code", e.Code, "status", resp.StatusCode)
		w.WriteHeader(http.StatusBadGateway)
		renderPage(w, pageData{Error: fmt.Sprintf(
			"The token exchange was rejected (%s): %s", orUnknown(e.Code), e.Message)})
		return
	}
	var creds stsCredentials
	if err := xml.Unmarshal(body, &creds); err != nil || creds.AccessKeyID == "" {
		p.fail(w, "the STS response could not be parsed", err)
		return
	}
	p.logger.Info("credentials minted", "user", username, "subject", creds.Subject, "access_key_id", creds.AccessKeyID)

	renderPage(w, pageData{
		Username:   username,
		Endpoint:   p.publicEndpoint,
		Creds:      creds,
		Expiration: creds.Expiration,
	})
}

func (p *portal) fail(w http.ResponseWriter, msg string, err error) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	p.logger.Error(msg, "error", detail)
	w.WriteHeader(http.StatusBadGateway)
	renderPage(w, pageData{Error: msg})
}

// bearerToken extracts the user's access token: oauth2-proxy forwards it as
// X-Forwarded-Access-Token; a direct Bearer header also works (testing).
func bearerToken(r *http.Request) string {
	if t := r.Header.Get("X-Forwarded-Access-Token"); t != "" {
		return t
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

// sessionName derives an STS-safe RoleSessionName from oauth2-proxy's user
// headers ([A-Za-z0-9_=,.@-], 2..64 chars — internal/sts enforces the same).
func sessionName(r *http.Request) string {
	raw := r.Header.Get("X-Forwarded-Preferred-Username")
	if raw == "" {
		raw = r.Header.Get("X-Forwarded-User")
	}
	var b strings.Builder
	for i := 0; i < len(raw) && b.Len() < 64; i++ {
		c := raw[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '_', c == '=', c == ',', c == '.', c == '@', c == '-':
			b.WriteByte(c)
		}
	}
	if b.Len() < 2 {
		return "portal"
	}
	return b.String()
}

type pageData struct {
	Username   string
	Endpoint   string
	Creds      stsCredentials
	Expiration string
	Error      string
}

func renderPage(w http.ResponseWriter, d pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = page.Execute(w, d)
}

var page = template.Must(template.New("portal").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ozone S3 credentials</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 62rem; margin: 3rem auto; padding: 0 1rem; color: #1a2333; }
  h1 { font-size: 1.4rem; } h2 { font-size: 1.05rem; margin-top: 2rem; }
  pre { background: #f4f6fa; border: 1px solid #d8dee9; border-radius: 6px; padding: .8rem 1rem; overflow-x: auto; }
  table { border-collapse: collapse; } td { padding: .25rem .8rem .25rem 0; vertical-align: top; }
  td:first-child { color: #5a6578; white-space: nowrap; }
  code { word-break: break-all; }
  .err { background: #fdf2f2; border: 1px solid #e8b4b4; border-radius: 6px; padding: 1rem; }
  .note { color: #5a6578; font-size: .9rem; }
  a.again { display: inline-block; margin-top: 1.5rem; }
</style>
</head>
<body>
<h1>Ozone S3 temporary credentials</h1>
{{if .Error}}
<div class="err">{{.Error}}</div>
<a class="again" href="/">Try again</a>
{{else}}
<p>Minted for <strong>{{.Username}}</strong> — valid until <strong>{{.Expiration}}</strong>. Reload to mint a fresh set.</p>
<table>
  <tr><td>AccessKeyId</td><td><code>{{.Creds.AccessKeyID}}</code></td></tr>
  <tr><td>SecretAccessKey</td><td><code>{{.Creds.SecretAccessKey}}</code></td></tr>
  <tr><td>SessionToken</td><td><code>{{.Creds.SessionToken}}</code></td></tr>
</table>
<h2>Shell</h2>
<pre>export AWS_ACCESS_KEY_ID={{.Creds.AccessKeyID}}
export AWS_SECRET_ACCESS_KEY={{.Creds.SecretAccessKey}}
export AWS_SESSION_TOKEN={{.Creds.SessionToken}}
export AWS_ENDPOINT_URL_S3={{.Endpoint}}</pre>
<h2>~/.aws/credentials</h2>
<pre>[ozone]
aws_access_key_id     = {{.Creds.AccessKeyID}}
aws_secret_access_key = {{.Creds.SecretAccessKey}}
aws_session_token     = {{.Creds.SessionToken}}</pre>
<p class="note">Then: <code>aws s3 ls --profile ozone --endpoint-url {{.Endpoint}}</code></p>
<p class="note">Prefer long-lived automation? Use <code>ozone-login</code> (device flow) instead of copying credentials.</p>
{{end}}
</body>
</html>
`))

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
