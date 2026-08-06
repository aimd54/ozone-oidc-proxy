// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Command ozone-login signs a human in via the OAuth 2.0 device flow and
// keeps a web-identity token file fresh: point
// AWS_WEB_IDENTITY_TOKEN_FILE at the file it maintains and every AWS
// SDK/CLI exchanges it against the proxy's STS endpoint automatically.
//
//	ozone-login -issuer https://idp.example.com
//
// The refresh loop runs until interrupted; -once writes the first token and
// exits (cron-style usage).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/devicelogin"
)

// version is stamped by the build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	issuer := flag.String("issuer", os.Getenv("OZONE_ISSUER"),
		"OIDC issuer URL (env OZONE_ISSUER), e.g. https://idp.example.com")
	clientID := flag.String("client-id", envOr("OZONE_CLIENT_ID", "ozone-s3"),
		"OIDC client ID with the device grant enabled (env OZONE_CLIENT_ID)")
	tokenFile := flag.String("token-file", defaultTokenFile(),
		"where to write the access token (defaults to $AWS_WEB_IDENTITY_TOKEN_FILE, else ~/.ozone/token.jwt)")
	scope := flag.String("scope", "openid", "OAuth scope to request")
	once := flag.Bool("once", false, "exit after the first token instead of running the refresh loop")
	roleArn := flag.String("role-arn", "arn:ozone:iam::dev:role/oidc",
		"RoleArn to print in the setup recipe (must be in the proxy's allowlist)")
	endpoint := flag.String("endpoint", "http://localhost:9000",
		"proxy endpoint to print in the setup recipe")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ozone-login", version)
		return
	}
	if *issuer == "" {
		fmt.Fprintln(os.Stderr, "ozone-login: -issuer (or OZONE_ISSUER) is required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := &devicelogin.Client{Issuer: *issuer, ClientID: *clientID, Scope: *scope}
	ep, err := client.Discover(ctx)
	if err != nil {
		fail(err)
	}
	da, err := client.Start(ctx, ep)
	if err != nil {
		fail(err)
	}

	fmt.Println("Open this URL in your browser to sign in:")
	fmt.Println()
	if da.VerificationURIComplete != "" {
		fmt.Printf("    %s\n", da.VerificationURIComplete)
	} else {
		fmt.Printf("    %s   (code: %s)\n", da.VerificationURI, da.UserCode)
	}
	fmt.Println()
	fmt.Println("Waiting for approval...")

	tok, err := client.Poll(ctx, ep, da)
	if err != nil {
		fail(err)
	}
	if err := devicelogin.WriteTokenFile(*tokenFile, tok.AccessToken); err != nil {
		fail(err)
	}
	fmt.Printf("Signed in. Token written to %s (expires in %s).\n\n",
		*tokenFile, (time.Duration(tok.ExpiresIn) * time.Second).Round(time.Second))
	fmt.Println("Point AWS tooling at the proxy:")
	fmt.Printf("  export AWS_ROLE_ARN=%s\n", *roleArn)
	fmt.Printf("  export AWS_WEB_IDENTITY_TOKEN_FILE=%s\n", *tokenFile)
	fmt.Printf("  export AWS_ENDPOINT_URL_STS=%s\n", *endpoint)
	fmt.Printf("  export AWS_ENDPOINT_URL_S3=%s\n", *endpoint)
	fmt.Println()

	if *once {
		return
	}

	fmt.Println("Refreshing the token in the background; leave this running (Ctrl-C to stop).")
	refresh := tok.RefreshToken
	expiresIn := tok.ExpiresIn
	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nozone-login: stopped")
			return
		case <-time.After(refreshAfter(expiresIn)):
		}
		tok, err = client.Refresh(ctx, ep, refresh)
		if err != nil {
			if errors.Is(err, devicelogin.ErrSessionExpired) {
				fmt.Fprintln(os.Stderr, "ozone-login: session expired; run ozone-login again")
				os.Exit(1)
			}
			// Transient (IdP restart, network): retry on a short fuse rather
			// than dying with a stale-but-maybe-still-valid token on disk.
			fmt.Fprintf(os.Stderr, "ozone-login: refresh failed (%v), retrying in 30s\n", err)
			expiresIn = 45
			continue
		}
		if tok.RefreshToken != "" {
			refresh = tok.RefreshToken
		}
		expiresIn = tok.ExpiresIn
		if err := devicelogin.WriteTokenFile(*tokenFile, tok.AccessToken); err != nil {
			fail(err)
		}
		fmt.Printf("Token refreshed (next in %s).\n", refreshAfter(expiresIn).Round(time.Second))
	}
}

// refreshAfter schedules the refresh at two thirds of the token lifetime,
// with a floor so a misbehaving IdP cannot make the loop spin.
func refreshAfter(expiresIn int) time.Duration {
	d := time.Duration(expiresIn) * time.Second * 2 / 3
	if d < 15*time.Second {
		return 15 * time.Second
	}
	return d
}

func defaultTokenFile() string {
	if v := os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "token.jwt"
	}
	return filepath.Join(home, ".ozone", "token.jwt")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "ozone-login:", err)
	os.Exit(1)
}
