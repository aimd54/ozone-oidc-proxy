// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Command proxy runs ozone-oidc-proxy: OIDC STS token exchange, Bearer and
// SigV4 data-path authentication in front of an Apache Ozone S3 Gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/config"
	"github.com/aimd54/ozone-oidc-proxy/internal/oidc"
	"github.com/aimd54/ozone-oidc-proxy/internal/server"
	"github.com/aimd54/ozone-oidc-proxy/internal/store"
)

// version is stamped by the build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	configPath := flag.String("config",
		envOr("OZPX_CONFIG", "/etc/ozone-oidc-proxy/config.yaml"),
		"path to the YAML configuration file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("configuration rejected", "config", *configPath, "error", err.Error())
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := newStore(cfg)
	if err != nil {
		logger.Error("credential store init failed", "error", err.Error())
		os.Exit(1)
	}
	defer func() { _ = st.Close() }()

	validator, err := oidc.New(ctx, cfg)
	if err != nil {
		logger.Error("oidc validator init failed", "error", err.Error())
		os.Exit(1)
	}

	srv, err := server.New(cfg, validator, st, logger)
	if err != nil {
		logger.Error("server init failed", "error", err.Error())
		os.Exit(1)
	}

	mainSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: S3 GET/PUT streams can legitimately run long.
	}
	adminSrv := &http.Server{
		Addr:              cfg.AdminListen,
		Handler:           srv.AdminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() { errCh <- mainSrv.ListenAndServe() }()
	go func() { errCh <- adminSrv.ListenAndServe() }()

	logger.Info("ozone-oidc-proxy started",
		"version", version,
		"listen", cfg.Listen,
		"admin_listen", cfg.AdminListen,
		"upstream", cfg.Upstream.S3Endpoint,
		"forward_mode", cfg.Upstream.ForwardMode,
		"store", cfg.CredentialStore.Type,
		"strict", cfg.DataPath.StrictEnabled(),
		"accept_bearer", cfg.DataPath.BearerEnabled(),
		"issuers", len(cfg.Issuers),
	)

	select {
	case <-ctx.Done():
		logger.Info("signal received, shutting down")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listener failed", "error", err.Error())
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = mainSrv.Shutdown(shutdownCtx)
	_ = adminSrv.Shutdown(shutdownCtx)
}

// newStore builds the credential store per configuration. The valkey value
// key comes from the environment (never the config file); its value is never
// logged.
func newStore(cfg *config.Config) (store.Store, error) {
	switch cfg.CredentialStore.Type {
	case config.StoreValkey:
		vk := cfg.CredentialStore.Valkey
		raw := os.Getenv(vk.KeyEnv)
		if raw == "" {
			return nil, fmt.Errorf("credential_store.type %q requires the %s environment variable (32-byte base64 key)",
				config.StoreValkey, vk.KeyEnv)
		}
		key, err := store.ParseStoreKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", vk.KeyEnv, err)
		}
		return store.NewValkey(vk.Addr, key)
	default:
		return store.NewMemory(), nil
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
