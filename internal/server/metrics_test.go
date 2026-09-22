// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/aimd54/ozone-oidc-proxy/internal/store"
)

// samples parses a text exposition into sample values keyed by series, so a
// test can assert an exact value where a substring would also match another.
func samples(t *testing.T, exposition string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(exposition, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			t.Fatalf("unparseable exposition line %q", line)
		}
		out[line[:i]] = line[i+1:]
	}
	return out
}

// render exposes a collector the way the admin listener does.
func render(c prometheus.Collector) string {
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func expose(t *testing.T, c prometheus.Collector) map[string]string {
	t.Helper()
	return samples(t, render(c))
}

// unreadableStore is a credential store whose every call fails, standing in
// for a valkey that has gone away.
type unreadableStore struct{}

var errStoreDown = errors.New("store unreachable")

func (unreadableStore) Put(context.Context, store.Credentials) error { return errStoreDown }
func (unreadableStore) Get(context.Context, string) (store.Credentials, bool, error) {
	return store.Credentials{}, false, errStoreDown
}
func (unreadableStore) Delete(context.Context, string) error { return errStoreDown }
func (unreadableStore) Count(context.Context) (int, error)   { return 0, errStoreDown }
func (unreadableStore) Close() error                         { return nil }

// hangingStore answers nothing until the caller gives up, standing in for a
// store whose packets are being dropped.
type hangingStore struct{ unreadableStore }

func (hangingStore) Count(ctx context.Context) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestStoreCollector(t *testing.T) {
	t.Run("a readable store reports its live credentials", func(t *testing.T) {
		mem := store.NewMemory()
		t.Cleanup(func() { _ = mem.Close() })
		for _, user := range []string{"alice", "bob"} {
			creds, err := store.Mint(user, "keycloak", time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if err := mem.Put(context.Background(), creds); err != nil {
				t.Fatal(err)
			}
		}
		got := expose(t, newStoreCollector(mem, time.Second))
		if got["credential_store_up"] != "1" {
			t.Errorf("credential_store_up = %q, want 1", got["credential_store_up"])
		}
		if got["active_credentials"] != "2" {
			t.Errorf("active_credentials = %q, want 2", got["active_credentials"])
		}
	})

	// The defect this collector exists to prevent: a store that could not be
	// read was reported as a store with nothing in it, a plausible value that
	// would alert nobody.
	t.Run("an unreadable store is reported down, not empty", func(t *testing.T) {
		got := expose(t, newStoreCollector(unreadableStore{}, time.Second))
		if got["credential_store_up"] != "0" {
			t.Errorf("credential_store_up = %q, want 0", got["credential_store_up"])
		}
		if v, ok := got["active_credentials"]; ok {
			t.Errorf("active_credentials = %s for a store that could not be read", v)
		}
	})

	// A store that never answers must still produce an answer inside the
	// scrape. Otherwise the scrape itself times out and the proxy reads as
	// down, which sends whoever responds to the wrong component.
	t.Run("a hanging store is reported down before the scrape gives up", func(t *testing.T) {
		done := make(chan string, 1)
		go func() { done <- render(newStoreCollector(hangingStore{}, 50*time.Millisecond)) }()
		select {
		case exposition := <-done:
			got := samples(t, exposition)
			if got["credential_store_up"] != "0" {
				t.Errorf("credential_store_up = %q, want 0", got["credential_store_up"])
			}
		case <-time.After(5 * time.Second):
			t.Fatal("collection has not returned after 5s: the store read is not bounded")
		}
	})
}
