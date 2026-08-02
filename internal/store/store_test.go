// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMintFormats(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	c, err := Mint("alice", "keycloak", exp)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !regexp.MustCompile(`^OZPX[0-9ABCDEFGHJKMNPQRSTVWXYZ]{16}$`).MatchString(c.AccessKeyID) {
		t.Errorf("AKID %q not OZPX + 16 Crockford-base32 chars", c.AccessKeyID)
	}
	if len(c.SecretAccessKey) != 40 || strings.ContainsAny(c.SecretAccessKey, "+/=") {
		t.Errorf("secret %q not 40 base64url chars", c.SecretAccessKey)
	}
	if len(c.SessionToken) != 43 || strings.ContainsAny(c.SessionToken, "+/=") {
		t.Errorf("session token %q not 43 base64url chars", c.SessionToken)
	}
	if c.Username != "alice" || c.Issuer != "keycloak" || !c.ExpiresAt.Equal(exp) {
		t.Errorf("metadata not carried: %+v", c)
	}
}

func TestMintUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		c, err := Mint("u", "i", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if seen[c.AccessKeyID] {
			t.Fatalf("duplicate AKID after %d mints", i)
		}
		seen[c.AccessKeyID] = true
	}
}

func TestMemoryPutGetDelete(t *testing.T) {
	m := NewMemory()
	defer func() { _ = m.Close() }()
	ctx := context.Background()

	c, _ := Mint("alice", "kc", time.Now().Add(time.Hour))
	if err := m.Put(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, ok, err := m.Get(ctx, c.AccessKeyID)
	if err != nil || !ok || got.SecretAccessKey != c.SecretAccessKey {
		t.Fatalf("Get = %+v, %v, %v", got, ok, err)
	}
	if _, ok, _ := m.Get(ctx, "OZPXDOESNOTEXIST0000"); ok {
		t.Error("Get of unknown AKID reported found")
	}
	if n, _ := m.Count(ctx); n != 1 {
		t.Errorf("Count = %d, want 1", n)
	}
	if err := m.Delete(ctx, c.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.Get(ctx, c.AccessKeyID); ok {
		t.Error("Get after Delete reported found")
	}
}

func TestMemoryExpiryVisibleUntilSwept(t *testing.T) {
	start := time.Now()
	// The sweeper goroutine reads the clock while this test advances it, so
	// the shared instant has to be atomic (go test -race).
	var nowNanos atomic.Int64
	nowNanos.Store(start.UnixNano())
	clock := func() time.Time { return time.Unix(0, nowNanos.Load()) }

	m := NewMemory(WithSweepInterval(10*time.Millisecond), WithRetention(30*time.Minute), WithClock(clock))
	defer func() { _ = m.Close() }()
	ctx := context.Background()

	c, _ := Mint("alice", "kc", start.Add(-time.Minute)) // already expired
	_ = m.Put(ctx, c)

	got, ok, _ := m.Get(ctx, c.AccessKeyID)
	if !ok || !got.Expired(start) {
		t.Fatalf("expired record must stay visible before retention: ok=%v expired=%v", ok, got.Expired(start))
	}
	if n, _ := m.Count(ctx); n != 0 {
		t.Errorf("Count must exclude expired records, got %d", n)
	}

	// Move past the retention window; the sweeper must drop the record.
	nowNanos.Store(start.Add(31 * time.Minute).UnixNano())
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok, _ := m.Get(ctx, c.AccessKeyID); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sweeper did not remove expired record within retention+2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
