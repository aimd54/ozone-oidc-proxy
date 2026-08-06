// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseStoreKey(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if _, err := ParseStoreKey(good); err != nil {
		t.Fatalf("ParseStoreKey(valid) = %v", err)
	}
	for name, in := range map[string]string{
		"not base64":  "!!!",
		"wrong size":  base64.StdEncoding.EncodeToString([]byte("short")),
		"empty input": "",
	} {
		if _, err := ParseStoreKey(in); err == nil {
			t.Errorf("ParseStoreKey(%s) accepted", name)
		}
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	aead, err := newAEAD(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"secret":"do-not-leak"}`)
	aad := []byte("OZPXAAAAAAAAAAAAAAAA")
	sealed, err := seal(aead, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("do-not-leak")) {
		t.Fatal("sealed value contains plaintext")
	}
	got, err := open(aead, sealed, aad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open(seal(x)) = %q, %v", got, err)
	}

	// Tampering, wrong keys and a wrong AAD (a record grafted onto another
	// store key) must fail, and short inputs must not panic.
	sealed[len(sealed)-1] ^= 1
	if _, err := open(aead, sealed, aad); err == nil {
		t.Error("tampered value decrypted")
	}
	sealed[len(sealed)-1] ^= 1
	other, _ := newAEAD(bytes.Repeat([]byte{2}, 32))
	if _, err := open(other, sealed, aad); err == nil {
		t.Error("wrong key decrypted")
	}
	if _, err := open(aead, sealed, []byte("OZPXBBBBBBBBBBBBBBBB")); err == nil {
		t.Error("record decrypted under a different AKID (AAD not enforced)")
	}
	if _, err := open(aead, []byte("tiny"), aad); err == nil {
		t.Error("short value accepted")
	}
}

// liveValkey returns a store connected to OZPX_TEST_VALKEY_ADDR, or skips.
// (The HA e2e exercises this against the compose stack; this test allows a
// quick local run: docker run --rm -p 6379:6379 valkey/valkey &&
// OZPX_TEST_VALKEY_ADDR=localhost:6379 go test ./internal/store/)
func liveValkey(t *testing.T, opts ...ValkeyOption) *Valkey {
	t.Helper()
	addr := os.Getenv("OZPX_TEST_VALKEY_ADDR")
	if addr == "" {
		t.Skip("set OZPX_TEST_VALKEY_ADDR to run live valkey tests")
	}
	v, err := NewValkey(addr, bytes.Repeat([]byte{9}, 32), opts...)
	if err != nil {
		t.Fatalf("NewValkey: %v", err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func TestValkeyLiveRoundTrip(t *testing.T) {
	v := liveValkey(t)
	ctx := context.Background()

	creds, err := Mint("alice", "keycloak", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, creds); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() { _ = v.Delete(ctx, creds.AccessKeyID) })

	got, found, err := v.Get(ctx, creds.AccessKeyID)
	if err != nil || !found {
		t.Fatalf("Get = found=%v, err=%v", found, err)
	}
	// Field-wise compare: JSON strips the monotonic clock from ExpiresAt.
	if got.AccessKeyID != creds.AccessKeyID || got.SecretAccessKey != creds.SecretAccessKey ||
		got.SessionToken != creds.SessionToken || got.Username != creds.Username ||
		got.Issuer != creds.Issuer || !got.ExpiresAt.Equal(creds.ExpiresAt) {
		t.Errorf("Get = %+v, want %+v", got, creds)
	}

	// The raw stored value must not contain any secret material.
	raw, err := v.client.Do(ctx, v.client.B().Get().Key(valkeyPrefix+creds.AccessKeyID).Build()).AsBytes()
	if err != nil {
		t.Fatalf("raw GET: %v", err)
	}
	for _, needle := range []string{creds.SecretAccessKey, creds.SessionToken, "alice"} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("stored value contains plaintext %q", needle)
		}
	}

	// The record is AAD-bound to its AKID: grafting the raw ciphertext onto
	// another key must fail decryption, not impersonate.
	grafted := "OZPXGRAFTEDRECORD000"
	if err := v.client.Do(ctx, v.client.B().Set().Key(valkeyPrefix+grafted).
		Value(string(raw)).Build()).Error(); err != nil {
		t.Fatalf("raw SET: %v", err)
	}
	t.Cleanup(func() { _ = v.Delete(ctx, grafted) })
	if _, _, err := v.Get(ctx, grafted); err == nil {
		t.Error("grafted record decrypted under a different AKID")
	}

	if n, err := v.Count(ctx); err != nil || n < 1 {
		t.Errorf("Count = %d, %v; want >= 1", n, err)
	}
	if _, found, _ := v.Get(ctx, "OZPXDOESNOTEXIST0000"); found {
		t.Error("Get(unknown) reported found")
	}
	if err := v.Delete(ctx, creds.AccessKeyID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	waitGone(t, v, creds.AccessKeyID, "record still found after Delete")
}

// waitGone polls until akid disappears from the store's view; the CSC
// invalidation push after DEL is asynchronous (milliseconds).
func waitGone(t *testing.T, v *Valkey, akid, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, found, err := v.Get(context.Background(), akid)
		if err != nil {
			t.Fatalf("Get while polling: %v", err)
		}
		if !found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestValkeyLiveInvalidation proves the design point: a Delete through
// one client invalidates another client's local cache (server-assisted CSC),
// so revocation propagates across replicas within the invalidation push, not
// the cache TTL.
func TestValkeyLiveInvalidation(t *testing.T) {
	a := liveValkey(t, WithValkeyCacheTTL(time.Minute))
	b := liveValkey(t, WithValkeyCacheTTL(time.Minute))
	ctx := context.Background()

	creds, err := Mint("bob", "keycloak", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Put(ctx, creds); err != nil {
		t.Fatal(err)
	}
	if _, found, err := b.Get(ctx, creds.AccessKeyID); !found || err != nil {
		t.Fatalf("replica b Get before revocation = found=%v, err=%v", found, err)
	}

	if err := a.Delete(ctx, creds.AccessKeyID); err != nil {
		t.Fatal(err)
	}
	waitGone(t, b, creds.AccessKeyID,
		"replica b still serves revoked credentials after 2s (cache not invalidated)")
}
