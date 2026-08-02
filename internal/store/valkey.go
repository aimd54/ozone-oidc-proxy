// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
)

// valkeyPrefix namespaces credential keys inside the valkey keyspace.
const valkeyPrefix = "ozpx:cred:"

// StoreKeyBytes is the decoded length of the valkey value-encryption key
// (AES-256-GCM).
const StoreKeyBytes = 32

// ParseStoreKey decodes the base64 proxy key that encrypts valkey values
// (secrets live only in the store, encrypted at rest here). Error messages
// never include the input.
func ParseStoreKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("store key is not valid base64")
	}
	if len(key) != StoreKeyBytes {
		return nil, fmt.Errorf("store key must decode to %d bytes, got %d", StoreKeyBytes, len(key))
	}
	return key, nil
}

// Valkey is the shared credential store: values are AES-256-GCM
// encrypted with the proxy key, and valkey-go's server-assisted client-side
// cache is the design's "small local LRU", a Delete on any replica
// invalidates the cached entry on every other replica.
type Valkey struct {
	client    valkey.Client
	aead      cipher.AEAD
	retention time.Duration
	cacheTTL  time.Duration
	now       func() time.Time
}

// ValkeyOption customizes the valkey store (tests).
type ValkeyOption func(*Valkey)

// WithValkeyRetention sets how long records outlive their expiry (the window
// in which clients get ExpiredToken instead of InvalidAccessKeyId).
func WithValkeyRetention(d time.Duration) ValkeyOption {
	return func(v *Valkey) { v.retention = d }
}

// WithValkeyCacheTTL bounds the client-side cache entry lifetime.
func WithValkeyCacheTTL(d time.Duration) ValkeyOption {
	return func(v *Valkey) { v.cacheTTL = d }
}

// WithValkeyClock overrides the time source.
func WithValkeyClock(now func() time.Time) ValkeyOption {
	return func(v *Valkey) { v.now = now }
}

// NewValkey connects to addr and encrypts every stored value with key
// (32 bytes, see ParseStoreKey).
func NewValkey(addr string, key []byte, opts ...ValkeyOption) (*Valkey, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		return nil, fmt.Errorf("valkey connect %s: %w", addr, err)
	}
	v := &Valkey{
		client:    client,
		aead:      aead,
		retention: time.Hour, // matches the memory store's sweeper retention
		cacheTTL:  10 * time.Second,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v, nil
}

func (v *Valkey) Put(ctx context.Context, creds Credentials) error {
	// #nosec G117 -- the marshaled record does carry the session token and
	// secret; that is why it is sealed with AES-256-GCM below and
	// never leaves this function in plaintext.
	plain, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	ttl := creds.ExpiresAt.Add(v.retention).Sub(v.now())
	if ttl <= 0 {
		ttl = v.retention
	}
	sealed, err := seal(v.aead, plain, []byte(creds.AccessKeyID))
	if err != nil {
		return err
	}
	return v.client.Do(ctx, v.client.B().Set().
		Key(valkeyPrefix+creds.AccessKeyID).
		Value(valkey.BinaryString(sealed)).
		PxMilliseconds(ttl.Milliseconds()).Build()).Error()
}

func (v *Valkey) Get(ctx context.Context, akid string) (Credentials, bool, error) {
	resp := v.client.DoCache(ctx, v.client.B().Get().Key(valkeyPrefix+akid).Cache(), v.cacheTTL)
	data, err := resp.AsBytes()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return Credentials{}, false, nil
		}
		return Credentials{}, false, fmt.Errorf("valkey get: %w", err)
	}
	plain, err := open(v.aead, data, []byte(akid))
	if err != nil {
		return Credentials{}, false, fmt.Errorf("credential record failed decryption (store key mismatch or record/key mismatch?)")
	}
	var creds Credentials
	if err := json.Unmarshal(plain, &creds); err != nil {
		return Credentials{}, false, fmt.Errorf("credential record corrupt: %w", err)
	}
	return creds, true, nil
}

func (v *Valkey) Delete(ctx context.Context, akid string) error {
	// DEL triggers a server-assisted invalidation push to every client that
	// has the key in its client-side cache (this one included). The push is
	// asynchronous: a revoked credential may be served from a local cache for
	// a few more milliseconds, cluster-wide, before it disappears.
	return v.client.Do(ctx, v.client.B().Del().Key(valkeyPrefix+akid).Build()).Error()
}

func (v *Valkey) Count(ctx context.Context) (int, error) {
	// SCAN is O(keyspace) per scrape; fine at the credential volumes this
	// proxy handles (thousands, not millions).
	var cursor uint64
	total := 0
	for {
		resp := v.client.Do(ctx, v.client.B().Scan().Cursor(cursor).
			Match(valkeyPrefix+"*").Count(1000).Build())
		entry, err := resp.AsScanEntry()
		if err != nil {
			return 0, fmt.Errorf("valkey scan: %w", err)
		}
		total += len(entry.Elements)
		cursor = entry.Cursor
		if cursor == 0 {
			return total, nil
		}
	}
}

func (v *Valkey) Close() error {
	v.client.Close()
	return nil
}

// newAEAD builds the AES-256-GCM cipher for value encryption.
func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != StoreKeyBytes {
		return nil, fmt.Errorf("store key must be %d bytes, got %d", StoreKeyBytes, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plain as nonce||ciphertext. aad (the access key ID) is
// authenticated but not encrypted: it cryptographically binds the record to
// its store key, so an attacker with write access to valkey cannot graft one
// record's ciphertext onto another AKID.
func seal(aead cipher.AEAD, plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, aad), nil
}

// open decrypts a nonce||ciphertext value; aad must match what seal bound.
func open(aead cipher.AEAD, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < aead.NonceSize() {
		return nil, fmt.Errorf("sealed value too short")
	}
	return aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], aad)
}
