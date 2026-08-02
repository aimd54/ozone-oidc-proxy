// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Package store holds the temporary credentials minted by the STS handler and
// looked up by the SigV4 data path.
package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

// Credentials is one minted credential set, keyed by AccessKeyID.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Username        string
	Issuer          string
	ExpiresAt       time.Time
}

// Expired reports whether the credentials are past their expiry.
func (c Credentials) Expired(now time.Time) bool { return !now.Before(c.ExpiresAt) }

// Store is the credential store interface. The memory implementation serves a
// single replica; the valkey implementation is the shared alternative.
type Store interface {
	// Put stores creds, replacing any record with the same AccessKeyID.
	Put(ctx context.Context, creds Credentials) error
	// Get returns the record for akid. Expired records are still returned
	// (found=true) until swept, so callers can distinguish "expired" from
	// "never existed" and answer ExpiredToken vs InvalidAccessKeyId.
	Get(ctx context.Context, akid string) (Credentials, bool, error)
	// Delete removes a record (future admin revocation endpoint).
	Delete(ctx context.Context, akid string) error
	// Count returns the number of live records (active_credentials gauge).
	Count(ctx context.Context) (int, error)
	// Close releases background resources.
	Close() error
}

// akidPrefix marks proxy-minted access key IDs (never a valid AWS prefix, so
// mixups with real AWS credentials are visible at a glance).
const akidPrefix = "OZPX"

// crockford32 is Crockford's base32 alphabet (no I, L, O, U).
const crockford32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// Mint generates a fresh credential set for username/issuer expiring at
// expiresAt: AKID = "OZPX" + 16 Crockford-base32 chars, 40-char base64url
// secret, 43-char base64url session token (opaque, bound to the AKID).
func Mint(username, issuer string, expiresAt time.Time) (Credentials, error) {
	akid, err := randCrockford(16)
	if err != nil {
		return Credentials{}, fmt.Errorf("mint access key id: %w", err)
	}
	secret, err := randBase64URL(30) // 30 bytes -> exactly 40 chars
	if err != nil {
		return Credentials{}, fmt.Errorf("mint secret: %w", err)
	}
	token, err := randBase64URL(32) // 32 bytes -> exactly 43 chars
	if err != nil {
		return Credentials{}, fmt.Errorf("mint session token: %w", err)
	}
	return Credentials{
		AccessKeyID:     akidPrefix + akid,
		SecretAccessKey: secret,
		SessionToken:    token,
		Username:        username,
		Issuer:          issuer,
		ExpiresAt:       expiresAt,
	}, nil
}

func randCrockford(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = crockford32[int(b)%len(crockford32)]
	}
	return string(out), nil
}

func randBase64URL(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
