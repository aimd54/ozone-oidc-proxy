// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"sync"
	"time"
)

// Memory is the in-process credential store (single replica). Expired records
// linger until the sweeper removes them so Get can report "expired" rather
// than "unknown"; the retention window below bounds that grace period.
type Memory struct {
	mu    sync.RWMutex
	creds map[string]Credentials

	sweepEvery time.Duration
	retention  time.Duration
	now        func() time.Time
	stop       chan struct{}
	stopOnce   sync.Once
}

// MemoryOption customizes the memory store (tests).
type MemoryOption func(*Memory)

// WithSweepInterval sets how often the TTL sweeper runs.
func WithSweepInterval(d time.Duration) MemoryOption {
	return func(m *Memory) { m.sweepEvery = d }
}

// WithRetention sets how long expired records stay visible to Get before the
// sweeper drops them (the window in which clients get ExpiredToken instead of
// InvalidAccessKeyId).
func WithRetention(d time.Duration) MemoryOption {
	return func(m *Memory) { m.retention = d }
}

// WithClock overrides the time source.
func WithClock(now func() time.Time) MemoryOption {
	return func(m *Memory) { m.now = now }
}

// NewMemory creates the store and starts its TTL sweeper.
func NewMemory(opts ...MemoryOption) *Memory {
	m := &Memory{
		creds:      make(map[string]Credentials),
		sweepEvery: time.Minute,
		retention:  time.Hour,
		now:        time.Now,
		stop:       make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	go m.sweeper()
	return m
}

func (m *Memory) Put(_ context.Context, creds Credentials) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creds[creds.AccessKeyID] = creds
	return nil
}

func (m *Memory) Get(_ context.Context, akid string) (Credentials, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.creds[akid]
	return c, ok, nil
}

func (m *Memory) Delete(_ context.Context, akid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.creds, akid)
	return nil
}

func (m *Memory) Count(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	now := m.now()
	for _, c := range m.creds {
		if !c.Expired(now) {
			n++
		}
	}
	return n, nil
}

func (m *Memory) Close() error {
	m.stopOnce.Do(func() { close(m.stop) })
	return nil
}

func (m *Memory) sweeper() {
	ticker := time.NewTicker(m.sweepEvery)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.sweep()
		}
	}
}

func (m *Memory) sweep() {
	cutoff := m.now().Add(-m.retention)
	m.mu.Lock()
	defer m.mu.Unlock()
	for akid, c := range m.creds {
		if c.ExpiresAt.Before(cutoff) {
			delete(m.creds, akid)
		}
	}
}
