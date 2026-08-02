// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/aimd54/ozone-oidc-proxy/internal/store"
)

// metrics implements the proxy's observability surface.
type metrics struct {
	registry *prometheus.Registry

	stsExchanges      *prometheus.CounterVec // issuer, result
	bearerAuth        *prometheus.CounterVec // issuer, result
	sigv4Verifies     *prometheus.CounterVec // result
	presignedVerifies *prometheus.CounterVec // result
	upstream          *prometheus.CounterVec // code
	revocations       *prometheus.CounterVec // result
	duration          *prometheus.HistogramVec
	verifyDuration    *prometheus.HistogramVec // lane
}

func newMetrics(st store.Store) *metrics {
	m := &metrics{
		registry: prometheus.NewRegistry(),
		stsExchanges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sts_exchanges_total",
			Help: "AssumeRoleWithWebIdentity exchanges by issuer and result.",
		}, []string{"issuer", "result"}),
		bearerAuth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "bearer_auth_total",
			Help: "Bearer-lane authentications by issuer and result.",
		}, []string{"issuer", "result"}),
		sigv4Verifies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sigv4_verifications_total",
			Help: "Data-path SigV4 verifications by result.",
		}, []string{"result"}),
		presignedVerifies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "presigned_verifications_total",
			Help: "Presigned-URL (SigV4 query auth) verifications by result.",
		}, []string{"result"}),
		upstream: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "upstream_requests_total",
			Help: "Responses received from the Ozone S3 Gateway by status code.",
		}, []string{"code"}),
		revocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "revocations_total",
			Help: "Admin credential revocations by result; a revocation is a store delete.",
		}, []string{"result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "request_duration_seconds",
			Help:    "Wall time per proxy request by lane.",
			Buckets: prometheus.DefBuckets,
		}, []string{"lane"}),
		verifyDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "verification_duration_seconds",
			Help: "Wall time of the pure verification step by lane; target p99 under 1 ms.",
			// Fine sub-millisecond buckets: the whole point is resolving <1ms.
			Buckets: []float64{0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01},
		}, []string{"lane"}),
	}
	active := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "active_credentials",
		Help: "Unexpired temporary credentials currently in the store.",
	}, func() float64 {
		n, err := st.Count(context.Background())
		if err != nil {
			return 0
		}
		return float64(n)
	})
	m.registry.MustRegister(
		m.stsExchanges, m.bearerAuth, m.sigv4Verifies, m.presignedVerifies, m.upstream, m.revocations,
		m.duration, m.verifyDuration, active,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

func (m *metrics) observeUpstream(status int) {
	m.upstream.WithLabelValues(strconv.Itoa(status)).Inc()
}

func (m *metrics) observeDuration(lane string, start time.Time) {
	m.duration.WithLabelValues(lane).Observe(time.Since(start).Seconds())
}

// observeVerification records the pure verification cost (always real wall
// time, independent of the server's injectable clock).
func (m *metrics) observeVerification(lane string, start time.Time) {
	m.verifyDuration.WithLabelValues(lane).Observe(time.Since(start).Seconds())
}

// resultLabel normalizes counter results: "" means success.
func resultLabel(code string) string {
	if code == "" {
		return "success"
	}
	return code
}
