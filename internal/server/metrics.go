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

// storeProbeTimeout bounds the store read made on every scrape. It stays well
// inside any scrape timeout, so a store that has stopped answering is reported
// as down rather than making the whole scrape fail.
const storeProbeTimeout = 2 * time.Second

// metrics implements the proxy's observability surface.
type metrics struct {
	registry *prometheus.Registry

	stsExchanges      *prometheus.CounterVec // issuer, result
	bearerAuth        *prometheus.CounterVec // issuer, result
	sigv4Verifies     *prometheus.CounterVec // result
	presignedVerifies *prometheus.CounterVec // result
	upstream          *prometheus.CounterVec // code
	upstreamErrors    prometheus.Counter
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
		upstreamErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "upstream_errors_total",
			Help: "Requests the Ozone S3 Gateway never answered: refused, reset or timed out. A client that disconnects first is not counted.",
		}),
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
	m.registry.MustRegister(
		m.stsExchanges, m.bearerAuth, m.sigv4Verifies, m.presignedVerifies, m.upstream, m.upstreamErrors,
		m.revocations, m.duration, m.verifyDuration,
		newStoreCollector(st, storeProbeTimeout),
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

func (m *metrics) observeUpstream(status int) {
	m.upstream.WithLabelValues(strconv.Itoa(status)).Inc()
}

func (m *metrics) observeUpstreamError() {
	m.upstreamErrors.Inc()
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

// storeCollector reads the credential store once per scrape. It reports
// whether the store answered, and the number of live credentials only when it
// did: a store that cannot be read is not a store with nothing in it.
type storeCollector struct {
	store   store.Store
	timeout time.Duration
	up      *prometheus.Desc
	active  *prometheus.Desc
}

func newStoreCollector(st store.Store, timeout time.Duration) *storeCollector {
	return &storeCollector{
		store:   st,
		timeout: timeout,
		up: prometheus.NewDesc("credential_store_up",
			"Whether the credential store answered at the last scrape.", nil, nil),
		active: prometheus.NewDesc("active_credentials",
			"Unexpired temporary credentials currently in the store; absent while the store cannot be read.", nil, nil),
	}
}

func (c *storeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.up
	ch <- c.active
}

func (c *storeCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	n, err := c.store.Count(ctx)
	if err != nil {
		ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 0)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.up, prometheus.GaugeValue, 1)
	ch <- prometheus.MustNewConstMetric(c.active, prometheus.GaugeValue, float64(n))
}
