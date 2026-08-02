// Copyright The ozone-oidc-proxy Authors
// SPDX-License-Identifier: Apache-2.0

// Command loadtest drives SigV4 GET traffic through the proxy and checks the
// Verification overhead target: p99 under 1 ms, read from the
// proxy's verification_duration_seconds histogram (bucket-delta method, so
// only this run's samples count). It signs requests with the proxy's own
// sigv4 package, no AWS SDK involved.
//
// Part of the main module (it imports internal/sigv4); test/deploy tooling,
// not shipped in the production image.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aimd54/ozone-oidc-proxy/internal/sigv4"
)

func main() {
	endpoint := flag.String("endpoint", "http://proxy:9000", "proxy S3 endpoint")
	admin := flag.String("admin", "http://proxy:9090", "proxy admin endpoint (metrics)")
	bucket := flag.String("bucket", "", "bucket to use (must exist and be writable)")
	akid := flag.String("akid", "", "temporary access key ID (OZPX...)")
	secret := flag.String("secret", "", "temporary secret access key")
	token := flag.String("token", "", "session token")
	region := flag.String("region", "us-east-1", "signing region")
	n := flag.Int("n", 5000, "total requests")
	c := flag.Int("c", 20, "concurrency")
	limitMs := flag.Float64("p99-limit-ms", 1.0, "fail if the sigv4 verification p99 upper bound exceeds this")
	flag.Parse()
	if *bucket == "" || *akid == "" || *secret == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "-bucket, -akid, -secret and -token are required")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	key := "loadtest-fixture.txt"

	// Fixture: one signed PUT so the GETs have something to fetch.
	if err := do(client, *endpoint, http.MethodPut, *bucket, key, strings.NewReader("loadtest"), *akid, *secret, *token, *region); err != nil {
		fmt.Fprintf(os.Stderr, "fixture PUT failed: %v\n", err)
		os.Exit(1)
	}

	before, err := buckets(client, *admin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scrape before: %v\n", err)
		os.Exit(1)
	}

	var errs atomic.Int64
	latencies := make([]time.Duration, *n)
	var wg sync.WaitGroup
	work := make(chan int)
	start := time.Now()
	for range *c {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				t0 := time.Now()
				if err := do(client, *endpoint, http.MethodGet, *bucket, key, nil, *akid, *secret, *token, *region); err != nil {
					errs.Add(1)
				}
				latencies[i] = time.Since(t0)
			}
		}()
	}
	for i := 0; i < *n; i++ {
		work <- i
	}
	close(work)
	wg.Wait()
	elapsed := time.Since(start)

	after, err := buckets(client, *admin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scrape after: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	q := func(p float64) time.Duration { return latencies[int(p*float64(len(latencies)-1))] }
	fmt.Printf("requests=%d errors=%d elapsed=%s rate=%.0f req/s\n",
		*n, errs.Load(), elapsed.Round(time.Millisecond), float64(*n)/elapsed.Seconds())
	fmt.Printf("client latency: p50=%s p95=%s p99=%s\n",
		q(0.50).Round(10*time.Microsecond), q(0.95).Round(10*time.Microsecond), q(0.99).Round(10*time.Microsecond))

	bound, total, ok := p99Bound(before, after)
	if !ok {
		fmt.Fprintln(os.Stderr, "no verification_duration_seconds sigv4 samples recorded during the run")
		os.Exit(1)
	}
	fmt.Printf("proxy sigv4 verification: samples=%d p99 <= %.3fms (histogram bucket bound)\n", total, bound*1000)
	if errs.Load() > 0 {
		fmt.Fprintln(os.Stderr, "FAIL: request errors")
		os.Exit(1)
	}
	if bound*1000 > *limitMs {
		fmt.Fprintf(os.Stderr, "FAIL: verification p99 bound %.3fms exceeds limit %.3fms\n", bound*1000, *limitMs)
		os.Exit(1)
	}
	fmt.Printf("PASS: verification p99 < %.1fms\n", *limitMs)
}

// do signs and sends one request; non-2xx is an error.
func do(client *http.Client, endpoint, method, bucket, key string, body io.Reader, akid, secret, token, region string) error {
	req, err := http.NewRequest(method, endpoint+"/"+bucket+"/"+key, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Amz-Security-Token", token)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	if err := sigv4.Sign(sigv4.SignInput{
		Request:     req,
		AccessKeyID: akid,
		Secret:      secret,
		Region:      region,
		Service:     "s3",
		Now:         time.Now(),
	}); err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

// buckets scrapes cumulative verification_duration_seconds sigv4 bucket
// counts, keyed by the "le" value (+Inf included).
func buckets(client *http.Client, admin string) (map[string]float64, error) {
	resp, err := client.Get(admin + "/metrics")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]float64{}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "verification_duration_seconds_bucket") ||
			!strings.Contains(line, `lane="sigv4"`) {
			continue
		}
		le := line[strings.Index(line, `le="`)+4:]
		le = le[:strings.Index(le, `"`)]
		fields := strings.Fields(line)
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			return nil, err
		}
		out[le] = v
	}
	return out, sc.Err()
}

// p99Bound computes the p99 upper bound from the bucket deltas between two
// scrapes: the smallest bucket boundary whose cumulative delta covers 99 % of
// this run's samples.
func p99Bound(before, after map[string]float64) (bound float64, total int, ok bool) {
	type edge struct {
		le  float64
		cum float64
	}
	var edges []edge
	for le, v := range after {
		delta := v - before[le]
		if le == "+Inf" {
			total = int(delta)
			continue
		}
		f, err := strconv.ParseFloat(le, 64)
		if err != nil {
			continue
		}
		edges = append(edges, edge{f, delta})
	}
	if total == 0 {
		return 0, 0, false
	}
	sort.Slice(edges, func(i, j int) bool { return edges[i].le < edges[j].le })
	need := 0.99 * float64(total)
	for _, e := range edges {
		if e.cum >= need {
			return e.le, total, true
		}
	}
	// p99 falls beyond the largest finite bucket.
	return math.Inf(1), total, true
}
