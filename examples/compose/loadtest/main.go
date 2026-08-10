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

	bound, total, ok := quantileBound(before, after, 0.99)
	if !ok {
		fmt.Fprintln(os.Stderr, "no verification_duration_seconds sigv4 samples recorded during the run")
		os.Exit(1)
	}
	p50, _, _ := quantileBound(before, after, 0.50)
	p95, _, _ := quantileBound(before, after, 0.95)
	mean := meanMs(before, after)

	// The whole distribution, not just the gated number: a run that fails only
	// at the tail looks very different from one that is slow throughout, and
	// the bounds alone cannot tell them apart.
	fmt.Printf("proxy sigv4 verification (%d samples, histogram bucket bounds)\n", total)
	fmt.Printf("  p50  %s\n", fmtBound(p50))
	fmt.Printf("  mean    %7.3fms  (exact)\n", mean)
	fmt.Printf("  p95  %s\n", fmtBound(p95))
	fmt.Printf("  p99  %s\n", fmtBound(bound))

	if errs.Load() > 0 {
		fmt.Fprintln(os.Stderr, "FAIL: request errors")
		os.Exit(1)
	}
	if bound*1000 > *limitMs {
		fmt.Fprintf(os.Stderr, "\nFAIL: verification p99 bound %.3fms exceeds limit %.3fms\n", bound*1000, *limitMs)
		// A fast median with a slow tail is what host contention looks like:
		// the verification work itself fits the budget and the wall clock does
		// not, because the goroutine was not running for part of it. Saying so
		// is the difference between this failure and a real regression.
		if p50*1000 <= *limitMs && mean <= *limitMs {
			fmt.Fprintf(os.Stderr,
				"\n  The median and mean are inside the budget, so the verification\n"+
					"  path itself is not slow; only the tail is. That is usually the\n"+
					"  host rather than the proxy. Check load average, swap usage and\n"+
					"  the CPU frequency governor, then re-run against an otherwise\n"+
					"  idle stack. This run achieved %.0f req/s; the conditions the\n"+
					"  recorded figures were taken under are in docs/verification.md.\n",
				float64(*n)/elapsed.Seconds())
		}
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

// verifySample is one scrape of the sigv4 verification histogram: cumulative
// bucket counts keyed by the "le" value (+Inf included), plus the sum and
// count series that give the mean.
type verifySample struct {
	buckets map[string]float64
	sum     float64
	count   float64
}

// buckets scrapes the sigv4 verification histogram.
func buckets(client *http.Client, admin string) (verifySample, error) {
	out := verifySample{buckets: map[string]float64{}}
	resp, err := client.Get(admin + "/metrics")
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "verification_duration_seconds") ||
			!strings.Contains(line, `lane="sigv4"`) {
			continue
		}
		fields := strings.Fields(line)
		v, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			return out, err
		}
		switch {
		case strings.HasPrefix(line, "verification_duration_seconds_bucket"):
			le := line[strings.Index(line, `le="`)+4:]
			out.buckets[le[:strings.Index(le, `"`)]] = v
		case strings.HasPrefix(line, "verification_duration_seconds_sum"):
			out.sum = v
		case strings.HasPrefix(line, "verification_duration_seconds_count"):
			out.count = v
		}
	}
	return out, sc.Err()
}

// quantileBound computes a quantile's upper bound from the bucket deltas
// between two scrapes: the smallest bucket boundary whose cumulative delta
// covers q of this run's samples. Buckets give a bound rather than a value,
// so a result reads "at or below this", never "exactly this".
func quantileBound(before, after verifySample, q float64) (bound float64, total int, ok bool) {
	type edge struct {
		le  float64
		cum float64
	}
	var edges []edge
	for le, v := range after.buckets {
		delta := v - before.buckets[le]
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
	need := q * float64(total)
	for _, e := range edges {
		if e.cum >= need {
			return e.le, total, true
		}
	}
	// The quantile falls beyond the largest finite bucket.
	return math.Inf(1), total, true
}

// meanMs is the mean verification time over the run, from the sum and count
// deltas. Unlike the bucket bounds this is exact, which is what makes it
// useful for telling slow work apart from a stretched tail.
func meanMs(before, after verifySample) float64 {
	n := after.count - before.count
	if n <= 0 {
		return 0
	}
	return (after.sum - before.sum) / n * 1000
}

// fmtBound renders a bucket bound, keeping +Inf readable.
func fmtBound(b float64) string {
	if math.IsInf(b, 1) {
		return "  over 10ms"
	}
	return fmt.Sprintf("<= %7.3fms", b*1000)
}
