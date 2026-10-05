//go:build sshscale && (darwin || linux)

package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/batch"
	"github.com/grafana/alloy/internal/agentless/sshrunner"
)

var scaleReads = []agentless.Read{agentless.CommandRead("printf", "ssh-scale-payload")}

// validResults is used on every actual SSH round trip, including recovery.
// A timeout returning partial results must never be reported as recovery.
func validResults(results []agentless.Result, err error) bool {
	if err != nil || len(results) != len(scaleReads) {
		return false
	}
	for _, result := range results {
		if result.TimedOut || result.Truncated || result.NotExist || result.ExitStatus != 0 || string(result.Output) != "ssh-scale-payload" {
			return false
		}
	}
	return true
}

func TestValidResults(t *testing.T) {
	good := agentless.Result{Read: scaleReads[0], Output: []byte("ssh-scale-payload")}
	cases := []struct {
		name    string
		results []agentless.Result
		err     error
		want    bool
	}{
		{"complete", []agentless.Result{good}, nil, true},
		{"error", []agentless.Result{good}, errors.New("transport"), false},
		{"empty", nil, nil, false},
		{"partial", []agentless.Result{{Read: good.Read, TimedOut: true}}, nil, false},
		{"truncated", []agentless.Result{{Read: good.Read, Output: good.Output, Truncated: true}}, nil, false},
		{"missing", []agentless.Result{{Read: good.Read, Output: good.Output, NotExist: true}}, nil, false},
		{"nonzero", []agentless.Result{{Read: good.Read, Output: good.Output, ExitStatus: 1}}, nil, false},
		{"corrupt", []agentless.Result{{Read: good.Read, Output: []byte("wrong")}}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validResults(tc.results, tc.err); got != tc.want {
				t.Fatalf("validResults = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAllowedScript(t *testing.T) {
	script, err := batch.Build(scaleReads, strings.Repeat("a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if !allowedScript([]byte(script)) {
		t.Fatal("compiled batch rejected")
	}
	for _, bad := range []string{"", "touch /tmp/unowned", script + "touch /tmp/unowned\n", strings.Repeat("a", 8193)} {
		if allowedScript([]byte(bad)) {
			t.Fatal("non-compiled shell script admitted")
		}
	}
}

func writeTrust(tb testing.TB, farm []*targetServer, path string) {
	tb.Helper()
	var lines strings.Builder
	for _, s := range farm {
		fmt.Fprintln(&lines, knownhosts.Line([]string{s.address}, s.host.PublicKey()))
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
		tb.Fatal(err)
	}
}

func poolFor(tb testing.TB, farm []*targetServer) (*sshrunner.Pool, sshrunner.Config, *prometheus.Registry) {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "known_hosts")
	writeTrust(tb, farm, path)
	cfg := sshrunner.DefaultConfig
	cfg.Auths = map[string]sshrunner.Auth{sshrunner.DefaultAuthName: {Username: "reader", Password: []byte("local-benchmark")}}
	cfg.KnownHostsFiles = []string{path}
	reg := prometheus.NewRegistry()
	p, err := sshrunner.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), reg)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = p.Close() })
	return p, cfg, reg
}

func TestRealSSH(t *testing.T) {
	farm, err := startFarm(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopFarm(farm) })
	p, _, _ := poolFor(t, farm)
	if got := wave(p, farm); len(got) != 0 {
		t.Fatalf("real SSH batch did not return exact payload: %v", got)
	}
}

// wave bounds workload concurrency separately from the pool's 16-dial cap.
// It returns only unsuccessful targets, so recovery never hides partial success.
func wave(p *sshrunner.Pool, farm []*targetServer) []*targetServer {
	jobs := make(chan *targetServer)
	failed := make(chan *targetServer, len(farm))
	var wg sync.WaitGroup
	for range min(64, len(farm)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				results, err := p.Run(ctx, agentless.Target{Address: s.address}, scaleReads)
				cancel()
				if !validResults(results, err) {
					s.mu.Lock()
					s.lastFailure = fmt.Sprintf("error=%v results=%+v", err, results)
					s.mu.Unlock()
					failed <- s
				}
			}
		}()
	}
	for _, s := range farm {
		jobs <- s
	}
	close(jobs)
	wg.Wait()
	close(failed)
	var result []*targetServer
	for s := range failed {
		result = append(result, s)
	}
	return result
}

func failureDetails(farm []*targetServer) []string {
	var details []string
	for _, s := range farm[:min(5, len(farm))] {
		s.mu.Lock()
		details = append(details, s.lastFailure)
		s.mu.Unlock()
	}
	return details
}

func emit(tb testing.TB, value any) {
	tb.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Log(string(data))
}

type attempts struct {
	Auths   int64 `json:"auths"`
	Rejects int64 `json:"rejects"`
	Accepts int64 `json:"tcp_accepts"`
}

func countAttempts(farm []*targetServer) []attempts {
	out := make([]attempts, len(farm))
	for i, s := range farm {
		out[i] = attempts{s.auths.Load(), s.rejects.Load(), s.accepts.Load()}
	}
	return out
}

func reportFault(b *testing.B, name string, farm []*targetServer, before []attempts, injected, restored time.Time, detectionFailures, affected, bound int) {
	b.Helper()
	after := countAttempts(farm)
	var total attempts
	var maxAuth int64
	for i, a := range after {
		delta := attempts{a.Auths - before[i].Auths, a.Rejects - before[i].Rejects, a.Accepts - before[i].Accepts}
		total.Auths += delta.Auths
		total.Rejects += delta.Rejects
		total.Accepts += delta.Accepts
		maxAuth = max(maxAuth, delta.Auths)
	}
	emit(b, map[string]any{"kind": "fault", "profile": name, "affected_streams": affected, "detection_failures": detectionFailures,
		"injection_to_all_recovered_seconds": time.Since(injected).Seconds(), "restoration_to_all_recovered_seconds": time.Since(restored).Seconds(),
		"attempts": total, "max_auth_attempts_per_target": maxAuth, "auth_attempt_bound": bound})
	if maxAuth > int64(bound) {
		b.Fatalf("%s: auth attempts %d exceed configured observation-window bound %d", name, maxAuth, bound)
	}
}

func recoverAll(b *testing.B, p *sshrunner.Pool, farm []*targetServer) {
	b.Helper()
	deadline := time.Now().Add(45 * time.Second)
	remaining := farm
	for len(remaining) != 0 {
		remaining = wave(p, remaining)
		if len(remaining) == 0 {
			return
		}
		if time.Now().After(deadline) {
			b.Fatalf("capacity/recovery limit: %d/%d targets unrecovered in 45s (plus last bounded wave): %v", len(remaining), len(farm), failureDetails(remaining))
		}
		time.Sleep(time.Second)
	}
}

// BenchmarkSSHScale intentionally requires exactly one iteration: calibrating
// b.N would create farms repeatedly and turn a capacity experiment into noise.
func BenchmarkSSHScale(b *testing.B) {
	if b.N != 1 {
		b.Fatal("run with -benchtime=1x; repeated calibration is not supported")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	source, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	cancel()
	if err != nil {
		b.Fatal(err)
	}
	emit(b, map[string]any{"kind": "method", "source_sha": strings.TrimSpace(string(source)), "targets": 500, "interval_seconds": 60,
		"rounds": 3, "pid": os.Getpid(), "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
		"cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0), "pool_config": "sshrunner.DefaultConfig",
		"workload": "one real sh -s exec with compiled printf read per target; 64 scrape workers; separate loopback listener and Ed25519 host key per target"})
	emit(b, readResources("before_farm", nil, nil))
	farm, err := startFarm(500)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { stopFarm(farm) })
	p, cfg, reg := poolFor(b, farm)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				sample := readResources("running", farm, reg)
				emit(b, sample)
				if sample.Error != "" {
					b.Errorf("process resource measurement failed: %s", sample.Error)
				}
			}
		}
	}()
	b.Cleanup(func() { close(stop); <-done })
	start := time.Now()
	for round := range 3 {
		if delay := time.Until(start.Add(time.Duration(round) * 60 * time.Second)); delay > 0 {
			time.Sleep(delay)
		}
		began := time.Now()
		failures := wave(p, farm)
		emit(b, map[string]any{"kind": "round", "round": round, "start_offset_seconds": began.Sub(start).Seconds(),
			"duration_seconds": time.Since(began).Seconds(), "successes": len(farm) - len(failures), "failures": len(failures)})
		if len(failures) != 0 {
			b.Fatalf("capacity limit: %d/%d baseline targets failed: %v", len(failures), len(farm), failureDetails(failures))
		}
		sample := readResources("round_complete", farm, reg)
		emit(b, sample)
		if sample.Error != "" || sample.PoolConnections != 500 || sample.ServerConnections != 500 {
			b.Fatalf("expected 500 established real SSH connections, got %+v", sample)
		}
	}
	// Restart every listener and transport at the same port (not just a mock
	// failure flag). Rebind failures are reported rather than stealing ports.
	before, injected := countAttempts(farm), time.Now()
	stopFarm(farm)
	time.Sleep(2 * time.Second)
	for _, s := range farm {
		if err := s.start(s.address); err != nil {
			b.Fatalf("restart rebind capacity: %v", err)
		}
	}
	restored := time.Now()
	recoverAll(b, p, farm)
	reportFault(b, "restart_storm", farm, before, injected, restored, 0, len(farm), 1)

	before, injected = countAttempts(farm), time.Now()
	affected := 0
	for _, s := range farm {
		affected += s.disconnect(true)
	}
	if affected < len(farm) {
		b.Fatalf("half-open injection only affected %d streams", affected)
	}
	// Leave injected streams blackholed. The defaults probe at 15s and time
	// out at 5s; no client scrape assists detection during this 25s window.
	time.Sleep(25 * time.Second)
	detected := readResources("half_open_detected", farm, reg)
	emit(b, detected)
	if detected.Error != "" || detected.PoolConnections != 0 || detected.ServerConnections != 0 {
		b.Fatalf("half-open streams were not retired by default keepalives: %+v", detected)
	}
	restored = time.Now() // new connections always have a working path
	recoverAll(b, p, farm)
	reportFault(b, "half_open", farm, before, injected, restored, 0, affected, 1)

	before, injected = countAttempts(farm), time.Now()
	trustBefore := readResources("before_host_rotation", farm, reg)
	stopFarm(farm)
	for _, s := range farm {
		host, err := newSigner()
		if err != nil {
			b.Fatal(err)
		}
		s.host = host
		if err := s.start(s.address); err != nil {
			b.Fatal(err)
		}
	}
	time.Sleep(2 * time.Second) // allow disconnect observation and minimum transport backoff
	failures := wave(p, farm)
	if len(failures) != len(farm) {
		b.Fatalf("rotated untrusted host key accepted: %d successes", len(farm)-len(failures))
	}
	trustAfter := readResources("untrusted_host_rotation", farm, reg)
	emit(b, trustAfter)
	if trustBefore.Error != "" || trustAfter.Error != "" || trustAfter.HostKeyErrors-trustBefore.HostKeyErrors != 500 {
		b.Fatalf("did not observe 500 real host-key rejections: before=%+v after=%+v", trustBefore, trustAfter)
	}
	for i, a := range countAttempts(farm) {
		if a.Auths != before[i].Auths {
			b.Fatal("credentials reached a host before its rotated key was trusted")
		}
	}
	writeTrust(b, farm, cfg.KnownHostsFiles[0])
	if err := p.Update(cfg); err != nil {
		b.Fatal(err)
	}
	restored = time.Now()
	recoverAll(b, p, farm)
	reportFault(b, "host_key_rotation", farm, before, injected, restored, len(failures), len(farm), 1)

	before, injected = countAttempts(farm), time.Now()
	for _, s := range farm {
		s.mu.Lock()
		s.deny = true
		s.mu.Unlock()
		s.disconnect(false)
	}
	time.Sleep(2 * time.Second)
	failures = wave(p, farm)
	if len(failures) != len(farm) {
		b.Fatal("denied credentials still yielded valid output")
	}
	// Demand retries during the 60s minimum auth quiet period. Observe 8s
	// rather than waiting for the randomized 1-2 minute default expiry.
	for range 8 {
		time.Sleep(time.Second)
		if len(wave(p, farm)) != len(farm) {
			b.Fatal("authentication outage unexpectedly recovered")
		}
	}
	for i, a := range countAttempts(farm) {
		if a.Auths-before[i].Auths != 1 || a.Rejects-before[i].Rejects != 1 {
			b.Fatalf("auth backoff failed at target %d: auth=%d rejects=%d, want exactly one", i, a.Auths-before[i].Auths, a.Rejects-before[i].Rejects)
		}
	}
	for _, s := range farm {
		s.mu.Lock()
		s.deny, s.password = false, "rotated-local-benchmark"
		s.mu.Unlock()
	}
	cfg.Auths = map[string]sshrunner.Auth{sshrunner.DefaultAuthName: {Username: "reader", Password: []byte("rotated-local-benchmark")}}
	if err := p.Update(cfg); err != nil {
		b.Fatal(err)
	}
	restored = time.Now()
	recoverAll(b, p, farm)
	reportFault(b, "auth_failure_credential_update", farm, before, injected, restored, len(failures), len(farm), 2)
	if err := p.Close(); err != nil {
		b.Fatal(err)
	}
	stopFarm(farm)
	time.Sleep(time.Second)
	emit(b, readResources("after_cleanup", farm, reg))
	b.ReportMetric(500, "targets")
	b.ReportMetric(60, "interval_s")
}

// parseRSS interprets ps's resident-set size in KiB, not Go heap bytes.
func parseRSS(data []byte) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("invalid process RSS %q", data)
	}
	return value * 1024, nil
}
