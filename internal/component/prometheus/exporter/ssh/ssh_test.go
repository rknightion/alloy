package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/agentless/sshrunner"
	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/discovery"
	"github.com/grafana/alloy/syntax/alloytypes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// inlineSSHServer runs the actual batch script, without emulating its framing.
func inlineSSHServer(t *testing.T) (string, string, *atomic.Int32) {
	t.Helper()
	return inlineSSHServerWithFiles(t, nil)
}

// Replace procfs paths only at the server/process edge so Linux fixture data
// exercises the real SSH framing and public handler on every development host.
func inlineSSHServerWithFiles(t *testing.T, files map[string]string) (string, string, *atomic.Int32) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(private)
	require.NoError(t, err)
	cfg := &gossh.ServerConfig{PasswordCallback: func(meta gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		if meta.User() == "reader" && string(password) == "test-only" {
			return nil, nil
		}
		return nil, errors.New("denied")
	}}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	var authenticated atomic.Int32
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("SSH server did not stop")
		}
	})
	go func() {
		defer close(done)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			// Sequential service proves Update closes the old connection: a
			// replacement cannot authenticate until its predecessor closes.
			_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
			conn, channels, requests, err := gossh.NewServerConn(raw, cfg)
			if err != nil {
				_ = raw.Close()
				continue
			}
			authenticated.Add(1)
			go gossh.DiscardRequests(requests)
			for ch := range channels {
				if ch.ChannelType() != "session" {
					_ = ch.Reject(gossh.UnknownChannelType, "unsupported")
					continue
				}
				channel, reqs, err := ch.Accept()
				if err != nil {
					break
				}
				for req := range reqs {
					var payload struct{ Command string }
					if req.Type != "exec" || gossh.Unmarshal(req.Payload, &payload) != nil || payload.Command != "sh -s" {
						_ = req.Reply(false, nil)
						continue
					}
					_ = req.Reply(true, nil)
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					cmd := exec.CommandContext(ctx, "sh", "-s")
					cmd.Stdin, cmd.Stdout, cmd.Stderr = channel, channel, io.Discard
					if len(files) > 0 {
						script, err := io.ReadAll(channel)
						if err != nil {
							cancel()
							_ = channel.Close()
							break
						}
						fixed := string(script)
						for path, fixture := range files {
							fixed = strings.ReplaceAll(fixed, path, fixture)
						}
						cmd.Stdin = strings.NewReader(fixed)
					}
					cmd.WaitDelay = 100 * time.Millisecond
					status := uint32(0)
					if cmd.Run() != nil {
						status = 1
					}
					cancel()
					_, _ = channel.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{status}))
					break
				}
				_ = channel.Close()
			}
			_ = conn.Close()
		}
	}()
	address := listener.Addr().String()
	return address, knownhosts.Line([]string{address}, signer.PublicKey()), &authenticated
}

func TestInlineKnownHostsErrorsAreRedacted(t *testing.T) {
	address, trust, _ := inlineSSHServer(t)
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}}
	args.Targets = []Target{{Address: address}}
	const canary = "PRIVATE_TRUST_CANARY"
	args.KnownHosts = alloytypes.OptionalSecret{Value: "@" + canary + " host ssh-ed25519 AAAA", IsSecret: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := sshrunner.New(args.poolConfig(), logger, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), canary)

	args.KnownHosts.Value = trust
	pool, err := sshrunner.New(args.poolConfig(), logger, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	c := &Component{pool: pool, opts: component.Options{Logger: logger, OnStateChange: func(component.Exports) {}}, base: discovery.NewTargetFromMap(map[string]string{"job": "test"})}
	require.NoError(t, c.Update(args))
	args.KnownHosts.Value = "@" + canary + " host ssh-ed25519 AAAA"
	err = c.Update(args)
	require.Error(t, err)
	require.NotContains(t, err.Error(), canary)
}

func TestInlineKnownHostsConsumer(t *testing.T) {
	address, trust, authenticated := inlineSSHServer(t)
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}}
	args.KnownHosts = alloytypes.OptionalSecret{Value: trust, IsSecret: true}
	args.Targets = []Target{{Address: address}}
	args.EnabledCollectors = []string{"loadavg"}
	args.Timeout, args.DialTimeout = time.Second, time.Second
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool, err := sshrunner.New(args.poolConfig(), logger, prometheus.NewRegistry())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, pool.Close()) })
	c := &Component{pool: pool, opts: component.Options{Logger: logger, OnStateChange: func(component.Exports) {}}, base: discovery.NewTargetFromMap(map[string]string{"job": "test"})}
	require.NoError(t, c.Update(args))
	scrape := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics?target="+url.QueryEscape(address), nil))
		require.Equal(t, want, w.Code, w.Body.String())
		if want == 200 {
			// Missing procfs on Darwin is a collector failure, not a transport
			// failure; the real batch still delivers collector health metrics.
			require.Contains(t, w.Body.String(), "node_scrape_collector_success{collector=\"loadavg\"}")
		}
	}
	results, err := pool.Run(context.Background(), agentless.Target{Address: address}, []agentless.Read{agentless.CommandRead("uname", "-s")})
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Zero(t, results[0].ExitStatus)
	require.NotEmpty(t, results[0].Output)
	scrape(200)
	scrape(200)
	require.EqualValues(t, 1, authenticated.Load(), "unchanged trust reuses the verified connection")
	args.KnownHosts.Value = "# no hosts listed"
	require.NoError(t, c.Update(args))
	scrape(503)
	require.EqualValues(t, 1, authenticated.Load(), "unlisted host must not authenticate")

	// File trust must work alongside nonmatching inline content, including
	// when the file does not end in a newline.
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(trust), 0600))
	args.KnownHostsFiles = []string{path}
	args.KnownHosts.Value = "# inline comment"
	require.NoError(t, c.Update(args))
	scrape(200)
	require.EqualValues(t, 2, authenticated.Load())
	// Conversely, inline trust must work alongside nonmatching file content.
	require.NoError(t, os.WriteFile(path, []byte("# file comment"), 0600))
	args.KnownHosts.Value = trust
	require.NoError(t, c.Update(args))
	scrape(200)
	require.EqualValues(t, 3, authenticated.Load())
}

type runnerFunc func(context.Context, agentless.Target, []agentless.Read) ([]agentless.Result, error)

func (f runnerFunc) Run(ctx context.Context, t agentless.Target, r []agentless.Read) ([]agentless.Result, error) {
	return f(ctx, t, r)
}

func TestHandlerContract(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name, target, header string
		want                 int
		transportError       bool
		budget               time.Duration
	}{
		{name: "allowed", target: "host", want: 200, budget: time.Second},
		{name: "unknown", target: "other", want: 400},
		{name: "missing", want: 400},
		{name: "duplicate", target: "host&target=other", want: 400},
		{name: "transport", target: "host", want: 503, transportError: true, budget: time.Second},
		{name: "header", target: "host", header: "0.8", want: 200, budget: 300 * time.Millisecond},
		{name: "capped", target: "host", header: "100", want: 200, budget: time.Second},
		{name: "invalid", target: "host", header: "NaN", want: 400},
		{name: "exhausted", target: "host", header: "0.4", want: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			run := runnerFunc(func(ctx context.Context, target agentless.Target, reads []agentless.Read) ([]agentless.Result, error) {
				calls++
				require.Equal(t, "host", target.Address)
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.InDelta(t, tc.budget.Seconds(), time.Until(deadline).Seconds(), 0.08)
				if tc.transportError {
					return nil, errors.New("sensitive transport detail")
				}
				return []agentless.Result{{Read: reads[0], Output: []byte("1.5 2.0 3.0 1/42 100\n")}}, nil
			})
			cs, err := collectors.Build([]string{"loadavg"}, collectors.DefaultConfigs(), logger)
			require.NoError(t, err)
			scraper, err := agentless.NewScraper(run, cs, logger)
			require.NoError(t, err)
			c := &Component{scraper: scraper, allowed: map[string]agentless.Target{"host": {Address: "host"}}, timeout: time.Second}
			req := httptest.NewRequest("GET", "/metrics?target="+tc.target, nil)
			req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", tc.header)
			w := httptest.NewRecorder()
			c.Handler().ServeHTTP(w, req)
			require.Equal(t, tc.want, w.Code)
			require.NotContains(t, w.Body.String(), "sensitive")
			if tc.want == 200 {
				require.Contains(t, w.Body.String(), "node_load1 1.5")
				require.Contains(t, w.Body.String(), "node_scrape_collector_success{collector=\"loadavg\"} 1")
			}
			if tc.want == 400 {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls)
			}
		})
	}
}

func TestTargets(t *testing.T) {
	base := discovery.NewTargetFromMap(map[string]string{"__address__": "alloy.internal:12345", "__metrics_path__": "/component/metrics", "job": "integrations/ssh"})
	a := Arguments{TargetsList: []discovery.Target{discovery.NewTargetFromMap(map[string]string{"__address__": "host:2222", "env": "prod", "instance": "wrong", "__param_target": "attacker", "__scheme__": "https"})}}
	out := buildTargets(base, a.targets())
	require.Len(t, out, 1)
	for key, want := range map[string]string{"instance": "host:2222", "__param_target": "host:2222", "__address__": "alloy.internal:12345", "__metrics_path__": "/component/metrics", "env": "prod", "job": "integrations/ssh"} {
		value, ok := out[0].Get(key)
		require.True(t, ok)
		require.Equal(t, want, value)
	}
}

func TestValidation(t *testing.T) {
	valid := func() Arguments {
		var a Arguments
		a.SetToDefault()
		a.Auths = []Auth{{Name: "default", Username: "reader", Password: "test-only"}}
		a.KnownHostsFiles = []string{"fixture"}
		a.Targets = []Target{{Address: "host"}}
		return a
	}
	require.NoError(t, valid().Validate())
	for _, tc := range []struct {
		name   string
		mutate func(*Arguments)
	}{
		{"unknown", func(a *Arguments) { a.EnabledCollectors = []string{"arbitrary"} }},
		{"duplicate", func(a *Arguments) { a.EnabledCollectors = []string{"cpu", "cpu"} }},
		{"regex", func(a *Arguments) { a.Netdev.DeviceExclude = "[" }},
		{"filesystem regex", func(a *Arguments) { a.Filesystem.FSTypesExclude = "[" }},
		{"auth", func(a *Arguments) { a.Targets[0].Auth = "missing" }},
		{"duplicate target", func(a *Arguments) { a.Targets = append(a.Targets, a.Targets[0]) }},
		{"duplicate default port", func(a *Arguments) { a.Targets = append(a.Targets, Target{Address: "host:22"}) }},
		{"duplicate IPv6 default port", func(a *Arguments) { a.Targets = []Target{{Address: "::1"}, {Address: "[::1]:22"}} }},
		{"ambiguous", func(a *Arguments) {
			a.TargetsList = []discovery.Target{discovery.NewTargetFromMap(map[string]string{"__address__": "host"})}
		}},
		{"URL", func(a *Arguments) { a.Targets[0].Address = "ssh://host" }},
		{"port", func(a *Arguments) { a.Targets[0].Address = "host:0" }},
		{"timeout", func(a *Arguments) { a.Timeout = 0 }},
		{"sessions", func(a *Arguments) { a.MaxSessionsPerTarget = 10 }},
		{"trust", func(a *Arguments) { a.KnownHostsFiles = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) { a := valid(); tc.mutate(&a); require.Error(t, a.Validate()) })
	}
	a := valid()
	a.Netdev.DeviceInclude = "eth"
	a.Netdev.DeviceExclude = "["
	require.NoError(t, a.Validate())
}
