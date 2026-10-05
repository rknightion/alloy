package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/prometheus/exporter"
	httpservice "github.com/grafana/alloy/internal/service/http"
	"github.com/grafana/alloy/internal/util"
)

type stalledResponseWriter struct {
	header  http.Header
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *stalledResponseWriter) Header() http.Header { return w.header }
func (w *stalledResponseWriter) WriteHeader(int)     {}
func (w *stalledResponseWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

// This bounded loopback SSH server executes only the compiled batch via stdin.
// It uses generated host keys and a synthetic password, never lab credentials.
func TestPoolSurvivesUpdate(t *testing.T) {
	procStat := filepath.Join(t.TempDir(), "stat")
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	host, err := gossh.NewSignerFromKey(key)
	require.NoError(t, err)
	cfg := &gossh.ServerConfig{PasswordCallback: func(_ gossh.ConnMetadata, pass []byte) (*gossh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var dials atomic.Int32
	var wg sync.WaitGroup
	var connMu sync.Mutex
	var conns []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			connMu.Lock()
			conns = append(conns, raw)
			connMu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
				conn, channels, reqs, err := gossh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go gossh.DiscardRequests(reqs)
				for pending := range channels {
					ch, requests, err := pending.Accept()
					if err != nil {
						return
					}
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer ch.Close()
						for req := range requests {
							var command struct{ Command string }
							if req.Type != "exec" || gossh.Unmarshal(req.Payload, &command) != nil || command.Command != "sh -s" {
								_ = req.Reply(false, nil)
								continue
							}
							_ = req.Reply(true, nil)
							ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
							script, err := io.ReadAll(ch)
							if err != nil {
								cancel()
								return
							}
							cmd := exec.CommandContext(ctx, "sh", "-s")
							// Supply Linux proc data at the server/process edge on
							// any host, retaining the real SSH batch protocol.
							cmd.Stdin = strings.NewReader(strings.ReplaceAll(string(script), "/proc/stat", procStat))
							cmd.Stdout = ch
							cmd.Stderr = io.Discard
							cmd.WaitDelay = 100 * time.Millisecond
							err = cmd.Run()
							cancel()
							status := uint32(0)
							if err != nil {
								status = 1
							}
							_, _ = ch.SendRequest("exit-status", false, gossh.Marshal(struct{ Status uint32 }{status}))
							return
						}
					}()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		connMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connMu.Unlock()
		wg.Wait()
	})
	trust := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(trust, []byte(knownhosts.Line([]string{listener.Addr().String()}, host.PublicKey())+"\n"), 0600))
	var args Arguments
	args.SetToDefault()
	args.Auths = []Auth{{Name: "default", Username: "reader", Password: "synthetic"}}
	args.KnownHostsFiles = []string{trust}
	args.Targets = []Target{{Name: "loopback", Address: listener.Addr().String()}}
	args.EnabledCollectors = []string{"loadavg"}
	var exports exporter.Exports
	opts := component.Options{ID: "prometheus.exporter.ssh.test", Logger: util.TestAlloyLogger(t).Slog(), Registerer: prometheus.NewRegistry(),
		OnStateChange: func(e component.Exports) { exports = e.(exporter.Exports) },
		GetServiceData: func(string) (any, error) {
			return httpservice.Data{MemoryListenAddr: "alloy.internal:12345", BaseHTTPPath: "/"}, nil
		},
	}
	c, err := New(opts, args)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.pool.Close() })
	original := c.pool
	scrape := func() string {
		t.Helper()
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics?target="+listener.Addr().String(), nil))
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "node_scrape_collector_success")
		return w.Body.String()
	}
	scrape()
	require.EqualValues(t, 1, dials.Load())
	args.Timeout = 3 * time.Second
	args.EnabledCollectors = []string{"uname"}
	require.NoError(t, c.Update(args))
	require.Same(t, original, c.pool)
	scrape()
	require.EqualValues(t, 1, dials.Load(), "Update must retain the established SSH connection")
	instance, _ := exports.Targets[0].Get("instance")
	require.Equal(t, listener.Addr().String(), instance)
	// A credentials/timeout/label-only update must not reset CPU's per-target
	// backwards-counter guard. Keep idle unchanged so this is not hotplug.
	args.EnabledCollectors = []string{"cpu"}
	require.NoError(t, os.WriteFile(procStat, []byte("cpu 1000 0 0 1000 0 0 0 0 0 0\ncpu0 1000 0 0 1000 0 0 0 0 0 0\n"), 0o600))
	require.NoError(t, c.Update(args))
	require.Contains(t, scrape(), `node_cpu_seconds_total{cpu="0",mode="user"} 10`)
	args.Timeout = 4 * time.Second
	args.Auths[0].Password = "synthetic-new"
	args.Targets[0].Labels = map[string]string{"env": "updated"}
	require.NoError(t, c.Update(args))
	require.NoError(t, os.WriteFile(procStat, []byte("cpu 900 0 0 1000 0 0 0 0 0 0\ncpu0 900 0 0 1000 0 0 0 0 0 0\n"), 0o600))
	if body := scrape(); !strings.Contains(body, `node_cpu_seconds_total{cpu="0",mode="user"} 10`) {
		t.Errorf("CPU counter guard reset after unrelated configuration update: %s", body)
	}

	// Block the process-edge response writer after SSH collection completes.
	// Target revocation must complete while that client remains stalled.
	writer := &stalledResponseWriter{header: make(http.Header), started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(writer.release) }) }
	t.Cleanup(release)
	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		c.Handler().ServeHTTP(writer, httptest.NewRequest("GET", "/metrics?target="+listener.Addr().String(), nil))
	}()
	select {
	case <-writer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("metrics response never reached the stalled writer")
	}
	args.Targets = nil
	updated := make(chan error, 1)
	go func() { updated <- c.Update(args) }()
	select {
	case err := <-updated:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Error("stalled HTTP response blocks target revocation")
		release()
		select {
		case err := <-updated:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("configuration update did not recover after response release")
		}
	}
	release()
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("released response handler did not finish")
	}
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics?target="+listener.Addr().String(), nil))
	require.Equal(t, 400, w.Code)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, c.Run(ctx))
	require.Error(t, c.Update(args), "Run exit must close the lifetime pool")
}
