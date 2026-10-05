package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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

// This bounded loopback SSH server executes only the compiled batch via stdin.
// It uses generated host keys and a synthetic password, never lab credentials.
func TestPoolSurvivesUpdate(t *testing.T) {
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
							cmd := exec.CommandContext(ctx, "sh", "-s")
							cmd.Stdin = ch
							cmd.Stdout = ch
							cmd.Stderr = io.Discard
							cmd.WaitDelay = 100 * time.Millisecond
							err := cmd.Run()
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
	scrape := func() {
		t.Helper()
		w := httptest.NewRecorder()
		c.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics?target="+listener.Addr().String(), nil))
		require.Equal(t, 200, w.Code)
		require.Contains(t, w.Body.String(), "node_scrape_collector_success")
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
	args.Targets = nil
	require.NoError(t, c.Update(args))
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics?target="+listener.Addr().String(), nil))
	require.Equal(t, 400, w.Code)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, c.Run(ctx))
	require.Error(t, c.Update(args), "Run exit must close the lifetime pool")
}
