package sshrunner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/grafana/alloy/internal/agentless"
)

// Only loopback sockets and bounded local sh processes are used. No sshd,
// target machine or system known_hosts/credential file is touched.
type testServer struct {
	listener  net.Listener
	config    *ssh.ServerConfig
	mu        sync.Mutex
	conns     map[net.Conn]bool
	wg        sync.WaitGroup
	dials     atomic.Int32
	auths     atomic.Int32
	sessions  atomic.Int32
	peak      atomic.Int32
	commands  chan string
	mute      bool
	silent    atomic.Bool
	stallExec atomic.Bool
}

func signer(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return s, key
}

func serve(t *testing.T, address string, host ssh.Signer, password string, userKey ssh.PublicKey, mute bool, extraKeys ...ssh.Signer) *testServer {
	t.Helper()
	l, err := net.Listen("tcp", address)
	require.NoError(t, err)
	s := &testServer{listener: l, conns: make(map[net.Conn]bool), commands: make(chan string, 50), mute: mute}
	s.config = &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.auths.Add(1)
			if meta.User() == "reader" && string(pass) == password {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.auths.Add(1)
			if meta.User() == "reader" && userKey != nil && bytes.Equal(key.Marshal(), userKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	s.config.AddHostKey(host)
	for _, key := range extraKeys {
		s.config.AddHostKey(key)
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.dials.Add(1)
			s.mu.Lock()
			s.conns[c] = true
			s.mu.Unlock()
			s.wg.Add(1)
			go s.connection(c)
		}
	}()
	t.Cleanup(s.stop)
	return s
}

func (s *testServer) connection(raw net.Conn) {
	defer s.wg.Done()
	defer func() { _ = raw.Close(); s.mu.Lock(); delete(s.conns, raw); s.mu.Unlock() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	conn, channels, requests, err := ssh.NewServerConn(raw, s.config)
	if err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	defer conn.Close()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for r := range requests {
			if !s.mute {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for ch := range channels {
		if ch.ChannelType() != "session" {
			_ = ch.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}
		c, reqs, err := ch.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.session(c, reqs)
	}
}

func (s *testServer) session(c ssh.Channel, reqs <-chan *ssh.Request) {
	defer s.wg.Done()
	defer c.Close()
	n := s.sessions.Add(1)
	defer s.sessions.Add(-1)
	for old := s.peak.Load(); n > old && !s.peak.CompareAndSwap(old, n); old = s.peak.Load() {
	}
	for r := range reqs {
		if r.Type != "exec" {
			_ = r.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if ssh.Unmarshal(r.Payload, &payload) != nil {
			return
		}
		s.commands <- payload.Command
		if payload.Command != "sh -s" {
			_ = r.Reply(false, nil)
			return
		}
		if s.stallExec.Load() {
			for range reqs {
			}
			return
		}
		_ = r.Reply(true, nil)
		if s.silent.Load() {
			_, _ = io.Copy(io.Discard, c)
			for range reqs {
			}
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, "sh", "-s")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = c, c, io.Discard
		cmd.WaitDelay = 100 * time.Millisecond
		err := cmd.Run()
		cancel()
		status := uint32(0)
		if err != nil {
			status = 1
		}
		_, _ = c.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
		return
	}
}

func (s *testServer) stop() {
	_ = s.listener.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func configFor(t *testing.T, s *testServer, host ssh.PublicKey) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path, []byte(knownhosts.Line([]string{s.listener.Addr().String()}, host)+"\n"), 0600))
	return Config{
		Auths: map[string]Auth{DefaultAuthName: {Username: "reader", Password: []byte("test-password")}}, KnownHostsFiles: []string{path},
		DialTimeout: time.Second, Timeout: time.Second, KeepaliveInterval: 50 * time.Millisecond, KeepaliveTimeout: 50 * time.Millisecond,
		IdleTimeout: time.Second, ReconnectBackoffMin: 10 * time.Millisecond, ReconnectBackoffMax: 30 * time.Millisecond,
		AuthFailureBackoffMin: 500 * time.Millisecond, AuthFailureBackoffMax: time.Second,
	}
}

func newPool(t *testing.T, cfg Config) *Pool {
	t.Helper()
	p, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), prometheus.NewRegistry())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	return p
}

func run(t *testing.T, p *Pool, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reads := []agentless.Read{agentless.CommandRead("printf", "hello"), agentless.FileRead("/alloy-agentless-missing-file")}
	results, err := p.Run(ctx, agentless.Target{Address: address}, reads)
	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, "hello", string(results[0].Output))
	require.False(t, results[0].TimedOut)
	require.True(t, results[1].NotExist)
}

func TestBatchAndUnchangedUpdate(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	p := newPool(t, cfg)
	run(t, p, s.listener.Addr().String())
	cfg.Auths["other"] = Auth{Username: "reader", Password: []byte("another-password")}
	cfg.Timeout = 2 * time.Second
	require.NoError(t, p.Update(cfg))
	run(t, p, s.listener.Addr().String())
	require.EqualValues(t, 1, s.dials.Load(), "unchanged identity must retain the connection")
	require.Equal(t, "sh -s", <-s.commands)
	require.Equal(t, "sh -s", <-s.commands)
}

func TestAuthSelection(t *testing.T) {
	host, _ := signer(t)
	user, key := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", user.PublicKey(), false)
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint(encrypted), func(t *testing.T) {
			cfg := configFor(t, s, host.PublicKey())
			var block *pem.Block
			var err error
			if encrypted {
				block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("test-passphrase"))
			} else {
				block, err = ssh.MarshalPrivateKey(key, "")
			}
			require.NoError(t, err)
			auth := Auth{Username: "reader", PrivateKey: pem.EncodeToMemory(block)}
			if encrypted {
				auth.Passphrase = []byte("test-passphrase")
			}
			cfg.Auths["key"] = auth
			p := newPool(t, cfg)
			results, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String(), Auth: "key"}, []agentless.Read{agentless.CommandRead("printf", "key")})
			require.NoError(t, err)
			require.Equal(t, "key", string(results[0].Output))
			run(t, p, s.listener.Addr().String())
		})
	}
}

func TestAuthBackoff(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "different", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	var logs bytes.Buffer
	p, err := New(cfg, slog.New(slog.NewTextHandler(&logs, nil)), prometheus.NewRegistry())
	require.NoError(t, err)
	defer p.Close()
	_, err = p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.Error(t, err)
	for range 20 {
		_, err = p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
		require.ErrorIs(t, err, ErrAuthBackoff)
	}
	require.EqualValues(t, 1, s.auths.Load())
	require.NotContains(t, logs.String(), "test-password")
}

func TestHostMismatchAndMetric(t *testing.T) {
	host, _ := signer(t)
	wrong, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, wrong.PublicKey())
	reg := prometheus.NewRegistry()
	p, err := New(cfg, nil, reg)
	require.NoError(t, err)
	defer p.Close()
	_, err = p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorContains(t, err, "host key")
	require.EqualValues(t, 0, s.auths.Load())
	families, err := reg.Gather()
	require.NoError(t, err)
	found := false
	for _, family := range families {
		if family.GetName() == "agentless_ssh_host_key_failures_total" {
			found = true
			require.Equal(t, float64(1), family.Metric[0].GetCounter().GetValue())
		}
	}
	require.True(t, found)
}

func TestCertificateAuthority(t *testing.T) {
	ca, _ := signer(t)
	host, _ := signer(t)
	cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	certSigner, err := ssh.NewCertSigner(cert, host)
	require.NoError(t, err)
	s := serve(t, "127.0.0.1:0", certSigner, "test-password", nil, false)
	cfg := configFor(t, s, ca.PublicKey())
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte("@cert-authority "+knownhosts.Line([]string{s.listener.Addr().String()}, ca.PublicKey())+"\n"), 0600))
	p := newPool(t, cfg)
	run(t, p, s.listener.Addr().String())
}

func TestDeadlineReleasesSession(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	cfg.MaxSessionsPerTarget = 1
	p := newPool(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	results, err := p.Run(ctx, agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("printf", "done"), agentless.CommandRead("sleep", "0.3")})
	require.NoError(t, err)
	require.Equal(t, "done", string(results[0].Output))
	require.True(t, results[1].TimedOut)
	start := time.Now()
	run(t, p, s.listener.Addr().String())
	require.Less(t, time.Since(start), 200*time.Millisecond)
}

func TestSessionCap(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	cfg.MaxSessionsPerTarget = 2
	p := newPool(t, cfg)
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("sleep", "0.03")})
			require.NoError(t, err)
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, s.peak.Load(), int32(2))
	require.EqualValues(t, 1, s.dials.Load())
}

func TestIdleAndHalfOpen(t *testing.T) {
	for _, halfOpen := range []bool{false, true} {
		t.Run(fmt.Sprint(halfOpen), func(t *testing.T) {
			host, _ := signer(t)
			s := serve(t, "127.0.0.1:0", host, "test-password", nil, halfOpen)
			cfg := configFor(t, s, host.PublicKey())
			if !halfOpen {
				cfg.IdleTimeout = 100 * time.Millisecond
			}
			p := newPool(t, cfg)
			run(t, p, s.listener.Addr().String())
			require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) == 0 }, time.Second, 5*time.Millisecond)
		})
	}
}

func TestRestartAndChangedHostKey(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	address := s.listener.Addr().String()
	cfg := configFor(t, s, host.PublicKey())
	p := newPool(t, cfg)
	run(t, p, address)
	s.stop()
	s2 := serve(t, address, host, "test-password", nil, false)
	require.Eventually(t, func() bool {
		_, err := p.Run(context.Background(), agentless.Target{Address: address}, []agentless.Read{agentless.CommandRead("true")})
		return err == nil
	}, time.Second, 20*time.Millisecond)
	s2.stop()
	changed, _ := signer(t)
	s3 := serve(t, address, changed, "test-password", nil, false)
	var last error
	require.Eventually(t, func() bool {
		_, last = p.Run(context.Background(), agentless.Target{Address: address}, []agentless.Read{agentless.CommandRead("true")})
		return last != nil && strings.Contains(last.Error(), "host key")
	}, time.Second, 20*time.Millisecond)
	require.EqualValues(t, 0, s3.auths.Load())
	// Re-reading trust on Update replaces the old client only after validation.
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte(knownhosts.Line([]string{address}, changed.PublicKey())+"\n"), 0600))
	require.NoError(t, p.Update(cfg))
	run(t, p, address)
}

func TestConfigValidation(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	for _, mutate := range []func(*Config){func(c *Config) { c.KnownHostsFiles = nil }, func(c *Config) { c.MaxSessionsPerTarget = 10 }, func(c *Config) { c.Auths = nil }, func(c *Config) {
		c.Auths = map[string]Auth{"default": {Username: "reader", PrivateKey: []byte("invalid-secret")}}
	}} {
		bad := cfg
		mutate(&bad)
		_, err := New(bad, nil, nil)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "invalid-secret")
	}
	p := newPool(t, cfg)
	bad := cfg
	bad.KnownHostsFiles = nil
	require.Error(t, p.Update(bad))
	run(t, p, s.listener.Addr().String())
	require.NoError(t, p.Close())
	_, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, nil)
	require.Error(t, err)
}
