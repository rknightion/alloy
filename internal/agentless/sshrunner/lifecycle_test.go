package sshrunner

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"
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

func rsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return s
}

func TestOnlyTrustedHostKeyAlgorithm(t *testing.T) {
	ed, _ := signer(t)
	rsa := rsaSigner(t)
	// x/crypto's default preference puts RSA before Ed25519. Restricting
	// algorithms must select the trusted Ed25519 key, not the untrusted RSA.
	s := serve(t, "127.0.0.1:0", rsa, "test-password", nil, false, ed)
	cfg := configFor(t, s, ed.PublicKey())
	p := newPool(t, cfg)
	run(t, p, s.listener.Addr().String())
}

func TestHostAlgorithmMismatchMetric(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, rsaSigner(t).PublicKey())
	reg := prometheus.NewRegistry()
	p, err := New(cfg, nil, reg)
	require.NoError(t, err)
	defer p.Close()
	_, err = p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorContains(t, err, "host key")
	require.EqualValues(t, 0, s.auths.Load())
	families, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	require.Equal(t, float64(1), families[0].Metric[0].GetCounter().GetValue())
}

func TestDifferentCAAndHostAlgorithms(t *testing.T) {
	ca := rsaSigner(t)
	host, _ := signer(t)
	cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity}
	require.NoError(t, cert.SignCert(rand.Reader, ca))
	certSigner, err := ssh.NewCertSigner(cert, host)
	require.NoError(t, err)
	s := serve(t, "127.0.0.1:0", certSigner, "test-password", nil, false)
	cfg := configFor(t, s, ca.PublicKey())
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte("@cert-authority\t"+knownhosts.Line([]string{s.listener.Addr().String()}, ca.PublicKey())+"\n"), 0600))
	p := newPool(t, cfg)
	run(t, p, s.listener.Addr().String())
}

func TestKnownHostsMatchingAndRevocation(t *testing.T) {
	for _, mode := range []string{"hashed", "wildcard", "negated", "revoked", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			host, _ := signer(t)
			s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
			cfg := configFor(t, s, host.PublicKey())
			address := s.listener.Addr().String()
			_, port, err := net.SplitHostPort(address)
			require.NoError(t, err)
			pattern := knownhosts.Normalize(address)
			switch mode {
			case "hashed":
				pattern = knownhosts.HashHostname(pattern)
			case "wildcard":
				pattern = "[127.*]:" + port
			case "negated":
				pattern = "[127.*]:" + port + ",!" + pattern
			case "unknown":
				pattern = "[192.0.2.1]:" + port
			}
			line := pattern + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.PublicKey()))) + "\n"
			if mode == "revoked" {
				line += "@revoked " + line
			}
			require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte(line), 0600))
			p := newPool(t, cfg)
			if mode == "hashed" || mode == "wildcard" {
				run(t, p, address)
			} else {
				_, err := p.Run(context.Background(), agentless.Target{Address: address}, []agentless.Read{agentless.CommandRead("true")})
				require.ErrorContains(t, err, "host key")
				require.EqualValues(t, 0, s.auths.Load())
			}
		})
	}
}

func TestCredentialUpdateAndCallerMutation(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	p := newPool(t, cfg)
	// Mutating caller-owned bytes does not mutate the prepared credentials.
	cfg.Auths["default"].Password[0] = 'X'
	run(t, p, s.listener.Addr().String())
	require.NoError(t, p.Update(cfg))
	_, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorContains(t, err, "authentication")
	require.EqualValues(t, 2, s.dials.Load())
	cfg.Auths["default"].Password[0] = 't'
	require.NoError(t, p.Update(cfg))
	run(t, p, s.listener.Addr().String())
	require.EqualValues(t, 3, s.dials.Load())
}

func TestQueueCancellationAndNoOutputDeadline(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	cfg.MaxSessionsPerTarget = 1
	p := newPool(t, cfg)
	finished := make(chan error, 1)
	go func() {
		_, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("sleep", "0.15")})
		finished <- err
	}()
	select {
	case <-s.commands:
	case <-time.After(time.Second):
		t.Fatal("no exec")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := p.Run(ctx, agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, <-finished)
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	_, err = p.Run(ctx2, agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorIs(t, err, context.Canceled)
	run(t, p, s.listener.Addr().String())
}

// The edge server accepts TCP but never reads the SSH handshake. Its lifetime
// is bounded by client deadlines/Close and explicit cleanup, not a live host.
func TestDialCapHandshakeTimeoutAndClose(t *testing.T) {
	host, _ := signer(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var wg sync.WaitGroup
	var accepted atomic.Int32
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				select {
				case <-stop:
				case <-time.After(time.Second):
				}
			}()
		}
	}()
	defer func() { _ = l.Close(); close(stop); wg.Wait() }()
	cfg := Config{Auths: map[string]Auth{"default": {Username: "reader", Password: []byte("test")}, "other": {Username: "reader", Password: []byte("test")}}, KnownHostsFiles: []string{}}
	file := t.TempDir() + "/known_hosts"
	require.NoError(t, os.WriteFile(file, []byte(knownhosts.Line([]string{l.Addr().String()}, host.PublicKey())+"\n"), 0600))
	cfg.KnownHostsFiles = []string{file}
	cfg.MaxConcurrentDials = 1
	cfg.DialTimeout = 150 * time.Millisecond
	p := newPool(t, cfg)
	out := make(chan error, 2)
	go func() {
		_, err := p.Run(context.Background(), agentless.Target{Address: l.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
		out <- err
	}()
	require.Eventually(t, func() bool { return accepted.Load() == 1 }, time.Second, 5*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = p.Run(ctx, agentless.Target{Address: l.Addr().String(), Auth: "other"}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.EqualValues(t, 1, accepted.Load())
	select {
	case err := <-out:
		require.ErrorContains(t, err, "handshake")
	case <-time.After(time.Second):
		t.Fatal("unbounded handshake")
	}
	go func() {
		_, err := p.Run(context.Background(), agentless.Target{Address: l.Addr().String(), Auth: "other"}, []agentless.Read{agentless.CommandRead("true")})
		out <- err
	}()
	require.Eventually(t, func() bool { return accepted.Load() == 2 }, time.Second, 5*time.Millisecond)
	require.NoError(t, p.Close())
	select {
	case err := <-out:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel handshake")
	}
}

func TestBackoffBoundsAndJitter(t *testing.T) {
	values := map[time.Duration]bool{}
	for range 100 {
		d := backoff(time.Millisecond, 8*time.Millisecond, 50)
		require.GreaterOrEqual(t, d, time.Millisecond)
		require.LessOrEqual(t, d, 8*time.Millisecond)
		values[d] = true
	}
	require.Greater(t, len(values), 1)
	require.Equal(t, time.Millisecond, backoff(time.Millisecond, time.Millisecond, 100))
}

func TestConcurrentAuthFailuresBounded(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "wrong", nil, false)
	p := newPool(t, configFor(t, s, host.PublicKey()))
	var wg sync.WaitGroup
	var backoffs atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
			if errors.Is(err, ErrAuthBackoff) {
				backoffs.Add(1)
			} else {
				require.ErrorContains(t, err, "authentication")
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, s.auths.Load())
	require.EqualValues(t, 19, backoffs.Load())
}
