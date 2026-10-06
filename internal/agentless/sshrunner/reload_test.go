package sshrunner

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/grafana/alloy/internal/agentless"
)

func TestReloadKnownHostsSnapshot(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	p := newPool(t, cfg)
	address := s.listener.Addr().String()
	run(t, p, address)
	p.reloadKnownHosts()
	run(t, p, address)
	require.EqualValues(t, 1, s.dials.Load(), "unchanged hash must preserve the connection")

	// An atomic replacement is observed by content, not by mtime or inode.
	replacement := cfg.KnownHostsFiles[0] + ".new"
	require.NoError(t, os.WriteFile(replacement, nil, 0600))
	require.NoError(t, os.Rename(replacement, cfg.KnownHostsFiles[0]))
	p.reloadKnownHosts()
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) == 0 }, time.Second, time.Millisecond)
	_, err := p.Run(context.Background(), agentless.Target{Address: address}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorContains(t, err, "host key")
	require.EqualValues(t, 1, s.auths.Load(), "removed host key must not reach authentication")

	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte(knownhosts.Line([]string{address}, host.PublicKey())+"\n"), 0600))
	p.reloadKnownHosts()
	run(t, p, address)
	require.EqualValues(t, 2, s.dials.Load())
}

func TestUpdateCannotRestoreRevokedSnapshot(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	p := newPool(t, cfg)
	address := s.listener.Addr().String()
	run(t, p, address)

	prepared := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		first := true
		done <- p.update(cfg, func(cfg Config) (*settings, error) {
			next, err := prepare(cfg)
			if first {
				first = false
				close(prepared)
				<-release
			}
			return next, err
		})
	}()
	select {
	case <-prepared:
	case <-time.After(time.Second):
		t.Fatal("Update did not prepare its initial snapshot")
	}
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], nil, 0600))
	p.reloadKnownHosts()
	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Update did not finish after reload")
	}
	_, err := p.Run(context.Background(), agentless.Target{Address: address}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorContains(t, err, "host key", "an older Update must not restore revoked trust")
	require.EqualValues(t, 1, s.auths.Load(), "revoked trust must not reach fresh authentication")
}

func TestReloadFailureKeepsSnapshot(t *testing.T) {
	for _, mode := range []string{"read", "parse", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			host, _ := signer(t)
			s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
			cfg := configFor(t, s, host.PublicKey())
			reg := prometheus.NewRegistry()
			var logs bytes.Buffer
			p, err := New(cfg, slog.New(slog.NewTextHandler(&logs, nil)), reg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, p.Close()) })
			run(t, p, s.listener.Addr().String())
			previous := p.cfg
			switch mode {
			case "read":
				require.NoError(t, os.Remove(cfg.KnownHostsFiles[0]))
			case "parse":
				require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte("attacker-controlled-secret not-a-key\n"), 0600))
			case "oversize":
				require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], bytes.Repeat([]byte("#\n"), (5<<20)/2), 0600))
			}
			p.reloadKnownHosts()
			require.Same(t, previous, p.cfg)
			run(t, p, s.listener.Addr().String())
			require.EqualValues(t, 1, s.dials.Load())
			require.Equal(t, float64(1), poolValues(t, reg)["agentless_ssh_known_hosts_reload_failures_total"])
			require.Contains(t, logs.String(), "retaining previous snapshot")
			require.NotContains(t, logs.String(), "attacker-controlled-secret")
			// The retained verifier also works for a fresh connection.
			p.mu.Lock()
			for target, e := range p.entries {
				p.retire(e)
				delete(p.entries, target)
			}
			p.mu.Unlock()
			run(t, p, s.listener.Addr().String())
		})
	}
}

func TestUpdatePrunesTargetMembership(t *testing.T) {
	host, _ := signer(t)
	s1 := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	s2 := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s1, host.PublicKey())
	line := knownhosts.Line([]string{s1.listener.Addr().String(), s2.listener.Addr().String()}, host.PublicKey()) + "\n"
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte(line), 0600))
	cfg.Targets = []agentless.Target{{Address: s1.listener.Addr().String()}, {Address: s2.listener.Addr().String()}}
	p := newPool(t, cfg)
	run(t, p, s1.listener.Addr().String())
	run(t, p, s2.listener.Addr().String())
	cfg.Targets = cfg.Targets[:1]
	require.NoError(t, p.Update(cfg))
	require.Eventually(t, func() bool { s2.mu.Lock(); defer s2.mu.Unlock(); return len(s2.conns) == 0 }, time.Second, time.Millisecond)
	_, err := p.Run(context.Background(), agentless.Target{Address: s2.listener.Addr().String()}, nil)
	require.ErrorContains(t, err, "not configured")
	cfg.Targets[0].Address = "invalid-caller-mutation"
	run(t, p, s1.listener.Addr().String())
	require.EqualValues(t, 1, s1.dials.Load(), "retained membership must preserve the connection")
	cfg.Targets = []agentless.Target{}
	require.NoError(t, p.Update(cfg))
	require.Eventually(t, func() bool { s1.mu.Lock(); defer s1.mu.Unlock(); return len(s1.conns) == 0 }, time.Second, time.Millisecond)
}

func TestRetirementDuringHandshake(t *testing.T) {
	for _, mode := range []string{"membership", "trust"} {
		t.Run(mode, func(t *testing.T) {
			host, _ := signer(t)
			s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
			s.authDelay.Store(200 * time.Millisecond)
			cfg := configFor(t, s, host.PublicKey())
			cfg.Targets = []agentless.Target{{Address: s.listener.Addr().String()}}
			p := newPool(t, cfg)
			done := make(chan error, 1)
			go func() {
				_, err := p.Run(context.Background(), cfg.Targets[0], []agentless.Read{agentless.CommandRead("true")})
				done <- err
			}()
			require.Eventually(t, func() bool { return s.auths.Load() == 1 }, time.Second, time.Millisecond)
			if mode == "membership" {
				next := cfg
				next.Targets = []agentless.Target{}
				require.NoError(t, p.Update(next))
			} else {
				require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], nil, 0600))
				p.reloadKnownHosts()
			}
			select {
			case err := <-done:
				require.ErrorContains(t, err, "retired")
			case <-time.After(time.Second):
				t.Fatal("retirement failed to cancel handshake")
			}
			require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) == 0 }, time.Second, time.Millisecond)
		})
	}
}

func TestConcurrentReloadUpdateClose(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	p, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], []byte("# changed snapshot\n"), 0600))
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				p.reloadKnownHosts()
				_ = p.Update(cfg)
			}
		}()
	}
	require.NoError(t, p.Close())
	wg.Wait()
	select {
	case <-p.reloadDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not stop reload worker")
	}
}
