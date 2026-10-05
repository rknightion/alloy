package sshrunner

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
)

func TestNoOutputDeadlineAndRecovery(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	s.silent.Store(true)
	cfg := configFor(t, s, host.PublicKey())
	cfg.Timeout = 100 * time.Millisecond
	cfg.MaxSessionsPerTarget = 1
	p := newPool(t, cfg)
	start := time.Now()
	results, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorContains(t, err, "no trusted section")
	require.Nil(t, results)
	require.Less(t, time.Since(start), 500*time.Millisecond)
	s.silent.Store(false)
	run(t, p, s.listener.Addr().String())
	require.EqualValues(t, 1, s.dials.Load(), "ordinary batch cancellation leaves the connection open")
}

// Cancellation is a caller decision, not evidence that the credentials or
// transport failed. A short scrape must not put the next healthy scrape into
// the much longer authentication (or transport) backoff window.
func TestCanceledHandshakeDoesNotBackOff(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "canceled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			host, _ := signer(t)
			s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
			s.authDelay.Store(500 * time.Millisecond)
			cfg := configFor(t, s, host.PublicKey())
			p := newPool(t, cfg)
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 250*time.Millisecond)
			}
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				_, err := p.Run(ctx, agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
				finished <- err
			}()
			// A password request proves host verification already succeeded.
			require.Eventually(t, func() bool { return s.auths.Load() == 1 }, time.Second, 5*time.Millisecond)
			if !deadline {
				cancel()
			}
			select {
			case err := <-finished:
				require.Error(t, err)
			case <-time.After(time.Second):
				t.Fatal("canceled handshake did not return")
			}
			s.authDelay.Store(0)
			run(t, p, s.listener.Addr().String())
			require.EqualValues(t, 2, s.dials.Load(), "the next scrape must be allowed to dial immediately")
		})
	}
}

func TestDialDeadlineIsNotAuthenticationFailure(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	s.authDelay.Store(300 * time.Millisecond)
	cfg := configFor(t, s, host.PublicKey())
	cfg.DialTimeout = 100 * time.Millisecond
	cfg.ReconnectBackoffMin = 200 * time.Millisecond
	cfg.ReconnectBackoffMax = 300 * time.Millisecond
	p := newPool(t, cfg)
	_, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.Error(t, err)
	require.EqualValues(t, 1, s.auths.Load(), "the timeout must occur after host verification")
	s.authDelay.Store(0)
	_, err = p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.ErrorContains(t, err, "transport failure")
	require.NotErrorIs(t, err, ErrAuthBackoff)
	require.EqualValues(t, 1, s.dials.Load(), "a pool dial timeout must retain transport backoff")
}

func TestExecRequestDeadlineClosesTransport(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	s.stallExec.Store(true)
	cfg := configFor(t, s, host.PublicKey())
	cfg.Timeout = 100 * time.Millisecond
	p := newPool(t, cfg)
	start := time.Now()
	_, err := p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
	require.Error(t, err)
	require.Less(t, time.Since(start), 500*time.Millisecond)
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.conns) == 0 }, time.Second, 5*time.Millisecond)
}
