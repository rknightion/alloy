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
