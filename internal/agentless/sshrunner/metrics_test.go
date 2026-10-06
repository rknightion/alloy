package sshrunner

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
)

func poolValues(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	require.NoError(t, err)
	values := map[string]float64{}
	for _, f := range families {
		for _, m := range f.Metric {
			name := f.GetName()
			for _, l := range m.Label {
				require.Equal(t, "reason", l.GetName(), "pool metrics must not carry targets or credentials")
				name += "/" + l.GetValue()
			}
			values[name] = m.GetCounter().GetValue() + m.GetGauge().GetValue()
		}
	}
	return values
}

func TestPoolObservability(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	cfg := configFor(t, s, host.PublicKey())
	cfg.IdleTimeout = 5 * time.Second
	reg := prometheus.NewRegistry()
	p, err := New(cfg, nil, reg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	run(t, p, s.listener.Addr().String())
	require.Equal(t, float64(1), poolValues(t, reg)["agentless_ssh_dials_total"])
	require.Equal(t, float64(1), poolValues(t, reg)["agentless_ssh_open_connections"])
	require.Eventually(t, func() bool { return poolValues(t, reg)["agentless_ssh_sessions_in_use"] == 0 }, time.Second, time.Millisecond)
	s.silent.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := p.Run(ctx, agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
		done <- err
	}()
	require.Eventually(t, func() bool { return poolValues(t, reg)["agentless_ssh_sessions_in_use"] == 1 }, time.Second, time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled scrape stuck")
	}
	require.Eventually(t, func() bool { return poolValues(t, reg)["agentless_ssh_sessions_in_use"] == 0 }, time.Second, time.Millisecond)
	require.NoError(t, p.Close())
	require.Zero(t, poolValues(t, reg)["agentless_ssh_open_connections"])
}

func TestCancelledDialMetrics(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	s.authDelay.Store(200 * time.Millisecond)
	reg := prometheus.NewRegistry()
	p, err := New(configFor(t, s, host.PublicKey()), nil, reg)
	require.NoError(t, err)
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := p.Run(ctx, agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
		done <- err
	}()
	require.Eventually(t, func() bool { return s.auths.Load() == 1 }, time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("cancelled handshake did not return")
	}
	values := poolValues(t, reg)
	require.Equal(t, float64(1), values["agentless_ssh_dials_total"])
	for _, reason := range []string{"auth", "host_key", "timeout", "refused", "other"} {
		require.Zero(t, values["agentless_ssh_dial_errors_total/"+reason], "caller cancellation is not a dial failure")
	}
}

func TestDialErrorMetrics(t *testing.T) {
	for _, reason := range []string{"auth", "host_key", "timeout", "refused"} {
		t.Run(reason, func(t *testing.T) {
			host, _ := signer(t)
			s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
			cfg := configFor(t, s, host.PublicKey())
			switch reason {
			case "auth":
				cfg.Auths[DefaultAuthName] = Auth{Username: "reader", Password: []byte("wrong-secret")}
			case "host_key":
				wrong, _ := signer(t)
				cfg = configFor(t, s, wrong.PublicKey())
			case "timeout":
				s.authDelay.Store(100 * time.Millisecond)
				cfg.DialTimeout = 20 * time.Millisecond
			case "refused":
				s.stop()
			}
			reg := prometheus.NewRegistry()
			p, err := New(cfg, nil, reg)
			require.NoError(t, err)
			defer p.Close()
			_, err = p.Run(context.Background(), agentless.Target{Address: s.listener.Addr().String()}, []agentless.Read{agentless.CommandRead("true")})
			require.Error(t, err)
			values := poolValues(t, reg)
			require.Equal(t, float64(1), values["agentless_ssh_dials_total"])
			require.Equal(t, float64(1), values["agentless_ssh_dial_errors_total/"+reason])
			require.Zero(t, values["agentless_ssh_open_connections"])
			require.Zero(t, values["agentless_ssh_sessions_in_use"])
			require.Len(t, values, 10, "fixed five reason series plus five pool metrics regardless of target or error text")
		})
	}
}
