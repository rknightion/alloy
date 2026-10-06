//go:build hostile

package sshrunner

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
)

// This exercises the real 30-second worker with an established SSH connection,
// without Update or a test-only timer. It is opt-in because it takes >10 seconds.
func TestKnownHostsRemovalWithin60Seconds(t *testing.T) {
	host, _ := signer(t)
	s := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	// The long-lived scrape loop must consume the fixture's bounded command
	// trace. Otherwise its 50-entry buffer stalls exec before the reload tick.
	stopTrace := make(chan struct{})
	traceDone := make(chan struct{})
	go func() {
		defer close(traceDone)
		for {
			select {
			case command := <-s.commands:
				if command != "sh -s" {
					t.Errorf("unexpected remote command: %q", command)
				}
			case <-stopTrace:
				return
			}
		}
	}()
	t.Cleanup(func() { s.stop(); close(stopTrace); <-traceDone })
	cfg := configFor(t, s, host.PublicKey())
	cfg.IdleTimeout = 2 * time.Minute
	cfg.KeepaliveInterval = DefaultConfig.KeepaliveInterval
	cfg.KeepaliveTimeout = DefaultConfig.KeepaliveTimeout
	p := newPool(t, cfg)
	address := s.listener.Addr().String()
	run(t, p, address)
	require.NoError(t, os.WriteFile(cfg.KnownHostsFiles[0], nil, 0600))
	start := time.Now()
	var last error
	require.Eventually(t, func() bool {
		_, last = p.Run(context.Background(), agentless.Target{Address: address}, []agentless.Read{agentless.CommandRead("true")})
		return last != nil && strings.Contains(last.Error(), "host key")
	}, 55*time.Second, 500*time.Millisecond)
	require.Less(t, time.Since(start), 60*time.Second)
	require.EqualValues(t, 1, s.dials.Load(), "revocation must retire the old connection before another TCP dial")
	require.EqualValues(t, 1, s.auths.Load())
}
