//go:build unix

package sshrunner

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Relocate only the fixed listing directory to a local fixture, retaining its
// ID and the real collector's Expand/Update. The transport still executes the
// compiled script over SSH; no result or collector assertion is substituted.
type fixtureListingCollector struct {
	agentless.Expander
	path string
}

func (c fixtureListingCollector) Reads() []agentless.Read {
	read := c.Expander.Reads()[0]
	read.Argv = []string{"ls", "-1", c.path}
	return []agentless.Read{read}
}

// Only local child processes opt into the privilege drop. The SSH connection,
// runner and all existing server callers retain their original execution mode.
func listingFixture(t *testing.T) (string, func(*exec.Cmd)) {
	t.Helper()
	//nolint:usetesting // t.TempDir may sit below private, non-test-owned TMPDIR ancestors.
	root, err := os.MkdirTemp("/tmp", "alloy-ssh-listing-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(root)) })
	require.NoError(t, os.Chmod(root, 0755))
	uid := os.Geteuid()
	configure := func(cmd *exec.Cmd) {
		cmd.Dir = root
		if uid == 0 {
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		}
	}
	childUID := uid
	if uid == 0 {
		childUID = 65534
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "id", "-u")
	cmd.WaitDelay = 100 * time.Millisecond
	configure(cmd)
	output, err := cmd.Output()
	require.NoError(t, err)
	require.Equal(t, strconv.Itoa(childUID)+"\n", string(output))
	t.Logf("process uid=%d; SSH shell child uid=%d (no permission cases skipped)", uid, childUID)
	return root, configure
}

func TestListingScraper(t *testing.T) {
	root, configure := listingFixture(t)
	host, _ := signer(t)
	server := serve(t, "127.0.0.1:0", host, "test-password", nil, false)
	server.mu.Lock()
	server.configureCommand = configure
	server.mu.Unlock()
	pool := newPool(t, configFor(t, server, host.PublicKey()))
	target := agentless.Target{Address: server.listener.Addr().String()}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	built, err := collectors.Build([]string{"fibrechannel", "tapestats"}, collectors.DefaultConfigs(), logger)
	require.NoError(t, err)
	present := filepath.Join(root, "present")
	require.NoError(t, os.Mkdir(present, 0755))
	file := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(file, nil, 0644))
	denied := filepath.Join(root, "denied")
	require.NoError(t, os.Mkdir(denied, 0700))
	require.NoError(t, os.Chmod(denied, 0000))
	t.Cleanup(func() { require.NoError(t, os.Chmod(denied, 0700)) })
	broken := filepath.Join(root, "broken")
	require.NoError(t, os.Symlink(filepath.Join(root, "absent-target"), broken))

	for _, tc := range []struct {
		name, path string
		missing    bool
		success    float64
	}{
		{"missing", filepath.Join(root, "absent"), true, 1},
		{"missing-parent", filepath.Join(root, "absent", "child"), true, 1},
		{"present-empty", present, false, 1},
		{"permission-denied", denied, false, 0},
		{"permission-denied-parent", filepath.Join(denied, "absent"), false, 0},
		{"wrong-kind-parent", filepath.Join(file, "child"), false, 0},
		{"broken-symlink-parent", filepath.Join(broken, "child"), false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var relocated []agentless.Collector
			var reads []agentless.Read
			for _, original := range built {
				c := fixtureListingCollector{Expander: original.(agentless.Expander), path: tc.path}
				relocated = append(relocated, c)
				reads = append(reads, c.Reads()...)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			results, err := pool.Run(ctx, target, reads)
			require.NoError(t, err)
			require.Len(t, results, 2)
			for _, result := range results {
				require.Equal(t, tc.missing, result.NotExist)
				require.False(t, result.TimedOut)
				require.False(t, result.Truncated)
				if tc.missing || tc.success == 0 {
					require.NotZero(t, result.ExitStatus)
				} else {
					require.Zero(t, result.ExitStatus)
				}
			}
			scraper, err := agentless.NewScraper(pool, relocated, logger)
			require.NoError(t, err)
			collected, err := scraper.Scrape(ctx, target)
			require.NoError(t, err)
			registry := prometheus.NewRegistry()
			require.NoError(t, registry.Register(collected))
			families, err := registry.Gather()
			require.NoError(t, err)
			// No hardware metrics or expansion reads on absent/empty/error
			// listings; only the actual Scraper's status and duration remain.
			require.Len(t, families, 2)
			seenSuccess := false
			for _, family := range families {
				switch family.GetName() {
				case "node_scrape_collector_success":
					seenSuccess = true
					require.Len(t, family.Metric, 2)
					for _, metric := range family.Metric {
						require.Equal(t, tc.success, metric.GetGauge().GetValue())
					}
				case "node_scrape_collector_duration_seconds":
					require.Len(t, family.Metric, 2)
				default:
					t.Fatalf("unexpected hardware family %s", family.GetName())
				}
			}
			require.True(t, seenSuccess)
		})
	}
}
