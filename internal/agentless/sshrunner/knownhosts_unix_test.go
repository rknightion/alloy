//go:build unix

package sshrunner

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestKnownHostsUnsafeFiles(t *testing.T) {
	if path := os.Getenv("ALLOY_SSH_TEST_KNOWN_HOSTS"); path != "" {
		_, err := New(Config{Auths: map[string]Auth{DefaultAuthName: {Username: "reader", Password: []byte("fixture")}}, KnownHostsFiles: []string{path}}, nil, nil)
		require.Error(t, err)
		return
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	large := filepath.Join(t.TempDir(), "large")
	require.NoError(t, os.WriteFile(large, bytes.Repeat([]byte("#\n"), (5<<20)/2), 0600))
	for _, path := range []string{"/dev/zero", fifo, large} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			// A faulty loader must not hang the test binary or allocate without
			// bound on /dev/zero. Kill the isolated child after two seconds.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKnownHostsUnsafeFiles$")
			cmd.Env = append(os.Environ(), "ALLOY_SSH_TEST_KNOWN_HOSTS="+path)
			output, err := cmd.CombinedOutput()
			require.NoError(t, ctx.Err(), "unsafe file blocked: %s", output)
			require.NoError(t, err, "%s", output)
		})
	}
}

func TestKnownHostsNonblockingOpen(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0600))
	// Verify the race defence independently: even if a regular file was
	// swapped for a FIFO after Stat, opening it does not wait for a writer.
	f, err := openKnownHosts(fifo)
	require.NoError(t, err)
	require.NoError(t, f.Close())
}
