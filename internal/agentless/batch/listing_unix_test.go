//go:build unix

package batch

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/stretchr/testify/require"
)

// Use a directly-owned /tmp directory, not t.TempDir's potentially private
// ancestors. Only these fixtures become traversable; denied stays mode 0000.
func listingFixture(t *testing.T) (string, func(*exec.Cmd)) {
	t.Helper()
	//nolint:usetesting // t.TempDir may sit below private, non-test-owned TMPDIR ancestors.
	root, err := os.MkdirTemp("/tmp", "alloy-listing-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(root)) })
	require.NoError(t, os.Chmod(root, 0755))
	uid := os.Geteuid()
	configure := func(cmd *exec.Cmd) {
		cmd.Dir = root
		cmd.WaitDelay = 100 * time.Millisecond
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
	configure(cmd)
	output, err := cmd.Output()
	require.NoError(t, err)
	require.Equal(t, strconv.Itoa(childUID)+"\n", string(output))
	t.Logf("process uid=%d; listing child uid=%d (no permission cases skipped)", uid, childUID)
	return root, configure
}

// Run the actual compiled script, not recorded framing or a fake runner.
func shellResults(t *testing.T, reads []agentless.Read, env []string, configure func(*exec.Cmd)) []agentless.Result {
	t.Helper()
	script, err := Build(reads, testNonce)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-s")
	configure(cmd)
	cmd.Stdin = strings.NewReader(script)
	cmd.Env = env
	output, err := cmd.Output()
	require.NoError(t, err)
	results, err := Demux(ctx, bytes.NewReader(output), testNonce, reads, DefaultLimits)
	require.NoError(t, err)
	return results
}

func TestListingShell(t *testing.T) {
	root, configure := listingFixture(t)
	present := filepath.Join(root, "present")
	require.NoError(t, os.Mkdir(present, 0755))
	for _, name := range []string{"host0", "st0", "white space", "semi;colon"} {
		require.NoError(t, os.WriteFile(filepath.Join(present, name), nil, 0644))
	}
	file := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(file, nil, 0644))
	denied := filepath.Join(root, "denied")
	require.NoError(t, os.Mkdir(denied, 0700))
	require.NoError(t, os.Mkdir(filepath.Join(denied, "exists"), 0700))
	require.NoError(t, os.Chmod(denied, 0000))
	t.Cleanup(func() { require.NoError(t, os.Chmod(denied, 0700)) })
	broken := filepath.Join(root, "broken")
	require.NoError(t, os.Symlink(filepath.Join(root, "missing-target"), broken))
	loop := filepath.Join(root, "loop")
	require.NoError(t, os.Symlink(loop, loop))
	link := filepath.Join(root, "link")
	require.NoError(t, os.Symlink(present, link))

	for _, tc := range []struct {
		name, path string
		missing    bool
	}{
		{"absent", filepath.Join(root, "absent"), true},
		{"absent-ancestor", filepath.Join(root, "absent", "child"), true},
		{"absent-trailing-slash", filepath.Join(root, "absent") + "/", true},
		{"absent-under-link", filepath.Join(link, "absent"), true},
		{"denied-listing", denied, false},
		{"denied-existing-child", filepath.Join(denied, "exists"), false},
		{"denied-absent-child", filepath.Join(denied, "absent"), false},
		{"wrong-kind-parent", filepath.Join(file, "child"), false},
		{"broken-link-child", filepath.Join(broken, "child"), false},
		{"broken-link-slash", broken + "/", false},
		{"symlink-loop-slash", loop + "/", false},
		{"symlink-loop-child", filepath.Join(loop, "child"), false},
		{"overlong-component", filepath.Join(root, strings.Repeat("a", 256)), false},
		{"overlong-path", root + strings.Repeat("/component", 500), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := agentless.CommandRead("ls", "-1", tc.path)
			result := shellResults(t, []agentless.Read{read}, nil, configure)[0]
			require.NotZero(t, result.ExitStatus)
			require.Equal(t, tc.missing, result.NotExist)
			require.False(t, result.TimedOut)
			require.False(t, result.Truncated)
		})
	}
	// ls may successfully print a non-directory or dangling symlink itself;
	// preserve that existing success rather than inventing an error category.
	for _, path := range []string{present, link, file, broken} {
		read := agentless.CommandRead("ls", "-1", path)
		result := shellResults(t, []agentless.Read{read}, nil, configure)[0]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ls", "-1", path)
		configure(cmd)
		want, err := cmd.Output()
		require.NoError(t, err)
		require.Zero(t, result.ExitStatus)
		require.False(t, result.NotExist)
		require.Equal(t, want, result.Output, "successful listing bytes must not change")
	}
	t.Run("bare-symlink-loop", func(t *testing.T) {
		// GNU ls fails here, whereas BSD ls prints the symlink. Compare the
		// exact native status and bytes rather than assuming either behaviour.
		read := agentless.CommandRead("ls", "-1", loop)
		result := shellResults(t, []agentless.Read{read}, nil, configure)[0]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ls", "-1", loop)
		configure(cmd)
		want, err := cmd.Output()
		status := 0
		if err != nil {
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			status = exit.ExitCode()
		}
		require.Equal(t, status, result.ExitStatus)
		require.Equal(t, want, result.Output)
		require.False(t, result.NotExist)
	})
	t.Run("command-missing", func(t *testing.T) {
		result := shellResults(t, []agentless.Read{agentless.CommandRead("ls", "-1", present)}, []string{"PATH=" + root}, configure)[0]
		require.Equal(t, 127, result.ExitStatus)
		require.True(t, result.NotExist)
	})
	t.Run("other-command-error", func(t *testing.T) {
		bin := filepath.Join(root, "bin")
		require.NoError(t, os.Mkdir(bin, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(bin, "ls"), []byte("#!/bin/sh\nprintf partial\nexit 2\n"), 0755))
		result := shellResults(t, []agentless.Read{agentless.CommandRead("ls", "-1", present)}, []string{"PATH=" + bin}, configure)[0]
		require.Equal(t, 2, result.ExitStatus)
		require.False(t, result.NotExist)
		require.Equal(t, "partial", string(result.Output))
	})
	t.Run("noncanonical-forms", func(t *testing.T) {
		reads := []agentless.Read{
			agentless.CommandRead("ls", "-1d", filepath.Join(root, "absent")),
			agentless.CommandRead("ls", "-1", filepath.Join(root, "absent"), present),
			agentless.CommandRead("ls", "-1", "alloy-agentless-absent-relative"),
		}
		for _, result := range shellResults(t, reads, nil, configure) {
			require.NotZero(t, result.ExitStatus)
			require.False(t, result.NotExist)
		}
	})
}
