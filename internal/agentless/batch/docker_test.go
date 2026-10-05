//go:build !nodocker

package batch

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/stretchr/testify/require"
)

// Exercise the real Docker test's failure path without contacting the daemon.
// Even an apparent container ID on a failed create must not authorize removal.
func TestDockerCreateFailureDoesNotRemoveContainers(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "commands.log")
	fake := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$BATCH_DOCKER_COMMAND_LOG\"\nprintf '%064d\\n' 0\nprintf 'simulated creation failure\\n' >&2\nexit 1\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("BATCH_DOCKER_COMMAND_LOG", log)
	binary, err := os.Executable()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, "-test.run=^TestDockerShells$", "-test.timeout=30s").CombinedOutput()
	require.Error(t, err)
	require.NoError(t, ctx.Err())
	require.Contains(t, string(output), "simulated creation failure")
	commands, err := os.ReadFile(log)
	require.NoError(t, err)
	require.NotContains(t, string(commands), "rm ", "a failed creation must never remove a container")
	require.Equal(t, "create -i busybox:1.37 sh -s\ncreate -i debian:bookworm-slim sh -s\n", string(commands))
}

// Docker assigns a unique ID; register cleanup only after creation succeeds.
// Never remove by name: a failed create must not delete another invocation's
// container. Each script has its own container, including the cancelled one.
func createDockerShell(t *testing.T, ctx context.Context, image string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "create", "-i", image, "sh", "-s")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	require.NoError(t, err, stderr.String())
	id := strings.TrimSpace(string(output))
	require.Regexp(t, "^[0-9a-f]{64}$", id)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		output, err := exec.CommandContext(cleanup, "docker", "rm", "-f", id).CombinedOutput()
		require.NoError(t, err, string(output))
	})
	return id
}

func TestDockerShells(t *testing.T) {
	for _, tc := range []struct{ name, image string }{{"busybox", "busybox:1.37"}, {"dash", "debian:bookworm-slim"}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			script, err := Build(fixtureReads(), testNonce)
			require.NoError(t, err)
			id := createDockerShell(t, ctx, tc.image)
			cmd := exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
			cmd.Stdin = strings.NewReader(script)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			require.NoError(t, err, stderr.String())
			if os.Getenv("BATCH_RECORD_FIXTURES") == "1" {
				require.NoError(t, os.MkdirAll("testdata", 0755))
				require.NoError(t, os.WriteFile("testdata/"+tc.name+".out", output, 0644))
			}
			recorded, err := os.ReadFile("testdata/" + tc.name + ".out")
			require.NoError(t, err)
			require.Equal(t, recorded, output)
			results, err := Demux(ctx, bytes.NewReader(output), testNonce, fixtureReads(), DefaultLimits)
			require.NoError(t, err)
			require.Equal(t, "hello", string(results[0].Output))
			require.Equal(t, 1, results[1].ExitStatus)
			require.True(t, results[2].NotExist)
			require.Equal(t, "tail", string(results[3].Output))
			// A read that exceeds the receiver cap must not lose the next section.
			reads := []agentless.Read{agentless.CommandRead("seq", "1", "10000"), agentless.CommandRead("printf", "tail")}
			script, err = Build(reads, testNonce)
			require.NoError(t, err)
			id = createDockerShell(t, ctx, tc.image)
			cmd = exec.CommandContext(ctx, "docker", "start", "-a", "-i", id)
			cmd.Stdin = strings.NewReader(script)
			output, err = cmd.Output()
			require.NoError(t, err)
			results, err = Demux(ctx, bytes.NewReader(output), testNonce, reads, Limits{MaxSectionBytes: 10, MaxOutputBytes: 100000})
			require.NoError(t, err)
			require.True(t, results[0].Truncated)
			require.Len(t, results[0].Output, 10)
			require.Equal(t, "tail", string(results[1].Output))

			reads = []agentless.Read{agentless.CommandRead("printf", "hello"), agentless.CommandRead("sleep", "10"), agentless.CommandRead("printf", "tail")}
			script, err = Build(reads, testNonce)
			require.NoError(t, err)
			id = createDockerShell(t, ctx, tc.image)
			deadline, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			cmd = exec.CommandContext(deadline, "docker", "start", "-a", "-i", id)
			cmd.Stdin = strings.NewReader(script)
			stream, err := cmd.StdoutPipe()
			require.NoError(t, err)
			require.NoError(t, cmd.Start())
			results, err = Demux(deadline, stream, testNonce, reads, DefaultLimits)
			require.NoError(t, err)
			require.Equal(t, "hello", string(results[0].Output))
			require.False(t, results[0].TimedOut)
			require.True(t, results[1].TimedOut)
			require.True(t, results[2].TimedOut)
			require.Error(t, cmd.Wait())
		})
	}
}
