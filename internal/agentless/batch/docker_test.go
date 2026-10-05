//go:build !nodocker

package batch

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/stretchr/testify/require"
)

func TestDockerShells(t *testing.T) {
	for _, tc := range []struct{ name, image string }{{"busybox", "busybox:1.37"}, {"dash", "debian:bookworm-slim"}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			name := "alloy-batch-" + tc.name
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
				defer stop()
				_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
			})
			script, err := Build(fixtureReads(), testNonce)
			require.NoError(t, err)
			cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--name", name, "-i", tc.image, "sh", "-s")
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
			cmd = exec.CommandContext(ctx, "docker", "run", "--rm", "--name", name, "-i", tc.image, "sh", "-s")
			cmd.Stdin = strings.NewReader(script)
			output, err = cmd.Output()
			require.NoError(t, err)
			results, err = Demux(ctx, bytes.NewReader(output), testNonce, reads, Limits{MaxSectionBytes: 10, MaxOutputBytes: 100000})
			require.NoError(t, err)
			require.True(t, results[0].Truncated)
			require.Len(t, results[0].Output, 10)
			require.Equal(t, "tail", string(results[1].Output))

			deadline, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			reads = []agentless.Read{agentless.CommandRead("printf", "hello"), agentless.CommandRead("sleep", "10"), agentless.CommandRead("printf", "tail")}
			script, err = Build(reads, testNonce)
			require.NoError(t, err)
			cmd = exec.CommandContext(deadline, "docker", "run", "--rm", "--name", name, "-i", tc.image, "sh", "-s")
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
