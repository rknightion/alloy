package agentlesstest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/stretchr/testify/require"
)

func TestFromFSListingAndExpandedReads(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys/devices/empty"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sys/devices/z"), []byte("value\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sys/devices/a"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sys/devices/.hidden"), nil, 0o600))
	listing := agentless.CommandRead("ls", "-1", "/sys/devices")
	runner, err := agentlesstest.FromFS(root, nil, []agentless.Read{listing})
	require.NoError(t, err)
	reads := []agentless.Read{listing, agentless.CommandRead("ls", "-1", "/sys/devices/empty"), agentless.CommandRead("ls", "-1", "/missing"), agentless.FileRead("/sys/devices/z"), agentless.FileRead("/missing"), agentless.CommandRead("ls", "-R", "/sys/devices")}
	results, err := runner.Run(t.Context(), agentless.Target{}, reads)
	require.NoError(t, err)
	require.Len(t, results, len(reads))
	for i, result := range results {
		require.Equal(t, reads[i], result.Read)
	}
	require.Equal(t, "a\nempty\nz\n", string(results[0].Output))
	require.Zero(t, results[0].ExitStatus)
	require.Empty(t, results[1].Output)
	require.Zero(t, results[1].ExitStatus)
	require.True(t, results[2].NotExist)
	require.Equal(t, 1, results[2].ExitStatus)
	require.Equal(t, "value\n", string(results[3].Output))
	require.True(t, results[4].NotExist)
	require.True(t, results[5].NotExist, "no recursive listing simulation")
}

func TestFromFSSecondLevelListingAndFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys/devices/a"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sys/devices/a/value"), []byte("42\n"), 0o600))
	listing := agentless.CommandRead("ls", "-1", "/sys/devices")
	runner, err := agentlesstest.FromFS(root, nil, []agentless.Read{listing})
	require.NoError(t, err)
	for _, phase := range []struct {
		read   agentless.Read
		output string
	}{
		{listing, "a\n"},
		{agentless.CommandRead("ls", "-1", "/sys/devices/a"), "value\n"},
		{agentless.FileRead("/sys/devices/a/value"), "42\n"},
	} {
		results, err := runner.Run(t.Context(), agentless.Target{}, []agentless.Read{phase.read})
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.Equal(t, phase.read, results[0].Read)
		require.Zero(t, results[0].ExitStatus)
		require.Equal(t, phase.output, string(results[0].Output))
	}
	require.Equal(t, 3, runner.Calls())
}

func TestFromFSExplicitListingOutput(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	require.NoError(t, os.WriteFile(output, []byte("override\n"), 0o600))
	listing := agentless.CommandRead("ls", "-1", "/missing")
	runner, err := agentlesstest.FromFS(root, map[string]string{listing.ID: output}, nil)
	require.NoError(t, err)
	results, err := runner.Run(t.Context(), agentless.Target{}, []agentless.Read{listing})
	require.NoError(t, err)
	require.Equal(t, "override\n", string(results[0].Output))
	require.Zero(t, results[0].ExitStatus)
}
