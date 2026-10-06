package collectors_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/collectors"
	"github.com/grafana/alloy/internal/util"
)

func TestDefaultEnabledCoversTheLandedCollectors(t *testing.T) {
	require.Equal(t, []string{
		"conntrack", "cpu", "diskstats", "entropy", "filefd", "filesystem", "loadavg", "meminfo", "netdev", "netstat", "os", "pressure", "stat", "uname", "vmstat",
	}, collectors.DefaultEnabled())
}

func TestBuildRejectsUnknownAndDuplicateNames(t *testing.T) {
	logger := util.TestLogger(t)
	_, err := collectors.Build([]string{"cpu", "nosuch"}, collectors.DefaultConfigs(), logger)
	require.ErrorContains(t, err, `unknown collector "nosuch"`)

	_, err = collectors.Build([]string{"cpu", "cpu"}, collectors.DefaultConfigs(), logger)
	require.ErrorContains(t, err, "listed twice")

	cs, err := collectors.Build([]string{"meminfo", "cpu"}, collectors.DefaultConfigs(), logger)
	require.NoError(t, err)
	require.Equal(t, "meminfo", cs[0].Name())
	require.Equal(t, "cpu", cs[1].Name())
}

func TestEveryRegisteredReadIsSafe(t *testing.T) {
	for _, r := range collectors.Registered() {
		c, err := r.Factory(collectors.DefaultConfigs(), util.TestLogger(t))
		require.NoError(t, err)
		require.Equal(t, r.Name, c.Name())
		for _, read := range c.Reads() {
			require.NoError(t, read.Validate(), "collector %s", r.Name)
		}
	}
}

func TestAllCollectorsFitInOneBatch(t *testing.T) {
	var names []string
	for _, r := range collectors.Registered() {
		names = append(names, r.Name)
	}
	cs, err := collectors.Build(names, collectors.DefaultConfigs(), util.TestLogger(t))
	require.NoError(t, err)
	_, err = agentless.NewScraper(&agentlesstest.FakeRunner{}, cs, util.TestLogger(t))
	require.NoError(t, err, "two collectors declare different reads under one ID")
}
