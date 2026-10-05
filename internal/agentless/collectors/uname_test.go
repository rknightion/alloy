package collectors

import (
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// This is a weaker, self-authored golden from real Linux SSH output, not a
// node_exporter e2e oracle (upstream disables uname in that test).
func TestUnameRealOutputGoldenWeakerProof(t *testing.T) {
	c, err := newUnameCollector(Configs{}, nil)
	require.NoError(t, err)
	commands := map[string]string{}
	for _, arg := range []string{"-s", "-n", "-r", "-v", "-m"} {
		commands[agentless.CommandRead("uname", arg).ID] = "testdata/uname/" + arg[1:]
	}
	conformance.Check(t, conformance.Case{Collector: c, Families: []string{"node_uname_info"}, Root: "testdata/uname", Commands: commands, Expected: "testdata/uname/expected.prom"})
}

func TestUnameReadFailuresEmitNothing(t *testing.T) {
	c, err := newUnameCollector(Configs{}, nil)
	require.NoError(t, err)
	for _, read := range c.Reads() {
		for _, failure := range []agentless.Result{{ExitStatus: 1}, {NotExist: true}, {Truncated: true}, {TimedOut: true}} {
			in := agentless.Input{}
			for _, r := range c.Reads() {
				in[r.ID] = agentless.Result{Read: r, Output: []byte("value\n")}
			}
			in[read.ID] = failure
			ch := make(chan prometheus.Metric, 1)
			require.Error(t, c.Update(agentless.Target{}, in, ch), read.ID)
			require.Empty(t, ch)
		}
	}
}
