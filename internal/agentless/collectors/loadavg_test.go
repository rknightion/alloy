package collectors

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
)

func TestLoadavgConformance(t *testing.T) {
	conformance.Check(t, conformance.Case{Collector: &loadavgCollector{}, Families: []string{"node_load1", "node_load5", "node_load15"}})
}

func TestLoadavgReadFailures(t *testing.T) {
	read := agentless.FileRead("/proc/loadavg")
	for name, in := range map[string]agentless.Input{
		"missing":   {},
		"exit":      {read.ID: {ExitStatus: 1}},
		"not found": {read.ID: {NotExist: true}},
		"truncated": {read.ID: {Truncated: true}},
		"timeout":   {read.ID: {TimedOut: true}},
	} {
		t.Run(name, func(t *testing.T) {
			ch := make(chan prometheus.Metric, 3)
			require.Error(t, (&loadavgCollector{}).Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		})
	}
}

func TestLoadavgRejectsMalformedInput(t *testing.T) {
	for _, data := range []string{"", "1 2", "bad 2 3", "1 bad 3", "1 2 bad", "NaN 2 3", "1 +Inf 3", "1 2 -Inf", "-1 2 3", "1 2 1e999"} {
		t.Run(data, func(t *testing.T) {
			read := agentless.FileRead("/proc/loadavg")
			ch := make(chan prometheus.Metric, 3)
			err := (&loadavgCollector{}).Update(agentless.Target{}, agentless.Input{read.ID: {Read: read, Output: []byte(data)}}, ch)
			require.Error(t, err)
			require.Empty(t, ch)
		})
	}
}
