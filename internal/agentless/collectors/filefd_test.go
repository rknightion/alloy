package collectors

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
)

func TestFilefdConformance(t *testing.T) {
	conformance.Check(t, conformance.Case{Collector: &filefdCollector{}, Root: "testdata/filefd", Families: []string{"node_filefd_allocated", "node_filefd_maximum"}})
}

func TestFilefdFixedRead(t *testing.T) {
	c, err := newFilefdCollector(Configs{}, nil)
	require.NoError(t, err)
	require.Equal(t, "filefd", c.Name())
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/sys/fs/file-nr")}, c.Reads())
	require.NoError(t, c.Reads()[0].Validate())
}

func TestFilefdReadFailures(t *testing.T) {
	read := (&filefdCollector{}).Reads()[0]
	for name, in := range map[string]agentless.Input{
		"missing result":    nil,
		"exit":              {read.ID: {ExitStatus: 1}},
		"truncated":         {read.ID: {Truncated: true}},
		"timeout":           {read.ID: {TimedOut: true}},
		"missing timeout":   {read.ID: {NotExist: true, TimedOut: true}},
		"missing truncated": {read.ID: {NotExist: true, Truncated: true}},
	} {
		t.Run(name, func(t *testing.T) {
			ch := make(chan prometheus.Metric, 2)
			require.Error(t, (&filefdCollector{}).Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		})
	}
	ch := make(chan prometheus.Metric, 2)
	require.NoError(t, (&filefdCollector{}).Update(agentless.Target{}, agentless.Input{read.ID: {NotExist: true, ExitStatus: 1}}, ch))
	require.Empty(t, ch)
}

func TestFilefdRejectsMalformed(t *testing.T) {
	for _, output := range []string{"", "1\t0", "1\t0\t2\t3", "bad\t0\t2", "1\t0\tbad", "-1\t0\t2", "1\t-1\t2", "1\t0\tNaN", "1\t0\t+Inf", "1\t0\t1e999", "1\t0\t18446744073709551616", "1\t0\t2\n3\t0\t4"} {
		t.Run(output, func(t *testing.T) {
			c := &filefdCollector{}
			read := c.Reads()[0]
			ch := make(chan prometheus.Metric, 2)
			require.Error(t, c.Update(agentless.Target{}, agentless.Input{read.ID: {Output: []byte(output)}}, ch))
			require.Empty(t, ch)
		})
	}
}
