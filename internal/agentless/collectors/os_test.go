package collectors

import (
	"bytes"
	"strings"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestOSConformancePinnedOracle(t *testing.T) {
	c, err := newOSCollector(Configs{}, nil)
	require.NoError(t, err)
	require.Equal(t, "os", c.Name())
	conformance.Check(t, conformance.Case{Collector: c, Families: []string{"node_os_info", "node_os_version"}})
}

func TestOSParsingAndVersion(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
		version          float64
	}{
		{"double quotes", "NAME=\"A \\\"quoted\\\" name\"\nVERSION_ID=24.04.3\n", "A \"quoted\" name", 24.04},
		{"single quotes", "NAME='A literal $HOME `command` $(command)'\nVERSION_ID=9\n", "A literal $HOME `command` $(command)", 9},
		{"comments and duplicate", "# ignored\nNAME=First\nNAME=Second\nVERSION_ID=rolling\n", "Second", 0},
		{"unknown and empty", "UNUSED=ignored\nNAME=\nVERSION_ID=0\n", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newOSCollector(Configs{}, nil)
			require.NoError(t, err)
			in := agentless.Input{agentless.FileRead("/etc/os-release").ID: {Output: []byte(tc.data)}}
			ch := make(chan prometheus.Metric, 2)
			require.NoError(t, c.Update(agentless.Target{}, in, ch))
			m := &dto.Metric{}
			require.NoError(t, (<-ch).Write(m))
			labels := map[string]string{}
			for _, l := range m.Label {
				labels[l.GetName()] = l.GetValue()
			}
			require.Len(t, labels, 12)
			require.Equal(t, tc.want, labels["name"])
			if tc.version > 0 {
				require.Len(t, ch, 1)
				require.NoError(t, (<-ch).Write(m))
				require.Equal(t, tc.version, m.Gauge.GetValue())
			} else {
				require.Empty(t, ch)
			}
		})
	}
}

func TestOSFallbackOnlyForMissingFile(t *testing.T) {
	c, err := newOSCollector(Configs{}, nil)
	require.NoError(t, err)
	etc := agentless.FileRead("/etc/os-release")
	usr := agentless.FileRead("/usr/lib/os-release")
	for _, tc := range []struct {
		name   string
		result agentless.Result
		ok     bool
	}{
		{"missing", agentless.Result{NotExist: true, ExitStatus: 1}, true},
		{"permission denied", agentless.Result{ExitStatus: 1}, false},
		{"truncated", agentless.Result{Truncated: true}, false},
		{"timeout", agentless.Result{TimedOut: true}, false},
		{"bad syntax", agentless.Result{Output: []byte("NAME=\"unterminated")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := agentless.Input{etc.ID: tc.result, usr.ID: {Output: []byte("NAME=Fallback\n")}}
			ch := make(chan prometheus.Metric, 2)
			err := c.Update(agentless.Target{}, in, ch)
			if tc.ok {
				require.NoError(t, err)
				require.Len(t, ch, 1)
			} else {
				require.Error(t, err)
				require.Empty(t, ch)
			}
		})
	}
	for _, in := range []agentless.Input{{}, {etc.ID: {NotExist: true}, usr.ID: {NotExist: true}}} {
		require.Error(t, c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 2)))
	}
}

func TestOSPrefersEtcWithoutMerging(t *testing.T) {
	c, err := newOSCollector(Configs{}, nil)
	require.NoError(t, err)
	in := agentless.Input{agentless.FileRead("/etc/os-release").ID: {Output: []byte("NAME=Preferred\n")}, agentless.FileRead("/usr/lib/os-release").ID: {Output: []byte("ID=must_not_merge\n")}}
	ch := make(chan prometheus.Metric, 2)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	m := &dto.Metric{}
	require.NoError(t, (<-ch).Write(m))
	var buf bytes.Buffer
	for _, l := range m.Label {
		buf.WriteString(l.GetValue())
	}
	require.Equal(t, "Preferred", strings.TrimSpace(buf.String()))
}
