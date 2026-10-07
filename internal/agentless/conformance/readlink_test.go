package conformance_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

type readlinkCollector struct {
	phase int
}

var identityRead = agentless.CommandRead("readlink", "-f", "/sys/class/device")

func (readlinkCollector) Name() string { return "identity" }
func (readlinkCollector) Reads() []agentless.Read {
	return []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class")}
}
func (c readlinkCollector) Expand(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	b, err := in.Output(c.Reads()[0])
	if err != nil || string(b) != "device\n" {
		return nil, fmt.Errorf("unexpected initial listing %q: %v", b, err)
	}
	if c.phase == 2 {
		return []agentless.Read{identityRead}, nil
	}
	return nil, nil
}
func (c readlinkCollector) ExpandDeep(_ agentless.Target, in agentless.Input) ([]agentless.Read, error) {
	if c.phase == 3 {
		return []agentless.Read{identityRead}, nil
	}
	b, err := in.Output(identityRead)
	if err != nil || string(b) != "/sys/chip\n" {
		return nil, fmt.Errorf("unexpected phase-two identity %q: %v", b, err)
	}
	return []agentless.Read{agentless.FileRead(strings.TrimSuffix(string(b), "\n") + "/value")}, nil
}
func (c readlinkCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	b, err := in.Output(identityRead)
	if err != nil {
		return err
	}
	if c.phase == 2 {
		value, err := in.Output(agentless.FileRead("/sys/chip/value"))
		if err != nil || string(value) != "42\n" {
			return fmt.Errorf("unexpected phase-three value %q: %v", value, err)
		}
	}
	ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("node_test_identity", "Identity.", []string{"path"}, nil), prometheus.GaugeValue, 1, strings.TrimSuffix(string(b), "\n"))
	return nil
}

func TestCheckReadlink(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys/class"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "sys/chip"), 0o700))
	require.NoError(t, os.Symlink("/sys/chip", filepath.Join(root, "sys/class/device")))
	require.NoError(t, os.WriteFile(filepath.Join(root, "sys/chip/value"), []byte("42\n"), 0o600))
	expected := filepath.Join(root, "expected")
	require.NoError(t, os.WriteFile(expected, []byte("# HELP node_test_identity Identity.\n# TYPE node_test_identity gauge\nnode_test_identity{path=\"/sys/chip\"} 1\n"), 0o600))
	for _, phase := range []int{2, 3} {
		t.Run(fmt.Sprintf("phase%d", phase), func(t *testing.T) {
			conformance.Check(t, conformance.Case{Collector: readlinkCollector{phase: phase}, Root: root, Expected: expected, Families: []string{"node_test_identity"}})
		})
	}
}
