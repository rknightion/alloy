package conformance

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// A minimal parser exercises the real fixture-to-Update-to-exposition path,
// independently of the production collectors that will use this harness.
type loadCollector struct {
	fault string
	read  agentless.Read
}

func (c loadCollector) Name() string            { return "loadavg" }
func (c loadCollector) Reads() []agentless.Read { return []agentless.Read{c.read} }
func (c loadCollector) Update(_ agentless.Target, in agentless.Input, ch chan<- prometheus.Metric) error {
	b, err := in.Output(c.read)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return errors.New("short loadavg input")
	}
	for i, name := range []string{"node_load1", "node_load5", "node_load15"} {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return err
		}
		if c.fault == "missing" && i == 0 {
			continue
		}
		if c.fault == "name" && i == 0 {
			name = "node_wrong_load1"
		}
		if c.fault == "value" && i == 0 {
			v++
		}
		labels := []string(nil)
		values := []string(nil)
		if c.fault == "label" {
			labels = []string{"unexpected"}
			values = []string{"label"}
		}
		kind := prometheus.GaugeValue
		if c.fault == "type" {
			kind = prometheus.CounterValue
		}
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc(name, []string{"1m load average.", "5m load average.", "15m load average."}[i], labels, nil), kind, v, values...)
	}
	if c.fault == "error" {
		return errors.New("deliberate Update error")
	}
	if c.fault == "extra" {
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("node_unowned", "Unowned.", nil, nil), prometheus.GaugeValue, 1)
	}
	return nil
}
func loadCase(fault string) Case {
	return Case{Collector: loadCollector{fault: fault, read: agentless.FileRead("/proc/loadavg")}, Families: []string{"node_load1", "node_load5", "node_load15"}}
}
func TestCheckFixtures(t *testing.T) { Check(t, loadCase("")) }

func TestCheckCommandAndCustomOracle(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "command")
	expected := filepath.Join(dir, "expected")
	require.NoError(t, os.WriteFile(input, []byte("2 3 4 1/10 9\n"), 0600))
	require.NoError(t, os.WriteFile(expected, []byte("# HELP node_load1 1m load average.\n# TYPE node_load1 gauge\nnode_load1 2\n# HELP node_load5 5m load average.\n# TYPE node_load5 gauge\nnode_load5 3\n# HELP node_load15 15m load average.\n# TYPE node_load15 gauge\nnode_load15 4\n"), 0600))
	read := agentless.CommandRead("uptime")
	c := loadCase("")
	c.Collector = loadCollector{read: read}
	c.Commands = map[string]string{read.ID: input}
	c.Expected = expected
	c.Root = dir
	Check(t, c)
}

// A real testing.TB cannot be faked (it has private methods). Subprocesses
// assert that Check itself fails the test, not merely that a comparison helper
// returns an error. A deadline bounds each deliberately failing test process.
func TestCheckRejectsBadCollectors(t *testing.T) {
	for _, fault := range []string{"name", "value", "label", "type", "missing", "extra", "error", "empty", "unknown", "duplicate", "missing-input", "bad-expected"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCheckProcess$", "-test.v")
			cmd.Env = append(os.Environ(), "CONFORMANCE_FAULT="+fault)
			out, err := cmd.CombinedOutput()
			require.NoError(t, ctx.Err(), "subprocess timed out: %s", out)
			require.Error(t, err, "Check unexpectedly accepted %s: %s", fault, out)
			require.Contains(t, string(out), "--- FAIL: TestCheckProcess")
			require.NotContains(t, string(out), "not implemented", "stub failure is not conformance evidence")
			require.Contains(t, string(out), "conformance:")
		})
	}
}
func TestCheckProcess(t *testing.T) {
	fault := os.Getenv("CONFORMANCE_FAULT")
	if fault == "" {
		return
	}
	c := loadCase(fault)
	switch fault {
	case "empty":
		c.Families = nil
	case "unknown":
		c.Families = append(c.Families, "node_nonexistent")
	case "duplicate":
		c.Families = append(c.Families, "node_load1")
	case "missing-input":
		c.Root = t.TempDir()
	case "bad-expected":
		c.Expected = filepath.Join(t.TempDir(), "expected")
		require.NoError(t, os.WriteFile(c.Expected, []byte("malformed{\n"), 0600))
	}
	Check(t, c)
}

func TestFixturePin(t *testing.T) {
	mod, err := os.ReadFile("../../../go.mod")
	require.NoError(t, err)
	notice, err := os.ReadFile("testdata/node_exporter/NOTICE")
	require.NoError(t, err)
	const pin = "github.com/grafana/node_exporter v0.18.1-grafana-r01.0.20251024135609-318b01780c89"
	require.Contains(t, string(mod), "replace github.com/prometheus/node_exporter => "+pin)
	require.Contains(t, strings.Join(strings.Fields(string(notice)), " "), pin, "fixture attribution must track go.mod")
}
