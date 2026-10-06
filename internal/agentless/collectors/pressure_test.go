package collectors

import (
	"os"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/grafana/alloy/internal/util"
)

func TestPressureConformance(t *testing.T) {
	conformance.Check(t, conformance.Case{Collector: &pressureCollector{}, Root: "testdata/pressure", Expected: "testdata/pressure/golden.prom", Families: []string{
		"node_pressure_cpu_waiting_seconds_total", "node_pressure_memory_waiting_seconds_total", "node_pressure_memory_stalled_seconds_total", "node_pressure_io_waiting_seconds_total", "node_pressure_io_stalled_seconds_total",
	}})
}

func pressureInput(t *testing.T) agentless.Input {
	t.Helper()
	in := agentless.Input{}
	for _, r := range (&pressureCollector{}).Reads() {
		output, err := os.ReadFile("testdata/pressure" + r.Path)
		if os.IsNotExist(err) {
			in[r.ID] = agentless.Result{Read: r, NotExist: true, ExitStatus: 1}
			continue
		}
		require.NoError(t, err)
		in[r.ID] = agentless.Result{Read: r, Output: output}
	}
	return in
}

func TestPressureRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"pressure"}, DefaultConfigs(), util.TestLogger(t))
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "pressure", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "pressure")
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/pressure/cpu"), agentless.FileRead("/proc/pressure/memory"), agentless.FileRead("/proc/pressure/io"), agentless.FileRead("/proc/pressure/irq")}, built[0].Reads())
	for _, r := range built[0].Reads() {
		require.NoError(t, r.Validate())
		require.Empty(t, r.Argv)
	}
}

func TestPressureRejectsMalformedWithoutPartialMetrics(t *testing.T) {
	valid := "some avg10=0.00 avg60=0.01 avg300=2.00 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"
	for _, output := range []string{"", "garbage", "some total=1", strings.ReplaceAll(valid, "total=123", "total=-1"), strings.ReplaceAll(valid, "total=123", "total=18446744073709551616"), strings.ReplaceAll(valid, "avg10=0.00", "avg10=NaN"), strings.ReplaceAll(valid, "avg10=0.00", "avg10=+Inf"), strings.ReplaceAll(valid, "avg10=0.00", "avg10=-1"), valid + valid, valid + "garbage\n", strings.Repeat("x", 70000), strings.Repeat(valid, 10000)} {
		t.Run(output[:min(len(output), 60)], func(t *testing.T) {
			in := pressureInput(t)
			r := (&pressureCollector{}).Reads()[2]
			in[r.ID] = agentless.Result{Read: r, Output: []byte(output)}
			ch := make(chan prometheus.Metric, 10)
			require.Error(t, (&pressureCollector{}).Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		})
	}
}

func TestPressureOptionalAndIsolatedFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		result  agentless.Result
		success string
	}{
		{"missing", agentless.Result{NotExist: true, ExitStatus: 1}, "1"},
		{"nonzero", agentless.Result{ExitStatus: 2}, "0"},
		{"malformed", agentless.Result{Output: []byte("bad\n")}, "0"},
		{"truncated", agentless.Result{Truncated: true}, "0"},
		{"timeout", agentless.Result{TimedOut: true}, "0"},
		{"missing timeout", agentless.Result{NotExist: true, ExitStatus: 1, TimedOut: true}, "0"},
		{"missing truncated", agentless.Result{NotExist: true, ExitStatus: 1, Truncated: true}, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := map[string]agentless.Result{}
			for _, r := range (&pressureCollector{}).Reads() {
				results[r.ID] = tc.result
			}
			mem := agentless.FileRead("/proc/meminfo")
			results[mem.ID] = agentless.Result{Output: []byte("MemTotal: 1 kB\n")}
			s, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: results}, []agentless.Collector{&pressureCollector{}, &meminfoCollector{}}, util.TestLogger(t))
			require.NoError(t, err)
			collected, err := s.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			require.NoError(t, testutil.CollectAndCompare(collected, strings.NewReader(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="meminfo"} 1
node_scrape_collector_success{collector="pressure"} `+tc.success+`
# HELP node_memory_MemTotal_bytes Memory information field MemTotal_bytes.
# TYPE node_memory_MemTotal_bytes gauge
node_memory_MemTotal_bytes 1024
`), "node_scrape_collector_success", "node_memory_MemTotal_bytes"))
			require.Zero(t, testutil.CollectAndCount(collected, "node_pressure_cpu_waiting_seconds_total", "node_pressure_memory_waiting_seconds_total", "node_pressure_memory_stalled_seconds_total", "node_pressure_io_waiting_seconds_total", "node_pressure_io_stalled_seconds_total"))
		})
	}
	require.Error(t, (&pressureCollector{}).Update(agentless.Target{}, nil, make(chan prometheus.Metric, 10)))
}

func TestPressureOptionalIRQAndCPUFull(t *testing.T) {
	in := pressureInput(t)
	c := &pressureCollector{}
	cpu, irq := c.Reads()[0], c.Reads()[3]
	res := in[cpu.ID]
	res.Output = append(res.Output, []byte("full avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n")...)
	in[cpu.ID] = res
	in[irq.ID] = agentless.Result{Output: []byte("full avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n")}
	ch := make(chan prometheus.Metric, 10)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, 5, "CPU full and IRQ must not add non-default families")
	in[irq.ID] = agentless.Result{Output: []byte("garbage")}
	require.Error(t, c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 10)))
}
