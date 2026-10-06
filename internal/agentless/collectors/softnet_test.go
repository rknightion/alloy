package collectors

import (
	"fmt"
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

// Fixture and golden are copied unchanged (golden filtered to owned families)
// from node_exporter v0.18.1-grafana-r01.0.20251024135609-318b01780c89.
func TestSoftnetConformance(t *testing.T) {
	c, err := newSoftnetCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/softnet", Expected: "testdata/softnet/golden.prom", Families: []string{
		"node_softnet_processed_total", "node_softnet_dropped_total", "node_softnet_times_squeezed_total", "node_softnet_cpu_collision_total", "node_softnet_received_rps_total", "node_softnet_flow_limit_count_total", "node_softnet_backlog_len",
	}})
}

func TestSoftnetRegistrationAndReads(t *testing.T) {
	cs, err := Build([]string{"softnet"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, cs, 1)
	require.Equal(t, "softnet", cs[0].Name())
	require.NotContains(t, DefaultEnabled(), "softnet")
	found := false
	for _, r := range Registered() {
		if r.Name == "softnet" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/softnet_stat")}, cs[0].Reads())
	for _, read := range cs[0].Reads() {
		require.NoError(t, read.Validate())
		require.Empty(t, read.Argv)
	}
}

func TestSoftnetFailuresAndScraperIsolation(t *testing.T) {
	fixture, err := os.ReadFile("testdata/softnet/proc/net/softnet_stat")
	require.NoError(t, err)
	cases := map[string]agentless.Result{
		"missing": {NotExist: true, ExitStatus: 1}, "nonzero": {ExitStatus: 2}, "truncated": {Truncated: true}, "timeout": {TimedOut: true},
		"missing truncated": {NotExist: true, Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true},
	}
	for i, output := range []string{"", "garbage", "1 2 3", "1 2 3 4 5 6 7 8 -1", "1 2 3 4 5 6 7 8 100000000", strings.Repeat("x", 70000), string(fixture) + "\nmalformed\n", "1 2 3 4 5 6 7 8 9 a b c d\n1 2 3 4 5 6 7 8 9 a b c d\n"} {
		cases[fmt.Sprint(i)] = agentless.Result{Output: []byte(output)}
	}
	for name, result := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := newSoftnetCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			read := c.Reads()[0]
			in := agentless.Input{read.ID: result}
			ch := make(chan prometheus.Metric, 20000)
			if name == "missing" {
				require.NoError(t, c.Update(agentless.Target{}, in, ch))
			} else {
				require.Error(t, c.Update(agentless.Target{}, in, ch))
			}
			require.Empty(t, ch)
			load := &loadavgCollector{}
			lr := load.Reads()[0]
			in[lr.ID] = agentless.Result{Output: []byte("1 2 3 1/1 1\n")}
			scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, util.TestLogger(t))
			require.NoError(t, err)
			snapshot, err := scraper.Scrape(t.Context(), agentless.Target{})
			require.NoError(t, err)
			success := 0
			if name == "missing" {
				success = 1
			}
			require.NoError(t, testutil.CollectAndCompare(snapshot, strings.NewReader(fmt.Sprintf(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="loadavg"} 1
node_scrape_collector_success{collector="softnet"} %d
# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 1
`, success)), "node_scrape_collector_success", "node_load1", "node_softnet_processed_total"))
		})
	}
	c, err := newSoftnetCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Error(t, c.Update(agentless.Target{}, agentless.Input{}, make(chan prometheus.Metric, 7)))
}

func TestSoftnetKernelLayouts(t *testing.T) {
	for width := 9; width <= 15; width++ {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			var line strings.Builder
			for i := 1; i <= width; i++ {
				fmt.Fprintf(&line, "%x ", i)
			}
			rows, err := parseSoftnetStats([]byte(line.String() + "\n"))
			require.NoError(t, err)
			want := [8]uint32{1, 2, 3, 9, 0, 0, 0, 0}
			if width >= 10 {
				want[4] = 10
			}
			if width >= 11 {
				want[5] = 11
			}
			if width >= 13 {
				want[6] = 12
				want[7] = 13
			}
			require.Equal(t, [][8]uint32{want}, rows)
		})
	}
	rows, err := parseSoftnetStats([]byte(strings.Repeat("1 2 3 4 5 6 7 8 9\n", 2)))
	require.NoError(t, err)
	require.Equal(t, uint32(1), rows[1][7])
	rows, err = parseSoftnetStats([]byte("ffffffff 0 0 0 0 0 0 0 0 0 0 0 ffffffff\n"))
	require.NoError(t, err)
	require.Equal(t, uint32(4294967295), rows[0][0])
	require.Equal(t, uint32(4294967295), rows[0][7])
}

func TestSoftnetPreRetentionBounds(t *testing.T) {
	row := "1 2 3 4 5 6 7 8 9 a b\n"
	for _, count := range []int{maxSoftnetCPUs - 1, maxSoftnetCPUs, maxSoftnetCPUs + 1, 25000} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c, err := newSoftnetCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			read := c.Reads()[0]
			in := agentless.Input{read.ID: {Output: []byte(strings.Repeat(row, count))}}
			ch := make(chan prometheus.Metric, 20000)
			err = c.Update(agentless.Target{}, in, ch)
			if count > maxSoftnetCPUs {
				require.ErrorContains(t, err, "CPU limit exceeded")
				require.Empty(t, ch)
			} else {
				require.NoError(t, err)
				require.Len(t, ch, count*7)
			}
		})
	}
	small := []byte(strings.Repeat(row, maxSoftnetCPUs+1))
	large := []byte(strings.Repeat(row, 25000))
	measure := func(output []byte) float64 {
		return testing.AllocsPerRun(3, func() { _, err := parseSoftnetStats(output); require.ErrorContains(t, err, "CPU limit exceeded") })
	}
	require.LessOrEqual(t, measure(large), measure(small)+2)
	// Extra columns are scanned without a fields slice or per-token allocations.
	small = []byte("1 2 3 4 5 6 7 8 9 " + strings.Repeat("0 ", 20) + "\n")
	large = []byte("1 2 3 4 5 6 7 8 9 " + strings.Repeat("0 ", 20000) + "\n")
	columns := func(output []byte) float64 {
		return testing.AllocsPerRun(3, func() { _, err := parseSoftnetStats(output); require.NoError(t, err) })
	}
	require.LessOrEqual(t, columns(large), columns(small)+2)
}
