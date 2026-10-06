package collectors

import (
	"fmt"
	"strings"
	"testing"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/grafana/alloy/internal/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func schedstatInput(text string) agentless.Input {
	r := agentless.FileRead("/proc/schedstat")
	return agentless.Input{r.ID: {Read: r, Output: []byte(text)}}
}

// Input and golden are copied unchanged from the pinned node_exporter fixture
// and its e2e output. All three default families are covered.
func TestSchedstatConformance(t *testing.T) {
	c, err := newSchedstatCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/schedstat", Expected: "testdata/schedstat/golden.prom", Families: []string{
		"node_schedstat_running_seconds_total", "node_schedstat_waiting_seconds_total", "node_schedstat_timeslices_total",
	}})
}

func TestSchedstatRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"schedstat"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "schedstat", built[0].Name())
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/schedstat")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
	require.Empty(t, built[0].Reads()[0].Argv)
	require.Contains(t, DefaultEnabled(), "schedstat")
	for _, r := range Registered() {
		if r.Name == "schedstat" {
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
}

func TestSchedstatMalformedAtomic(t *testing.T) {
	for _, bad := range []string{"", "garbage", "cpu0", "cpu0 0 0 0 0 0 0 1 2", "cpu0 0 0 0 0 0 0 1 2 3 4", "cpu0 0 0 0 0 0 0 nope 2 3", "cpu0 0 0 0 0 0 0 -1 2 3", "cpu0 0 0 0 0 0 0 18446744073709551616 2 3", "cpu0 0 0 0 0 0 0 +1 2 3", "cpuX 0 0 0 0 0 0 1 2 3", "cpu1 0 0 0 0 0 0 1 2 3", "timestamp", "version nope", "\n", strings.Repeat("x", 70000)} {
		t.Run(bad[:min(len(bad), 40)], func(t *testing.T) {
			c, err := newSchedstatCollector(DefaultConfigs(), nil)
			require.NoError(t, err)
			ch := make(chan prometheus.Metric, 10)
			text := "cpu1 0 0 0 0 0 0 1 2 3\n" + bad
			if bad == "" {
				text = ""
			}
			require.Error(t, c.Update(agentless.Target{}, schedstatInput(text), ch))
			require.Empty(t, ch)
		})
	}
}

func TestSchedstatBoundsBeforeRetention(t *testing.T) {
	for _, n := range []int{maxSchedstatCPUs, maxSchedstatCPUs + 1} {
		var text strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&text, "cpu%d 0 0 0 0 0 0 1 2 3\n", i)
		}
		rows, err := parseSchedstat([]byte(text.String()))
		if n > maxSchedstatCPUs {
			require.ErrorContains(t, err, "CPU limit exceeded")
			require.Nil(t, rows)
		} else {
			require.NoError(t, err)
			require.Len(t, rows, n)
		}
	}
	for _, n := range []int{4096, 4097} {
		rows, err := parseSchedstat([]byte("cpu" + strings.Repeat("0", n) + " 0 0 0 0 0 0 1 2 3\n"))
		if n > 4096 {
			require.Error(t, err)
			require.Nil(t, rows)
		} else {
			require.NoError(t, err)
			require.Len(t, rows, 1)
		}
	}
	prefix := "cpu0 0 0 0 0 0 0 1 2 3\n" + strings.Repeat("domain0 0\n", maxSchedstatLines-1)
	rows, err := parseSchedstat([]byte(prefix))
	require.NoError(t, err)
	require.Len(t, rows, 1)
	short := []byte(prefix + "domain0 0\n")
	long := []byte(string(short) + strings.Repeat("domain0 0\n", 100000))
	allocs := func(data []byte) float64 {
		return testing.AllocsPerRun(5, func() {
			rows, err := parseSchedstat(data)
			if err == nil || rows != nil {
				panic("hostile input accepted")
			}
		})
	}
	require.LessOrEqual(t, allocs(long), allocs(short)+10)
	// A huge number of fields in one CPU line must not allocate a field slice.
	short = []byte("cpu0 0 0 0 0 0 0 1 2 3 4\n")
	long = []byte("cpu0 " + strings.Repeat("0 ", 30000) + "\n")
	require.LessOrEqual(t, allocs(long), allocs(short)+10)
}

func TestSchedstatReadFailuresAndIsolation(t *testing.T) {
	c, err := newSchedstatCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	r := c.Reads()[0]
	require.Error(t, c.Update(agentless.Target{}, nil, make(chan prometheus.Metric, 10)))
	mem := agentless.FileRead("/proc/meminfo")
	for _, result := range []agentless.Result{{ExitStatus: 1}, {TimedOut: true}, {Truncated: true}, {NotExist: true, TimedOut: true}, {NotExist: true, Truncated: true}, {Output: []byte("cpu0 garbage")}, {NotExist: true}, {NotExist: true, ExitStatus: 1}} {
		ch := make(chan prometheus.Metric, 10)
		err := c.Update(agentless.Target{}, agentless.Input{r.ID: result}, ch)
		success := 0
		if result.NotExist && !result.TimedOut && !result.Truncated {
			require.NoError(t, err)
			success = 1
		} else {
			require.Error(t, err)
		}
		require.Empty(t, ch)
		runner := &agentlesstest.FakeRunner{Results: map[string]agentless.Result{r.ID: result, mem.ID: {Output: []byte("MemFree: 1 kB\n")}}}
		s, err := agentless.NewScraper(runner, []agentless.Collector{c, &meminfoCollector{}}, util.TestLogger(t))
		require.NoError(t, err)
		metrics, err := s.Scrape(t.Context(), agentless.Target{Address: "fixture"})
		require.NoError(t, err)
		require.NoError(t, testutil.CollectAndCompare(metrics, strings.NewReader(fmt.Sprintf(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="meminfo"} 1
node_scrape_collector_success{collector="schedstat"} %d
# HELP node_memory_MemFree_bytes Memory information field MemFree_bytes.
# TYPE node_memory_MemFree_bytes gauge
node_memory_MemFree_bytes 1024
`, success)), "node_scrape_collector_success", "node_memory_MemFree_bytes"))
		require.Zero(t, testutil.CollectAndCount(metrics, "node_schedstat_running_seconds_total"))
	}
}
