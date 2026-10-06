package collectors

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/grafana/alloy/internal/util"
)

func vmstatInput(output string) agentless.Input {
	r := agentless.FileRead("/proc/vmstat")
	return agentless.Input{r.ID: {Read: r, Output: []byte(output)}}
}

// The fixture and golden are copied from the pinned node_exporter's proc/vmstat
// and e2e-output.txt, respectively, without changing values or descriptors.
func TestVmstatConformance(t *testing.T) {
	c, err := newVmstatCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/vmstat", Expected: "testdata/vmstat/golden.prom", Families: []string{
		"node_vmstat_oom_kill", "node_vmstat_pgfault", "node_vmstat_pgmajfault",
		"node_vmstat_pgpgin", "node_vmstat_pgpgout", "node_vmstat_pswpin", "node_vmstat_pswpout",
	}})
}

func TestVmstatRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"vmstat"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "vmstat", built[0].Name())
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/vmstat")}, built[0].Reads())
	for _, r := range built[0].Reads() {
		require.NoError(t, r.Validate())
		require.Empty(t, r.Argv, "unprivileged fixed file read only")
	}
	require.Contains(t, DefaultEnabled(), "vmstat")
	for _, r := range Registered() {
		if r.Name == "vmstat" {
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
}

func TestVmstatParsingAndDefaultFilter(t *testing.T) {
	c := &vmstatCollector{}
	ch := make(chan prometheus.Metric, 20)
	// The regex is not end-anchored: all default-flags matching families belong
	// to this collector, not just the seven names found in the upstream fixture.
	require.NoError(t, c.Update(agentless.Target{}, vmstatInput("\npgpgin 1.5\t\npswpout 2\npgcustomfault_extra 3\noom_kill_extra 4\nnr_free_pages 5\n"), ch))
	require.Len(t, ch, 4)
	require.NoError(t, c.Update(agentless.Target{}, vmstatInput("nr_free_pages 5\n"), make(chan prometheus.Metric)))
}

func TestVmstatRejectsMalformedWithoutPartialMetrics(t *testing.T) {
	for _, bad := range []string{"", "garbage", "pgfault", "pgfault 1 2", "pgfault nope", "pgfault -1", "pgfault NaN", "pgfault Inf", "pgfault 1e999", "pgfault-bad 1", "pgfault 1\npgfault 2", "nr_free_pages nope", strings.Repeat("x", 70000)} {
		t.Run(bad[:min(len(bad), 40)], func(t *testing.T) {
			ch := make(chan prometheus.Metric, 10)
			output := "pswpin 1\n" + bad
			if bad == "" {
				output = ""
			}
			require.Error(t, (&vmstatCollector{}).Update(agentless.Target{}, vmstatInput(output), ch))
			require.Empty(t, ch)
		})
	}
}

func TestVmstatFamilyLimitBeforeRetention(t *testing.T) {
	for _, fields := range []int{499, 500, 501, 10000} {
		t.Run(fmt.Sprint(fields), func(t *testing.T) {
			var output strings.Builder
			for i := 0; i < fields; i++ {
				fmt.Fprintf(&output, "pgpg_hostile_%d 1\n", i)
			}
			ch := make(chan prometheus.Metric, 501)
			err := (&vmstatCollector{}).Update(agentless.Target{}, vmstatInput(output.String()), ch)
			if fields > 500 {
				require.ErrorContains(t, err, "field limit exceeded (500)")
				require.Empty(t, ch)
			} else {
				require.NoError(t, err)
				require.Len(t, ch, fields)
			}
		})
	}
	var prefix strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&prefix, "pswp%d 1\n", i)
	}
	for _, tail := range []string{"ignored 1\n", "malformed\n", "pswp0 2\n", strings.Repeat("x", 70000)} {
		ch := make(chan prometheus.Metric, 501)
		err := (&vmstatCollector{}).Update(agentless.Target{}, vmstatInput(prefix.String()+tail), ch)
		if tail == "ignored 1\n" {
			require.NoError(t, err)
			require.Len(t, ch, 500)
		} else {
			require.Error(t, err)
			require.Empty(t, ch)
		}
	}
}

func TestVmstatHostileTailDoesNotAllocatePerLine(t *testing.T) {
	var prefix strings.Builder
	for i := 0; i < 501; i++ {
		fmt.Fprintf(&prefix, "pgpg_hostile_%d 1\n", i)
	}
	short := vmstatInput(prefix.String())
	long := vmstatInput(prefix.String() + strings.Repeat("pgpg_new_hostile_key 1\n", 10000))
	c := &vmstatCollector{}
	allocations := func(in agentless.Input) float64 {
		return testing.AllocsPerRun(5, func() {
			ch := make(chan prometheus.Metric, 501)
			err := c.Update(agentless.Target{}, in, ch)
			if err == nil || len(ch) != 0 {
				panic("hostile snapshot accepted")
			}
		})
	}
	// Map growth has small random allocation variance; the allowance is fixed,
	// not proportional to the 10,000 extra attacker-controlled field names.
	require.LessOrEqual(t, allocations(long), allocations(short)+20)
}

func TestVmstatReadFailuresAndMissing(t *testing.T) {
	c := &vmstatCollector{}
	r := c.Reads()[0]
	for _, result := range []agentless.Result{{ExitStatus: 1}, {TimedOut: true}, {Truncated: true}, {NotExist: true, TimedOut: true}, {NotExist: true, Truncated: true}} {
		ch := make(chan prometheus.Metric, 10)
		require.Error(t, c.Update(agentless.Target{}, agentless.Input{r.ID: result}, ch))
		require.Empty(t, ch)
	}
	require.Error(t, c.Update(agentless.Target{}, nil, make(chan prometheus.Metric, 10)))
	for _, result := range []agentless.Result{{NotExist: true}, {NotExist: true, ExitStatus: 1}} {
		ch := make(chan prometheus.Metric, 10)
		require.NoError(t, c.Update(agentless.Target{}, agentless.Input{r.ID: result}, ch))
		require.Empty(t, ch)
	}
}

func TestVmstatFailureIsolatedThroughScraper(t *testing.T) {
	c := &vmstatCollector{}
	r := c.Reads()[0]
	mem := agentless.FileRead("/proc/meminfo")
	for _, result := range []agentless.Result{{ExitStatus: 1}, {Output: []byte("pgfault 1\ngarbage")}, {NotExist: true, ExitStatus: 1}} {
		runner := &agentlesstest.FakeRunner{Results: map[string]agentless.Result{r.ID: result, mem.ID: {Output: []byte("MemFree: 1 kB\n")}}}
		s, err := agentless.NewScraper(runner, []agentless.Collector{c, &meminfoCollector{}}, util.TestLogger(t))
		require.NoError(t, err)
		metrics, err := s.Scrape(t.Context(), agentless.Target{Address: "fixture"})
		require.NoError(t, err)
		success := 0
		if result.NotExist {
			success = 1
		}
		require.NoError(t, testutil.CollectAndCompare(metrics, strings.NewReader(fmt.Sprintf(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="meminfo"} 1
node_scrape_collector_success{collector="vmstat"} %d
# HELP node_memory_MemFree_bytes Memory information field MemFree_bytes.
# TYPE node_memory_MemFree_bytes gauge
node_memory_MemFree_bytes 1024
`, success)), "node_scrape_collector_success", "node_memory_MemFree_bytes"))
		require.Zero(t, testutil.CollectAndCount(metrics, "node_vmstat_pgfault"))
	}
}

func TestVmstatConcurrentUpdates(t *testing.T) {
	data, err := os.ReadFile("testdata/vmstat/proc/vmstat")
	require.NoError(t, err)
	c := &vmstatCollector{}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Go(func() {
			ch := make(chan prometheus.Metric, 10)
			require.NoError(t, c.Update(agentless.Target{}, vmstatInput(string(data)), ch))
			require.Len(t, ch, 7)
		})
	}
	wg.Wait()
}
