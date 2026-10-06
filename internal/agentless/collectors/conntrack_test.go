package collectors

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
)

// Fixtures and golden.prom are copied unchanged (golden filtered to owned
// families) from node_exporter v0.18.1-grafana-r01.0.20251024135609-318b01780c89
// collector/fixtures. The oracle includes help, gauge types and CPU sums.
func TestConntrackConformance(t *testing.T) {
	c, err := newConntrackCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{
		Collector: c, Root: "testdata/conntrack", Expected: "testdata/conntrack/golden.prom",
		Families: []string{
			"node_nf_conntrack_entries", "node_nf_conntrack_entries_limit",
			"node_nf_conntrack_stat_found", "node_nf_conntrack_stat_invalid",
			"node_nf_conntrack_stat_ignore", "node_nf_conntrack_stat_insert",
			"node_nf_conntrack_stat_insert_failed", "node_nf_conntrack_stat_drop",
			"node_nf_conntrack_stat_early_drop", "node_nf_conntrack_stat_search_restart",
		},
	})
}

func conntrackFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newConntrackCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	in := agentless.Input{}
	for _, read := range c.Reads() {
		output, err := os.ReadFile("testdata/conntrack" + read.Path)
		require.NoError(t, err)
		in[read.ID] = agentless.Result{Read: read, Output: output}
	}
	return c, in
}

func TestConntrackRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"conntrack"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "conntrack", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "conntrack")
	for _, r := range Registered() {
		if r.Name == "conntrack" {
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	expected := []agentless.Read{
		agentless.FileRead("/proc/sys/net/netfilter/nf_conntrack_count"),
		agentless.FileRead("/proc/sys/net/netfilter/nf_conntrack_max"),
		agentless.FileRead("/proc/net/stat/nf_conntrack"),
	}
	require.Equal(t, expected, built[0].Reads())
	for _, read := range built[0].Reads() {
		require.NoError(t, read.Validate())
		require.Empty(t, read.Argv)
	}
}

func TestConntrackOptionalReads(t *testing.T) {
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			c, in := conntrackFixture(t)
			want := 0
			for i, read := range c.Reads() {
				if mask&(1<<i) != 0 {
					in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
				} else if i == 2 {
					want += 8
				} else {
					want++
				}
			}
			ch := make(chan prometheus.Metric, 10)
			require.NoError(t, c.Update(agentless.Target{}, in, ch))
			require.Len(t, ch, want)
		})
	}
}

func TestConntrackReadFailures(t *testing.T) {
	for index := range 3 {
		for name, bad := range map[string]agentless.Result{
			"nonzero": {ExitStatus: 2}, "truncated": {Truncated: true}, "timeout": {TimedOut: true},
			"missing truncated": {NotExist: true, Truncated: true},
			"missing timeout":   {NotExist: true, TimedOut: true},
		} {
			t.Run(fmt.Sprintf("%d/%s", index, name), func(t *testing.T) {
				c, in := conntrackFixture(t)
				in[c.Reads()[index].ID] = bad
				ch := make(chan prometheus.Metric, 10)
				require.Error(t, c.Update(agentless.Target{}, in, ch))
				require.Empty(t, ch)
			})
		}
		c, in := conntrackFixture(t)
		delete(in, c.Reads()[index].ID)
		require.Error(t, c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 10)))
	}
}

func TestConntrackMalformed(t *testing.T) {
	for index := range 3 {
		cases := []string{"", "nope", "-1", "18446744073709551616", "1 2", strings.Repeat("x", 70000)}
		if index == 2 {
			prefix := conntrackHeader + "\n" + strings.Repeat("1 ", 17) + "\n"
			cases = append(cases,
				prefix+strings.Repeat("1 ", 16), prefix+strings.Repeat("1 ", 18),
				prefix+"badhex "+strings.Repeat("1 ", 16),
				prefix+strings.Repeat("1 ", 16)+"10000000000000000",
				prefix+strings.Repeat("1 ", 16)+"-1", prefix+"\n",
				prefix+strings.Repeat("x", 70000))
		}
		for n, output := range cases {
			t.Run(fmt.Sprintf("%d/%d", index, n), func(t *testing.T) {
				c, in := conntrackFixture(t)
				read := c.Reads()[index]
				in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
				ch := make(chan prometheus.Metric, 10)
				require.Error(t, c.Update(agentless.Target{}, in, ch))
				require.Empty(t, ch, "must validate all reads before emission")
			})
		}
	}
}

func TestConntrackStatAggregation(t *testing.T) {
	for _, columns := range []int{16, 17} {
		t.Run(fmt.Sprint(columns), func(t *testing.T) {
			header := conntrackHeader
			if columns == 16 {
				header = strings.TrimSuffix(header, " search_restart")
			}
			var output strings.Builder
			output.WriteString(header + "\n")
			for cpu := 1; cpu <= 3; cpu++ {
				for column := 0; column < columns; column++ {
					fmt.Fprintf(&output, "%x ", cpu*(column+1))
				}
				output.WriteByte('\n')
			}
			stats, err := parseConntrackStats([]byte(output.String()))
			require.NoError(t, err)
			require.Equal(t, [8]uint64{18, 30, 36, 54, 60, 66, 72, uint64(102 * (columns - 16))}, stats)
		})
	}
}

func TestConntrackCurrentKernelHeader(t *testing.T) {
	// Linux v6.12 nf_conntrack_standalone.c uses this layout. Renamed
	// columns are not exported; aggregation retains the same positions.
	header := "entries clashres found new invalid ignore delete chainlength insert insert_failed drop early_drop icmp_error expect_new expect_create expect_delete search_restart"
	output := []byte(header + "\n" + strings.Repeat("a ", 17) + "\n")
	stats, err := parseConntrackStats(output)
	require.NoError(t, err)
	require.Equal(t, [8]uint64{10, 10, 10, 10, 10, 10, 10, 10}, stats)
}

func TestConntrackHostileRowsBoundedRetention(t *testing.T) {
	// A large CPU count still yields only eight sums. AllocsPerRun observes
	// whole-snapshot retention: a per-CPU slice would grow its allocation count.
	row := strings.Repeat("1 ", 17) + "\n"
	small := []byte(conntrackHeader + "\n" + row)
	large := []byte(conntrackHeader + "\n" + strings.Repeat(row, 25000))
	measure := func(output []byte) float64 {
		return testing.AllocsPerRun(2, func() {
			_, err := parseConntrackStats(output)
			require.NoError(t, err)
		})
	}
	require.LessOrEqual(t, measure(large), measure(small)+2)
	stats, err := parseConntrackStats(large)
	require.NoError(t, err)
	require.Equal(t, [8]uint64{25000, 25000, 25000, 25000, 25000, 25000, 25000, 25000}, stats)
	_, err = parseConntrackStats(append(large, []byte("malformed\n")...))
	require.Error(t, err, "must examine hostile tail, not stop after a row cap")
}

func TestConntrackScraperIsolation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint(missing), func(t *testing.T) {
			c, in := conntrackFixture(t)
			read := c.Reads()[2]
			in[read.ID] = agentless.Result{Read: read, Output: []byte("malformed")}
			if missing {
				in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
			}
			load := &loadavgCollector{}
			lr := load.Reads()[0]
			in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
			scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := scraper.Scrape(ctx, agentless.Target{})
			require.NoError(t, err)
			registry := prometheus.NewRegistry()
			registry.MustRegister(result)
			families, err := registry.Gather()
			require.NoError(t, err)
			byName := map[string]*dto.MetricFamily{}
			for _, family := range families {
				byName[family.GetName()] = family
			}
			require.Equal(t, 1.0, byName["node_load1"].Metric[0].GetGauge().GetValue())
			success := map[string]float64{}
			for _, metric := range byName["node_scrape_collector_success"].Metric {
				success[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
			}
			require.Equal(t, 1.0, success["loadavg"])
			if missing {
				require.Equal(t, 1.0, success["conntrack"])
				require.NotNil(t, byName["node_nf_conntrack_entries"])
			} else {
				require.Equal(t, 0.0, success["conntrack"])
				require.Nil(t, byName["node_nf_conntrack_entries"])
			}
			require.Nil(t, byName["node_nf_conntrack_stat_found"])
		})
	}
}
