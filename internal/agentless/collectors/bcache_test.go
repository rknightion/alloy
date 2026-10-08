package collectors

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

const bcacheTestUUID = "deaddd54-c735-46d5-868e-f331c5fd7c74"

// Unmodified inputs and oracle from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89 collector/fixtures.
// sys.ttar's bdev0/cache0 symlinks are materialized from their target contents.
// All 26 default families are compared, including pseudo-float conversions;
// opt-in priority_stats_unused_percent/priority_stats_metadata_percent are not ported.
func TestBcacheConformance(t *testing.T) {
	c, err := newBcacheCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	families := make([]string, 0, len(bcacheSpecs))
	for _, s := range bcacheSpecs {
		families = append(families, "node_bcache_"+s.family)
	}
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/bcache", Expected: "testdata/bcache/golden.prom", Families: families})
}
func bcacheFixture(t *testing.T) (*bcacheCollector, agentless.Input) {
	t.Helper()
	c0, err := newBcacheCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := c0.(*bcacheCollector)
	r, err := agentlesstest.FromFS("testdata/bcache", nil, c.Reads())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in := agentless.Input{}
	reads := c.Reads()
	for phase := 0; phase < 3; phase++ {
		results, err := r.Run(ctx, agentless.Target{}, reads)
		require.NoError(t, err)
		for _, res := range results {
			in[res.Read.ID] = res
		}
		if phase == 0 {
			reads, err = c.Expand(agentless.Target{}, in)
		}
		if phase == 1 {
			reads, err = c.ExpandDeep(agentless.Target{}, in)
		}
		require.NoError(t, err)
	}
	return c, in
}
func bcacheSet(in agentless.Input, r agentless.Read, out string) {
	in[r.ID] = agentless.Result{Read: r, Output: []byte(out)}
}
func bcacheRows(prefix string, count int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "%s%d\n", prefix, i)
	}
	return b.String()
}
func TestBcacheRegistration(t *testing.T) {
	cs, err := Build([]string{"bcache"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, cs, 1)
	require.Contains(t, DefaultEnabled(), "bcache")
	found := false
	for _, r := range Registered() {
		if r.Name == "bcache" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	c, in := bcacheFixture(t)
	second, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	third, err := c.ExpandDeep(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, second, 11)
	require.Len(t, third, 12)
	for _, r := range append(append(c.Reads(), second...), third...) {
		require.NoError(t, r.Validate())
	}
	for _, r := range third {
		require.Empty(t, r.Argv)
	}
}
func TestBcacheBounds(t *testing.T) {
	c, _ := bcacheFixture(t)
	for _, count := range []int{agentless.MaxDeepListings, agentless.MaxDeepListings + 1} {
		in := agentless.Input{}
		bcacheSet(in, c.Reads()[0], bcacheRows("set-", count))
		reads, err := c.Expand(agentless.Target{}, in)
		if count == agentless.MaxDeepListings {
			require.NoError(t, err)
			require.Len(t, reads, count*11)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	// One set costs 11 phase-two reads; cache devices cost 3, backing 9.
	// 337 cache devices + 11 = 1022, with no room for another cache device.
	for _, prefix := range []string{"cache", "bdev"} {
		cost := 3
		if prefix == "bdev" {
			cost = 9
		}
		max := (agentless.MaxExpandedReads - 11) / cost
		for _, count := range []int{max, max + 1} {
			in := agentless.Input{}
			bcacheSet(in, c.Reads()[0], bcacheTestUUID+"\n")
			bcacheSet(in, bcacheList(bcacheTestUUID), bcacheRows(prefix, count))
			reads, err := c.ExpandDeep(agentless.Target{}, in)
			if count == max {
				require.NoError(t, err)
				require.Len(t, reads, count*cost)
			} else {
				require.Error(t, err)
				require.Nil(t, reads)
			}
		}
	}
	// Both phases and every set share a single read budget: reach exactly 1024.
	in := agentless.Input{}
	bcacheSet(in, c.Reads()[0], "set-0\nset-1\n")
	for i := 0; i < 2; i++ {
		bcacheSet(in, bcacheList(fmt.Sprintf("set-%d", i)), "")
	}
	bcacheSet(in, bcacheList("set-0"), bcacheRows("cache", (agentless.MaxExpandedReads-22)/3))
	reads, err := c.ExpandDeep(agentless.Target{}, in)
	require.NoError(t, err)
	require.Equal(t, agentless.MaxExpandedReads, 22+len(reads))
	bcacheSet(in, bcacheList("set-1"), "cache0\n")
	reads, err = c.ExpandDeep(agentless.Target{}, in)
	require.Error(t, err)
	require.Nil(t, reads)
	for _, r := range []agentless.Read{c.Reads()[0], bcacheList(bcacheTestUUID)} {
		for _, size := range []int{4096, 4097} {
			in := agentless.Input{}
			bcacheSet(in, r, strings.Repeat("x", size)+"\n")
			names, err := bcacheNames(in, r, func([]byte) bool { return false }, agentless.MaxExpandedReads)
			if size == 4096 {
				require.NoError(t, err)
				require.Empty(t, names)
			} else {
				require.Error(t, err)
				require.Nil(t, names)
			}
		}
		for _, count := range []int{agentless.MaxExpandedReads, agentless.MaxExpandedReads + 1} {
			in := agentless.Input{}
			bcacheSet(in, r, strings.Repeat("ignored\n", count))
			names, err := bcacheNames(in, r, func([]byte) bool { return false }, agentless.MaxExpandedReads)
			if count == agentless.MaxExpandedReads {
				require.NoError(t, err)
				require.Empty(t, names)
			} else {
				require.Error(t, err)
				require.Nil(t, names)
			}
		}
	}
	for _, out := range []string{"\n", bcacheTestUUID, bcacheTestUUID + "\n" + bcacheTestUUID + "\n"} {
		in := agentless.Input{}
		bcacheSet(in, c.Reads()[0], out)
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	in = agentless.Input{}
	bcacheSet(in, c.Reads()[0], bcacheTestUUID+"\n../escape\nx-;id\nx-/y\n")
	bcacheSet(in, bcacheList(bcacheTestUUID), "cache0\nbdev0\nbdev1/escape\ncache1;id\n../escape\n")
	reads, err = c.ExpandDeep(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 12)
}
func bcacheScrape(t *testing.T, in agentless.Input, c agentless.Collector) (float64, int) {
	t.Helper()
	load := &loadavgCollector{}
	bcacheSet(in, load.Reads()[0], "1 2 3 1/1 1\n")
	s, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := s.Scrape(ctx, agentless.Target{})
	require.NoError(t, err)
	reg := prometheus.NewRegistry()
	reg.MustRegister(result)
	families, err := reg.Gather()
	require.NoError(t, err)
	success := map[string]float64{}
	series := 0
	loadSeen := false
	for _, f := range families {
		if f.GetName() == "node_load1" {
			loadSeen = true
			require.Equal(t, 1.0, f.Metric[0].GetGauge().GetValue())
		}
		if strings.HasPrefix(f.GetName(), "node_bcache_") {
			series += len(f.Metric)
		}
		if f.GetName() == "node_scrape_collector_success" {
			for _, m := range f.Metric {
				success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
			}
		}
	}
	require.True(t, loadSeen)
	require.Equal(t, 1.0, success["loadavg"])
	return success["bcache"], series
}
func TestBcacheFailuresAtomicAndIsolated(t *testing.T) {
	c, original := bcacheFixture(t)
	second, err := c.Expand(agentless.Target{}, original)
	require.NoError(t, err)
	third, err := c.ExpandDeep(agentless.Target{}, original)
	require.NoError(t, err)
	for _, read := range append(append(c.Reads(), second...), third...) {
		for name, failure := range map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "exit": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "malformed": {Output: []byte("rate: INVALID")}} {
			t.Run(read.ID+"/"+name, func(t *testing.T) {
				in := agentless.Input{}
				for k, v := range original {
					in[k] = v
				}
				failure.Read = read
				in[read.ID] = failure
				ch := make(chan prometheus.Metric, agentless.MaxExpandedReads*2)
				err := c.Update(agentless.Target{}, in, ch)
				if name == "missing" {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Empty(t, ch)
				}
				success, series := bcacheScrape(t, in, c)
				if name == "missing" {
					require.Equal(t, 1.0, success)
					if read.ID == c.Reads()[0].ID {
						require.Zero(t, series)
					}
					if strings.HasSuffix(read.Path, "/written") {
						require.Equal(t, 25, series)
					}
				} else {
					require.Zero(t, success)
					require.Zero(t, series)
				}
			})
		}
	}
	// Expansion failure itself must not poison a sibling collector.
	in := agentless.Input{}
	for k, v := range original {
		in[k] = v
	}
	bcacheSet(in, bcacheList(bcacheTestUUID), bcacheRows("cache", agentless.MaxExpandedReads/3+1))
	success, series := bcacheScrape(t, in, c)
	require.Zero(t, success)
	require.Zero(t, series)
}
func TestBcacheNumbers(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want float64
	}{{"1.1k", 1124}, {"1.10k", 2024}, {"512", 512}, {"20.4G", 21894266880}, {"-1.1k", -1124}, {"0", 0}} {
		value, err := bcacheNumber([]byte(tc.raw), true)
		require.NoError(t, err, tc.raw)
		require.Equal(t, tc.want, value, tc.raw)
	}
	for _, raw := range []string{"", "-1", "NaN", "Inf", "1Q", "1e3", "1..2k", "1.k", "18446744073709551616", strings.Repeat("1", 33), strings.Repeat(" ", 1<<20)} {
		_, err := bcacheNumber([]byte(raw), false)
		require.Error(t, err, raw[:min(len(raw), 40)])
	}
	for _, out := range []string{"rate:", "rate: NaN", "rate: 1\nrate: 2\n", "integral: -NaN", strings.Repeat("x", 4097), strings.Repeat("\n", 65), strings.Repeat("x", 257)} {
		_, err := bcacheDebug([]byte(out))
		require.Error(t, err)
	}
	c, in := bcacheFixture(t)
	bcacheSet(in, bcacheFile(bcacheTestUUID, "bdev0", "stats_total/cache_readaheads"), "0\n")
	success, series := bcacheScrape(t, in, c)
	require.Equal(t, 1.0, success)
	require.Equal(t, 25, series)
}
