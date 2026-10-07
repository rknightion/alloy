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

// Files are unchanged extractions from the pinned node_exporter's sys.ttar.
// The golden transcribes its edac_linux.go emitter for these six counters.
// All four upstream families, including noinfo's unknown csrow, are covered;
// there are no left-out EDAC families. DIMM/channel attributes are not exported.
func TestEdacConformance(t *testing.T) {
	c, err := newEdacCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/edac", Expected: "testdata/edac/golden.prom", Families: []string{"node_edac_correctable_errors_total", "node_edac_uncorrectable_errors_total", "node_edac_csrow_correctable_errors_total", "node_edac_csrow_uncorrectable_errors_total"}})
}
func edacFixture(t *testing.T) (*edacCollector, agentless.Input) {
	t.Helper()
	c0, err := newEdacCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := c0.(*edacCollector)
	r, err := agentlesstest.FromFS("testdata/edac", nil, c.Reads())
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
func edacSet(in agentless.Input, read agentless.Read, output string) {
	in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
}
func edacRows(prefix string, count int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "%s%d\n", prefix, i)
	}
	return b.String()
}
func TestEdacRegistration(t *testing.T) {
	built, err := Build([]string{"edac"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.NotContains(t, DefaultEnabled(), "edac")
	for _, r := range Registered() {
		if r.Name == "edac" {
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	c, in := edacFixture(t)
	second, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, second, 5)
	third, err := c.ExpandDeep(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, third, 2)
	for _, r := range append(second, third...) {
		require.NoError(t, r.Validate())
	}
	for _, r := range third {
		require.Empty(t, r.Argv)
	}
}
func TestEdacBounds(t *testing.T) {
	c, in := edacFixture(t)
	for _, count := range []int{agentless.MaxDeepListings, agentless.MaxDeepListings + 1} {
		edacSet(in, c.Reads()[0], edacRows("mc", count))
		reads, err := c.Expand(agentless.Target{}, in)
		if count == agentless.MaxDeepListings {
			require.NoError(t, err)
			require.Len(t, reads, count*(1+len(edacAttributes)))
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	// Two controllers make the shared read budget exactly divisible by two.
	edacSet(in, c.Reads()[0], "mc0\nmc1\n")
	edacSet(in, edacListing("mc1"), "")
	budget := agentless.MaxExpandedReads - 2*(1+len(edacAttributes))
	for _, count := range []int{budget / 2, budget/2 + 1} {
		edacSet(in, edacListing("mc0"), edacRows("csrow", count))
		reads, err := c.ExpandDeep(agentless.Target{}, in)
		if count == budget/2 {
			require.NoError(t, err)
			require.Len(t, reads, budget)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, prefix := range []string{"mc", "csrow"} {
		read := c.Reads()[0]
		if prefix == "csrow" {
			read = edacListing("mc0")
			edacSet(in, c.Reads()[0], "mc0\n")
		}
		for _, count := range []int{agentless.MaxExpandedReads, agentless.MaxExpandedReads + 1} {
			edacSet(in, read, strings.Repeat("ignored\n", count))
			var err error
			if prefix == "mc" {
				_, err = c.Expand(agentless.Target{}, in)
			} else {
				_, err = c.ExpandDeep(agentless.Target{}, in)
			}
			if count == agentless.MaxExpandedReads {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		}
	}
	// The transport's per-scrape bound is larger than the per-collector bound;
	// a single collector must not exploit that extra shared capacity.
	require.Greater(t, agentless.MaxExpandedReadsPerScrape, agentless.MaxExpandedReads)
	for _, size := range []int{4096, 4097} {
		edacSet(in, c.Reads()[0], strings.Repeat("x", size)+"\n")
		reads, err := c.Expand(agentless.Target{}, in)
		if size == 4096 {
			require.NoError(t, err)
			require.Empty(t, reads)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, output := range []string{"mc0", "\n", "mc0\nmc0\n", strings.Repeat("x", 4097) + "\n"} {
		edacSet(in, c.Reads()[0], output)
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	edacSet(in, c.Reads()[0], "mc0\nmc1;id\nmc../evil\nmc0/x\nmc\n")
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 5)
}
func TestEdacFailuresAtomicAndIsolated(t *testing.T) {
	c, original := edacFixture(t)
	affected := []agentless.Read{c.Reads()[0], edacListing("mc0")}
	for _, attr := range edacAttributes {
		affected = append(affected, edacRead("mc0", "", attr))
	}
	for _, attr := range []string{"ce_count", "ue_count"} {
		affected = append(affected, edacRead("mc0", "csrow0", attr))
	}
	for _, read := range affected {
		for name, failure := range map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "exit": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "malformed": {Output: []byte("MALFORMED")}} {
			t.Run(read.ID+"/"+name, func(t *testing.T) {
				in := agentless.Input{}
				for k, v := range original {
					in[k] = v
				}
				failure.Read = read
				in[read.ID] = failure
				ch := make(chan prometheus.Metric, agentless.MaxExpandedReads)
				err := c.Update(agentless.Target{}, in, ch)
				if name == "missing" {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Empty(t, ch)
				}
				load := &loadavgCollector{}
				edacSet(in, load.Reads()[0], "1 2 3 1/1 1\n")
				runner := &agentlesstest.FakeRunner{Results: in}
				scraper, err := agentless.NewScraper(runner, []agentless.Collector{c, load}, nil)
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := scraper.Scrape(ctx, agentless.Target{})
				require.NoError(t, err)
				reg := prometheus.NewRegistry()
				reg.MustRegister(result)
				families, err := reg.Gather()
				require.NoError(t, err)
				loadSeen := false
				success := map[string]float64{}
				edacSeries := 0
				for _, f := range families {
					if f.GetName() == "node_load1" {
						loadSeen = true
						require.Equal(t, 1.0, f.Metric[0].GetGauge().GetValue())
					}
					if strings.HasPrefix(f.GetName(), "node_edac_") {
						edacSeries += len(f.Metric)
					}
					if f.GetName() == "node_scrape_collector_success" {
						for _, m := range f.Metric {
							success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
						}
					}
				}
				require.True(t, loadSeen)
				require.Equal(t, 1.0, success["loadavg"])
				if name == "missing" {
					require.Equal(t, 1.0, success["edac"])
					want := 5
					if read.ID == c.Reads()[0].ID {
						want = 0
					}
					if read.ID == edacListing("mc0").ID {
						want = 4
					}
					require.Equal(t, want, edacSeries)
				} else {
					require.Zero(t, success["edac"])
					require.Zero(t, edacSeries)
				}
			})
		}
	}
	for _, raw := range []string{"-1", "18446744073709551616", strings.Repeat("1", 1<<20), ""} {
		c, in := edacFixture(t)
		edacSet(in, edacRead("mc0", "csrow0", "ue_count"), raw)
		ch := make(chan prometheus.Metric, agentless.MaxExpandedReads)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch)
	}
}
