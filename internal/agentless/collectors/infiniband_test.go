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

// The sys files are unchanged extractions from the pinned node_exporter's
// fixtures/sys.ttar; golden.prom is its infiniband e2e-output.txt excerpt.
// All 28 families present in that oracle are ported, including info and
// counters_ext legacy counters. The oracle has no samples for these six
// upstream families, which are deliberately left out rather than claiming
// conformance from a fabricated fixture: excessive_buffer_overrun_errors_total,
// local_link_integrity_errors_total, port_receive_remote_physical_errors_total,
// port_receive_switch_relay_errors_total, symbol_error_total, vl15_dropped_total
// (all under node_infiniband_). link_layer, node_guid and hw_counters are not
// exported by that upstream collector.
func TestInfinibandConformance(t *testing.T) {
	c, err := newInfinibandCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	families := []string{"node_infiniband_info"}
	for _, spec := range infinibandSpecs {
		families = append(families, "node_infiniband_"+spec.family)
	}
	require.Len(t, families, 28)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/infiniband", Expected: "testdata/infiniband/golden.prom", Families: families})
}
func infinibandFixture(t *testing.T) (*infinibandCollector, agentless.Input) {
	t.Helper()
	c0, err := newInfinibandCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := c0.(*infinibandCollector)
	r, err := agentlesstest.FromFS("testdata/infiniband", nil, c.Reads())
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
func infinibandSet(in agentless.Input, read agentless.Read, output string) {
	in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
}
func infinibandRows(prefix string, count int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "%s%d\n", prefix, i)
	}
	return b.String()
}
func TestInfinibandRegistration(t *testing.T) {
	built, err := Build([]string{"infiniband"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Contains(t, DefaultEnabled(), "infiniband")
	found := false
	for _, r := range Registered() {
		if r.Name == "infiniband" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	c, in := infinibandFixture(t)
	require.NoError(t, c.Reads()[0].Validate())
	second, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, second, 8)
	third, err := c.ExpandDeep(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, third, 3*len(infinibandSpecs))
	for _, r := range append(second, third...) {
		require.NoError(t, r.Validate())
	}
	for _, r := range third {
		require.Empty(t, r.Argv)
	}
}
func TestInfinibandBounds(t *testing.T) {
	c, in := infinibandFixture(t)
	for _, count := range []int{agentless.MaxDeepListings, agentless.MaxDeepListings + 1} {
		infinibandSet(in, c.Reads()[0], infinibandRows("ib", count))
		reads, err := c.Expand(agentless.Target{}, in)
		if count == agentless.MaxDeepListings {
			require.NoError(t, err)
			require.Len(t, reads, count*(1+len(infinibandInfoAttributes)))
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	// One shared budget across both phases and all devices, not per port listing.
	infinibandSet(in, c.Reads()[0], "ib0\nib1\n")
	infinibandSet(in, infinibandListing("ib0"), "0\n")
	budget := agentless.MaxExpandedReads - 2*(1+len(infinibandInfoAttributes))
	maxPorts := budget / len(infinibandSpecs)
	require.Greater(t, agentless.MaxExpandedReadsPerScrape, agentless.MaxExpandedReads)
	for _, count := range []int{maxPorts - 1, maxPorts} {
		infinibandSet(in, infinibandListing("ib1"), infinibandRows("", count))
		reads, err := c.ExpandDeep(agentless.Target{}, in)
		if count == maxPorts-1 {
			require.NoError(t, err)
			require.Len(t, reads, maxPorts*len(infinibandSpecs))
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	// With 13 device listings/info sets the current 27-attribute port set
	// exactly fills MaxExpandedReads, exercising equality rather than rounding.
	infinibandSet(in, c.Reads()[0], infinibandRows("ib", 13))
	for i := 0; i < 13; i++ {
		infinibandSet(in, infinibandListing(fmt.Sprintf("ib%d", i)), "")
	}
	exactPorts := (agentless.MaxExpandedReads - 13*(1+len(infinibandInfoAttributes))) / len(infinibandSpecs)
	for _, count := range []int{exactPorts, exactPorts + 1} {
		infinibandSet(in, infinibandListing("ib0"), infinibandRows("", count))
		reads, err := c.ExpandDeep(agentless.Target{}, in)
		if count == exactPorts {
			require.NoError(t, err)
			require.Equal(t, agentless.MaxExpandedReads, len(reads)+13*(1+len(infinibandInfoAttributes)))
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	// The device row's current byte boundary is checked before retaining it.
	for _, size := range []int{4096, 4097} {
		infinibandSet(in, c.Reads()[0], strings.Repeat("x", size)+"\n")
		reads, err := c.Expand(agentless.Target{}, in)
		if size == 4096 {
			require.NoError(t, err)
			require.Len(t, reads, 4)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, output := range []string{"ib0", "\n", "ib0\nib0\n", ".\n", "../ib0\n", "ib0;id\n", "ib0/x\n", strings.Repeat("ib\n", agentless.MaxExpandedReads+1)} {
		infinibandSet(in, c.Reads()[0], output)
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	infinibandSet(in, c.Reads()[0], "ib0\n")
	for _, output := range []string{"1", "\n", "1\n1\n", "01\n", "4294967296\n", "-1\n", "1/evil\n", strings.Repeat("1", 4097) + "\n"} {
		infinibandSet(in, infinibandListing("ib0"), output)
		reads, err := c.ExpandDeep(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	for _, tc := range []struct {
		attribute, raw string
		want           uint64
	}{
		{"counters/port_rcv_packets", "18446744073709551615", ^uint64(0)},
		{"state", "4: ACTIVE", 4}, {"phys_state", "5: LinkUp", 5},
		{"rate", "2.5 Gb/sec (1X SDR)", 312500000},
	} {
		got, err := infinibandValue([]byte(tc.raw), tc.attribute)
		require.NoError(t, err)
		require.Equal(t, tc.want, got)
	}
	for _, size := range []int{256, 257} {
		c, in := infinibandFixture(t)
		infinibandSet(in, infinibandRead("mlx4_0", "", "board_id"), strings.Repeat("x", size))
		ch := make(chan prometheus.Metric, agentless.MaxExpandedReads)
		err := c.Update(agentless.Target{}, in, ch)
		if size == 256 {
			require.NoError(t, err)
			require.NotEmpty(t, ch)
		} else {
			require.Error(t, err)
			require.Empty(t, ch)
		}
	}
	for _, tc := range []struct {
		attribute string
		values    []string
	}{
		{"counters/port_rcv_packets", []string{"", "-1", "18446744073709551616", strings.Repeat("1", 21), strings.Repeat("1", 1<<20)}},
		{"state", []string{"4", "4:", "4: ACTIVE:bad", "4294967296: bad"}},
		{"phys_state", []string{"bad: state"}},
		{"rate", []string{"NaN Gb/sec", "+Inf Gb/sec", "-1 Gb/sec", "1e30 Gb/sec", "100", "100 nonsense"}},
	} {
		for _, raw := range tc.values {
			_, err := infinibandValue([]byte(raw), tc.attribute)
			require.Error(t, err, "%s %q", tc.attribute, raw)
		}
	}
}
func TestInfinibandFailuresAtomicAndIsolated(t *testing.T) {
	c, original := infinibandFixture(t)
	affected := []agentless.Read{c.Reads()[0], infinibandListing("mlx4_0")}
	for _, spec := range infinibandSpecs {
		affected = append(affected, infinibandRead("mlx4_0", "2", spec.attribute))
	}
	for _, attr := range infinibandInfoAttributes {
		affected = append(affected, infinibandRead("mlx4_0", "", attr))
	}
	baseline := make(chan prometheus.Metric, agentless.MaxExpandedReads)
	require.NoError(t, c.Update(agentless.Target{}, original, baseline))
	// The unchanged upstream oracle contains 51 series (46 on mlx4_0 ports).
	require.Len(t, baseline, 51)
	for _, read := range affected {
		failures := map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "exit": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true}}
		// Info values are arbitrary strings, not numeric attributes.
		if strings.Contains(read.Path, "/ports/") || len(read.Argv) != 0 {
			failures["malformed"] = agentless.Result{Output: []byte("MALFORMED")}
		}
		for name, failure := range failures {
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
					want := 50
					if original[read.ID].NotExist || strings.TrimSpace(string(original[read.ID].Output)) == "N/A (no PMA)" {
						want = 51 // This optional attribute exported no upstream sample.
					}
					if read.ID == c.Reads()[0].ID {
						want = 0
					}
					if read.ID == infinibandListing("mlx4_0").ID {
						want = 5
					}
					require.Len(t, ch, want)
				} else {
					require.Error(t, err)
					require.Empty(t, ch)
				}
				load := &loadavgCollector{}
				infinibandSet(in, load.Reads()[0], "1 2 3 1/1 1\n")
				scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, nil)
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
				series := 0
				for _, f := range families {
					if f.GetName() == "node_load1" {
						loadSeen = true
						require.Equal(t, 1.0, f.Metric[0].GetGauge().GetValue())
					}
					if strings.HasPrefix(f.GetName(), "node_infiniband_") {
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
				if name == "missing" {
					require.Equal(t, 1.0, success["infiniband"])
					require.Equal(t, len(ch), series)
				} else {
					require.Zero(t, success["infiniband"])
					require.Zero(t, series)
				}
			})
		}
	}
}
