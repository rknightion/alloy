package collectors

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Unchanged sys.ttar stats and e2e-output.txt families from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89. All 39 exported
// families are covered; no exported family is left out.
func TestXfsConformance(t *testing.T) {
	c, err := newXfsCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	families := make([]string, 0, len(xfsMetrics))
	for _, spec := range xfsMetrics {
		families = append(families, "node_xfs_"+spec.name)
	}
	require.Len(t, families, 39)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/xfs", Expected: "testdata/xfs/golden.prom", Families: families})
}
func xfsFixture(t *testing.T) (*xfsCollector, agentless.Input) {
	t.Helper()
	collector, err := newXfsCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := collector.(*xfsCollector)
	stats, err := os.ReadFile("testdata/xfs/sys/fs/xfs/sda1/stats/stats")
	require.NoError(t, err)
	listing, read := c.Reads()[0], xfsRead("sda1")
	return c, agentless.Input{listing.ID: {Read: listing, Output: []byte("sda1\n")}, read.ID: {Read: read, Output: stats}}
}
func TestXfsRegistration(t *testing.T) {
	built, err := Build([]string{"xfs"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "xfs", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "xfs")
	found := false
	for _, r := range Registered() {
		if r.Name == "xfs" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/fs/xfs")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
}
func TestXfsListingBounds(t *testing.T) {
	c, in := xfsFixture(t)
	listing := c.Reads()[0]
	for _, count := range []int{512, 513, 1024, 1025} {
		var out strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&out, "sd%d\n", i)
		}
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(out.String())}
		reads, err := c.Expand(agentless.Target{}, in)
		if count == 512 {
			require.NoError(t, err)
			require.Len(t, reads, 512)
			for _, r := range reads {
				require.NoError(t, r.Validate())
				require.Empty(t, r.Argv)
			}
		} else {
			require.Error(t, err)
			require.Nil(t, reads, "reject the entire expansion")
		}
	}
	for _, out := range []string{"sda1", "\n", "sda1\n\n", "sda1\nsda1\n", strings.Repeat("x", 4097) + "\n", strings.Repeat("bad name\n", 1025)} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(out)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	for _, out := range []string{strings.Repeat("bad name\n", 1024), strings.Repeat("x", 4096) + "\n", "sda1\nbad name\n../evil\nx/y\n.\nx..y\nx;id\nx\x00y\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(out)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.NoError(t, err)
		for _, r := range reads {
			require.NoError(t, r.Validate())
		}
		if strings.HasPrefix(out, "sda1\n") {
			require.Equal(t, []agentless.Read{xfsRead("sda1")}, reads)
		}
	}
}
func TestXfsStatsBounds(t *testing.T) {
	for _, out := range []string{strings.Repeat(" ", 64*1024+1), strings.Repeat("\n", 128), strings.Repeat(" ", 1025), strings.Repeat("0 ", 33), strings.Repeat("x", 33), "extent_alloc 1 2\n", "rw -1 2\n", "rw 4294967296 2\n", "rw bad 2\n"} {
		_, err := xfsStats([]byte(out))
		require.Error(t, err)
	}
	for _, out := range []string{strings.Repeat(" ", 1024), strings.Repeat("\n", 127)} {
		_, err := xfsStats([]byte(out))
		require.NoError(t, err)
	}
	out := strings.Repeat(strings.Repeat(" ", 1023)+"\n", 64)
	require.Len(t, out, 64*1024)
	_, err := xfsStats([]byte(out))
	require.NoError(t, err)
	_, err = xfsStats([]byte(strings.Repeat("a", 32)))
	require.NoError(t, err)
	_, err = xfsStats([]byte("future " + strings.Repeat("0 ", 31)))
	require.NoError(t, err)
	_, err = xfsStats([]byte("vnodes 1 2 3 4 5 6 7\n"))
	require.NoError(t, err)
}
func TestXfsScraperIsolation(t *testing.T) {
	var large strings.Builder
	for i := 0; i < 513; i++ {
		fmt.Fprintf(&large, "sd%d\n", i)
	}
	cases := map[string]struct {
		listing bool
		result  agentless.Result
		success float64
		series  int
	}{
		"valid":             {false, agentless.Result{}, 1, 39},
		"missing listing":   {true, agentless.Result{NotExist: true, ExitStatus: 1}, 1, 0},
		"empty listing":     {true, agentless.Result{}, 1, 0},
		"missing stats":     {false, agentless.Result{NotExist: true, ExitStatus: 1}, 1, 0},
		"failed listing":    {true, agentless.Result{ExitStatus: 2, Output: []byte("sda1\n")}, 0, 0},
		"listing timeout":   {true, agentless.Result{NotExist: true, TimedOut: true}, 0, 0},
		"listing truncated": {true, agentless.Result{NotExist: true, Truncated: true}, 0, 0},
		"oversized listing": {true, agentless.Result{Output: []byte(large.String())}, 0, 0},
		"malformed stats":   {false, agentless.Result{Output: []byte("extent_alloc bad 2 3 4\n")}, 0, 0},
		"failed stats":      {false, agentless.Result{ExitStatus: 2}, 0, 0},
		"stats timeout":     {false, agentless.Result{NotExist: true, TimedOut: true}, 0, 0},
		"stats truncated":   {false, agentless.Result{NotExist: true, Truncated: true}, 0, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, in := xfsFixture(t)
			if name != "valid" {
				read := xfsRead("sda1")
				if tc.listing {
					read = c.Reads()[0]
				}
				tc.result.Read = read
				in[read.ID] = tc.result
			}
			load := &loadavgCollector{}
			lr := load.Reads()[0]
			in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
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
			success := map[string]float64{}
			series := 0
			loadSeen := false
			for _, f := range families {
				if strings.HasPrefix(f.GetName(), "node_xfs_") {
					series += len(f.Metric)
				}
				if f.GetName() == "node_load1" {
					loadSeen = true
					require.Equal(t, 1.0, f.Metric[0].GetGauge().GetValue())
				}
				if f.GetName() == "node_scrape_collector_success" {
					for _, m := range f.Metric {
						success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
					}
				}
			}
			require.True(t, loadSeen)
			require.Equal(t, 1.0, success["loadavg"])
			require.Equal(t, tc.success, success["xfs"])
			require.Equal(t, tc.series, series)
			if tc.listing {
				require.Equal(t, 1, runner.Calls(), "rejected expansion never reaches runner")
			}
		})
	}
}
func TestXfsSeriesBoundary(t *testing.T) {
	c, in := xfsFixture(t)
	listing := c.Reads()[0]
	stats := in[xfsRead("sda1").ID].Output
	for _, count := range []int{512, 513} {
		var out strings.Builder
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("sd%d", i)
			fmt.Fprintln(&out, name)
			read := xfsRead(name)
			in[read.ID] = agentless.Result{Read: read, Output: stats}
		}
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(out.String())}
		ch := make(chan prometheus.Metric, 20000)
		err := c.Update(agentless.Target{}, in, ch)
		if count == 512 {
			require.NoError(t, err)
			require.Len(t, ch, 19968, "largest full-device result under the current 20000-series cap")
		} else {
			require.Error(t, err)
			require.Empty(t, ch)
		}
	}
}

func TestXfsMalformedSecondDeviceAtomic(t *testing.T) {
	c, in := xfsFixture(t)
	listing := c.Reads()[0]
	in[listing.ID] = agentless.Result{Read: listing, Output: []byte("sda1\nsda2\n")}
	read := xfsRead("sda2")
	in[read.ID] = agentless.Result{Read: read, Output: []byte("rw nope 2\n")}
	ch := make(chan prometheus.Metric, 100)
	require.Error(t, c.Update(agentless.Target{}, in, ch))
	require.Empty(t, ch)
}
