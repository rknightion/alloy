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

// Files come from the pinned node_exporter's collector/fixtures/sys.ttar.
// slave_<iface>/bonding_slave/mii_status is materialized at the real interface
// path: these sysfs aliases refer to the same interface on Linux. Both exported
// families are checked against upstream e2e output; no families are left out.
func TestBondingConformance(t *testing.T) {
	c, err := newBondingCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/bonding", Expected: "testdata/bonding/golden.prom", Families: []string{"node_bonding_slaves", "node_bonding_active"}})
}
func bondingFixture(t *testing.T) (*bondingCollector, agentless.Input) {
	t.Helper()
	collector, err := newBondingCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := collector.(*bondingCollector)
	runner, err := agentlesstest.FromFS("testdata/bonding", nil, c.Reads())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in := agentless.Input{}
	results, err := runner.Run(ctx, agentless.Target{}, c.Reads())
	require.NoError(t, err)
	for _, result := range results {
		in[result.Read.ID] = result
	}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	results, err = runner.Run(ctx, agentless.Target{}, reads)
	require.NoError(t, err)
	for _, result := range results {
		in[result.Read.ID] = result
	}
	return c, in
}
func TestBondingRegistrationAndExpansion(t *testing.T) {
	built, err := Build([]string{"bonding"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Contains(t, DefaultEnabled(), "bonding")
	found := false
	for _, r := range Registered() {
		if r.Name == "bonding" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	c, in := bondingFixture(t)
	require.Equal(t, []agentless.Read{agentless.FileRead("/sys/class/net/bonding_masters"), agentless.CommandRead("ls", "-1", "/sys/class/net")}, c.Reads())
	for _, r := range c.Reads() {
		require.NoError(t, r.Validate())
	}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	listing, err := bondingInterfaces(in[c.Reads()[1].ID].Output, agentless.MaxExpandedReads)
	require.NoError(t, err)
	require.Len(t, reads, 3+len(listing))
	for _, iface := range listing {
		require.Contains(t, reads, bondingRead(iface, "bonding_slave/mii_status"))
	}
	for _, r := range reads {
		require.NoError(t, r.Validate())
		require.Empty(t, r.Argv)
	}
	require.True(t, in[bondingRead("bond0", "bonding_slave/mii_status").ID].NotExist)
}
func bondingTestListing(count int) string {
	var output strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&output, "eth%d\n", i)
	}
	return output.String()
}

func TestBondingBounds(t *testing.T) {
	c, in := bondingFixture(t)
	listing := c.Reads()[1]
	masters, err := bondingNames(in[c.Reads()[0].ID].Output)
	require.NoError(t, err)
	budget := agentless.MaxExpandedReads - len(masters)
	// Retain the old corpus sizes: all now fit the shared 1024-read cap.
	// Check the exact combined master/interface cap and one beyond it too.
	for _, count := range []int{253, 254, 257, budget, budget + 1, agentless.MaxExpandedReads + 1} {
		for _, control := range []string{"", "bonding_masters\n"} {
			t.Run(fmt.Sprintf("interfaces=%d/control=%t", count, control != ""), func(t *testing.T) {
				in[listing.ID] = agentless.Result{Read: listing, Output: []byte(control + bondingTestListing(count))}
				reads, err := c.Expand(agentless.Target{}, in)
				if count <= budget {
					require.NoError(t, err)
					require.Len(t, reads, len(masters)+count)
					for _, read := range reads {
						require.NoError(t, read.Validate())
					}
				} else {
					require.Error(t, err)
					require.Nil(t, reads, "reject whole expansion, never truncate")
				}
			})
		}
	}
	// Control entries consume row budget even though they add no reads.
	for _, count := range []int{257, agentless.MaxExpandedReads, agentless.MaxExpandedReads + 1} {
		t.Run(fmt.Sprintf("control-rows=%d", count), func(t *testing.T) {
			in[listing.ID] = agentless.Result{Read: listing, Output: []byte(strings.Repeat("bonding_masters\n", count))}
			reads, err := c.Expand(agentless.Target{}, in)
			if count <= agentless.MaxExpandedReads {
				require.NoError(t, err)
				require.Len(t, reads, len(masters))
			} else {
				require.ErrorContains(t, err, "listing limit exceeded")
				require.Nil(t, reads, "control rows cannot bypass the listing cap")
			}
		})
	}
	// Exercise the master token cap with distinct names, not duplicates that
	// would fail earlier for a different reason.
	for _, count := range []int{agentless.MaxExpandedReads, agentless.MaxExpandedReads + 1} {
		t.Run(fmt.Sprintf("masters=%d", count), func(t *testing.T) {
			c, in := bondingFixture(t)
			r := c.Reads()[0]
			in[r.ID] = agentless.Result{Read: r, Output: []byte(bondingTestListing(count))}
			in[listing.ID] = agentless.Result{Read: listing}
			reads, err := c.Expand(agentless.Target{}, in)
			if count == agentless.MaxExpandedReads {
				require.NoError(t, err)
				require.Len(t, reads, agentless.MaxExpandedReads)
			} else {
				require.ErrorContains(t, err, "listing limit exceeded")
				require.Nil(t, reads)
			}
		})
	}
	for _, output := range []string{"eth0", "\n", "eth0\neth0\n", "../evil\n", "a/b\n", "bad name\n", "x;id\n", "x\x00y\n", strings.Repeat("x", 4097) + "\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	for _, output := range []string{strings.Repeat("a ", 257), strings.Repeat("a ", agentless.MaxExpandedReads+1), strings.Repeat("x", 4097), "../evil", "a a"} {
		c, in := bondingFixture(t)
		r := c.Reads()[0]
		in[r.ID] = agentless.Result{Read: r, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
}
func TestBondingScraperIsolation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		read    agentless.Read
		result  agentless.Result
		success float64
		series  int
	}{
		{"missing driver", agentless.FileRead("/sys/class/net/bonding_masters"), agentless.Result{NotExist: true, ExitStatus: 1}, 1, 0},
		{"missing listing", agentless.CommandRead("ls", "-1", "/sys/class/net"), agentless.Result{NotExist: true, ExitStatus: 1}, 1, 0},
		{"missing slaves", bondingRead("dmz", "bonding/slaves"), agentless.Result{NotExist: true, ExitStatus: 1}, 1, 4},
		{"missing state", bondingRead("eth0", "bonding_slave/mii_status"), agentless.Result{NotExist: true, ExitStatus: 1}, 1, 4},
		{"permission", bondingRead("eth0", "bonding_slave/mii_status"), agentless.Result{ExitStatus: 2}, 0, 0},
		{"non-slave error", bondingRead("bond0", "bonding_slave/mii_status"), agentless.Result{ExitStatus: 2}, 0, 0},
		{"timeout", bondingRead("dmz", "bonding/slaves"), agentless.Result{NotExist: true, TimedOut: true}, 0, 0},
		{"truncated", bondingRead("eth0", "bonding_slave/mii_status"), agentless.Result{NotExist: true, Truncated: true}, 0, 0},
		{"malformed slaves", bondingRead("dmz", "bonding/slaves"), agentless.Result{Output: []byte("../evil")}, 0, 0},
		{"oversized state", bondingRead("eth0", "bonding_slave/mii_status"), agentless.Result{Output: []byte(strings.Repeat("x", 4097))}, 0, 0},
		{"oversized listing", agentless.CommandRead("ls", "-1", "/sys/class/net"), agentless.Result{Output: []byte(bondingTestListing(agentless.MaxExpandedReads + 1))}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, in := bondingFixture(t)
			tc.result.Read = tc.read
			in[tc.read.ID] = tc.result
			load := &loadavgCollector{}
			lr := load.Reads()[0]
			in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
			runner := &netclassRecordingRunner{fake: &agentlesstest.FakeRunner{Results: in}}
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
				if strings.HasPrefix(f.GetName(), "node_bonding_") {
					series += len(f.Metric)
				}
				if f.GetName() == "node_load1" {
					loadSeen = true
				}
				if f.GetName() == "node_scrape_collector_success" {
					for _, m := range f.Metric {
						success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
					}
				}
			}
			require.True(t, loadSeen)
			require.Equal(t, 1.0, success["loadavg"])
			require.Equal(t, tc.success, success["bonding"])
			require.Equal(t, tc.series, series)
			if tc.name == "oversized listing" || tc.name == "missing driver" || tc.name == "missing listing" {
				require.Len(t, runner.batches, 1)
			} else {
				require.Len(t, runner.batches, 2)
			}
		})
	}
}
