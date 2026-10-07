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

// Unchanged files from the pinned node_exporter collector/fixtures/sys.ttar
// and its e2e-output.txt. All exported NVMe families (node_nvme_info) are
// checked. cntlid and procfs namespace properties (nuse, size,
// queue/logical_block_size, ana_state) have no upstream metric families.
func TestNVMeConformance(t *testing.T) {
	c, err := newNVMeCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/nvme", Expected: "testdata/nvme/golden.prom", Families: []string{"node_nvme_info"}})
}

func nvmeFixture(t *testing.T) (*nvmeCollector, agentless.Input) {
	t.Helper()
	collector, err := newNVMeCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := collector.(*nvmeCollector)
	runner, err := agentlesstest.FromFS("testdata/nvme", nil, c.Reads())
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

func TestNVMeRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"nvme"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "nvme", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "nvme")
	found := false
	for _, r := range Registered() {
		if r.Name == "nvme" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	c, in := nvmeFixture(t)
	require.Equal(t, []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/class/nvme")}, c.Reads())
	require.NoError(t, c.Reads()[0].Validate())
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 5)
	for i, attribute := range []string{"firmware_rev", "model", "serial", "state", "cntlid"} {
		require.Equal(t, nvmeRead("nvme0", attribute), reads[i])
		require.NoError(t, reads[i].Validate())
	}
}

func TestNVMeListingBounds(t *testing.T) {
	c, in := nvmeFixture(t)
	read := c.Reads()[0]
	maxDevices := agentless.MaxExpandedReads / len(nvmeAttributes)
	for _, count := range []int{maxDevices, maxDevices + 1, agentless.MaxExpandedReads + 1} {
		var listing strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&listing, "nvme%d\n", i)
		}
		in[read.ID] = agentless.Result{Read: read, Output: []byte(listing.String())}
		reads, err := c.Expand(agentless.Target{}, in)
		if count == maxDevices {
			require.NoError(t, err)
			require.Len(t, reads, maxDevices*len(nvmeAttributes))
			for _, r := range reads {
				require.NoError(t, r.Validate())
			}
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, output := range []string{"nvme0", "\n", "nvme0\n\n", "nvme0\nnvme0\n", strings.Repeat("bad name\n", agentless.MaxExpandedReads+1), strings.Repeat("x", 1<<20) + "\n"} {
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	in[read.ID] = agentless.Result{Read: read, Output: []byte(strings.Repeat("bad name\n", agentless.MaxExpandedReads))}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Empty(t, reads)
	in[read.ID] = agentless.Result{Read: read, Output: []byte("nvme0\nnvme1\nnvme\nnvme1n1\n../evil\nnvme1/evil\nnvme2;id\nnvme\xff\n")}
	reads, err = c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 10)
	for _, r := range reads {
		require.NoError(t, r.Validate())
	}
}

func TestNVMeMalformedAttributeRejectsCollectorAtomically(t *testing.T) {
	for _, output := range []string{strings.Repeat("x", 4097), "\xff", "a\x00b"} {
		c, in := nvmeFixture(t)
		listing := c.Reads()[0]
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte("nvme0\nnvme1\n")}
		for _, attribute := range nvmeAttributes {
			r := nvmeRead("nvme1", attribute)
			in[r.ID] = agentless.Result{Read: r, Output: []byte("good\n")}
		}
		r := nvmeRead("nvme1", "model")
		in[r.ID] = agentless.Result{Read: r, Output: []byte(output)}
		ch := make(chan prometheus.Metric, 10)
		require.ErrorContains(t, c.Update(agentless.Target{}, in, ch), "invalid attribute model")
		require.Empty(t, ch, "no metrics from the earlier healthy controller may escape")
	}
}

func TestNVMeMalformedAttributeScraperIsolation(t *testing.T) {
	for _, attribute := range nvmeAttributes {
		for _, output := range []string{strings.Repeat("x", 4097), "\xff", "a\x00b"} {
			t.Run(attribute+fmt.Sprintf("/%x", []byte(output[:1])), func(t *testing.T) {
				c, in := nvmeFixture(t)
				listing := c.Reads()[0]
				in[listing.ID] = agentless.Result{Read: listing, Output: []byte("nvme0\nnvme1\n")}
				for _, attr := range nvmeAttributes {
					r := nvmeRead("nvme1", attr)
					in[r.ID] = agentless.Result{Read: r, Output: []byte("good\n")}
				}
				// A healthy first controller must not leak buffered metrics when
				// a subsequent controller has a malformed attribute.
				r := nvmeRead("nvme1", attribute)
				in[r.ID] = agentless.Result{Read: r, Output: []byte(output)}
				load := &loadavgCollector{}
				lr := load.Reads()[0]
				in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
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
				success := map[string]float64{}
				loadSeen := false
				for _, family := range families {
					require.NotEqual(t, "node_nvme_info", family.GetName(), "malformed attributes reject all NVMe series")
					if family.GetName() == "node_load1" {
						loadSeen = true
						require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
					}
					if family.GetName() == "node_scrape_collector_success" {
						for _, m := range family.Metric {
							success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
						}
					}
				}
				require.True(t, loadSeen)
				require.Contains(t, success, "nvme")
				require.Equal(t, 0.0, success["nvme"])
				require.Equal(t, 1.0, success["loadavg"])
			})
		}
	}
}

func TestNVMeScraperIsolation(t *testing.T) {
	for _, attribute := range []string{"listing", "model", "cntlid"} {
		for name, failure := range map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "nonzero": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true}} {
			t.Run(attribute+"/"+name, func(t *testing.T) {
				c, in := nvmeFixture(t)
				read := c.Reads()[0]
				if attribute != "listing" {
					read = nvmeRead("nvme0", attribute)
				}
				failure.Read = read
				failure.Output = []byte("nvme0\n")
				in[read.ID] = failure
				load := &loadavgCollector{}
				lr := load.Reads()[0]
				in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
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
				success := map[string]float64{}
				info, loadSeen := false, false
				for _, family := range families {
					if family.GetName() == "node_nvme_info" {
						info = true
					}
					if family.GetName() == "node_load1" {
						loadSeen = true
					}
					if family.GetName() == "node_scrape_collector_success" {
						for _, m := range family.Metric {
							success[m.Label[0].GetValue()] = m.GetGauge().GetValue()
						}
					}
				}
				require.True(t, loadSeen)
				require.Equal(t, 1.0, success["loadavg"])
				want := 0.0
				if name == "missing" {
					want = 1
				}
				require.Equal(t, want, success["nvme"])
				require.Equal(t, name == "missing" && attribute == "cntlid", info)
			})
		}
	}
}
