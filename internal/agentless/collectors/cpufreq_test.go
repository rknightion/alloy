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
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// Files are unchanged extractions of the pinned node_exporter's sys.ttar.
// All four families present in that fixture are compared to upstream e2e.
// Left out of this fixture check: node_cpu_frequency_hertz,
// node_cpu_frequency_min_hertz and node_cpu_frequency_max_hertz, because
// sys.ttar has no cpuinfo frequency files. TestCpufreqNumeric covers these.
// Transition latency, driver, related CPUs and setspeed are not exported.
func TestCpufreqConformance(t *testing.T) {
	c, err := newCpufreqCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/cpufreq", Families: []string{"node_cpu_scaling_frequency_hertz", "node_cpu_scaling_frequency_min_hertz", "node_cpu_scaling_frequency_max_hertz", "node_cpu_scaling_governor"}})
}
func cpufreqFixture(t *testing.T) (*cpufreqCollector, agentless.Input) {
	t.Helper()
	built, err := newCpufreqCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := built.(*cpufreqCollector)
	runner, err := agentlesstest.FromFS("testdata/cpufreq", nil, c.Reads())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, err := runner.Run(ctx, agentless.Target{}, c.Reads())
	require.NoError(t, err)
	in := agentless.Input{}
	for _, r := range results {
		in[r.Read.ID] = r
	}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	results, err = runner.Run(ctx, agentless.Target{}, reads)
	require.NoError(t, err)
	for _, r := range results {
		in[r.Read.ID] = r
	}
	return c, in
}
func cpufreqUpdate(t *testing.T, c *cpufreqCollector, in agentless.Input) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 2000)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	close(ch)
	var out []prometheus.Metric
	for m := range ch {
		out = append(out, m)
	}
	return out
}
func TestCpufreqRegistration(t *testing.T) {
	built, err := Build([]string{"cpufreq"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "cpufreq", built[0].Name())
	require.Contains(t, DefaultEnabled(), "cpufreq")
	found := false
	for _, r := range Registered() {
		if r.Name == "cpufreq" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.CommandRead("ls", "-1", "/sys/devices/system/cpu")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
	c, in := cpufreqFixture(t)
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 32)
	for _, r := range reads {
		require.NoError(t, r.Validate())
		require.Empty(t, r.Argv)
	}
}
func TestCpufreqListing(t *testing.T) {
	c, in := cpufreqFixture(t)
	listing := c.Reads()[0]
	maxCPUs := agentless.MaxExpandedReads / 8
	for _, count := range []int{maxCPUs, maxCPUs + 1, agentless.MaxExpandedReads + 1} {
		var b strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&b, "cpu%d\n", i)
		}
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(b.String())}
		reads, err := c.Expand(agentless.Target{}, in)
		if count == maxCPUs {
			require.NoError(t, err)
			require.Len(t, reads, maxCPUs*8)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, s := range []string{"cpu0", "\n", "cpu0\ncpu0\n", strings.Repeat("invalid\n", agentless.MaxExpandedReads+1), strings.Repeat("x", 1<<20) + "\n"} {
		in[listing.ID] = agentless.Result{Read: listing, Output: []byte(s)}
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
		ch := make(chan prometheus.Metric, 2000)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch)
	}
	in[listing.ID] = agentless.Result{Read: listing, Output: []byte("cpu0\ncpufreq\nonline\ncpu../x\ncpu1;id\ncpu1/evil\n")}
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 8)
	for _, r := range reads {
		require.NoError(t, r.Validate())
		require.Contains(t, r.Path, "/cpu0/cpufreq/")
	}
}
func TestCpufreqNumeric(t *testing.T) {
	c, in := cpufreqFixture(t)
	for _, spec := range cpufreqNumbers {
		r := cpufreqRead("cpu0", spec.attribute)
		in[r.ID] = agentless.Result{Read: r, Output: []byte("1234\n")}
	}
	metrics := cpufreqUpdate(t, c, in)
	require.Len(t, metrics, 23)
	for _, spec := range cpufreqNumbers {
		found := false
		for _, m := range metrics {
			if strings.Contains(m.Desc().String(), "fqName: \"node_cpu_"+spec.family+"\"") {
				// Inspect actual protobuf value and CPU label, not only descriptor presence.
				var value dto.Metric
				require.NoError(t, m.Write(&value))
				if value.Label[0].GetValue() == "0" {
					found = true
					require.Equal(t, 1234000.0, value.GetGauge().GetValue())
				}
			}
		}
		require.True(t, found)
	}
}
func TestCpufreqMalformedAttributeIsolation(t *testing.T) {
	for _, raw := range []string{"bad", "-1", "18446744073709551616", strings.Repeat("1", 1<<20)} {
		c, in := cpufreqFixture(t)
		r := cpufreqRead("cpu0", "scaling_cur_freq")
		in[r.ID] = agentless.Result{Read: r, Output: []byte(raw)}
		require.Len(t, cpufreqUpdate(t, c, in), 19)
	}
	for _, raw := range []string{strings.Repeat("x", 1<<20), strings.Repeat("g ", 33), "performance performance", "\xff", "bad\tname"} {
		c, in := cpufreqFixture(t)
		r := cpufreqRead("cpu0", "scaling_available_governors")
		in[r.ID] = agentless.Result{Read: r, Output: []byte(raw)}
		require.Len(t, cpufreqUpdate(t, c, in), 18)
	}
}
func TestCpufreqScraperIsolation(t *testing.T) {
	for _, attribute := range []string{"listing", "scaling_cur_freq"} {
		for name, failure := range map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "error": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true}} {
			t.Run(attribute+"/"+name, func(t *testing.T) {
				c, in := cpufreqFixture(t)
				r := c.Reads()[0]
				if attribute != "listing" {
					r = cpufreqRead("cpu0", attribute)
				}
				failure.Read = r
				failure.Output = []byte("1234\n")
				in[r.ID] = failure
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
				series := 0
				loadSeen := false
				for _, f := range families {
					if strings.HasPrefix(f.GetName(), "node_cpu_") {
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
				if name == "missing" {
					require.Equal(t, 1.0, success["cpufreq"])
					if attribute == "listing" {
						require.Zero(t, series)
					} else {
						require.Equal(t, 19, series)
					}
				} else {
					require.Zero(t, success["cpufreq"])
					require.Zero(t, series)
				}
			})
		}
	}
	c, in := cpufreqFixture(t)
	reads, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	for _, r := range reads {
		in[r.ID] = agentless.Result{Read: r, NotExist: true, ExitStatus: 1}
	}
	require.Empty(t, cpufreqUpdate(t, c, in), "VM without cpufreq is successful and emits no series")
}
