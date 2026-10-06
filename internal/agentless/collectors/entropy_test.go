package collectors

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/grafana/alloy/internal/util"
)

func TestEntropyConformance(t *testing.T) {
	c, err := newEntropyCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Equal(t, "entropy", c.Name())
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/sys/kernel/random/entropy_avail"), agentless.FileRead("/proc/sys/kernel/random/poolsize")}, c.Reads())
	for _, read := range c.Reads() {
		require.NoError(t, read.Validate())
		require.Empty(t, read.Argv)
	}
	require.NoError(t, Validate([]string{"entropy"}))
	require.NotContains(t, DefaultEnabled(), "entropy")
	for _, r := range Registered() {
		if r.Name == "entropy" {
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	conformance.Check(t, conformance.Case{Collector: c, Families: []string{"node_entropy_available_bits", "node_entropy_pool_size_bits"}, Root: "testdata/entropy"})
}

func entropyInput() agentless.Input {
	in := agentless.Input{}
	for _, read := range (&entropyCollector{}).Reads() {
		in[read.ID] = agentless.Result{Read: read, Output: []byte("256\n")}
	}
	return in
}

func TestEntropyOptionalMissing(t *testing.T) {
	c := &entropyCollector{}
	for mask := 1; mask < 4; mask++ {
		in := entropyInput()
		for i, read := range c.Reads() {
			if mask&(1<<i) != 0 {
				in[read.ID] = agentless.Result{NotExist: true, ExitStatus: 1}
			}
		}
		ch := make(chan prometheus.Metric, 2)
		require.NoError(t, c.Update(agentless.Target{}, in, ch))
		want := 1
		if mask == 3 {
			want = 0
		}
		require.Len(t, ch, want)
	}
}

func TestEntropyRejectsBadSnapshots(t *testing.T) {
	c := &entropyCollector{}
	for _, read := range c.Reads() {
		for _, bad := range []string{"", "bad", "-1", "+1", "NaN", "Inf", "1.5", "1 2", "18446744073709551616"} {
			in := entropyInput()
			in[read.ID] = agentless.Result{Output: []byte(bad)}
			ch := make(chan prometheus.Metric, 2)
			require.Error(t, c.Update(agentless.Target{}, in, ch), bad)
			require.Empty(t, ch)
		}
		for _, result := range []agentless.Result{{ExitStatus: 1}, {Truncated: true}, {TimedOut: true}, {NotExist: true, TimedOut: true}, {NotExist: true, Truncated: true}} {
			in := entropyInput()
			in[read.ID] = result
			ch := make(chan prometheus.Metric, 2)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		}
		in := entropyInput()
		delete(in, read.ID)
		require.Error(t, c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 2)))
	}
}

func TestEntropyScraperIsolation(t *testing.T) {
	for _, result := range []agentless.Result{{Output: []byte("malformed")}, {ExitStatus: 2}} {
		results := entropyInput()
		results[(&entropyCollector{}).Reads()[1].ID] = result
		read := agentless.FileRead("/proc/loadavg")
		results[read.ID] = agentless.Result{Output: []byte("1 2 3 1/1 1\n")}
		runner := &agentlesstest.FakeRunner{Results: results}
		scraper, err := agentless.NewScraper(runner, []agentless.Collector{&entropyCollector{}, &loadavgCollector{}}, util.TestLogger(t))
		require.NoError(t, err)
		snapshot, err := scraper.Scrape(t.Context(), agentless.Target{Address: "fixture"})
		require.NoError(t, err)
		require.NoError(t, testutil.CollectAndCompare(snapshot, strings.NewReader(`
# HELP node_scrape_collector_success node_exporter: Whether a collector succeeded.
# TYPE node_scrape_collector_success gauge
node_scrape_collector_success{collector="entropy"} 0
node_scrape_collector_success{collector="loadavg"} 1
# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 1
`), "node_scrape_collector_success", "node_load1"))
	}
}
