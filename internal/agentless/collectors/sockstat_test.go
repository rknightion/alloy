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

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

// Proc fixtures and golden (filtered to owned families) are unchanged from
// node_exporter v0.18.1-grafana-r01.0.20251024135609-318b01780c89.
// The command fixture supplies the target page size used by that oracle.
func TestSockstatConformance(t *testing.T) {
	c, _ := newSockstatCollector(DefaultConfigs(), nil)
	conformance.Check(t, conformance.Case{
		Collector: c, Root: "testdata/sockstat", Expected: "testdata/sockstat/golden.prom",
		Commands: map[string]string{c.Reads()[2].ID: "testdata/sockstat/pagesize"},
		Families: []string{
			"node_sockstat_sockets_used", "node_sockstat_TCP_inuse", "node_sockstat_TCP_orphan",
			"node_sockstat_TCP_tw", "node_sockstat_TCP_alloc", "node_sockstat_TCP_mem", "node_sockstat_TCP_mem_bytes",
			"node_sockstat_UDP_inuse", "node_sockstat_UDP_mem", "node_sockstat_UDP_mem_bytes",
			"node_sockstat_UDPLITE_inuse", "node_sockstat_RAW_inuse", "node_sockstat_FRAG_inuse", "node_sockstat_FRAG_memory",
			"node_sockstat_TCP6_inuse", "node_sockstat_UDP6_inuse", "node_sockstat_UDPLITE6_inuse", "node_sockstat_RAW6_inuse",
			"node_sockstat_FRAG6_inuse", "node_sockstat_FRAG6_memory",
		},
	})
}

func sockstatFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newSockstatCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	in := agentless.Input{}
	for _, read := range c.Reads() {
		path := "testdata/sockstat" + read.Path
		if len(read.Argv) != 0 {
			path = "testdata/sockstat/pagesize"
		}
		output, err := os.ReadFile(path)
		require.NoError(t, err)
		in[read.ID] = agentless.Result{Read: read, Output: output}
	}
	return c, in
}

func sockstatMetrics(t *testing.T, c agentless.Collector, in agentless.Input) map[string]float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 500)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	close(ch)
	values := map[string]float64{}
	for metric := range ch {
		var data dto.Metric
		require.NoError(t, metric.Write(&data))
		desc := metric.Desc().String()
		name := strings.Split(strings.Split(desc, `fqName: "`)[1], `"`)[0]
		require.Empty(t, data.Label)
		values[name] = data.GetGauge().GetValue()
	}
	return values
}

func TestSockstatRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"sockstat"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "sockstat", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "sockstat")
	found := false
	for _, registration := range Registered() {
		if registration.Name == "sockstat" {
			found = true
			require.Equal(t, "linux", registration.OS)
			require.False(t, registration.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/sockstat"), agentless.FileRead("/proc/net/sockstat6"), agentless.CommandRead("getconf", "PAGESIZE")}, built[0].Reads())
	for _, read := range built[0].Reads() {
		require.NoError(t, read.Validate())
	}
}

func TestSockstatTargetPageSize(t *testing.T) {
	for name, result := range map[string]agentless.Result{
		"4096": {Output: []byte("4096\n")}, "16384": {Output: []byte("16384\n")},
		"failure": {ExitStatus: 1, Output: []byte("4096")}, "missing": {NotExist: true},
		"truncated": {Truncated: true, Output: []byte("4096")}, "timeout": {TimedOut: true},
		"zero": {Output: []byte("0")}, "negative": {Output: []byte("-4096")},
		"malformed": {Output: []byte("four")}, "multiple": {Output: []byte("4096 8192")},
		"overflow": {Output: []byte("9223372036854775808")}, "empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			c, in := sockstatFixture(t)
			in[c.Reads()[2].ID] = result
			values := sockstatMetrics(t, c, in)
			require.Equal(t, 1.0, values["node_sockstat_TCP_mem"])
			require.Contains(t, values, "node_sockstat_UDP_mem")
			if name == "4096" || name == "16384" {
				want := 4096.0
				if name == "16384" {
					want = 16384
				}
				require.Len(t, values, 20)
				require.Equal(t, want, values["node_sockstat_TCP_mem_bytes"])
				require.Contains(t, values, "node_sockstat_UDP_mem_bytes")
			} else {
				require.Len(t, values, 18)
				for key := range values {
					require.NotContains(t, key, "mem_bytes")
				}
			}
		})
	}
	c, in := sockstatFixture(t)
	delete(in, c.Reads()[2].ID)
	require.Len(t, sockstatMetrics(t, c, in), 18)
}

func TestSockstatOptionalProcReads(t *testing.T) {
	for mask := range 4 {
		c, in := sockstatFixture(t)
		want := 20
		for index := range 2 {
			if mask&(1<<index) != 0 {
				read := c.Reads()[index]
				in[read.ID] = agentless.Result{NotExist: true, ExitStatus: 1}
				if index == 0 {
					want -= 14
				} else {
					want -= 6
				}
			}
		}
		require.Len(t, sockstatMetrics(t, c, in), want)
	}
}

func TestSockstatInvalidProcReads(t *testing.T) {
	for index := range 2 {
		for name, bad := range map[string]agentless.Result{
			"nonzero": {ExitStatus: 2}, "truncated": {Truncated: true}, "timeout": {TimedOut: true},
			"missing truncated": {NotExist: true, Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true},
		} {
			t.Run(fmt.Sprintf("%d/%s", index, name), func(t *testing.T) {
				c, in := sockstatFixture(t)
				in[c.Reads()[index].ID] = bad
				ch := make(chan prometheus.Metric, 500)
				require.Error(t, c.Update(agentless.Target{}, in, ch))
				require.Empty(t, ch)
			})
		}
		c, in := sockstatFixture(t)
		delete(in, c.Reads()[index].ID)
		require.Error(t, c.Update(agentless.Target{}, in, make(chan prometheus.Metric, 500)))
		for _, output := range []string{"", "nope", "TCP inuse 1", "TCP: inuse", "TCP: inuse nope", "TCP: inuse 9223372036854775808", "TCP: inuse 1 inuse 2", "sockets: inuse 1", "TCP: inuse 1\nTCP: inuse 2", "bad-name: inuse 1", "TCP: inuse 1\n\n", strings.Repeat("x", 70000), "TCP: " + strings.Repeat("future 1 ", 501), strings.Repeat("TCP: inuse 1\n", 25000), strings.Repeat("p", 4097) + ": inuse 1"} {
			c, in := sockstatFixture(t)
			read := c.Reads()[index]
			in[read.ID] = agentless.Result{Output: []byte(output)}
			ch := make(chan prometheus.Metric, 500)
			require.Error(t, c.Update(agentless.Target{}, in, ch), "index %d output %.80s", index, output)
			require.Empty(t, ch)
		}
	}
}

func TestSockstatOptionalFieldsAndBounds(t *testing.T) {
	c, in := sockstatFixture(t)
	in[c.Reads()[0].ID] = agentless.Result{Output: []byte("FUTURE: unknown 9 memory 7 mem -1\n")}
	in[c.Reads()[1].ID] = agentless.Result{NotExist: true}
	values := sockstatMetrics(t, c, in)
	require.Equal(t, map[string]float64{"node_sockstat_FUTURE_inuse": 0, "node_sockstat_FUTURE_memory": 7, "node_sockstat_FUTURE_mem": -1, "node_sockstat_FUTURE_mem_bytes": -4096}, values)
	// The family limit includes derived bytes and implicit inuse, not just
	// parsed pairs. No partial snapshot escapes when it is exceeded.
	var rows strings.Builder
	for i := range 251 {
		fmt.Fprintf(&rows, "P%d: mem 1\n", i)
	}
	in[c.Reads()[0].ID] = agentless.Result{Output: []byte(rows.String())}
	ch := make(chan prometheus.Metric, 500)
	require.ErrorContains(t, c.Update(agentless.Target{}, in, ch), "family limit")
	require.Empty(t, ch)
}

func TestSockstatScraperIsolation(t *testing.T) {
	for _, missing := range []bool{false, true} {
		c, in := sockstatFixture(t)
		for _, read := range c.Reads()[:2] {
			in[read.ID] = agentless.Result{Output: []byte("malformed")}
			if missing {
				in[read.ID] = agentless.Result{NotExist: true, ExitStatus: 1}
			}
		}
		load := &loadavgCollector{}
		read := load.Reads()[0]
		in[read.ID] = agentless.Result{Read: read, Output: []byte("1 2 3 1/1 1\n")}
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
		success := map[string]float64{}
		foundLoad := false
		for _, family := range families {
			require.False(t, strings.HasPrefix(family.GetName(), "node_sockstat_"))
			if family.GetName() == "node_load1" {
				foundLoad = true
				require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
			}
			if family.GetName() == "node_scrape_collector_success" {
				for _, metric := range family.Metric {
					success[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
				}
			}
		}
		require.True(t, foundLoad)
		require.Equal(t, 1.0, success["loadavg"])
		want := 0.0
		if missing {
			want = 1
		}
		require.Equal(t, want, success["sockstat"])
	}
}
