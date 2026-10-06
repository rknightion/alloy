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

const udpQueuesHeader = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
const udpQueuesRow = "0: 00000000:0016 00000000:0000 0A 00000015:00000002 00:00000000 00000000 0 0 2740 1 ffff88003d3af3c0 100\n"

// Fixture and golden are unchanged copies from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89 collector/fixtures;
// the golden is filtered to the one owned default family. Upstream has no udp6
// fixture, so the IPv6 aggregation test below supplements (not replaces) it.
func TestUDPQueuesConformance(t *testing.T) {
	c, err := newUDPQueuesCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/udp_queues", Expected: "testdata/udp_queues/golden.prom", Families: []string{"node_udp_queues"}})
}

func udpQueuesFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newUDPQueuesCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	output, err := os.ReadFile("testdata/udp_queues/proc/net/udp")
	require.NoError(t, err)
	in := agentless.Input{}
	for _, read := range c.Reads() {
		in[read.ID] = agentless.Result{Read: read, Output: output}
	}
	return c, in
}

func TestUDPQueuesRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"udp_queues"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "udp_queues", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "udp_queues")
	found := false
	for _, r := range Registered() {
		if r.Name == "udp_queues" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/udp"), agentless.FileRead("/proc/net/udp6")}, built[0].Reads())
	for _, read := range built[0].Reads() {
		require.NoError(t, read.Validate())
		require.Empty(t, read.Argv)
	}
}

func TestUDPQueuesOptionalReads(t *testing.T) {
	for mask := range 4 {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			c, in := udpQueuesFixture(t)
			want := 4
			for i, read := range c.Reads() {
				if mask&(1<<i) != 0 {
					in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
					want -= 2
				}
			}
			ch := make(chan prometheus.Metric, 4)
			require.NoError(t, c.Update(agentless.Target{}, in, ch))
			require.Len(t, ch, want)
		})
	}
}

func TestUDPQueuesReadFailures(t *testing.T) {
	for index := range 2 {
		for name, bad := range map[string]agentless.Result{
			"nonzero": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true},
			"missing truncated": {NotExist: true, Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true},
		} {
			t.Run(fmt.Sprintf("%d/%s", index, name), func(t *testing.T) {
				c, in := udpQueuesFixture(t)
				read := c.Reads()[index]
				bad.Read = read
				bad.Output = []byte(udpQueuesHeader + udpQueuesRow)
				in[read.ID] = bad
				ch := make(chan prometheus.Metric, 4)
				require.Error(t, c.Update(agentless.Target{}, in, ch))
				require.Empty(t, ch, "never emit a partial sum")
			})
		}
		c, in := udpQueuesFixture(t)
		delete(in, c.Reads()[index].ID)
		ch := make(chan prometheus.Metric, 4)
		require.Error(t, c.Update(agentless.Target{}, in, ch))
		require.Empty(t, ch)
	}
}

func TestUDPQueuesMalformed(t *testing.T) {
	cases := []string{"", "bad header\n", udpQueuesHeader + "\n", udpQueuesHeader + "0: 1 2\n",
		udpQueuesHeader + udpQueuesRow + strings.Repeat("x", 70000),
		udpQueuesHeader + udpQueuesRow + strings.Repeat("1 ", 25000),
	}
	for _, pair := range [][2]string{
		{"0:", "bad:"}, {"0:", "0:1"}, {"00000000:0016", "nope:0016"}, {"00000000:0016", "00000000:nope"},
		{"00000000:0000", "0000000000:0000"}, {"0A", "-1"}, {"00000015:00000002", "1"},
		{"00000015:00000002", "1:10000000000000000"}, {"00000015:00000002", "-1:2"},
		{" 0 0 2740 ", " bad 0 2740 "}, {" 2740 ", " nope "}, {" 100\n", " bad\n"},
	} {
		cases = append(cases, udpQueuesHeader+udpQueuesRow+strings.Replace(udpQueuesRow, pair[0], pair[1], 1))
	}
	for index := range 2 {
		for n, output := range cases {
			t.Run(fmt.Sprintf("%d/%d", index, n), func(t *testing.T) {
				c, in := udpQueuesFixture(t)
				read := c.Reads()[index]
				in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
				ch := make(chan prometheus.Metric, 4)
				require.Error(t, c.Update(agentless.Target{}, in, ch))
				require.Empty(t, ch)
			})
		}
	}
}

func TestUDPQueuesAggregation(t *testing.T) {
	c, in := udpQueuesFixture(t)
	v6 := strings.ReplaceAll(udpQueuesRow, "00000000:", "00000000000000000000000000000000:")
	for i, read := range c.Reads() {
		row := udpQueuesRow
		if i == 1 {
			row = v6
		}
		in[read.ID] = agentless.Result{Read: read, Output: []byte(udpQueuesHeader + strings.Repeat(row, i+2))}
	}
	ch := make(chan prometheus.Metric, 4)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	close(ch)
	values := map[string]float64{}
	for metric := range ch {
		m := &dto.Metric{}
		require.NoError(t, metric.Write(m))
		values[m.Label[0].GetValue()+"/"+m.Label[1].GetValue()] = m.GetGauge().GetValue()
	}
	require.Equal(t, map[string]float64{"v4/tx": 42, "v4/rx": 4, "v6/tx": 63, "v6/rx": 6}, values)
	sums, err := parseUDPQueues([]byte(udpQueuesHeader))
	require.NoError(t, err)
	require.Equal(t, [2]uint64{}, sums)
}

func TestUDPQueuesKernelHeaders(t *testing.T) {
	// procfs v0.16.1 testdata/fixtures.ttar includes the extended IPv6
	// header with remote_address and the ref/pointer/drops suffix.
	for _, remote := range []string{"rem_address", "remote_address"} {
		for _, suffix := range []string{"", " ref pointer drops"} {
			header := strings.Replace(strings.TrimSuffix(udpQueuesHeader, "\n"), "rem_address", remote, 1) + suffix + "\n"
			totals, err := parseUDPQueues([]byte(header + udpQueuesRow))
			require.NoError(t, err)
			require.Equal(t, [2]uint64{21, 2}, totals)
		}
	}
	for _, suffix := range []string{" ref pointer", " ref pointer drops extra", " wrong"} {
		_, err := parseUDPQueues([]byte(strings.TrimSuffix(udpQueuesHeader, "\n") + suffix + "\n" + udpQueuesRow))
		require.Error(t, err)
	}
}

func TestUDPQueuesHostileBoundedRetention(t *testing.T) {
	// Many sockets are aggregated, not retained as series. The hostile tail must
	// still be examined after crossing the central 20000-series cap.
	large := []byte(udpQueuesHeader + strings.Repeat(udpQueuesRow, 25000))
	totals, err := parseUDPQueues(large)
	require.NoError(t, err)
	require.Equal(t, [2]uint64{525000, 50000}, totals)
	_, err = parseUDPQueues(append(large, []byte("bad tail\n")...))
	require.Error(t, err)
	// One hostile line cannot allocate an input-sized token slice or IP object.
	huge := []byte(udpQueuesHeader + strings.Repeat("f", 1<<20))
	allocs := testing.AllocsPerRun(2, func() { _, err := parseUDPQueues(huge); require.Error(t, err) })
	require.Less(t, allocs, 20.0)
}

func TestUDPQueuesScraperIsolation(t *testing.T) {
	for index := range 2 {
		for _, mode := range []string{"missing", "malformed", "truncated", "nonzero"} {
			t.Run(fmt.Sprintf("%d/%s", index, mode), func(t *testing.T) {
				c, in := udpQueuesFixture(t)
				read := c.Reads()[index]
				bad := agentless.Result{Read: read, Output: []byte(udpQueuesHeader + udpQueuesRow)}
				switch mode {
				case "missing":
					bad.NotExist = true
					bad.ExitStatus = 1
				case "malformed":
					bad.Output = []byte("bad")
				case "truncated":
					bad.Truncated = true
				case "nonzero":
					bad.ExitStatus = 2
				}
				in[read.ID] = bad
				load := &loadavgCollector{}
				lr := load.Reads()[0]
				in[lr.ID] = agentless.Result{Read: lr, Output: []byte("1 2 3 1/1 1\n")}
				scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, []agentless.Collector{c, load}, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
				udpSeries := 0
				loadSeen := false
				for _, family := range families {
					switch family.GetName() {
					case "node_load1":
						loadSeen = true
						require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
					case "node_udp_queues":
						udpSeries = len(family.Metric)
					case "node_scrape_collector_success":
						for _, metric := range family.Metric {
							success[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
						}
					}
				}
				require.True(t, loadSeen)
				require.Equal(t, 1.0, success["loadavg"])
				if mode == "missing" {
					require.Equal(t, 1.0, success["udp_queues"])
					require.Equal(t, 2, udpSeries)
				} else {
					require.Equal(t, 0.0, success["udp_queues"])
					require.Zero(t, udpSeries)
				}
			})
		}
	}
}
