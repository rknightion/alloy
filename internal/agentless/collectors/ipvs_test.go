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
	"github.com/stretchr/testify/require"
)

func TestIPVSConformance(t *testing.T) {
	c, err := newIPVSCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	families := make([]string, 0, len(ipvsFamilies))
	for _, f := range ipvsFamilies {
		families = append(families, "node_ipvs_"+f.name)
	}
	// Unchanged upstream default-label golden and proc fixtures.
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/ipvs", Expected: "testdata/ipvs/golden.prom", Families: families})
}

func ipvsFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newIPVSCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	in := agentless.Input{}
	for _, read := range c.Reads() {
		output, err := os.ReadFile("testdata/ipvs" + read.Path)
		require.NoError(t, err)
		in[read.ID] = agentless.Result{Read: read, Output: output}
	}
	return c, in
}

func TestIPVSRegistration(t *testing.T) {
	built, err := Build([]string{"ipvs"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "ipvs", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "ipvs")
	for _, r := range Registered() {
		if r.Name == "ipvs" {
			require.Equal(t, "linux", r.OS)
			require.False(t, r.DefaultEnabled)
		}
	}
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/ip_vs_stats"), agentless.FileRead("/proc/net/ip_vs")}, built[0].Reads())
	for _, read := range built[0].Reads() {
		require.NoError(t, read.Validate())
	}
}

func TestIPVSOptionalReads(t *testing.T) {
	for mask := range 4 {
		c, in := ipvsFixture(t)
		want := 35
		for i, read := range c.Reads() {
			if mask&(1<<i) != 0 {
				in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
				if i == 0 {
					want -= 5
				} else {
					want -= 30
				}
			}
		}
		ch := make(chan prometheus.Metric, 100)
		require.NoError(t, c.Update(agentless.Target{}, in, ch))
		require.Len(t, ch, want)
	}
}

func TestIPVSIsolation(t *testing.T) {
	for index := range 2 {
		for _, mode := range []string{"missing", "malformed", "nonzero", "timeout", "truncated", "missing-timeout", "missing-truncated", "absent"} {
			t.Run(fmt.Sprintf("%d/%s", index, mode), func(t *testing.T) {
				c, in := ipvsFixture(t)
				read := c.Reads()[index]
				bad := in[read.ID]
				switch mode {
				case "missing":
					bad.NotExist = true
					bad.ExitStatus = 1
				case "malformed":
					bad.Output = []byte("bad\n")
				case "nonzero":
					bad.ExitStatus = 2
				case "timeout":
					bad.TimedOut = true
				case "truncated":
					bad.Truncated = true
				case "missing-timeout":
					bad.NotExist = true
					bad.TimedOut = true
				case "missing-truncated":
					bad.NotExist = true
					bad.Truncated = true
				}
				in[read.ID] = bad
				if mode == "absent" {
					delete(in, read.ID)
					ch := make(chan prometheus.Metric, 100)
					require.Error(t, c.Update(agentless.Target{}, in, ch))
					require.Empty(t, ch)
				}
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
				series := 0
				loadSeen := false
				for _, f := range families {
					if f.GetName() == "node_load1" {
						loadSeen = true
					}
					if strings.HasPrefix(f.GetName(), "node_ipvs_") {
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
				// FakeRunner turns an absent result into NotExist (fake.go), so
				// it has the same optional-file semantics as explicit missing.
				if mode == "missing" || mode == "absent" {
					require.Equal(t, 1.0, success["ipvs"])
					want := 30
					if index == 1 {
						want = 5
					}
					require.Equal(t, want, series)
				} else {
					require.Zero(t, success["ipvs"])
					require.Zero(t, series)
				}
			})
		}
	}
}

const ipvsTestHeader = "IP Virtual Server version 1.2.1 (size=4096)\nProt LocalAddress:Port Scheduler Flags\n  -> RemoteAddress:Port Forward Weight ActiveConn InActConn\n"
const ipvsTestService = "TCP C0A80016:0CEA wlc\n"
const ipvsTestBackend = " -> C0A85216:0CEA Tunnel 100 248 2\n"

func TestIPVSMalformed(t *testing.T) {
	for _, output := range []string{"", ipvsTestHeader + "TCP\n", ipvsTestHeader + ipvsTestBackend, ipvsTestHeader + ipvsTestService + " -> bad Tunnel 1 2 3\n", ipvsTestHeader + ipvsTestService + " -> C0A85216:0CEA Tunnel -1 2 3\n", ipvsTestHeader + ipvsTestService + ipvsTestBackend + "bad\n", ipvsTestHeader + strings.Repeat("x", 70000)} {
		_, err := parseIPVSBackends([]byte(output))
		require.Error(t, err)
	}
	for _, output := range []string{"", "a\nb\n1 2 3 4\n\n", "a\nb\n1 2 3 4 z\n\n"} {
		_, err := parseIPVSStats([]byte(output))
		require.Error(t, err)
	}
}

func TestIPVSAggregationAndIPv6(t *testing.T) {
	sums, err := parseIPVSBackends([]byte(ipvsTestHeader + ipvsTestService + strings.Repeat(ipvsTestBackend, 2)))
	require.NoError(t, err)
	require.Equal(t, []ipvsBackend{{labels: [6]string{"192.168.0.22", "3306", "192.168.82.22", "3306", "TCP", ""}, values: [3]uint64{496, 4, 200}}}, sums)
	address, port, err := parseIPVSEndpoint("[2001:0db8:0000:0000:0000:0000:0000:0001]:0050")
	require.NoError(t, err)
	require.Equal(t, "2001:db8::1", address)
	require.Equal(t, "80", port)
}

func TestIPVSHostileBoundedRetention(t *testing.T) {
	var b strings.Builder
	b.WriteString(ipvsTestHeader + ipvsTestService)
	for i := range maxIPVSBackends {
		fmt.Fprintf(&b, " -> %08X:0050 Tunnel 1 2 3\n", i)
	}
	full := []byte(b.String())
	sums, err := parseIPVSBackends(full)
	require.NoError(t, err)
	require.Len(t, sums, maxIPVSBackends)
	c, in := ipvsFixture(t)
	read := c.Reads()[1]
	in[read.ID] = agentless.Result{Read: read, Output: full}
	ch := make(chan prometheus.Metric, 20000)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, 20000)
	excess := append(append([]byte{}, full...), []byte(ipvsTestBackend)...)
	enormous := append(append([]byte{}, excess...), []byte(strings.Repeat(ipvsTestBackend, 25000))...)
	for _, output := range [][]byte{excess, enormous} {
		_, err := parseIPVSBackends(output)
		require.ErrorContains(t, err, "limit exceeded")
	}
	small := testing.AllocsPerRun(2, func() { _, _ = parseIPVSBackends(excess) })
	large := testing.AllocsPerRun(2, func() { _, _ = parseIPVSBackends(enormous) })
	require.Equal(t, small, large, "no allocations for excess lines")
}
