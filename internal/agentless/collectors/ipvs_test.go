package collectors

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grafana/alloy/internal/agentless"
	"github.com/grafana/alloy/internal/agentless/agentlesstest"
	"github.com/grafana/alloy/internal/agentless/conformance"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
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
	require.Contains(t, DefaultEnabled(), "ipvs")
	for _, r := range Registered() {
		if r.Name == "ipvs" {
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
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

// Exercise registration, scraping and gathered labels against the pinned procfs
// parser used by node_exporter, including aggregation across mapped/native IPv4.
func TestIPVSMappedIPv6PublicParity(t *testing.T) {
	const root = "testdata/ipvs/mapped/proc"
	fs, err := procfs.NewFS(root)
	require.NoError(t, err)
	backends, err := fs.IPVSBackendStatus()
	require.NoError(t, err)
	require.Len(t, backends, 4)
	require.Equal(t, "192.0.2.1", backends[0].LocalAddress.String())
	require.Equal(t, "192.0.2.2", backends[0].RemoteAddress.String())
	want := map[[6]string][3]uint64{}
	for _, backend := range backends {
		local := ""
		if backend.LocalAddress != nil {
			local = backend.LocalAddress.String()
		}
		labels := [6]string{local, strconv.FormatUint(uint64(backend.LocalPort), 10), backend.RemoteAddress.String(), strconv.FormatUint(uint64(backend.RemotePort), 10), backend.Proto, backend.LocalMark}
		values := want[labels]
		values[0] += backend.ActiveConn
		values[1] += backend.InactConn
		values[2] += backend.Weight
		want[labels] = values
	}
	require.Len(t, want, 3)

	built, err := Build([]string{"ipvs"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	_, in := ipvsFixture(t)
	read := built[0].Reads()[1]
	output, err := os.ReadFile(root + "/net/ip_vs")
	require.NoError(t, err)
	in[read.ID] = agentless.Result{Read: read, Output: output}
	scraper, err := agentless.NewScraper(&agentlesstest.FakeRunner{Results: in}, built, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := scraper.Scrape(ctx, agentless.Target{})
	require.NoError(t, err)
	reg := prometheus.NewRegistry()
	reg.MustRegister(result)
	families, err := reg.Gather()
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, family := range families {
		if family.GetName() == "node_scrape_collector_success" {
			require.Len(t, family.Metric, 1)
			require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
		}
		for i, descriptor := range ipvsFamilies {
			if family.GetName() != "node_ipvs_"+descriptor.name {
				continue
			}
			seen[family.GetName()] = true
			if i < 5 {
				require.Len(t, family.Metric, 1)
				continue
			}
			got := map[[6]string]float64{}
			for _, metric := range family.Metric {
				require.Len(t, metric.Label, 6)
				labels := map[string]string{}
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				key := [6]string{labels["local_address"], labels["local_port"], labels["remote_address"], labels["remote_port"], labels["proto"], labels["local_mark"]}
				got[key] = metric.GetGauge().GetValue()
			}
			expected := map[[6]string]float64{}
			for labels, values := range want {
				expected[labels] = float64(values[i-5])
			}
			require.Equal(t, expected, got, family.GetName())
		}
	}
	require.Len(t, seen, len(ipvsFamilies))
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
