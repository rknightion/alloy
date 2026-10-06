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

// Fixture and all six default families are unchanged copies from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89 collector/fixtures.
func TestNFSConformance(t *testing.T) {
	c, err := newNFSCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/nfs", Expected: "testdata/nfs/golden.prom", Families: []string{"node_nfs_packets_total", "node_nfs_connections_total", "node_nfs_rpcs_total", "node_nfs_rpc_retransmissions_total", "node_nfs_rpc_authentication_refreshes_total", "node_nfs_requests_total"}})
}

func nfsFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newNFSCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	output, err := os.ReadFile("testdata/nfs/proc/net/rpc/nfs")
	require.NoError(t, err)
	read := c.Reads()[0]
	return c, agentless.Input{read.ID: {Read: read, Output: output}}
}

func TestNFSRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"nfs"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "nfs", built[0].Name())
	require.Contains(t, DefaultEnabled(), "nfs")
	found := false
	for _, r := range Registered() {
		if r.Name == "nfs" {
			found = true
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/rpc/nfs")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
}

func TestNFSReadFailures(t *testing.T) {
	for name, result := range map[string]agentless.Result{
		"missing": {NotExist: true, ExitStatus: 1}, "nonzero": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true},
		"missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true},
	} {
		t.Run(name, func(t *testing.T) {
			c, in := nfsFixture(t)
			read := c.Reads()[0]
			result.Read = read
			result.Output = in[read.ID].Output
			in[read.ID] = result
			ch := make(chan prometheus.Metric, 200)
			err := c.Update(agentless.Target{}, in, ch)
			if name == "missing" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Empty(t, ch)
		})
	}
	c, _ := nfsFixture(t)
	require.Error(t, c.Update(agentless.Target{}, agentless.Input{}, make(chan prometheus.Metric, 200)))
}

func TestNFSMalformedAndHostile(t *testing.T) {
	cases := []string{"", "\n", "unknown 1\n", "net 1 2 3\n", "rpc 1 2 3 4\n", "proc2 0\n", "proc3 1 0\n", "proc4 2 1\n", "proc4 18446744073709551615\n", "rpc -1 0 0\n", "rpc 18446744073709551616 0 0\n", "rpc 1 2 3\nrpc 1 2 3\n", "proc4 500 " + strings.Repeat("1 ", 500), strings.Repeat("x", 1<<20), "proc4 1 " + strings.Repeat("1", 1000)}
	for i, output := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c, in := nfsFixture(t)
			read := c.Reads()[0]
			in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
			ch := make(chan prometheus.Metric, 200)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		})
	}
	for _, output := range [][]byte{[]byte(strings.Repeat("x", 1<<20)), []byte("proc4 1000000 " + strings.Repeat("1 ", 1000000))} {
		allocs := testing.AllocsPerRun(3, func() { _, err := parseNFSStats(output); require.Error(t, err) })
		require.Less(t, allocs, 20.0, "reject before input-sized token/value retention")
	}
}

func TestNFSProcedureWidths(t *testing.T) {
	for _, count := range []int{0, 1, 35, 59, 60, 498} {
		stats, err := parseNFSStats([]byte(fmt.Sprintf("proc4 %d %s\n", count, strings.Repeat("7 ", count))))
		require.NoError(t, err)
		if count == 0 {
			require.Zero(t, stats.ClientV4Stats.Null)
		} else {
			require.Equal(t, uint64(7), stats.ClientV4Stats.Null)
		}
		if count < 59 {
			require.Zero(t, stats.ClientV4Stats.Clone)
		} else {
			require.Equal(t, uint64(7), stats.ClientV4Stats.Clone)
		}
	}
	_, err := parseNFSStats([]byte("proc2 19 " + strings.Repeat("1 ", 19) + "\nproc3 23 " + strings.Repeat("2 ", 23)))
	require.NoError(t, err)
}

func TestNFSScraperIsolation(t *testing.T) {
	for _, mode := range []string{"missing", "malformed", "nonzero"} {
		t.Run(mode, func(t *testing.T) {
			c, in := nfsFixture(t)
			read := c.Reads()[0]
			bad := in[read.ID]
			switch mode {
			case "missing":
				bad.NotExist = true
				bad.ExitStatus = 1
			case "malformed":
				bad.Output = append(bad.Output, []byte("bad\n")...)
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
			loadSeen := false
			for _, family := range families {
				require.False(t, strings.HasPrefix(family.GetName(), "node_nfs_"))
				if family.GetName() == "node_load1" {
					loadSeen = true
					require.Equal(t, 1.0, family.Metric[0].GetGauge().GetValue())
				}
				if family.GetName() == "node_scrape_collector_success" {
					for _, metric := range family.Metric {
						success[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
					}
				}
			}
			require.True(t, loadSeen)
			require.Equal(t, 1.0, success["loadavg"])
			want := 0.0
			if mode == "missing" {
				want = 1
			}
			require.Equal(t, want, success["nfs"])
		})
	}
}
