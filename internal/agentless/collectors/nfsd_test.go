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

// Fixture is copied from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89; golden is generated
// by executing that pinned Linux collector on the byte-identical fixture.
// Its static e2e golden has stale v4 Verify/Write values (3 rather than 0).
// No default families are omitted. Upstream does not export unused file-handle fields,
// thread utilization, read-ahead histogram, v2/v3 Null, v4 Compound or the
// v4 operations absent from its requests mapping.
func TestNFSdConformance(t *testing.T) {
	c, err := newNFSdCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/nfsd", Expected: "testdata/nfsd/golden.prom", Families: []string{
		"node_nfsd_reply_cache_hits_total", "node_nfsd_reply_cache_misses_total", "node_nfsd_reply_cache_nocache_total",
		"node_nfsd_file_handles_stale_total", "node_nfsd_disk_bytes_read_total", "node_nfsd_disk_bytes_written_total",
		"node_nfsd_server_threads", "node_nfsd_read_ahead_cache_size_blocks", "node_nfsd_read_ahead_cache_not_found_total",
		"node_nfsd_packets_total", "node_nfsd_connections_total", "node_nfsd_rpc_errors_total", "node_nfsd_server_rpcs_total", "node_nfsd_requests_total",
	}})
}

func nfsdFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newNFSdCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	output, err := os.ReadFile("testdata/nfsd/proc/net/rpc/nfsd")
	require.NoError(t, err)
	read := c.Reads()[0]
	return c, agentless.Input{read.ID: {Read: read, Output: output}}
}

func TestNFSdRegistration(t *testing.T) {
	built, err := Build([]string{"nfsd"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "nfsd", built[0].Name())
	require.Contains(t, DefaultEnabled(), "nfsd")
	found := false
	for _, registration := range Registered() {
		if registration.Name == "nfsd" {
			found = true
			require.Equal(t, "linux", registration.OS)
			require.True(t, registration.DefaultEnabled)
		}
	}
	require.True(t, found)
	require.Equal(t, []agentless.Read{agentless.FileRead("/proc/net/rpc/nfsd")}, built[0].Reads())
	require.NoError(t, built[0].Reads()[0].Validate())
}

func TestNFSdReadFailures(t *testing.T) {
	for name, bad := range map[string]agentless.Result{
		"nonzero": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true},
		"missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true},
	} {
		t.Run(name, func(t *testing.T) {
			c, in := nfsdFixture(t)
			read := c.Reads()[0]
			bad.Read = read
			bad.Output = in[read.ID].Output
			in[read.ID] = bad
			ch := make(chan prometheus.Metric, 100)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		})
	}
	c, _ := nfsdFixture(t)
	require.Error(t, c.Update(agentless.Target{}, agentless.Input{}, make(chan prometheus.Metric, 100)))
}

func TestNFSdMalformed(t *testing.T) {
	for i, output := range []string{"", "\n", "rc\n", "rc 1 2\n", "th 1\n", "io -1 2\n", "io 18446744073709551616 0\n", "unknown 1\n", "proc2 18\n", "proc3 1 2\n", "proc4 1 2\n", "proc4ops 39 0\n", "rc 0 0 0\nrc 0 0 0\n", "wdeleg_getattr\n"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c, in := nfsdFixture(t)
			read := c.Reads()[0]
			in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
			ch := make(chan prometheus.Metric, 100)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch)
		})
	}
}

func TestNFSdHostileBoundedRetention(t *testing.T) {
	for _, output := range [][]byte{
		[]byte("proc4ops 25000 " + strings.Repeat("0 ", 25000)),
		[]byte("rc " + strings.Repeat("1", 1<<20)),
		[]byte(strings.Repeat("rc 0 0 0\n", 25000)),
		[]byte("proc4ops 129 " + strings.Repeat("0 ", 129)),
	} {
		allocs := testing.AllocsPerRun(2, func() { _, err := parseNFSd(output); require.Error(t, err) })
		require.Less(t, allocs, 20.0)
	}
	c, in := nfsdFixture(t)
	ch := make(chan prometheus.Metric, 100)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, 87)
	close(ch)
	families := make(map[string]bool)
	for metric := range ch {
		families[metric.Desc().String()] = true
		var value dto.Metric
		require.NoError(t, metric.Write(&value))
		for _, label := range value.Label {
			require.LessOrEqual(t, len(label.GetValue()), 4096)
		}
	}
	require.Len(t, families, 14)
}

func TestNFSdProcedureBounds(t *testing.T) {
	for _, count := range []int{39, 40, 72, 126} {
		_, err := parseNFSd([]byte(fmt.Sprintf("proc4ops %d %s\n", count, strings.Repeat("1 ", count))))
		require.NoError(t, err)
	}
	_, err := parseNFSd([]byte("proc4ops 127 " + strings.Repeat("1 ", 127)))
	require.ErrorContains(t, err, "too many fields")
}

func TestNFSdScraperIsolation(t *testing.T) {
	for _, mode := range []string{"missing", "malformed", "nonzero", "timeout", "truncated", "hostile"} {
		t.Run(mode, func(t *testing.T) {
			c, in := nfsdFixture(t)
			read := c.Reads()[0]
			bad := in[read.ID]
			switch mode {
			case "missing":
				bad.NotExist = true
				bad.ExitStatus = 1
			case "malformed":
				bad.Output = []byte("bad")
			case "nonzero":
				bad.ExitStatus = 2
			case "timeout":
				bad.TimedOut = true
			case "truncated":
				bad.Truncated = true
			case "hostile":
				bad.Output = []byte("proc4ops 25000 " + strings.Repeat("0 ", 25000))
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
				require.False(t, strings.HasPrefix(family.GetName(), "node_nfsd_"))
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
			require.Equal(t, want, success["nfsd"])
		})
	}
}
