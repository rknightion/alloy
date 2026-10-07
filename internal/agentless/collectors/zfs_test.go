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

// Fixtures and golden are unchanged fixed-file families from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89. Pool IO, state and
// dataset families (node_zfs_zpool_*) are intentionally not ported.
func TestZFSConformance(t *testing.T) {
	c, in := zfsFixture(t)
	var families []string
	// Enumerate every ported family independently from upstream fixture keys.
	for index, read := range c.Reads() {
		lines := strings.Split(string(in[read.ID].Output), "\n")
		for _, line := range lines[2:] {
			fields := strings.Fields(line)
			if len(fields) == 3 && (fields[1] == "3" || fields[1] == "4") {
				families = append(families, "node_"+zfsFiles[index].subsystem+"_"+strings.ReplaceAll(fields[0], "-", "_"))
			}
		}
	}
	require.Len(t, families, 258)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/zfs", Expected: "testdata/zfs/golden.prom", Families: families})
}

func zfsFixture(t *testing.T) (agentless.Collector, agentless.Input) {
	t.Helper()
	c, err := newZFSCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	in := make(agentless.Input)
	for _, read := range c.Reads() {
		output, err := os.ReadFile("testdata/zfs" + read.Path)
		require.NoError(t, err)
		in[read.ID] = agentless.Result{Read: read, Output: output}
	}
	return c, in
}

func TestZFSRegistrationAndReads(t *testing.T) {
	built, err := Build([]string{"zfs"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Equal(t, "zfs", built[0].Name())
	require.NotContains(t, DefaultEnabled(), "zfs")
	for _, registration := range Registered() {
		if registration.Name == "zfs" {
			require.Equal(t, "linux", registration.OS)
			require.False(t, registration.DefaultEnabled)
		}
	}
	require.Len(t, built[0].Reads(), 11)
	for index, read := range built[0].Reads() {
		require.Equal(t, agentless.FileRead("/proc/spl/kstat/zfs/"+zfsFiles[index].file), read)
		require.NoError(t, read.Validate())
	}
}

func TestZFSReadFailures(t *testing.T) {
	for name, result := range map[string]agentless.Result{
		"missing": {NotExist: true, ExitStatus: 1}, "nonzero": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true},
		"missing timeout": {NotExist: true, TimedOut: true}, "missing truncated": {NotExist: true, Truncated: true},
	} {
		t.Run(name, func(t *testing.T) {
			c, in := zfsFixture(t)
			for _, read := range c.Reads() {
				result.Read = read
				result.Output = in[read.ID].Output
				in[read.ID] = result
			}
			ch := make(chan prometheus.Metric, 500)
			err := c.Update(agentless.Target{}, in, ch)
			if name == "missing" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Empty(t, ch)
		})
	}
	c, _ := zfsFixture(t)
	require.Error(t, c.Update(agentless.Target{}, agentless.Input{}, make(chan prometheus.Metric, 500)))
}

func TestZFSMalformedAndHostile(t *testing.T) {
	header := "name type data\n"
	cases := []string{"", "bad\n", header + "x 4\n", header + "x 4 -1\n", header + "x 4 18446744073709551616\n", header + "x 8 1\n", header + "x 4 1 extra\n", header + "x.y 4 1\n", header + "x-y 4 1\nx_y 4 2\n", header + strings.Repeat("x", 1<<20), header + "x 4 " + strings.Repeat("1 ", 1000000), header + strings.Repeat("ignored 7 text\n", 501)}
	for index, output := range cases {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			c, in := zfsFixture(t)
			read := c.Reads()[len(c.Reads())-1]
			in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
			ch := make(chan prometheus.Metric, 500)
			require.Error(t, c.Update(agentless.Target{}, in, ch))
			require.Empty(t, ch, "no partial metrics from earlier files")
		})
	}
	for _, output := range []string{header + strings.Repeat("x", 1<<20), header + "x 4 " + strings.Repeat("1 ", 1000000)} {
		c, in := zfsFixture(t)
		read := c.Reads()[0]
		in[read.ID] = agentless.Result{Read: read, Output: []byte(output)}
		ch := make(chan prometheus.Metric, 500)
		allocs := testing.AllocsPerRun(3, func() { require.Error(t, c.Update(agentless.Target{}, in, ch)) })
		require.Less(t, allocs, 30.0, "reject before input-sized token retention")
	}
}

func TestZFSTypesAndNames(t *testing.T) {
	c, in := zfsFixture(t)
	for _, read := range c.Reads() {
		in[read.ID] = agentless.Result{Read: read, NotExist: true}
	}
	read := c.Reads()[0]
	in[read.ID] = agentless.Result{Read: read, Output: []byte("name type data\nsigned 3 7\nunsigned-key 4 18446744073709551615\nignored 7 text\n")}
	ch := make(chan prometheus.Metric, 500)
	require.NoError(t, c.Update(agentless.Target{}, in, ch))
	require.Len(t, ch, 2)
	require.Contains(t, (<-ch).Desc().String(), "node_zfs_abd_signed")
	require.Contains(t, (<-ch).Desc().String(), "node_zfs_abd_unsigned_key")
}

func TestZFSScraperIsolation(t *testing.T) {
	for _, mode := range []string{"missing", "malformed", "nonzero", "hostile"} {
		t.Run(mode, func(t *testing.T) {
			c, in := zfsFixture(t)
			if mode == "missing" {
				for _, read := range c.Reads() {
					in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
				}
			} else {
				read := c.Reads()[len(c.Reads())-1]
				bad := in[read.ID]
				switch mode {
				case "malformed":
					bad.Output = append(bad.Output, []byte("bad\n")...)
				case "nonzero":
					bad.ExitStatus = 2
				case "hostile":
					bad.Output = []byte("name type data\n" + strings.Repeat("x 4 1\n", 501))
				}
				in[read.ID] = bad
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
			loadSeen := false
			for _, family := range families {
				require.False(t, strings.HasPrefix(family.GetName(), "node_zfs_"))
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
			require.Equal(t, want, success["zfs"])
		})
	}
}
