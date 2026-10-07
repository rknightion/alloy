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

// Unmodified sys.ttar inputs and e2e-output from node_exporter
// v0.18.1-grafana-r01.0.20251024135609-318b01780c89. All seven sysfs
// families are compared. Ioctl-only device_errors_total (write/read/flush/
// corruption/generation), device_unused_bytes and btrfs_dev_uuid are omitted.
func TestBtrfsConformance(t *testing.T) {
	c, err := newBtrfsCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	conformance.Check(t, conformance.Case{Collector: c, Root: "testdata/btrfs", Expected: "testdata/btrfs/golden.prom", Families: []string{"node_btrfs_info", "node_btrfs_global_rsv_size_bytes", "node_btrfs_reserved_bytes", "node_btrfs_used_bytes", "node_btrfs_size_bytes", "node_btrfs_allocation_ratio", "node_btrfs_device_size_bytes"}})
}
func btrfsFixture(t *testing.T) (*btrfsCollector, agentless.Input) {
	t.Helper()
	c0, err := newBtrfsCollector(DefaultConfigs(), nil)
	require.NoError(t, err)
	c := c0.(*btrfsCollector)
	r, err := agentlesstest.FromFS("testdata/btrfs", nil, c.Reads())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	in := agentless.Input{}
	reads := c.Reads()
	for phase := 0; phase < 3; phase++ {
		results, err := r.Run(ctx, agentless.Target{}, reads)
		require.NoError(t, err)
		for _, res := range results {
			in[res.Read.ID] = res
		}
		if phase == 0 {
			reads, err = c.Expand(agentless.Target{}, in)
		}
		if phase == 1 {
			reads, err = c.ExpandDeep(agentless.Target{}, in)
		}
		require.NoError(t, err)
	}
	return c, in
}
func btrfsSet(in agentless.Input, read agentless.Read, out string) {
	in[read.ID] = agentless.Result{Read: read, Output: []byte(out)}
}
func btrfsRows(count int) string {
	var b strings.Builder
	for i := 0; i < count; i++ {
		fmt.Fprintf(&b, "dev%d\n", i)
	}
	return b.String()
}

const btrfsTestUUID = "0abb23a9-579b-43e6-ad30-227ef47fcb9d"

func btrfsBudgetInput(c *btrfsCollector, count int) agentless.Input {
	in := agentless.Input{}
	btrfsSet(in, c.Reads()[0], btrfsTestUUID+"\n")
	btrfsSet(in, btrfsList(btrfsTestUUID, "devices"), btrfsRows(count))
	for _, group := range btrfsGroups {
		btrfsSet(in, btrfsList(btrfsTestUUID, "allocation/"+group), "")
	}
	return in
}
func TestBtrfsRegistration(t *testing.T) {
	built, err := Build([]string{"btrfs"}, DefaultConfigs(), nil)
	require.NoError(t, err)
	require.Len(t, built, 1)
	require.Contains(t, DefaultEnabled(), "btrfs")
	for _, r := range Registered() {
		if r.Name == "btrfs" {
			require.Equal(t, "linux", r.OS)
			require.True(t, r.DefaultEnabled)
		}
	}
	c, in := btrfsFixture(t)
	second, err := c.Expand(agentless.Target{}, in)
	require.NoError(t, err)
	third, err := c.ExpandDeep(agentless.Target{}, in)
	require.NoError(t, err)
	for _, r := range append(second, third...) {
		require.NoError(t, r.Validate())
	}
	for _, r := range third {
		require.Empty(t, r.Argv)
	}
}
func TestBtrfsBounds(t *testing.T) {
	c, _ := btrfsFixture(t)
	for _, count := range []int{16, 17} {
		in := agentless.Input{}
		var b strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&b, "%08x-0000-0000-0000-000000000000\n", i)
		}
		btrfsSet(in, c.Reads()[0], b.String())
		reads, err := c.Expand(agentless.Target{}, in)
		if count == 16 {
			require.NoError(t, err)
			listings := 0
			for _, r := range reads {
				if len(r.Argv) > 0 {
					listings++
				}
			}
			require.Equal(t, agentless.MaxDeepListings, listings)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, count := range []int{1014, 1015, 4096, 4097} {
		in := btrfsBudgetInput(c, count)
		reads, err := c.ExpandDeep(agentless.Target{}, in)
		if count == 1014 {
			require.NoError(t, err)
			require.Len(t, reads, 1014)
			second, err := c.Expand(agentless.Target{}, in)
			require.NoError(t, err)
			require.Equal(t, agentless.MaxExpandedReads, len(second)+len(reads))
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, size := range []int{4096, 4097} {
		in := agentless.Input{}
		btrfsSet(in, c.Reads()[0], strings.Repeat("x", size)+"\n")
		reads, err := c.Expand(agentless.Target{}, in)
		if size == 4096 {
			require.NoError(t, err)
			require.Empty(t, reads)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, count := range []int{1024, 1025} {
		in := agentless.Input{}
		btrfsSet(in, c.Reads()[0], strings.Repeat("ignored\n", count))
		reads, err := c.Expand(agentless.Target{}, in)
		if count == 1024 {
			require.NoError(t, err)
			require.Empty(t, reads)
		} else {
			require.Error(t, err)
			require.Nil(t, reads)
		}
	}
	for _, out := range []string{"\n", btrfsTestUUID, btrfsTestUUID + "\n" + btrfsTestUUID + "\n"} {
		in := agentless.Input{}
		btrfsSet(in, c.Reads()[0], out)
		reads, err := c.Expand(agentless.Target{}, in)
		require.Error(t, err)
		require.Nil(t, reads)
	}
	in := btrfsBudgetInput(c, 0)
	btrfsSet(in, btrfsList(btrfsTestUUID, "devices"), "dev0\n../escape\nx;id\nx/y\n")
	reads, err := c.ExpandDeep(agentless.Target{}, in)
	require.NoError(t, err)
	require.Len(t, reads, 1)
	// Layout reads share the device and phase-two budget, not a separate cap.
	in = btrfsBudgetInput(c, 1013)
	btrfsSet(in, btrfsList(btrfsTestUUID, "allocation/data"), "single\n")
	reads, err = c.ExpandDeep(agentless.Target{}, in)
	require.Error(t, err)
	require.Nil(t, reads)
}
func btrfsScrape(t *testing.T, in agentless.Input, cs ...agentless.Collector) (map[string]float64, int) {
	t.Helper()
	load := &loadavgCollector{}
	btrfsSet(in, load.Reads()[0], "1 2 3 1/1 1\n")
	cs = append(cs, load)
	runner := &agentlesstest.FakeRunner{Results: in}
	s, err := agentless.NewScraper(runner, cs, nil)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := s.Scrape(ctx, agentless.Target{})
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
			require.Equal(t, 1.0, f.Metric[0].GetGauge().GetValue())
		}
		if strings.HasPrefix(f.GetName(), "node_btrfs_") {
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
	return success, series
}
func TestBtrfsFailuresAtomicAndIsolated(t *testing.T) {
	c, original := btrfsFixture(t)
	second, err := c.Expand(agentless.Target{}, original)
	require.NoError(t, err)
	third, err := c.ExpandDeep(agentless.Target{}, original)
	require.NoError(t, err)
	for _, read := range append(append(c.Reads(), second...), third...) {
		for name, failure := range map[string]agentless.Result{"missing": {NotExist: true, ExitStatus: 1}, "exit": {ExitStatus: 2}, "timeout": {TimedOut: true}, "truncated": {Truncated: true}, "missing timeout": {NotExist: true, TimedOut: true}, "malformed": {Output: []byte("MALFORMED")}} {
			t.Run(read.ID+"/"+name, func(t *testing.T) {
				in := agentless.Input{}
				for k, v := range original {
					in[k] = v
				}
				failure.Read = read
				in[read.ID] = failure
				// Arbitrary short label text is valid, unlike numeric attributes and listings.
				validText := name == "malformed" && strings.HasSuffix(read.Path, "/label")
				ch := make(chan prometheus.Metric, agentless.MaxExpandedReads)
				err := c.Update(agentless.Target{}, in, ch)
				if name == "missing" || validText {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.Empty(t, ch)
				}
				success, series := btrfsScrape(t, in, c)
				if name == "missing" || validText {
					require.Equal(t, 1.0, success["btrfs"])
					if read.ID == c.Reads()[0].ID {
						require.Zero(t, series)
					}
				} else {
					require.Zero(t, success["btrfs"])
					require.Zero(t, series)
				}
			})
		}
	}
	for _, raw := range []string{"-1", "18446744073709551616", strings.Repeat("1", 1<<20), ""} {
		c, in := btrfsFixture(t)
		btrfsSet(in, btrfsFile(btrfsTestUUID, "allocation/global_rsv_size"), raw)
		success, series := btrfsScrape(t, in, c)
		require.Zero(t, success["btrfs"])
		require.Zero(t, series)
	}
	for _, attr := range []string{"label", "metadata_uuid"} {
		c, in := btrfsFixture(t)
		btrfsSet(in, btrfsFile(btrfsTestUUID, attr), strings.Repeat("x", 1<<20))
		success, series := btrfsScrape(t, in, c)
		require.Zero(t, success["btrfs"])
		require.Zero(t, series)
	}
	for _, count := range []int{1015, 4097} {
		c, _ := btrfsFixture(t)
		success, series := btrfsScrape(t, btrfsBudgetInput(c, count), c)
		require.Zero(t, success["btrfs"])
		require.Zero(t, series)
	}
}

// Populate the shared scrape budget through real Expander admission, then prove
// the btrfs third phase is accepted exactly at 4096 and rejected at 4097.
type btrfsBudgetFiller struct{ index, count int }

func (c btrfsBudgetFiller) Name() string          { return fmt.Sprintf("filler%d", c.index) }
func (btrfsBudgetFiller) Reads() []agentless.Read { return nil }
func (btrfsBudgetFiller) Update(agentless.Target, agentless.Input, chan<- prometheus.Metric) error {
	return nil
}
func (c btrfsBudgetFiller) Expand(agentless.Target, agentless.Input) ([]agentless.Read, error) {
	reads := make([]agentless.Read, c.count)
	for i := range reads {
		reads[i] = agentless.FileRead(fmt.Sprintf("/sys/filler%d/attr%d", c.index, i))
	}
	return reads, nil
}
func TestBtrfsScrapeBudgetBoundary(t *testing.T) {
	for _, extra := range []int{0, 1} {
		c, _ := btrfsFixture(t)
		in := btrfsBudgetInput(c, 1014)
		second, err := c.Expand(agentless.Target{}, in)
		require.NoError(t, err)
		third, err := c.ExpandDeep(agentless.Target{}, in)
		require.NoError(t, err)
		for _, read := range append(second, third...) {
			if _, ok := in[read.ID]; !ok {
				in[read.ID] = agentless.Result{Read: read, NotExist: true, ExitStatus: 1}
			}
		}
		cs := []agentless.Collector{btrfsBudgetFiller{0, 1024}, btrfsBudgetFiller{1, 1024}, btrfsBudgetFiller{2, 1024}}
		if extra != 0 {
			cs = append(cs, btrfsBudgetFiller{3, extra})
		}
		cs = append(cs, c)
		success, series := btrfsScrape(t, in, cs...)
		require.Zero(t, series)
		require.Equal(t, float64(1-extra), success["btrfs"])
	}
}
